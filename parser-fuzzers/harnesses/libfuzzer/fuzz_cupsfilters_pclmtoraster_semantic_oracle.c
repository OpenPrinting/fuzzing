// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/filter.h>
#include <pdfio-content.h>
#include <pdfio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PCLM_SELECTOR_BYTES 1
#define PCLM_MAX_STREAM_BYTES 4096
#define PCLM_MAX_INPUT (PCLM_SELECTOR_BYTES + PCLM_MAX_STREAM_BYTES)
#define PCLM_COMPONENTS 3
#define PCLM_CURRENT_OUTPUT_PAGES 2

typedef struct
{
  unsigned int width;
  unsigned int height;
  unsigned int num_strips;
  unsigned int strip_heights[2];
  int use_flate;
  int mixed_compression;
  uint8_t selector;
} pclm_case_t;

/*
 * Older pclmtoraster revisions neither drained nor closed image streams, so
 * this oracle could close a tracked /Type /image stream after one read.  Newer
 * revisions own that lifecycle themselves; the V3 native-lifecycle build keeps
 * these wrappers observational and never performs the historical early close.
 */
extern pdfio_stream_t *__real_pdfioObjOpenStream(pdfio_obj_t *obj, bool decode);
extern ssize_t __real_pdfioStreamRead(pdfio_stream_t *stream, void *buffer,
                                     size_t bytes);

static pdfio_stream_t *tracked_image_stream;

static int
pclm_trace_streams(void)
{
  static int enabled = -1;

  if (enabled < 0)
    enabled = getenv("CF_V2_TRACE_PCLM_STREAMS") != NULL;
  return (enabled);
}

#ifndef CUPSFILTERS_PCLM_SHOULD_CLOSE_TRACKED_STREAM
#  define CUPSFILTERS_PCLM_SHOULD_CLOSE_TRACKED_STREAM() 1
#endif

#ifdef CUPSFILTERS_PCLM_NATIVE_STREAM_LIFECYCLE
#  undef CUPSFILTERS_PCLM_SHOULD_CLOSE_TRACKED_STREAM
#  define CUPSFILTERS_PCLM_SHOULD_CLOSE_TRACKED_STREAM() 0
#endif

pdfio_stream_t *
__wrap_pdfioObjOpenStream(pdfio_obj_t *obj, bool decode)
{
  pdfio_stream_t *stream = __real_pdfioObjOpenStream(obj, decode);
  const char *type = pdfioObjGetType(obj);

  if (stream && type && strcmp(type, "image") == 0)
    tracked_image_stream = stream;
  if (pclm_trace_streams())
    fprintf(stderr, "pclm-stream: open object=%p stream=%p tracked=%p\n",
            (void *)obj, (void *)stream, (void *)tracked_image_stream);
  return (stream);
}

ssize_t
__wrap_pdfioStreamRead(pdfio_stream_t *stream, void *buffer, size_t bytes)
{
  ssize_t result;

  if (pclm_trace_streams())
    fprintf(stderr, "pclm-stream: read stream=%p tracked=%p bytes=%zu\n",
            (void *)stream, (void *)tracked_image_stream, bytes);
  result = __real_pdfioStreamRead(stream, buffer, bytes);

  if (stream && stream == tracked_image_stream)
  {
    tracked_image_stream = NULL;
    if (CUPSFILTERS_PCLM_SHOULD_CLOSE_TRACKED_STREAM())
    {
      if (pclm_trace_streams())
        fprintf(stderr, "pclm-stream: close stream=%p result=%zd\n",
                (void *)stream, result);
      tracked_image_stream = NULL;
      (void)pdfioStreamClose(stream);
    }
  }
  return (result);
}

static void
fuzz_log(void *data, cf_loglevel_t level, const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static int
fuzz_not_canceled(void *data)
{
  (void)data;
  return (0);
}

static bool
pdfio_error(pdfio_file_t *pdf, const char *message, void *data)
{
  (void)pdf;
  (void)message;
  (void)data;
  return (false);
}

static int
read_all(int fd, uint8_t *buffer, size_t length)
{
  size_t offset = 0;

  while (offset < length)
  {
    ssize_t bytes = read(fd, buffer + offset, length - offset);

    if (bytes < 0 && errno == EINTR)
      continue;
    if (bytes <= 0)
      return (-1);
    offset += (size_t)bytes;
  }

  return (0);
}

static int
write_all_at(int fd, const uint8_t *buffer, size_t length)
{
  size_t offset = 0;

  while (offset < length)
  {
    ssize_t bytes = pwrite(fd, buffer + offset, length - offset, (off_t)offset);

    if (bytes < 0 && errno == EINTR)
      continue;
    if (bytes <= 0)
      return (-1);
    offset += (size_t)bytes;
  }

  return (0);
}

static int
is_pdf_delimiter(uint8_t ch)
{
  return (ch == 0 || ch == '\t' || ch == '\n' || ch == '\f' || ch == '\r' ||
          ch == ' ' || ch == '(' || ch == ')' || ch == '<' || ch == '>' ||
          ch == '[' || ch == ']' || ch == '{' || ch == '}' || ch == '/' ||
          ch == '%');
}

/*
 * pdfioFileCreatePage currently materializes MediaBox in every Page object.
 * pclmtoraster at libcupsfilters 905fd94f takes its deep path only when the
 * Page has no direct MediaBox.  Keep a valid inherited MediaBox on Pages and
 * erase the direct entry in place so that object offsets remain unchanged.
 */
static int
make_mediabox_inherited_only(const char *filename)
{
  static const uint8_t object_marker[] = " obj";
  static const uint8_t end_object_marker[] = "endobj";
  static const uint8_t page_type[] = "/Type/Page";
  static const uint8_t media_box[] = "/MediaBox";
  struct stat status;
  uint8_t *contents = NULL;
  uint8_t *cursor;
  uint8_t *end;
  int fd = -1;
  int patched_pages = 0;
  int result = -1;

  fd = open(filename, O_RDWR | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &status) < 0 || status.st_size <= 0 ||
      (uintmax_t)status.st_size > SIZE_MAX)
    goto cleanup;

  contents = (uint8_t *)malloc((size_t)status.st_size);
  if (!contents || read_all(fd, contents, (size_t)status.st_size) < 0)
    goto cleanup;

  cursor = contents;
  end = contents + (size_t)status.st_size;
  while ((size_t)(end - cursor) >= sizeof(object_marker) - 1)
  {
    uint8_t *object_start =
        (uint8_t *)memmem(cursor, (size_t)(end - cursor), object_marker,
                          sizeof(object_marker) - 1);
    uint8_t *object_end;
    uint8_t *type;
    uint8_t *box;
    uint8_t *box_end;

    if (!object_start)
      break;
    object_end =
        (uint8_t *)memmem(object_start, (size_t)(end - object_start),
                          end_object_marker, sizeof(end_object_marker) - 1);
    if (!object_end)
      goto cleanup;

    type = (uint8_t *)memmem(object_start,
                             (size_t)(object_end - object_start), page_type,
                             sizeof(page_type) - 1);
    if (!type ||
        (type + sizeof(page_type) - 1 < object_end &&
         !is_pdf_delimiter(type[sizeof(page_type) - 1])))
    {
      cursor = object_end + sizeof(end_object_marker) - 1;
      continue;
    }

    box = (uint8_t *)memmem(object_start,
                            (size_t)(object_end - object_start), media_box,
                            sizeof(media_box) - 1);
    if (!box)
      goto cleanup;

    box_end = box + sizeof(media_box) - 1;
    while (box_end < object_end && *box_end != '[')
      box_end ++;
    if (box_end == object_end)
      goto cleanup;
    while (box_end < object_end && *box_end != ']')
      box_end ++;
    if (box_end == object_end)
      goto cleanup;

    memset(box, ' ', (size_t)(box_end - box) + 1);
    patched_pages ++;
    cursor = object_end + sizeof(end_object_marker) - 1;
  }

  if (patched_pages != 1 ||
      write_all_at(fd, contents, (size_t)status.st_size) < 0)
    goto cleanup;

  result = 0;

cleanup:
  free(contents);
  if (fd >= 0)
    close(fd);
  return (result);
}

static void
select_case(uint8_t selector, pclm_case_t *test_case)
{
  static const unsigned int widths[] = {1, 2, 8, 64};
  static const unsigned int heights[] = {1, 2, 16, 17};

  memset(test_case, 0, sizeof(*test_case));
  test_case->selector = selector;
  test_case->height = heights[selector & 3U];
  test_case->width = widths[(selector >> 4) & 3U];
  test_case->use_flate = (selector >> 3) & 1U;
  test_case->mixed_compression = (selector >> 7) & 1U;
  test_case->num_strips = 1;
  test_case->strip_heights[0] = test_case->height;

  if ((selector & 4U) && test_case->height > 1)
  {
    test_case->num_strips = 2;
    if (test_case->height == 2)
    {
      test_case->strip_heights[0] = 1;
      test_case->strip_heights[1] = 1;
    }
    else if (test_case->height == 16)
    {
      test_case->strip_heights[0] = 8;
      test_case->strip_heights[1] = 8;
    }
    else if (selector & 64U)
    {
      test_case->strip_heights[0] = 1;
      test_case->strip_heights[1] = 16;
    }
    else
    {
      test_case->strip_heights[0] = 16;
      test_case->strip_heights[1] = 1;
    }
  }
}

static void
make_pixels(const pclm_case_t *test_case, const uint8_t *payload,
            size_t payload_size, uint8_t *pixels, size_t pixel_bytes)
{
  size_t middle;

  for (size_t i = 0; i < pixel_bytes; i ++)
    pixels[i] = payload[i % payload_size];

  pixels[0] = 0x11;
  pixels[1] = test_case->selector;
  pixels[2] = 0xe1;

  middle = ((pixel_bytes / PCLM_COMPONENTS) / 2) * PCLM_COMPONENTS;
  pixels[middle] = 0x22;
  pixels[middle + 1] = test_case->selector ^ 0x5aU;
  pixels[middle + 2] = 0xd2;

  pixels[pixel_bytes - 3] = 0x33;
  pixels[pixel_bytes - 2] = test_case->selector ^ 0xffU;
  pixels[pixel_bytes - 1] = 0xc3;
}

static int
create_image(pdfio_file_t *pdf, unsigned int width, unsigned int height,
             const uint8_t *pixels, size_t pixel_bytes, int use_flate,
             pdfio_obj_t **image)
{
  pdfio_dict_t *dict;
  pdfio_obj_t *obj;
  pdfio_stream_t *stream;

  if (pixel_bytes > PCLM_MAX_STREAM_BYTES ||
      pixel_bytes != (size_t)width * height * PCLM_COMPONENTS)
    return (-1);

  dict = pdfioDictCreate(pdf);
  if (!dict || !pdfioDictSetName(dict, "Type", "image") ||
      !pdfioDictSetName(dict, "Subtype", "Image") ||
      !pdfioDictSetNumber(dict, "Width", width) ||
      !pdfioDictSetNumber(dict, "Height", height) ||
      !pdfioDictSetName(dict, "ColorSpace", "DeviceRGB") ||
      !pdfioDictSetNumber(dict, "BitsPerComponent", 8) ||
      (use_flate && !pdfioDictSetName(dict, "Filter", "FlateDecode")))
    return (-1);

  obj = pdfioFileCreateObj(pdf, dict);
  if (!obj)
    return (-1);

  stream = pdfioObjCreateStream(
      obj, use_flate ? PDFIO_FILTER_FLATE : PDFIO_FILTER_NONE);
  if (!stream || !pdfioStreamWrite(stream, pixels, pixel_bytes) ||
      !pdfioStreamClose(stream))
    return (-1);

  *image = obj;
  return (0);
}

static int
verify_deep_gate(const char *filename, unsigned int expected_strips)
{
  pdfio_file_t *pdf = NULL;
  pdfio_obj_t *page;
  pdfio_obj_t *parent;
  pdfio_dict_t *page_dict;
  pdfio_dict_t *resources;
  pdfio_dict_t *xobjects;
  pdfio_rect_t rect;
  int result = -1;

  pdf = pdfioFileOpen(filename, NULL, NULL, pdfio_error, NULL);
  if (!pdf || pdfioFileGetNumPages(pdf) != 1)
    goto cleanup;

  page = pdfioFileGetPage(pdf, 0);
  page_dict = pdfioObjGetDict(page);
  if (!page_dict || pdfioDictGetRect(page_dict, "MediaBox", &rect) != NULL)
    goto cleanup;

  parent = pdfioDictGetObj(page_dict, "Parent");
  if (!parent ||
      pdfioDictGetRect(pdfioObjGetDict(parent), "MediaBox", &rect) == NULL)
    goto cleanup;

  resources = pdfioDictGetDict(page_dict, "Resources");
  xobjects = resources ? pdfioDictGetDict(resources, "XObject") : NULL;
  if (!xobjects || pdfioDictGetNumPairs(xobjects) != expected_strips)
    goto cleanup;

  result = 0;

cleanup:
  if (pdf)
    pdfioFileClose(pdf);
  return (result);
}

static int
build_pclm_pdf(const char *filename, const pclm_case_t *test_case,
               const uint8_t *pixels)
{
  pdfio_rect_t media_box = {0.0, 0.0, 612.0, 792.0};
  pdfio_file_t *pdf = NULL;
  pdfio_dict_t *catalog;
  pdfio_obj_t *pages;
  pdfio_dict_t *page_dict;
  pdfio_stream_t *page_stream;
  char names[2][16];
  size_t pixel_offset = 0;
  int result = -1;

  pdf = pdfioFileCreate(filename, "PCLm-1.0", &media_box, &media_box,
                        pdfio_error, NULL);
  if (!pdf)
    goto cleanup;

  catalog = pdfioFileGetCatalog(pdf);
  pages = catalog ? pdfioDictGetObj(catalog, "Pages") : NULL;
  if (!pages ||
      !pdfioDictSetRect(pdfioObjGetDict(pages), "MediaBox", &media_box))
    goto cleanup;

  page_dict = pdfioDictCreate(pdf);
  if (!page_dict)
    goto cleanup;

  for (unsigned int i = 0; i < test_case->num_strips; i ++)
  {
    pdfio_obj_t *image = NULL;
    size_t strip_bytes =
        (size_t)test_case->width * test_case->strip_heights[i] *
        PCLM_COMPONENTS;
    int strip_flate = test_case->use_flate;

    if (test_case->mixed_compression && i)
      strip_flate = !strip_flate;

    if (create_image(pdf, test_case->width, test_case->strip_heights[i],
                     pixels + pixel_offset, strip_bytes, strip_flate,
                     &image) < 0)
      goto cleanup;

    snprintf(names[i], sizeof(names[i]), "Strip%02u", i);
    if (!pdfioPageDictAddImage(page_dict, names[i], image))
      goto cleanup;
    pixel_offset += strip_bytes;
  }

  page_stream = pdfioFileCreatePage(pdf, page_dict);
  if (!page_stream || !pdfioStreamWrite(page_stream, "q\nQ\n", 4) ||
      !pdfioStreamClose(page_stream))
    goto cleanup;

  if (!pdfioFileClose(pdf))
  {
    pdf = NULL;
    goto cleanup;
  }
  pdf = NULL;

  if (make_mediabox_inherited_only(filename) < 0 ||
      verify_deep_gate(filename, test_case->num_strips) < 0)
    goto cleanup;

  result = 0;

cleanup:
  if (pdf)
    pdfioFileClose(pdf);
  return (result);
}

static void
init_filter_data(cf_filter_data_t *filter_data,
                 cups_page_header_t *sample_header)
{
  memset(sample_header, 0, sizeof(*sample_header));
  sample_header->HWResolution[0] = 300;
  sample_header->HWResolution[1] = 300;
  sample_header->PageSize[0] = 612;
  sample_header->PageSize[1] = 792;
  sample_header->cupsPageSize[0] = 612.0f;
  sample_header->cupsPageSize[1] = 792.0f;
  sample_header->cupsImagingBBox[2] = 612.0f;
  sample_header->cupsImagingBBox[3] = 792.0f;
  sample_header->ImagingBoundingBox[2] = 612;
  sample_header->ImagingBoundingBox[3] = 792;
  sample_header->cupsBitsPerColor = 8;
  sample_header->cupsBitsPerPixel = 24;
  sample_header->cupsNumColors = PCLM_COMPONENTS;
  sample_header->cupsColorOrder = CUPS_ORDER_CHUNKED;
  sample_header->cupsColorSpace = CUPS_CSPACE_RGB;
  memcpy(sample_header->cupsPageSizeName, "Letter", sizeof("Letter"));

  memset(filter_data, 0, sizeof(*filter_data));
  filter_data->printer = (char *)"oss-fuzz";
  filter_data->job_id = 1;
  filter_data->job_user = (char *)"fuzzer";
  filter_data->job_title = (char *)"pclmtoraster-semantic-oracle";
  filter_data->copies = 1;
  filter_data->content_type = (char *)"application/pdf";
  filter_data->final_content_type =
      (char *)"application/vnd.cups-raster";
  filter_data->header = sample_header;
  filter_data->back_pipe[0] = filter_data->back_pipe[1] = -1;
  filter_data->side_pipe[0] = filter_data->side_pipe[1] = -1;
  filter_data->logfunc = fuzz_log;
  filter_data->iscanceledfunc = fuzz_not_canceled;
}

static int
pixels_match(const uint8_t *actual, const uint8_t *expected, size_t length)
{
  size_t middle = ((length / PCLM_COMPONENTS) / 2) * PCLM_COMPONENTS;

  if (length < PCLM_COMPONENTS ||
      memcmp(actual, expected, length) != 0 ||
      memcmp(actual, expected, PCLM_COMPONENTS) != 0 ||
      memcmp(actual + middle, expected + middle, PCLM_COMPONENTS) != 0 ||
      memcmp(actual + length - PCLM_COMPONENTS,
             expected + length - PCLM_COMPONENTS, PCLM_COMPONENTS) != 0)
    return (0);

  return (1);
}

static int
validate_raster(const char *filename, const pclm_case_t *test_case,
                const uint8_t *expected_pixels, size_t expected_bytes)
{
  cups_raster_t *raster = NULL;
  cups_page_header2_t header;
  uint8_t *pixels = NULL;
  unsigned int expected_bpl = test_case->width * PCLM_COMPONENTS;
  unsigned int page_count = 0;
  int fd = -1;
  int result = -1;

  fd = open(filename, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    goto cleanup;
  raster = cupsRasterOpen(fd, CUPS_RASTER_READ);
  if (!raster)
    goto cleanup;

  while (cupsRasterReadHeader2(raster, &header))
  {
    if (page_count >= PCLM_CURRENT_OUTPUT_PAGES ||
        header.cupsWidth != test_case->width ||
        header.cupsHeight != test_case->height ||
        header.cupsBytesPerLine != expected_bpl ||
        header.cupsBitsPerColor != 8 || header.cupsBitsPerPixel != 24 ||
        header.cupsNumColors != PCLM_COMPONENTS ||
        header.cupsColorOrder != CUPS_ORDER_CHUNKED ||
        header.cupsColorSpace != CUPS_CSPACE_RGB ||
        expected_bytes != (size_t)expected_bpl * test_case->height)
      goto cleanup;

    pixels = (uint8_t *)malloc(expected_bytes);
    if (!pixels)
      goto cleanup;

    for (unsigned int row = 0; row < test_case->height; row ++)
    {
      if (cupsRasterReadPixels(raster, pixels + (size_t)row * expected_bpl,
                               expected_bpl) != expected_bpl)
        goto cleanup;
    }

    if (!pixels_match(pixels, expected_pixels, expected_bytes))
      goto cleanup;

    free(pixels);
    pixels = NULL;
    page_count ++;
  }

  /*
   * libcupsfilters 905fd94f invokes out_page() twice for every input page.
   * This continuation oracle validates both copies.  Requiring the semantic
   * one-input/one-output invariant would trap on every valid test case and
   * prevent fuzzing the strip, conversion, and raster serialization paths.
   */
  if (page_count != PCLM_CURRENT_OUTPUT_PAGES)
    goto cleanup;

  result = 0;

cleanup:
  free(pixels);
  if (raster)
    cupsRasterClose(raster);
  if (fd >= 0)
    close(fd);
  return (result);
}

#ifndef CUPSFILTERS_PCLM_SEMANTIC_ORACLE_SUPPORT_ONLY
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  pclm_case_t test_case;
  cf_filter_data_t filter_data;
  cf_filter_out_format_t output_format = CF_FILTER_OUT_FORMAT_CUPS_RASTER;
  cups_page_header_t sample_header;
  uint8_t *pixels = NULL;
  size_t pixel_bytes;
  int inputfd = -1;
  int outputfd = -1;
  int filter_result;
  int oracle_failed = 0;
  int construction_complete = 0;
  char input_name[] = "/tmp/pclmtoraster-oracle-input.XXXXXX";
  char output_name[] = "/tmp/pclmtoraster-oracle-output.XXXXXX";

  if (size <= PCLM_SELECTOR_BYTES || size > PCLM_MAX_INPUT)
    return (0);

  tracked_image_stream = NULL;
  select_case(data[0], &test_case);
  pixel_bytes =
      (size_t)test_case.width * test_case.height * PCLM_COMPONENTS;
  if (!pixel_bytes || pixel_bytes > PCLM_MAX_STREAM_BYTES)
    return (0);

  pixels = (uint8_t *)malloc(pixel_bytes);
  if (!pixels)
    goto cleanup;
  make_pixels(&test_case, data + PCLM_SELECTOR_BYTES,
              size - PCLM_SELECTOR_BYTES, pixels, pixel_bytes);

  inputfd = mkstemp(input_name);
  if (inputfd < 0)
    goto cleanup;
  close(inputfd);
  inputfd = -1;
  if (build_pclm_pdf(input_name, &test_case, pixels) < 0)
    goto cleanup;

  outputfd = mkstemp(output_name);
  if (outputfd < 0)
    goto cleanup;
  if (ftruncate(outputfd, 0) < 0)
    goto cleanup;

  inputfd = open(input_name, O_RDONLY | O_CLOEXEC);
  if (inputfd < 0)
    goto cleanup;

  init_filter_data(&filter_data, &sample_header);
  construction_complete = 1;
  filter_result = cfFilterPCLmToRaster(inputfd, outputfd, 1, &filter_data,
                                       &output_format);
  inputfd = -1;
  if (close(outputfd) < 0)
    oracle_failed = 1;
  outputfd = -1;

  if (filter_result != 0 ||
      validate_raster(output_name, &test_case, pixels, pixel_bytes) < 0)
    oracle_failed = 1;

cleanup:
  if (outputfd >= 0)
    close(outputfd);
  if (inputfd >= 0)
    close(inputfd);
  unlink(output_name);
  unlink(input_name);
  free(pixels);

  if (construction_complete && oracle_failed)
    __builtin_trap();
  return (0);
}
#endif
