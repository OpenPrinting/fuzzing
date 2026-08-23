// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <config.h>

#include <arpa/inet.h>
#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/colormanager.h>
#include <cupsfilters/filter.h>
#include <cupsfilters/image.h>
#include <cupsfilters/ipp.h>
#include <cupsfilters/libcups2-private.h>
#include <fcntl.h>
#include <lcms2.h>
#include <limits.h>
#include <math.h>
#include <pdfio-content.h>
#include <pdfio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#define CF_V2_PWG_PDF_MAGIC "PWGPDF01"
#define CF_V2_PWG_PDF_MAGIC_SIZE 8U
#define CF_V2_PWG_PDF_SELECTORS 12U
#define CF_V2_PWG_PDF_MAX_MATERIAL 4096U
#define CF_V2_PWG_PDF_MAX_TRACKED 4096U
#define CF_V2_PWG_PDF_MAX_OUTPUT (8U * 1024U * 1024U)

#ifndef CF_V2_PWG_TO_PDF_SOURCE
#error "CF_V2_PWG_TO_PDF_SOURCE must name pwgtopdf.c"
#endif

typedef struct cf_v2_pwg_pdf_format_s {
  cups_cspace_t color_space;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
  unsigned num_colors;
} cf_v2_pwg_pdf_format_t;

typedef struct cf_v2_pwg_pdf_page_s {
  unsigned width;
  unsigned height;
  unsigned bytes_per_line;
  const cf_v2_pwg_pdf_format_t *format;
} cf_v2_pwg_pdf_page_t;

typedef struct cf_v2_pwg_pdf_expected_s {
  unsigned page_count;
  cf_v2_pwg_pdf_page_t pages[3];
} cf_v2_pwg_pdf_expected_t;

typedef struct cf_v2_pwg_pdf_error_s {
  bool saw_error;
} cf_v2_pwg_pdf_error_t;

static void *cf_v2_pwg_pdf_tracked[CF_V2_PWG_PDF_MAX_TRACKED];
static size_t cf_v2_pwg_pdf_tracked_count;
static bool cf_v2_pwg_pdf_tracker_overflow;

static size_t cf_v2_pwg_pdf_find(void *pointer) {
  for (size_t index = 0; index < cf_v2_pwg_pdf_tracked_count; index++) {
    if (cf_v2_pwg_pdf_tracked[index] == pointer) {
      return index;
    }
  }
  return SIZE_MAX;
}

static void cf_v2_pwg_pdf_track(void *pointer) {
  if (!pointer || cf_v2_pwg_pdf_find(pointer) != SIZE_MAX) {
    return;
  }
  if (cf_v2_pwg_pdf_tracked_count >= CF_V2_PWG_PDF_MAX_TRACKED) {
    cf_v2_pwg_pdf_tracker_overflow = true;
    return;
  }
  cf_v2_pwg_pdf_tracked[cf_v2_pwg_pdf_tracked_count++] = pointer;
}

static void cf_v2_pwg_pdf_forget(void *pointer) {
  size_t index = cf_v2_pwg_pdf_find(pointer);

  if (index == SIZE_MAX) {
    return;
  }
  cf_v2_pwg_pdf_tracked[index] =
      cf_v2_pwg_pdf_tracked[--cf_v2_pwg_pdf_tracked_count];
  cf_v2_pwg_pdf_tracked[cf_v2_pwg_pdf_tracked_count] = NULL;
}

static void *cf_v2_pwg_pdf_malloc(size_t size) {
  void *pointer = malloc(size);

  cf_v2_pwg_pdf_track(pointer);
  return pointer;
}

static void *cf_v2_pwg_pdf_calloc(size_t count, size_t size) {
  void *pointer = calloc(count, size);

  cf_v2_pwg_pdf_track(pointer);
  return pointer;
}

static void *cf_v2_pwg_pdf_realloc(void *pointer, size_t size) {
  size_t index = cf_v2_pwg_pdf_find(pointer);
  void *replacement = realloc(pointer, size);

  if (!replacement) {
    if (size == 0U) {
      cf_v2_pwg_pdf_forget(pointer);
    }
    return NULL;
  }
  if (index == SIZE_MAX) {
    cf_v2_pwg_pdf_track(replacement);
  } else {
    cf_v2_pwg_pdf_tracked[index] = replacement;
  }
  return replacement;
}

static char *cf_v2_pwg_pdf_strdup(const char *value) {
  size_t length = strlen(value) + 1U;
  char *copy = (char *)malloc(length);

  if (copy) {
    memcpy(copy, value, length);
    cf_v2_pwg_pdf_track(copy);
  }
  return copy;
}

static void cf_v2_pwg_pdf_free(void *pointer) {
  cf_v2_pwg_pdf_forget(pointer);
  free(pointer);
}

static void cf_v2_pwg_pdf_release_source_allocations(void) {
  while (cf_v2_pwg_pdf_tracked_count) {
    free(cf_v2_pwg_pdf_tracked[--cf_v2_pwg_pdf_tracked_count]);
    cf_v2_pwg_pdf_tracked[cf_v2_pwg_pdf_tracked_count] = NULL;
  }
}

/* Compile an isolated copy so only allocations owned by pwgtopdf.c receive
 * the lifecycle continuation. The linked faithful filter remains unchanged. */
#define init_pdf_info cf_v2_pwg_pdf_init_info
#define free_pdf_info cf_v2_pwg_pdf_free_info
#define split_strings cf_v2_pwg_pdf_split_strings
#define int_to_fwstring cf_v2_pwg_pdf_int_to_fwstring
#define cfFilterPWGToPDF cf_v2_pwg_pdf_filter
#define malloc cf_v2_pwg_pdf_malloc
#define calloc cf_v2_pwg_pdf_calloc
#define realloc cf_v2_pwg_pdf_realloc
#define strdup cf_v2_pwg_pdf_strdup
#define free cf_v2_pwg_pdf_free
#include CF_V2_PWG_TO_PDF_SOURCE
#undef free
#undef strdup
#undef realloc
#undef calloc
#undef malloc
#undef cfFilterPWGToPDF
#undef int_to_fwstring
#undef split_strings
#undef free_pdf_info
#undef init_pdf_info

#define CF_V2_FILTER_FUNCTION cf_v2_pwg_pdf_filter
#define CF_V2_TARGET_NAME "fuzz_v2_cupsfilters_state_pwg_to_pdf_page_writer"
#define CF_V2_INPUT_MIME "image/pwg-raster"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_OUTPUT_FORMAT CF_FILTER_OUT_FORMAT_PDF
#define LLVMFuzzerTestOneInput cf_v2_pwg_pdf_unused_direct_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

static const unsigned cf_v2_pwg_pdf_widths[] = {
    1U, 2U, 7U, 8U, 15U, 16U, 31U, 32U, 63U, 127U,
};
static const unsigned cf_v2_pwg_pdf_heights[] = {
    1U, 2U, 3U, 15U, 16U, 17U, 31U, 32U, 33U, 64U,
};
static const unsigned cf_v2_pwg_pdf_dpi[] = {72U, 150U, 300U, 600U};
static const char *const cf_v2_pwg_pdf_intents[] = {
    "Perceptual", "Relative", "Saturation", "Absolute", "RelativeBpc",
};
static const cf_v2_pwg_pdf_format_t cf_v2_pwg_pdf_formats[] = {
    {CUPS_CSPACE_K, 8U, 8U, 1U},
    {CUPS_CSPACE_K, 16U, 16U, 1U},
    {CUPS_CSPACE_RGB, 8U, 24U, 3U},
    {CUPS_CSPACE_RGB, 16U, 48U, 3U},
    {CUPS_CSPACE_SRGB, 8U, 24U, 3U},
    {CUPS_CSPACE_ADOBERGB, 8U, 24U, 3U},
    {CUPS_CSPACE_CMYK, 8U, 32U, 4U},
    {CUPS_CSPACE_CMYK, 16U, 64U, 4U},
};

static uint8_t cf_v2_pwg_pdf_material(const uint8_t *material,
                                      size_t material_size,
                                      unsigned pattern, unsigned page,
                                      size_t offset) {
  uint8_t value = material_size
                      ? material[(offset + (size_t)page * 257U) % material_size]
                      : (uint8_t)(offset * 131U + page * 67U);

  switch (pattern % 6U) {
    case 0U:
      return value;
    case 1U:
      return 0x00U;
    case 2U:
      return 0xffU;
    case 3U:
      return offset & 1U ? 0xaaU : 0x55U;
    case 4U:
      return (uint8_t)(offset & 0xffU);
    default:
      return (uint8_t)(value ^ (uint8_t)(offset * 17U + page * 29U));
  }
}

static void cf_v2_pwg_pdf_page_state(
    const uint8_t selectors[CF_V2_PWG_PDF_SELECTORS], unsigned page,
    cf_v2_pwg_pdf_page_t *state) {
  size_t page_delta = selectors[7] & 1U ? page : 0U;
  size_t width_index = selectors[0] + page_delta * (1U + selectors[8] % 5U);
  size_t height_index = selectors[1] + page_delta * (1U + selectors[9] % 5U);
  size_t format_index = selectors[2] + page_delta * (1U + selectors[10] % 7U);

  state->width = cf_v2_pwg_pdf_widths[
      width_index % (sizeof(cf_v2_pwg_pdf_widths) /
                     sizeof(cf_v2_pwg_pdf_widths[0]))];
  state->height = cf_v2_pwg_pdf_heights[
      height_index % (sizeof(cf_v2_pwg_pdf_heights) /
                      sizeof(cf_v2_pwg_pdf_heights[0]))];
  state->format = &cf_v2_pwg_pdf_formats[
      format_index % (sizeof(cf_v2_pwg_pdf_formats) /
                      sizeof(cf_v2_pwg_pdf_formats[0]))];
  state->bytes_per_line =
      (state->width * state->format->bits_per_pixel + 7U) / 8U;
}

static uint8_t *cf_v2_pwg_pdf_document(
    const uint8_t selectors[CF_V2_PWG_PDF_SELECTORS],
    const uint8_t *material, size_t material_size,
    cf_v2_pwg_pdf_expected_t *expected, size_t *document_size) {
  unsigned x_dpi = cf_v2_pwg_pdf_dpi[selectors[3] % 4U];
  unsigned y_dpi = cf_v2_pwg_pdf_dpi[(selectors[3] >> 4U) % 4U];
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;

  expected->page_count = 1U + selectors[4] % 3U;
  for (unsigned page = 0; page < expected->page_count; page++) {
    cf_v2_pwg_pdf_page_state(selectors, page, &expected->pages[page]);
    total += sizeof(cups_page_header2_t) +
             (size_t)expected->pages[page].height *
                 expected->pages[page].bytes_per_line;
  }
  document = (uint8_t *)malloc(total);
  if (!document) {
    return NULL;
  }
  memcpy(document, "3SaR", 4U);
  for (unsigned page = 0; page < expected->page_count; page++) {
    const cf_v2_pwg_pdf_page_t *state = &expected->pages[page];
    cups_page_header2_t header;
    size_t page_bytes =
        (size_t)state->height * state->bytes_per_line;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "Plain", sizeof("Plain"));
    memcpy(header.cupsPageSizeName, "Tiny", sizeof("Tiny"));
    header.HWResolution[0] = x_dpi;
    header.HWResolution[1] = y_dpi;
    header.PageSize[0] =
        (unsigned)((uint64_t)state->width * 72U / x_dpi);
    header.PageSize[1] =
        (unsigned)((uint64_t)state->height * 72U / y_dpi);
    header.ImagingBoundingBox[2] = state->width;
    header.ImagingBoundingBox[3] = state->height;
    header.cupsPageSize[0] =
        (float)state->width * 72.0f / (float)x_dpi;
    header.cupsPageSize[1] =
        (float)state->height * 72.0f / (float)y_dpi;
    header.cupsImagingBBox[2] = header.cupsPageSize[0];
    header.cupsImagingBBox[3] = header.cupsPageSize[1];
    header.cupsWidth = state->width;
    header.cupsHeight = state->height;
    header.cupsBitsPerColor = state->format->bits_per_color;
    header.cupsBitsPerPixel = state->format->bits_per_pixel;
    header.cupsBytesPerLine = state->bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = state->format->color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = state->format->num_colors;
    header.NumCopies = 1U;
    header.Duplex = selectors[8] & 1U;
    header.Tumble = (selectors[8] >> 1U) & 1U;
    header.Orientation = (cups_orient_t)(selectors[9] % 4U);
    snprintf(header.cupsRenderingIntent, sizeof(header.cupsRenderingIntent),
             "%s", cf_v2_pwg_pdf_intents[selectors[5] % 5U]);
    header.cupsInteger[CUPS_RASTER_PWG_CrossFeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_FeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] = state->width;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] = state->height;
    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);
    for (size_t index = 0; index < page_bytes; index++) {
      document[offset + index] = cf_v2_pwg_pdf_material(
          material, material_size, selectors[6] + selectors[11], page,
          index);
    }
    offset += page_bytes;
  }
  *document_size = total;
  return document;
}

static bool cf_v2_pwg_pdf_error(pdfio_file_t *pdf, const char *message,
                                void *data) {
  cf_v2_pwg_pdf_error_t *error = (cf_v2_pwg_pdf_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static pdfio_dict_t *cf_v2_pwg_pdf_resolved_dict(pdfio_dict_t *parent,
                                                  const char *key) {
  if (!parent) {
    return NULL;
  }
  if (pdfioDictGetType(parent, key) == PDFIO_VALTYPE_DICT) {
    return pdfioDictGetDict(parent, key);
  }
  if (pdfioDictGetType(parent, key) == PDFIO_VALTYPE_INDIRECT) {
    pdfio_obj_t *object = pdfioDictGetObj(parent, key);
    return object ? pdfioObjGetDict(object) : NULL;
  }
  return NULL;
}

static bool cf_v2_pwg_pdf_content_stream(pdfio_obj_t *page) {
  pdfio_stream_t *stream;
  char token[256];
  bool saw_image = false;
  bool saw_draw = false;
  size_t tokens = 0;

  if (pdfioPageGetNumStreams(page) != 1U ||
      !(stream = pdfioPageOpenStream(page, 0U, true))) {
    return false;
  }
  while (tokens++ < 64U && pdfioStreamGetToken(stream, token, sizeof(token))) {
    saw_image |= strcmp(token, "/I") == 0;
    saw_draw |= strcmp(token, "Do") == 0;
  }
  if (!pdfioStreamClose(stream)) {
    return false;
  }
  return saw_image && saw_draw;
}

static bool cf_v2_pwg_pdf_image_stream(pdfio_obj_t *image,
                                       size_t expected_size) {
  pdfio_stream_t *stream = pdfioObjOpenStream(image, true);
  uint8_t buffer[4096];
  size_t total = 0;
  ssize_t bytes;

  if (!stream) {
    return false;
  }
  while ((bytes = pdfioStreamRead(stream, buffer, sizeof(buffer))) > 0) {
    total += (size_t)bytes;
    if (total > expected_size) {
      break;
    }
  }
  if (bytes < 0 || !pdfioStreamClose(stream)) {
    return false;
  }
  if (total != expected_size) {
    fprintf(stderr, "pwg-pdf-image-stream: expected=%zu decoded=%zu\n",
            expected_size, total);
  }
  return total == expected_size;
}

static bool cf_v2_pwg_pdf_validate(const char *path,
                                   const cf_v2_pwg_pdf_expected_t *expected,
                                   const char **failure) {
  cf_v2_pwg_pdf_error_t error = {false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_pwg_pdf_error, &error);
  bool valid = false;

#define CF_V2_PWG_PDF_REQUIRE(condition, reason) \
  do {                                             \
    if (!(condition)) {                            \
      *failure = (reason);                         \
      goto done;                                   \
    }                                              \
  } while (0)

  CF_V2_PWG_PDF_REQUIRE(pdf && !error.saw_error, "pdf-open");
  CF_V2_PWG_PDF_REQUIRE(pdfioFileGetNumPages(pdf) == expected->page_count,
                        "page-count");
  for (unsigned index = 0; index < expected->page_count; index++) {
    const cf_v2_pwg_pdf_page_t *state = &expected->pages[index];
    pdfio_obj_t *page = pdfioFileGetPage(pdf, index);
    pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
    pdfio_dict_t *resources;
    pdfio_dict_t *xobjects;
    pdfio_obj_t *image;
    pdfio_dict_t *image_dict;
    pdfio_rect_t media_box;
    size_t expected_bytes =
        (size_t)state->height * state->bytes_per_line;

    CF_V2_PWG_PDF_REQUIRE(
        page_dict && pdfioPageGetRect(page, "MediaBox", &media_box) &&
            isfinite(media_box.x1) && isfinite(media_box.y1) &&
            isfinite(media_box.x2) && isfinite(media_box.y2) &&
            media_box.x2 > media_box.x1 && media_box.y2 > media_box.y1,
        "media-box");
    CF_V2_PWG_PDF_REQUIRE(cf_v2_pwg_pdf_content_stream(page),
                          "page-content");
    resources = cf_v2_pwg_pdf_resolved_dict(page_dict, "Resources");
    xobjects = cf_v2_pwg_pdf_resolved_dict(resources, "XObject");
    image = xobjects ? pdfioDictGetObj(xobjects, "I") : NULL;
    image_dict = image ? pdfioObjGetDict(image) : NULL;
    CF_V2_PWG_PDF_REQUIRE(
        image_dict && pdfioObjGetSubtype(image) &&
            strcmp(pdfioObjGetSubtype(image), "Image") == 0 &&
            pdfioDictGetNumber(image_dict, "Width") == (double)state->width &&
            pdfioDictGetNumber(image_dict, "Height") ==
                (double)state->height &&
            pdfioDictGetNumber(image_dict, "BitsPerComponent") ==
                (double)state->format->bits_per_color,
        "image-object");
    CF_V2_PWG_PDF_REQUIRE(
        cf_v2_pwg_pdf_image_stream(image, expected_bytes), "image-stream");
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    *failure = "pdf-close";
    valid = false;
  }
#undef CF_V2_PWG_PDF_REQUIRE
  return valid && !error.saw_error;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  size_t document_size = 0;
  uint8_t *document = NULL;
  cf_v2_pwg_pdf_expected_t expected;
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-pwg-pdf.XXXXXX";
  const char *failure = NULL;
  int output_fd = -1;
  int executed;
  bool trap_after_cleanup = false;

  memset(&expected, 0, sizeof(expected));
  memset(&control, 0, sizeof(control));
  memset(&result, 0, sizeof(result));
  if (!data ||
      size < CF_V2_PWG_PDF_MAGIC_SIZE + CF_V2_PWG_PDF_SELECTORS + 1U ||
      size > CF_V2_PWG_PDF_MAGIC_SIZE + CF_V2_PWG_PDF_SELECTORS +
                 CF_V2_PWG_PDF_MAX_MATERIAL ||
      memcmp(data, CF_V2_PWG_PDF_MAGIC, CF_V2_PWG_PDF_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_PWG_PDF_MAGIC_SIZE;
  material = selectors + CF_V2_PWG_PDF_SELECTORS;
  material_size = size - CF_V2_PWG_PDF_MAGIC_SIZE -
                  CF_V2_PWG_PDF_SELECTORS;
  document = cf_v2_pwg_pdf_document(selectors, material, material_size,
                                    &expected, &document_size);
  if (!document) {
    return 0;
  }
  control.page_size = selectors[0];
  control.color_model = selectors[2];
  control.resolution = selectors[3];
  control.sides = selectors[8];
  control.orientation = selectors[9];
  control.scaling = selectors[10];
  control.media_type = selectors[11];

  executed = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &result);
  cf_v2_pwg_pdf_release_source_allocations();
  if (cf_v2_pwg_pdf_tracker_overflow) {
    failure = "source-allocation-tracker-overflow";
    trap_after_cleanup = true;
  } else if (executed && result.status != 0) {
    failure = "filter-status";
    trap_after_cleanup = true;
  } else if (executed &&
             (!result.captured || result.output_size == 0U ||
              result.output_size > CF_V2_PWG_PDF_MAX_OUTPUT)) {
    failure = "captured-output-bounds";
    trap_after_cleanup = true;
  } else if (executed) {
    output_fd = mkstemp(output_path);
    if (output_fd >= 0 &&
        cf_v2_write_all(output_fd, result.output, result.output_size) == 0 &&
        close(output_fd) == 0) {
      output_fd = -1;
      trap_after_cleanup =
          !cf_v2_pwg_pdf_validate(output_path, &expected, &failure);
    } else {
      output_fd = -1;
    }
  }

  if (output_fd >= 0) {
    close(output_fd);
  }
  unlink(output_path);
  cf_v2_free_run_result(&result);
  free(document);
  cf_v2_pwg_pdf_tracker_overflow = false;
  if (trap_after_cleanup) {
    fprintf(stderr, "pwg-pdf-page-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
