// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "pwg_filter_adapter.h"
#include "pwg_route.h"
#include "pwg_route_bridge.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"
#include "../../v2/include/profiles.h"

#include <cups/raster.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_PWG_PAGE_MAGIC "PWGPDF01"
#define CF_V3_PWG_PAGE_SELECTORS 12U

extern int cf_v3_pwg_direct_pdf_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pwg_direct_pclm_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pwg_job_pdf_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pwg_job_pclm_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pwg_page_writer_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pwg_strip_partition_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pwg_flate_object_legacy(const uint8_t *data, size_t size);

typedef struct cf_v3_pwg_format_s
{
  cups_cspace_t color_space;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
  unsigned num_colors;
} cf_v3_pwg_format_t;

static const unsigned cf_v3_pwg_widths[] = {
  1U, 2U, 7U, 8U, 15U, 16U, 31U, 32U, 63U, 127U,
  255U, 256U, 511U, 512U
};
static const unsigned cf_v3_pwg_heights[] = {
  1U, 2U, 3U, 15U, 16U, 17U, 31U, 32U, 33U, 64U,
  65U, 127U, 128U, 255U
};
static const unsigned cf_v3_pwg_dpi[] = {72U, 150U, 300U, 600U};
static const unsigned cf_v3_pwg_strip_heights[] = {0U, 1U, 2U, 7U, 16U, 32U};
static const char *const cf_v3_pwg_intents[] = {
  "Perceptual", "Relative", "Saturation", "Absolute", "RelativeBpc"
};
static const cf_v3_pwg_format_t cf_v3_pwg_formats[] = {
  {CUPS_CSPACE_K, 1U, 1U, 1U},
  {CUPS_CSPACE_K, 8U, 8U, 1U},
  {CUPS_CSPACE_K, 16U, 16U, 1U},
  {CUPS_CSPACE_RGB, 8U, 24U, 3U},
  {CUPS_CSPACE_RGB, 16U, 48U, 3U},
  {CUPS_CSPACE_SRGB, 8U, 24U, 3U},
  {CUPS_CSPACE_ADOBERGB, 8U, 24U, 3U},
  {CUPS_CSPACE_CMYK, 8U, 32U, 4U},
  {CUPS_CSPACE_CMYK, 16U, 64U, 4U},
};

static uint8_t
cf_v3_pwg_material(const uint8_t *material, size_t material_size,
                   unsigned pattern, unsigned page, size_t offset)
{
  uint8_t value = material_size
                      ? material[(offset + (size_t)page * 257U) % material_size]
                      : (uint8_t)(offset * 131U + page * 67U);

  switch (pattern % 6U)
  {
    case 0U:
      return value;
    case 1U:
      return 0U;
    case 2U:
      return 0xffU;
    case 3U:
      return offset & 1U ? 0xaaU : 0x55U;
    case 4U:
      return (uint8_t)offset;
    default:
      return (uint8_t)(value ^ (uint8_t)(offset * 17U + page * 29U));
  }
}

static void
cf_v3_pwg_safe_format(unsigned route, int faithful,
                      unsigned *width_index, unsigned *format_index)
{
  if (faithful)
    return;

  /* Current pwgtopdf inverts one byte per pixel for K1 instead of one byte
   * per packed row. Preserve K1 initialization in deploy mode at width 1;
   * faithful inputs retain the complete packed-width boundary. */
  if (*format_index == 0U)
    *width_index = 0U;

  /* PCLm supports the 8-bit Gray/RGB writer states. Other source formats
   * remain available through PDF routes and explicit faithful inputs. */
  if (route == CF_V3_PWG_ROUTE_DIRECT_PCLM ||
      route == CF_V3_PWG_ROUTE_JOB_PCLM)
  {
    if (*format_index <= 2U)
      *format_index = 1U;
    else if (*format_index == 4U || *format_index >= 7U)
      *format_index = 3U;
  }
}

static uint8_t *
cf_v3_pwg_document(const uint8_t *header, const uint8_t *material,
                   size_t material_size, unsigned route, int faithful,
                   size_t *document_size)
{
  unsigned width_index = header[2] %
      (sizeof(cf_v3_pwg_widths) / sizeof(cf_v3_pwg_widths[0]));
  unsigned height_index = header[3] %
      (sizeof(cf_v3_pwg_heights) / sizeof(cf_v3_pwg_heights[0]));
  unsigned format_index = header[4] %
      (sizeof(cf_v3_pwg_formats) / sizeof(cf_v3_pwg_formats[0]));
  unsigned x_dpi = cf_v3_pwg_dpi[header[5] % 4U];
  unsigned y_dpi = cf_v3_pwg_dpi[header[6] % 4U];
  unsigned pages = 1U + header[7] % 3U;
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;
  unsigned page;

  cf_v3_pwg_safe_format(route, faithful, &width_index, &format_index);
  for (page = 0U; page < pages; page ++)
  {
    unsigned delta = header[11] & 1U ? page : 0U;
    unsigned width = cf_v3_pwg_widths[
        (width_index + delta * (1U + header[12] % 5U)) %
        (sizeof(cf_v3_pwg_widths) / sizeof(cf_v3_pwg_widths[0]))];
    unsigned height = cf_v3_pwg_heights[
        (height_index + delta * (1U + header[13] % 5U)) %
        (sizeof(cf_v3_pwg_heights) / sizeof(cf_v3_pwg_heights[0]))];
    const cf_v3_pwg_format_t *format = &cf_v3_pwg_formats[
        (format_index + delta * (1U + header[14] % 7U)) %
        (sizeof(cf_v3_pwg_formats) / sizeof(cf_v3_pwg_formats[0]))];
    size_t bytes_per_line =
        ((size_t)width * format->bits_per_pixel + 7U) / 8U;

    if (!faithful && format->bits_per_pixel == 1U && width > 1U)
    {
      width = 1U;
      bytes_per_line = 1U;
    }
    if (height > (SIZE_MAX - total - sizeof(cups_page_header2_t)) /
                     bytes_per_line)
      return NULL;
    total += sizeof(cups_page_header2_t) + (size_t)height * bytes_per_line;
  }
  document = (uint8_t *)malloc(total);
  if (!document)
    return NULL;
  memcpy(document, "3SaR", 4U);

  for (page = 0U; page < pages; page ++)
  {
    unsigned delta = header[11] & 1U ? page : 0U;
    unsigned width = cf_v3_pwg_widths[
        (width_index + delta * (1U + header[12] % 5U)) %
        (sizeof(cf_v3_pwg_widths) / sizeof(cf_v3_pwg_widths[0]))];
    unsigned height = cf_v3_pwg_heights[
        (height_index + delta * (1U + header[13] % 5U)) %
        (sizeof(cf_v3_pwg_heights) / sizeof(cf_v3_pwg_heights[0]))];
    const cf_v3_pwg_format_t *format = &cf_v3_pwg_formats[
        (format_index + delta * (1U + header[14] % 7U)) %
        (sizeof(cf_v3_pwg_formats) / sizeof(cf_v3_pwg_formats[0]))];
    size_t bytes_per_line =
        ((size_t)width * format->bits_per_pixel + 7U) / 8U;
    size_t page_bytes;
    cups_page_header2_t page_header;

    if (!faithful && format->bits_per_pixel == 1U && width > 1U)
    {
      width = 1U;
      bytes_per_line = 1U;
    }
    page_bytes = (size_t)height * bytes_per_line;
    memset(&page_header, 0, sizeof(page_header));
    memcpy(page_header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(page_header.MediaType, "Plain", sizeof("Plain"));
    memcpy(page_header.cupsPageSizeName, "Tiny", sizeof("Tiny"));
    page_header.HWResolution[0] = x_dpi;
    page_header.HWResolution[1] = y_dpi;
    page_header.PageSize[0] = (unsigned)((uint64_t)width * 72U / x_dpi);
    page_header.PageSize[1] = (unsigned)((uint64_t)height * 72U / y_dpi);
    page_header.ImagingBoundingBox[2] = width;
    page_header.ImagingBoundingBox[3] = height;
    page_header.cupsPageSize[0] = (float)width * 72.0f / (float)x_dpi;
    page_header.cupsPageSize[1] = (float)height * 72.0f / (float)y_dpi;
    page_header.cupsImagingBBox[2] = page_header.cupsPageSize[0];
    page_header.cupsImagingBBox[3] = page_header.cupsPageSize[1];
    page_header.cupsWidth = width;
    page_header.cupsHeight = height;
    page_header.cupsBitsPerColor = format->bits_per_color;
    page_header.cupsBitsPerPixel = format->bits_per_pixel;
    page_header.cupsBytesPerLine = (unsigned)bytes_per_line;
    page_header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    page_header.cupsColorSpace = format->color_space;
    page_header.cupsCompression = 0U;
    page_header.cupsRowCount = 1U;
    page_header.cupsRowFeed = 1U;
    page_header.cupsRowStep = 1U;
    page_header.cupsNumColors = format->num_colors;
    page_header.NumCopies = 1U;
    page_header.Duplex = header[12] & 1U;
    page_header.Tumble = (header[12] >> 1U) & 1U;
    page_header.Orientation = (cups_orient_t)(header[13] % 4U);
    snprintf(page_header.cupsRenderingIntent,
             sizeof(page_header.cupsRenderingIntent), "%s",
             cf_v3_pwg_intents[header[15] % 5U]);
    page_header.cupsInteger[CUPS_RASTER_PWG_CrossFeedTransform] = 1U;
    page_header.cupsInteger[CUPS_RASTER_PWG_FeedTransform] = 1U;
    page_header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] = width;
    page_header.cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] = height;
    memcpy(document + offset, &page_header, sizeof(page_header));
    offset += sizeof(page_header);
    for (size_t index = 0U; index < page_bytes; index ++)
      document[offset + index] = cf_v3_pwg_material(
          material, material_size, header[10], page, index);
    offset += page_bytes;
  }
  *document_size = total;
  return document;
}

static void
cf_v3_pwg_control(const uint8_t *header, cf_v2_control_t *control)
{
  memset(control, 0, sizeof(*control));
  control->ppd_profile = header[13];
  control->page_size = header[2];
  control->color_model = header[4];
  control->resolution = header[5];
  control->sides = header[12];
  control->orientation = header[13];
  control->scaling = header[11];
  control->copies = header[7];
  control->number_up = header[14];
  control->position = header[15];
  control->quality = header[10];
  control->output_order = header[9];
  control->media_type = header[15];
  control->mirror = header[12] >> 2U;
  control->route_mode = header[0];
  control->reserved = header[15];
}

static int
cf_v3_pwg_make_ppd(const uint8_t *header, int pclm, int faithful,
                   char **buffer, size_t *size)
{
  cf_v2_control_t control;
  FILE *stream;
  unsigned preferred = cf_v3_pwg_strip_heights[
      header[8] % (sizeof(cf_v3_pwg_strip_heights) /
                   sizeof(cf_v3_pwg_strip_heights[0]))];

  if (pclm && !faithful && preferred == 0U)
    preferred = 1U;
  cf_v3_pwg_control(header, &control);
  *buffer = NULL;
  *size = 0U;
  stream = open_memstream(buffer, size);
  if (!stream)
    return 0;
  if (cf_v2_write_ppd(stream, &control, "pwgtopdf") != 0 ||
      fprintf(stream,
              "*cupsFilter2: \"application/vnd.cups-pwg application/%s 0 pwgtopdf\"\n"
              "*cupsPclmStripHeightPreferred: \"%u\"\n"
              "*cupsPclmStripHeightSupported: \"1,2,7,16,32\"\n"
              "*cupsPclmSourceResolutionSupported: \"72dpi,150dpi,300dpi,600dpi\"\n"
              "*cupsPclmSourceResolutionDefault: \"300dpi\"\n"
              "*cupsPclmCompressionMethodPreferred: \"%s\"\n",
              pclm ? "PCLm" : "pdf", preferred,
              header[9] & 1U ? "flate" : "jpeg") < 0 ||
      fclose(stream) != 0)
  {
    free(*buffer);
    *buffer = NULL;
    *size = 0U;
    return 0;
  }
  return 1;
}

static uint8_t *
cf_v3_pwg_direct_input(const uint8_t *header, const uint8_t *document,
                       size_t document_size, size_t *input_size)
{
  cf_v2_control_t control;
  uint8_t *input;

  if (document_size > SIZE_MAX - CF_V2_CONTROL_SIZE)
    return NULL;
  input = (uint8_t *)malloc(document_size + CF_V2_CONTROL_SIZE);
  if (!input)
    return NULL;
  cf_v3_pwg_control(header, &control);
  memcpy(input, document, document_size);
  memcpy(input + document_size, &control, CF_V2_CONTROL_SIZE);
  *input_size = document_size + CF_V2_CONTROL_SIZE;
  return input;
}

static uint8_t *
cf_v3_pwg_job_input(const uint8_t *header, const uint8_t *document,
                    size_t document_size, int pclm, int faithful,
                    size_t *input_size)
{
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  size_t ppd_size = 0U;
  const char title[] = "PWGV3";
  size_t options_size;
  size_t title_size = sizeof(title) - 1U;
  size_t total;
  size_t offset;
  uint8_t *input;

  cf_v3_pwg_control(header, &control);
  if (!cf_v3_pwg_make_ppd(header, pclm, faithful, &ppd, &ppd_size) ||
      cf_v2_build_options(options, sizeof(options), &control) != 0)
  {
    free(ppd);
    return NULL;
  }
  options_size = strlen(options);
  total = CF_V2_JOB_FIXED_SIZE;
  if (ppd_size > SIZE_MAX - total || options_size > SIZE_MAX - total - ppd_size ||
      title_size > SIZE_MAX - total - ppd_size - options_size ||
      document_size > SIZE_MAX - total - ppd_size - options_size - title_size)
  {
    free(ppd);
    return NULL;
  }
  total += ppd_size + options_size + title_size + document_size;
  input = (uint8_t *)malloc(total);
  if (!input)
  {
    free(ppd);
    return NULL;
  }
  cf_v2_job_store_u32le(input, (uint32_t)ppd_size);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)options_size);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_size);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)document_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, &control, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, ppd, ppd_size);
  offset += ppd_size;
  memcpy(input + offset, options, options_size);
  offset += options_size;
  memcpy(input + offset, title, title_size);
  offset += title_size;
  memcpy(input + offset, document, document_size);
  free(ppd);
  *input_size = total;
  return input;
}

static int
cf_v3_pwg_run_public(unsigned route, const uint8_t *header,
                     const uint8_t *material, size_t material_size,
                     int faithful)
{
  uint8_t *document = NULL;
  uint8_t *input = NULL;
  size_t document_size = 0U;
  size_t input_size = 0U;

  document = cf_v3_pwg_document(header, material, material_size, route,
                                faithful, &document_size);
  if (!document)
    return 0;
  if (route == CF_V3_PWG_ROUTE_DIRECT_PDF ||
      route == CF_V3_PWG_ROUTE_DIRECT_PCLM)
    input = cf_v3_pwg_direct_input(header, document, document_size,
                                   &input_size);
  else
    input = cf_v3_pwg_job_input(
        header, document, document_size,
        route == CF_V3_PWG_ROUTE_JOB_PCLM, faithful, &input_size);
  if (input)
  {
    switch (route)
    {
      case CF_V3_PWG_ROUTE_DIRECT_PDF:
        (void)cf_v3_pwg_direct_pdf_legacy(input, input_size);
        break;
      case CF_V3_PWG_ROUTE_DIRECT_PCLM:
        (void)cf_v3_pwg_direct_pclm_legacy(input, input_size);
        break;
      case CF_V3_PWG_ROUTE_JOB_PDF:
        (void)cf_v3_pwg_job_pdf_legacy(input, input_size);
        break;
      default:
        (void)cf_v3_pwg_job_pclm_legacy(input, input_size);
        break;
    }
  }
  cf_v3_pwg_filter_release();
  int tracker_overflow = cf_v3_pwg_filter_tracker_overflowed();
  if (getenv("CF_V3_TRACE_PWG") && tracker_overflow)
    fprintf(stderr, "pwg-route: allocation tracker overflow\n");
  free(input);
  free(document);
  return 0;
}

static int
cf_v3_pwg_run_page_writer(const uint8_t *header,
                          const uint8_t *material, size_t material_size)
{
  uint8_t input[8U + CF_V3_PWG_PAGE_SELECTORS + CF_V3_PWG_MAX_MATERIAL];
  uint8_t *selector = input + 8U;

  memcpy(input, CF_V3_PWG_PAGE_MAGIC, 8U);
  selector[0] = header[2];
  selector[1] = header[3];
  selector[2] = header[4] ? (uint8_t)(header[4] - 1U) : 0U;
  selector[3] = (uint8_t)((header[5] % 4U) | ((header[6] % 4U) << 4U));
  selector[4] = header[7];
  selector[5] = header[15];
  selector[6] = header[10];
  selector[7] = header[11];
  selector[8] = header[12];
  selector[9] = header[13];
  selector[10] = header[14];
  selector[11] = header[15];
  memcpy(selector + CF_V3_PWG_PAGE_SELECTORS, material, material_size);
  return cf_v3_pwg_page_writer_legacy(
      input, 8U + CF_V3_PWG_PAGE_SELECTORS + material_size);
}

static int
cf_v3_pwg_run_strip(const uint8_t *header,
                    const uint8_t *material, size_t material_size)
{
  uint8_t input[10U + CF_V3_PWG_MAX_MATERIAL];
  static const uint8_t sources[10] = {2U, 3U, 8U, 4U, 5U,
                                      6U, 9U, 10U, 11U, 15U};

  for (size_t index = 0U; index < 10U; index ++)
    input[index] = header[sources[index]];
  memcpy(input + 10U, material, material_size);
  return cf_v3_pwg_strip_partition_legacy(input, 10U + material_size);
}

static int
cf_v3_pwg_run_flate(const uint8_t *header,
                    const uint8_t *material, size_t material_size)
{
  uint8_t input[8U + CF_V3_PWG_MAX_MATERIAL];
  static const uint8_t sources[8] = {2U, 8U, 3U, 11U,
                                     4U, 10U, 15U, 9U};

  for (size_t index = 0U; index < 8U; index ++)
    input[index] = header[sources[index]];
  memcpy(input + 8U, material, material_size);
  return cf_v3_pwg_flate_object_legacy(input, 8U + material_size);
}

int
cf_v3_pwg_route_bridge(const uint8_t *data, size_t size)
{
  const uint8_t *header;
  const uint8_t *material;
  size_t material_size;
  unsigned route;
  int faithful;

  if (!cf_v3_pwg_route_input(data, size))
    return 0;
  header = cf_v3_pwg_route_const_header(data);
  material = data + CF_V3_PWG_FIXED_SIZE;
  material_size = size - CF_V3_PWG_FIXED_SIZE;
  route = cf_v3_pwg_route_id(header);
  faithful = cf_v3_pwg_route_faithful(header);
  if (getenv("CF_V3_TRACE_PWG"))
    fprintf(stderr, "pwg-route: route=%u faithful=%d format=%u strip=%u\n",
            route, faithful, header[4] % 9U, header[8] % 6U);

  if (route <= CF_V3_PWG_ROUTE_JOB_PCLM)
    return cf_v3_pwg_run_public(route, header, material, material_size,
                                faithful);
  if (route == CF_V3_PWG_ROUTE_PDF_PAGE_WRITER)
    return cf_v3_pwg_run_page_writer(header, material, material_size);
  if (route == CF_V3_PWG_ROUTE_PCLM_STRIP_PARTITION)
    return cf_v3_pwg_run_strip(header, material, material_size);
  return cf_v3_pwg_run_flate(header, material, material_size);
}
