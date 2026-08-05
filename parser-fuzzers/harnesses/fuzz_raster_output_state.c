#include "control.h"

#ifdef CF_FUZZ_RASTER_OUTPUT_PCLM_CHAIN
#include <cupsfilters/filter.h>
static int cf_fuzz_filter_raster_to_pclm(int inputfd, int outputfd,
                                       int inputseekable,
                                       cf_filter_data_t *data,
                                       void *parameters);
#endif

#include "direct_route.h"

#include <cups/raster.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef CF_FUZZ_RASTER_OUTPUT_PS_WRITE_ERROR_BOUNDARY
#define CF_FUZZ_RASTER_OUTPUT_MAGIC "PSWRITE1"
#elif defined(CF_FUZZ_RASTER_OUTPUT_PS_LIFECYCLE)
#define CF_FUZZ_RASTER_OUTPUT_MAGIC "PSLIFE01"
#else
#define CF_FUZZ_RASTER_OUTPUT_MAGIC "ROSTATE1"
#endif
#define CF_FUZZ_RASTER_OUTPUT_SELECTORS 8U
#define CF_FUZZ_RASTER_OUTPUT_MAX_MATERIAL 4096U

typedef struct cf_fuzz_raster_output_format_s {
  cups_cspace_t color_space;
  unsigned colors;
  unsigned bits_per_color;
} cf_fuzz_raster_output_format_t;

static const unsigned cf_fuzz_raster_output_widths[] = {
    1U, 2U, 7U, 8U, 15U, 31U, 63U, 127U, 128U, 255U, 256U,
};
static const unsigned cf_fuzz_raster_output_heights[] = {
    1U, 2U, 3U, 4U, 8U, 16U,
};
static const unsigned cf_fuzz_raster_output_margins[] = {
    0U, 1U, 2U, 4U, 8U,
};
#ifdef CF_FUZZ_RASTER_OUTPUT_PS
/* rastertops has distinct 1-bpc expansion, 16-bpc DataSource, SW decode,
 * process-color, and fallback-device paths. Keep their finite products
 * explicit so every branch is reachable without malformed Raster headers. */
static const cf_fuzz_raster_output_format_t cf_fuzz_raster_output_formats[] = {
    {CUPS_CSPACE_K, 1U, 1U},
    {CUPS_CSPACE_K, 1U, 8U},
    {CUPS_CSPACE_K, 1U, 16U},
    {CUPS_CSPACE_W, 1U, 1U},
    {CUPS_CSPACE_W, 1U, 8U},
    {CUPS_CSPACE_W, 1U, 16U},
    {CUPS_CSPACE_SW, 1U, 1U},
    {CUPS_CSPACE_SW, 1U, 8U},
    {CUPS_CSPACE_SW, 1U, 16U},
    {CUPS_CSPACE_RGB, 3U, 1U},
    {CUPS_CSPACE_RGB, 3U, 8U},
    {CUPS_CSPACE_RGB, 3U, 16U},
    {CUPS_CSPACE_SRGB, 3U, 1U},
    {CUPS_CSPACE_SRGB, 3U, 8U},
    {CUPS_CSPACE_SRGB, 3U, 16U},
    {CUPS_CSPACE_ADOBERGB, 3U, 1U},
    {CUPS_CSPACE_ADOBERGB, 3U, 8U},
    {CUPS_CSPACE_ADOBERGB, 3U, 16U},
    {CUPS_CSPACE_CMY, 3U, 1U},
    {CUPS_CSPACE_CMY, 3U, 8U},
    {CUPS_CSPACE_CMY, 3U, 16U},
    {CUPS_CSPACE_CMYK, 4U, 1U},
    {CUPS_CSPACE_CMYK, 4U, 8U},
    {CUPS_CSPACE_CMYK, 4U, 16U},
    {CUPS_CSPACE_DEVICE1, 1U, 8U},
    {CUPS_CSPACE_DEVICE4, 4U, 8U},
};
#else
static const cf_fuzz_raster_output_format_t cf_fuzz_raster_output_formats[] = {
    {CUPS_CSPACE_K, 1U, 1U},
    {CUPS_CSPACE_K, 1U, 8U},
    {CUPS_CSPACE_K, 1U, 16U},
    {CUPS_CSPACE_W, 1U, 1U},
    {CUPS_CSPACE_W, 1U, 8U},
    {CUPS_CSPACE_W, 1U, 16U},
    {CUPS_CSPACE_RGB, 3U, 8U},
    {CUPS_CSPACE_RGB, 3U, 16U},
    {CUPS_CSPACE_SRGB, 3U, 8U},
    {CUPS_CSPACE_ADOBERGB, 3U, 8U},
    {CUPS_CSPACE_CMYK, 4U, 8U},
    {CUPS_CSPACE_CMYK, 4U, 16U},
    {CUPS_CSPACE_DEVICE1, 1U, 8U},
    {CUPS_CSPACE_DEVICE4, 4U, 8U},
};
#endif

static void cf_fuzz_raster_output_page_state(
    const uint8_t selector[CF_FUZZ_RASTER_OUTPUT_SELECTORS], unsigned page,
    const cf_fuzz_raster_output_format_t **format, unsigned *width,
    unsigned *height) {
  size_t format_index = selector[1];
  size_t width_index = selector[0] & 0x0fU;
  size_t height_index = selector[0] >> 4U;

#ifdef CF_FUZZ_RASTER_OUTPUT_PS
  if (page) {
    format_index += (size_t)page * (1U + selector[4] % 13U);
    width_index += (size_t)page * (1U + (selector[5] & 0x0fU));
    height_index += (size_t)page * (1U + (selector[5] >> 4U));
  }
#else
  (void)page;
#endif
  *format = &cf_fuzz_raster_output_formats[
      format_index % (sizeof(cf_fuzz_raster_output_formats) /
                      sizeof(cf_fuzz_raster_output_formats[0]))];
  *width = cf_fuzz_raster_output_widths[
      width_index % (sizeof(cf_fuzz_raster_output_widths) /
                     sizeof(cf_fuzz_raster_output_widths[0]))];
  *height = cf_fuzz_raster_output_heights[
      height_index % (sizeof(cf_fuzz_raster_output_heights) /
                      sizeof(cf_fuzz_raster_output_heights[0]))];
}

#ifdef CF_FUZZ_RASTER_OUTPUT_PCLM_CHAIN
static int cf_fuzz_filter_raster_to_pclm(int inputfd, int outputfd,
                                       int inputseekable,
                                       cf_filter_data_t *data,
                                       void *parameters) {
  cf_filter_out_format_t format = CF_FILTER_OUT_FORMAT_PCLM;
  FILE *intermediate;
  int first_input = -1;
  int first_output = -1;
  int second_input = -1;
  int second_output = -1;
  int status = 1;

  (void)inputseekable;
  (void)parameters;
  intermediate = tmpfile();
  if (!intermediate ||
      (first_input = dup(inputfd)) < 0 ||
      (first_output = dup(fileno(intermediate))) < 0) {
    goto done;
  }
  status = cfFilterRasterToPWG(first_input, first_output, 1, data, NULL);
  first_input = -1;
  first_output = -1;
  if (status != 0 || fflush(intermediate) != 0 ||
      fseek(intermediate, 0, SEEK_SET) != 0 ||
      (second_input = dup(fileno(intermediate))) < 0 ||
      (second_output = dup(outputfd)) < 0) {
    goto done;
  }
  status = cfFilterPWGToPDF(second_input, second_output, 1, data, &format);
  second_input = -1;
  second_output = -1;

done:
  if (first_input >= 0) close(first_input);
  if (first_output >= 0) close(first_output);
  if (second_input >= 0) close(second_input);
  if (second_output >= 0) close(second_output);
  if (intermediate) fclose(intermediate);
  return status;
}
#endif

static uint8_t cf_fuzz_raster_output_material(const uint8_t *material,
                                             size_t material_size,
                                             unsigned pattern,
                                             unsigned page, size_t offset) {
  uint8_t value = material_size
                      ? material[(offset + (size_t)page * 257U) % material_size]
                      : (uint8_t)(1U + (offset * 131U + page * 67U) % 254U);

#ifdef CF_FUZZ_RASTER_OUTPUT_PS_WRITE_ERROR_BOUNDARY
  {
    uint32_t mixed = (uint32_t)offset ^ ((uint32_t)page * 0x9e3779b9U) ^
                     ((uint32_t)value << 24U);

    /* Keep the /dev/full case incompressible enough for fwrite to flush its
     * real stdio buffer and report ENOSPC inside rastertops. */
    mixed ^= mixed >> 16U;
    mixed *= 0x7feb352dU;
    mixed ^= mixed >> 15U;
    mixed *= 0x846ca68bU;
    mixed ^= mixed >> 16U;
    return (uint8_t)(mixed >> 24U);
  }
#endif

  switch (pattern % 6U) {
    case 0:
      return value;
    case 1:
      return 0x00U;
    case 2:
      return 0xffU;
    case 3:
      return offset & 1U ? 0xaaU : 0x55U;
    case 4:
      return (uint8_t)(value ^ (uint8_t)(page * 0x31U));
    default:
      return (uint8_t)(offset & 0xffU);
  }
}

static uint8_t *cf_fuzz_raster_output_document(const uint8_t selector[8],
                                              const uint8_t *material,
                                              size_t material_size,
                                              size_t *document_size) {
  unsigned pages = 1U + selector[7] % 3U;
  unsigned left = cf_fuzz_raster_output_margins[
      selector[2] % (sizeof(cf_fuzz_raster_output_margins) /
                     sizeof(cf_fuzz_raster_output_margins[0]))];
  unsigned right = cf_fuzz_raster_output_margins[
      (selector[2] >> 4U) % (sizeof(cf_fuzz_raster_output_margins) /
                             sizeof(cf_fuzz_raster_output_margins[0]))];
  unsigned bottom = cf_fuzz_raster_output_margins[
      selector[3] % (sizeof(cf_fuzz_raster_output_margins) /
                     sizeof(cf_fuzz_raster_output_margins[0]))];
  unsigned top = cf_fuzz_raster_output_margins[
      (selector[3] >> 4U) % (sizeof(cf_fuzz_raster_output_margins) /
                             sizeof(cf_fuzz_raster_output_margins[0]))];
  size_t total_size = 4U;
  uint8_t *document;
  size_t offset = 4U;

  for (unsigned page = 0; page < pages; page++) {
    const cf_fuzz_raster_output_format_t *format;
    unsigned width;
    unsigned height;
    unsigned bits_per_pixel;
    unsigned bytes_per_line;

    cf_fuzz_raster_output_page_state(selector, page, &format, &width, &height);
    bits_per_pixel = format->colors * format->bits_per_color;
    bytes_per_line = (width * bits_per_pixel + 7U) / 8U;
    total_size += sizeof(cups_page_header2_t) +
                  (size_t)height * bytes_per_line;
  }
  document = (uint8_t *)malloc(total_size);
  if (!document) {
    return NULL;
  }
  memcpy(document, "3SaR", 4U);
  for (unsigned page = 0; page < pages; page++) {
    const cf_fuzz_raster_output_format_t *format;
    unsigned width;
    unsigned height;
    unsigned bits_per_pixel;
    unsigned bytes_per_line;
    cups_page_header2_t header;
    size_t pixels;

    cf_fuzz_raster_output_page_state(selector, page, &format, &width, &height);
    bits_per_pixel = format->colors * format->bits_per_color;
    bytes_per_line = (width * bits_per_pixel + 7U) / 8U;
    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = width + left + right;
    header.PageSize[1] = height + bottom + top;
    header.ImagingBoundingBox[0] = left;
    header.ImagingBoundingBox[1] = bottom;
    header.ImagingBoundingBox[2] = left + width;
    header.ImagingBoundingBox[3] = bottom + height;
    header.cupsPageSize[0] = (float)header.PageSize[0];
    header.cupsPageSize[1] = (float)header.PageSize[1];
    header.cupsImagingBBox[0] = (float)header.ImagingBoundingBox[0];
    header.cupsImagingBBox[1] = (float)header.ImagingBoundingBox[1];
    header.cupsImagingBBox[2] = (float)header.ImagingBoundingBox[2];
    header.cupsImagingBBox[3] = (float)header.ImagingBoundingBox[3];
    header.cupsWidth = width;
    header.cupsHeight = height;
    header.cupsBitsPerColor = format->bits_per_color;
    header.cupsBitsPerPixel = bits_per_pixel;
    header.cupsBytesPerLine = bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = format->color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = format->colors;
    header.NumCopies = 1U;
    header.Duplex = selector[4] & 1U;
    header.Tumble = (selector[4] >> 1U) & 1U;
    header.Orientation = (cups_orient_t)(selector[5] % 4U);

    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);
    pixels = (size_t)height * bytes_per_line;
    for (size_t index = 0; index < pixels; index++) {
      document[offset + index] = cf_fuzz_raster_output_material(
          material, material_size, selector[6], page, index);
    }
    offset += pixels;
  }
  *document_size = total_size;
  return document;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const size_t magic_size = sizeof(CF_FUZZ_RASTER_OUTPUT_MAGIC) - 1U;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;
  size_t document_size = 0;
  uint8_t *document;
  cf_fuzz_control_t control;
  cf_fuzz_run_result_t result;
  int executed;

  if (!data || size < magic_size + CF_FUZZ_RASTER_OUTPUT_SELECTORS ||
      size > magic_size + CF_FUZZ_RASTER_OUTPUT_SELECTORS +
                 CF_FUZZ_RASTER_OUTPUT_MAX_MATERIAL ||
      memcmp(data, CF_FUZZ_RASTER_OUTPUT_MAGIC, magic_size) != 0) {
    return 0;
  }
  selector = data + magic_size;
  material = selector + CF_FUZZ_RASTER_OUTPUT_SELECTORS;
  material_size = size - magic_size - CF_FUZZ_RASTER_OUTPUT_SELECTORS;
  document = cf_fuzz_raster_output_document(selector, material, material_size,
                                           &document_size);
  if (!document) {
    return 0;
  }

  for (size_t index = 0; index < sizeof(control); index++) {
    ((uint8_t *)&control)[index] =
        selector[index % CF_FUZZ_RASTER_OUTPUT_SELECTORS] ^
        (uint8_t)(index * 29U);
  }
  cf_fuzz_apply_control_policy(&control);
#ifdef CF_FUZZ_RASTER_OUTPUT_PS_WRITE_ERROR_BOUNDARY
  control.reserved = CF_FUZZ_DIRECT_FAULT_OUTPUT_FULL;
#elif defined(CF_FUZZ_RASTER_OUTPUT_PS_LIFECYCLE)
  {
    static const uint8_t fault_modes[] = {
        CF_FUZZ_DIRECT_FAULT_NONE,
        CF_FUZZ_DIRECT_FAULT_EMPTY_INPUT,
        CF_FUZZ_DIRECT_FAULT_INVALID_INPUT,
        CF_FUZZ_DIRECT_FAULT_INVALID_OUTPUT,
        CF_FUZZ_DIRECT_FAULT_CANCELED,
    };
    control.reserved = fault_modes[
        selector[6] % (sizeof(fault_modes) / sizeof(fault_modes[0]))];
  }
#endif
  executed =
      cf_fuzz_execute_direct(document, document_size, &control, 0, &result);
  if (getenv("CF_FUZZ_TRACE_STATE")) {
    fprintf(stderr, "%s route_executed=%d status=%d document_size=%zu\n",
            CF_FUZZ_TARGET_NAME, executed, result.status, document_size);
  }
  cf_fuzz_free_run_result(&result);
  free(document);
  return 0;
}
