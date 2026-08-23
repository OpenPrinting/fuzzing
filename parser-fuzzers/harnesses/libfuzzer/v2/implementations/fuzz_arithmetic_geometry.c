// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#if (defined(CF_V2_ARITHMETIC_IMAGE_PAGE) + \
     defined(CF_V2_ARITHMETIC_IMAGE_ROW) + \
     defined(CF_V2_ARITHMETIC_PWG_HORIZONTAL) + \
     defined(CF_V2_ARITHMETIC_PWG_VERTICAL) + \
     defined(CF_V2_ARITHMETIC_PWG_PLANAR)) != 1
#error "select exactly one ArithmeticLayout projection"
#endif

#if defined(CF_V2_ARITHMETIC_IMAGE_PAGE)
#define CF_V2_FILTER_FUNCTION cfFilterImageToPDF
#define CF_V2_INPUT_MIME "image/png"
#define CF_V2_OUTPUT_MIME "application/pdf"
#elif defined(CF_V2_ARITHMETIC_IMAGE_ROW)
#define CF_V2_FILTER_FUNCTION cfFilterImageToRaster
#define CF_V2_INPUT_MIME "image/png"
#define CF_V2_OUTPUT_MIME "application/vnd.cups-raster"
#else
#define CF_V2_FILTER_FUNCTION cfFilterPWGToRaster
#define CF_V2_INPUT_MIME "image/pwg-raster"
#define CF_V2_OUTPUT_MIME "application/vnd.cups-raster"
#endif

#define CF_V2_JOIN_OPTIONS_CONTINUATION 1
#if defined(CF_V2_ARITHMETIC_IMAGE_PAGE) || \
    defined(CF_V2_ARITHMETIC_IMAGE_ROW)
#define CF_V2_IMAGE_CACHE_CONTINUATION 1
#endif
#define LLVMFuzzerTestOneInput cf_v2_arithmetic_unused_entrypoint
#include "fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include "../include/arithmetic_layout.h"

#include <cups/raster.h>
#include <math.h>
#include <png.h>
#include <stdbool.h>

#define CF_V2_ARITHMETIC_MAX_INPUT \
  (CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE + \
   CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE + 4096U)
#define CF_V2_ARITHMETIC_MAX_PNG (512U * 1024U)
#define CF_V2_ARITHMETIC_MAX_RASTER (2U * 1024U * 1024U)
#define CF_V2_ARITHMETIC_MAX_ROUTE_ALLOCATION (2U * 1024U * 1024U)
#define CF_V2_ARITHMETIC_MAX_MEDIA_POINTS (1U << 14U)
#define CF_V2_ARITHMETIC_MAX_SOURCE_PPI (1U << 16U)
#define CF_V2_ARITHMETIC_STRIDE_NEIGHBORHOOD (1U << 16U)
#define CF_V2_ARITHMETIC_MAX_ZOOM_ROW (384U * 1024U * 1024U)

typedef struct cf_v2_arithmetic_writer_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
  size_t limit;
} cf_v2_arithmetic_writer_t;

typedef struct cf_v2_arithmetic_image_plan_s {
  uint32_t source_ppi_x;
  uint32_t source_ppi_y;
  long double media_width;
  long double media_height;
  uint32_t output_resolution_x;
  uint32_t output_resolution_y;
  int natural_scaling;
  unsigned copies;
  size_t x_pages;
  size_t y_pages;
  uint64_t wide_pages;
  uint32_t encoded_pages;
  uint64_t logical_width;
  uint64_t wide_stride;
  uint32_t encoded_stride;
  uint32_t output_channels;
  uint32_t output_bits_per_pixel;
} cf_v2_arithmetic_image_plan_t;

typedef struct cf_v2_arithmetic_pwg_plan_s {
  uint32_t input_width;
  uint32_t input_height;
  uint32_t input_bytes_per_line;
  uint32_t input_resolution_x;
  uint32_t input_resolution_y;
  uint32_t output_resolution_x;
  uint32_t output_resolution_y;
  uint32_t page_width;
  uint32_t page_height;
  unsigned pages;
  uint64_t mathematical_product;
  uint32_t encoded_allocation;
} cf_v2_arithmetic_pwg_plan_t;

static cf_v2_relation_stats_t cf_v2_arithmetic_relation_stats;

#if defined(CF_V2_ARITHMETIC_IMAGE_ROW) || \
    defined(CF_V2_ARITHMETIC_PWG_HORIZONTAL) || \
    defined(CF_V2_ARITHMETIC_PWG_VERTICAL) || \
    defined(CF_V2_ARITHMETIC_PWG_PLANAR)
static cf_v2_arithmetic_source_format_t
    cf_v2_arithmetic_trace_source_format = CF_V2_ARITHMETIC_SOURCE_GRAY8;
static uint64_t cf_v2_arithmetic_trace_planned_product;
static uint32_t cf_v2_arithmetic_trace_planned_allocation;
static int cf_v2_arithmetic_trace_filter_active;

extern unsigned __real_cupsRasterWriteHeader2(cups_raster_t *r,
                                               cups_page_header2_t *header);

unsigned
__wrap_cupsRasterWriteHeader2(cups_raster_t *r, cups_page_header2_t *header)
{
  uint64_t inline_size;
  uint64_t wide_allocation;

  switch (cf_v2_arithmetic_trace_source_format) {
    case CF_V2_ARITHMETIC_SOURCE_RGB8:
      inline_size = (uint64_t)header->cupsWidth * 3U;
      break;
    case CF_V2_ARITHMETIC_SOURCE_BLACK1:
      inline_size = ((uint64_t)header->cupsWidth + 7U) / 8U;
      break;
    default:
      inline_size = header->cupsWidth;
      break;
  }
  wide_allocation = (uint64_t)header->cupsHeight * inline_size;
  if (cf_v2_arithmetic_trace_filter_active &&
      getenv("CF_V2_ARITHMETIC_TRACE_OUTPUT_HEADER"))
    fprintf(stderr,
            "ARITHMETIC_OUTPUT_HEADER width=%u height=%u bpc=%u bpp=%u "
            "bpl=%u order=%u colors=%u input_format=%u inline=%llu "
            "wide_allocation=%llu encoded_allocation=%u "
            "planned_product=%llu planned_allocation=%u\n",
            header->cupsWidth, header->cupsHeight,
            header->cupsBitsPerColor, header->cupsBitsPerPixel,
            header->cupsBytesPerLine, (unsigned)header->cupsColorOrder,
            header->cupsNumColors,
            (unsigned)cf_v2_arithmetic_trace_source_format,
            (unsigned long long)inline_size,
            (unsigned long long)wide_allocation,
            (uint32_t)wide_allocation,
            (unsigned long long)cf_v2_arithmetic_trace_planned_product,
            cf_v2_arithmetic_trace_planned_allocation);
  return __real_cupsRasterWriteHeader2(r, header);
}
#endif

static uint64_t
cf_v2_arithmetic_u64_product(uint64_t left, uint64_t right, int *overflow)
{
  if (right && left > UINT64_MAX / right) {
    if (overflow)
      *overflow = 1;
    return UINT64_MAX;
  }
  return left * right;
}

static uint64_t
cf_v2_arithmetic_ceil_div(uint64_t numerator, uint64_t denominator)
{
  if (!denominator)
    return 0U;
  return numerator / denominator + (numerator % denominator != 0U);
}

static uint64_t
cf_v2_arithmetic_floor_sqrt(uint64_t value)
{
  uint64_t root = (uint64_t)sqrtl((long double)value);

  while (root && root > value / root)
    root --;
  while (root < UINT64_MAX && root + 1U <= value / (root + 1U))
    root ++;
  return root;
}

static int
cf_v2_arithmetic_scalar_u32(cf_v2_scalar_relation_t *relation,
                            int64_t derived, uint32_t *value)
{
  int64_t selected;

  relation->derived_value = derived;
  selected = cf_v2_scalar_relation_value(relation);
  if (selected < 0 || (uint64_t)selected > UINT32_MAX)
    return 0;
  *value = (uint32_t)selected;
  return 1;
}

static uint8_t
cf_v2_arithmetic_material(const cf_v2_arithmetic_layout_t *layout,
                          size_t material_size, size_t offset)
{
  uint8_t value = material_size ?
      layout->opaque.data[(offset + layout->material_phase) % material_size] :
      (uint8_t)(offset * 131U + layout->material_phase * 17U);

  switch (layout->pattern % 6U) {
    case 0U: return value;
    case 1U: return 0U;
    case 2U: return 0xffU;
    case 3U: return (offset & 1U) ? 0xaaU : 0x55U;
    case 4U: return (uint8_t)offset;
    default: return (uint8_t)(value ^ (uint8_t)(offset * 29U));
  }
}

static void
cf_v2_arithmetic_apply_actions(const cf_v2_arithmetic_layout_t *layout,
                               unsigned *emits, unsigned *selection,
                               unsigned *phase)
{
  cf_v2_action_program_t program = layout->actions;
  cf_v2_action_t action;

  *emits = 0U;
  *selection = layout->option_mode;
  *phase = layout->material_phase;
  while (cf_v2_action_program_next(&program, &action)) {
    switch (action.kind) {
      case CF_V2_ACTION_SELECT:
        *selection = (*selection + action.argument + action.repetitions) & 3U;
        break;
      case CF_V2_ACTION_EMIT:
        *emits += action.repetitions;
        if (*emits > 3U)
          *emits = 3U;
        break;
      case CF_V2_ACTION_READ:
        *phase += action.argument + action.repetitions;
        break;
      case CF_V2_ACTION_PARSE:
      case CF_V2_ACTION_FINISH:
        *phase ^= action.argument;
        break;
      default:
        break;
    }
  }
}

static void
cf_v2_arithmetic_png_error(png_structp png, png_const_charp message)
{
  (void)message;
  longjmp(png_jmpbuf(png), 1);
}

static void
cf_v2_arithmetic_png_warning(png_structp png, png_const_charp message)
{
  (void)png;
  (void)message;
}

static void
cf_v2_arithmetic_writer_append(cf_v2_arithmetic_writer_t *writer,
                               const uint8_t *data, size_t size)
{
  size_t needed;
  size_t capacity;
  uint8_t *replacement;

  if (!writer || !data || size > writer->limit - writer->size)
    return;
  needed = writer->size + size;
  if (needed > writer->capacity) {
    capacity = writer->capacity ? writer->capacity : 1024U;
    while (capacity < needed && capacity <= writer->limit / 2U)
      capacity *= 2U;
    if (capacity < needed)
      capacity = needed;
    replacement = (uint8_t *)realloc(writer->data, capacity);
    if (!replacement)
      return;
    writer->data = replacement;
    writer->capacity = capacity;
  }
  memcpy(writer->data + writer->size, data, size);
  writer->size = needed;
}

static void
cf_v2_arithmetic_png_write(png_structp png, png_bytep data, png_size_t size)
{
  cf_v2_arithmetic_writer_t *writer =
      (cf_v2_arithmetic_writer_t *)png_get_io_ptr(png);
  size_t before = writer ? writer->size : 0U;

  cf_v2_arithmetic_writer_append(writer, data, (size_t)size);
  if (!writer || writer->size - before != (size_t)size)
    png_error(png, "bounded PNG output exceeded");
}

static void
cf_v2_arithmetic_png_flush(png_structp png)
{
  (void)png;
}

static uint32_t
cf_v2_arithmetic_ppm(uint32_t ppi)
{
  uint64_t ppm = ((uint64_t)ppi * 10000U + 127U) / 254U;

  return ppm > UINT32_MAX ? UINT32_MAX : (uint32_t)ppm;
}

static uint8_t *
cf_v2_arithmetic_build_png(const cf_v2_arithmetic_layout_t *layout,
                           uint32_t ppi_x, uint32_t ppi_y,
                           size_t *png_size)
{
  cf_v2_arithmetic_writer_t writer = {NULL, 0U, 0U,
                                       CF_V2_ARITHMETIC_MAX_PNG};
  png_structp png = NULL;
  png_infop info = NULL;
  uint8_t *row = NULL;
  size_t encoded_row = cf_v2_arithmetic_source_row_bytes(
      layout->source_width, layout->source_format);
  size_t relation_row = cf_v2_length_relation_value(&layout->row_length);
  size_t relation_payload =
      cf_v2_length_relation_value(&layout->payload_length);
  size_t relation_opaque =
      cf_v2_length_relation_value(&layout->opaque_length);
  size_t material_size = layout->opaque.size;
  int color_type;
  int bit_depth;

  if (!ppi_x || !ppi_y || !encoded_row || encoded_row > 256U * 3U)
    return NULL;
  if (relation_opaque < material_size)
    material_size = relation_opaque;
  if (relation_payload < material_size)
    material_size = relation_payload;
  if (layout->source_format == CF_V2_ARITHMETIC_SOURCE_RGB8) {
    color_type = PNG_COLOR_TYPE_RGB;
    bit_depth = 8;
  } else {
    color_type = PNG_COLOR_TYPE_GRAY;
    bit_depth = layout->source_format == CF_V2_ARITHMETIC_SOURCE_BLACK1 ?
                    1 : 8;
  }
  row = (uint8_t *)malloc(encoded_row);
  png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL,
                                cf_v2_arithmetic_png_error,
                                cf_v2_arithmetic_png_warning);
  if (!row || !png || !(info = png_create_info_struct(png)))
    goto cleanup;
  if (setjmp(png_jmpbuf(png)))
    goto cleanup;
  png_set_write_fn(png, &writer, cf_v2_arithmetic_png_write,
                   cf_v2_arithmetic_png_flush);
  png_set_IHDR(png, info, layout->source_width, layout->source_height,
               bit_depth, color_type, PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
  png_set_pHYs(png, info, cf_v2_arithmetic_ppm(ppi_x),
               cf_v2_arithmetic_ppm(ppi_y), PNG_RESOLUTION_METER);
  png_write_info(png, info);
  for (uint32_t y = 0U; y < layout->source_height; y ++) {
    for (size_t x = 0U; x < encoded_row; x ++) {
      size_t source_offset = relation_row ?
          (size_t)y * relation_row + x % relation_row : x;
      row[x] = cf_v2_arithmetic_material(layout, material_size,
                                         source_offset);
    }
    png_write_row(png, row);
  }
  png_write_end(png, info);
  if (writer.size) {
    *png_size = writer.size;
    free(row);
    png_destroy_write_struct(&png, &info);
    return writer.data;
  }

cleanup:
  free(row);
  if (png || info)
    png_destroy_write_struct(png ? &png : NULL, info ? &info : NULL);
  free(writer.data);
  return NULL;
}

static cups_cspace_t
cf_v2_arithmetic_cups_color(cf_v2_arithmetic_color_space_t color_space)
{
  switch (color_space) {
    case CF_V2_ARITHMETIC_COLOR_K: return CUPS_CSPACE_K;
    case CF_V2_ARITHMETIC_COLOR_RGB: return CUPS_CSPACE_RGB;
    case CF_V2_ARITHMETIC_COLOR_SRGB: return CUPS_CSPACE_SRGB;
    case CF_V2_ARITHMETIC_COLOR_CMY: return CUPS_CSPACE_CMY;
    case CF_V2_ARITHMETIC_COLOR_CMYK: return CUPS_CSPACE_CMYK;
    default: return CUPS_CSPACE_W;
  }
}

static const char *
cf_v2_arithmetic_color_name(cf_v2_arithmetic_color_space_t color_space)
{
  switch (color_space) {
    case CF_V2_ARITHMETIC_COLOR_K: return "Black";
    case CF_V2_ARITHMETIC_COLOR_RGB: return "RGB";
    case CF_V2_ARITHMETIC_COLOR_SRGB: return "sRGB";
    case CF_V2_ARITHMETIC_COLOR_CMY: return "CMY";
    case CF_V2_ARITHMETIC_COLOR_CMYK: return "CMYK";
    default: return "Gray";
  }
}

static char *
cf_v2_arithmetic_build_ppd(const cf_v2_arithmetic_layout_t *layout,
                           long double page_width, long double page_height,
                           uint32_t resolution_x, uint32_t resolution_y,
                           size_t *ppd_size)
{
  char *ppd = NULL;
  FILE *stream = NULL;
  int64_t channels = cf_v2_scalar_relation_value(&layout->channels);
  int64_t bits_per_pixel =
      cf_v2_scalar_relation_value(&layout->bits_per_pixel);
  cups_cspace_t color_space =
      cf_v2_arithmetic_cups_color(layout->output_color_space);
  const char *color_name =
      cf_v2_arithmetic_color_name(layout->output_color_space);
  int result;

  if (!(page_width > 0.0L) || !(page_height > 0.0L) ||
      page_width > (long double)UINT32_MAX ||
      page_height > (long double)UINT32_MAX ||
      channels < 1 || channels > 16 || bits_per_pixel < 1 ||
      bits_per_pixel > 64 ||
      !(stream = open_memstream(&ppd, ppd_size)))
    return NULL;
  result = fprintf(
      stream,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"2.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"Arithmetic layout\"\n"
      "*ShortNickName: \"Arithmetic layout\"\n"
      "*NickName: \"Arithmetic layout\"\n"
      "*PCFileName: \"ARITH.PPD\"\n"
      "*Product: \"(Arithmetic layout)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 2.4\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 arithmetic\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Geometry\n"
      "*PageSize Geometry/Geometry: \"<</PageSize[%.8Lf %.8Lf]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*OpenUI *PageRegion/Page Region: PickOne\n"
      "*DefaultPageRegion: Geometry\n"
      "*PageRegion Geometry/Geometry: \"<</PageSize[%.8Lf %.8Lf]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageRegion\n"
      "*DefaultImageableArea: Geometry\n"
      "*ImageableArea Geometry/Geometry: \"0 0 %.8Lf %.8Lf\"\n"
      "*DefaultPaperDimension: Geometry\n"
      "*PaperDimension Geometry/Geometry: \"%.8Lf %.8Lf\"\n"
      "*OpenUI *ColorModel/Color: PickOne\n"
      "*DefaultColorModel: Layout\n"
      "*ColorModel Layout/%s: \"<</cupsColorSpace %u/cupsColorOrder %u/cupsBitsPerColor %u/cupsBitsPerPixel %lld/cupsNumColors %lld>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *Resolution/Resolution: PickOne\n"
      "*DefaultResolution: Geometry\n"
      "*Resolution Geometry/Geometry: \"<</HWResolution[%u %u]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n",
      page_width, page_height, page_width, page_height,
      page_width, page_height, page_width, page_height, color_name,
      (unsigned)color_space, (unsigned)layout->output_color_order,
      layout->output_bits_per_color, (long long)bits_per_pixel,
      (long long)channels, resolution_x, resolution_y);
  if (result < 0 || fclose(stream) != 0) {
    free(ppd);
    return NULL;
  }
  return ppd;
}

static int
cf_v2_arithmetic_select_page_axes(const cf_v2_arithmetic_layout_t *layout,
                                  size_t *x_pages, size_t *y_pages)
{
  uint64_t product = cf_v2_cardinality_value(&layout->page_product);
  uint64_t root;
  uint64_t x = cf_v2_cardinality_value(&layout->x_pages);
  uint64_t y = cf_v2_cardinality_value(&layout->y_pages);

  switch (layout->axis_relation) {
    case CF_V2_ARITHMETIC_AXIS_Y_FOLLOWS_X:
      y = x;
      break;
    case CF_V2_ARITHMETIC_AXIS_X_FOLLOWS_Y:
      x = y;
      break;
    case CF_V2_ARITHMETIC_AXIS_SWAP: {
      uint64_t temporary = x;
      x = y;
      y = temporary;
      break;
    }
    default:
      break;
  }
  switch (layout->geometry_phase) {
    case 1U:
      root = cf_v2_arithmetic_floor_sqrt(product);
      x = root;
      y = root ? cf_v2_arithmetic_ceil_div(product, root) : 0U;
      break;
    case 2U:
      y = x ? cf_v2_arithmetic_ceil_div(product, x) : 0U;
      break;
    case 3U:
      x = y ? cf_v2_arithmetic_ceil_div(product, y) : 0U;
      break;
    default:
      break;
  }
  if (!x || !y || x > (1U << 20U) || y > (1U << 20U) ||
      x > SIZE_MAX || y > SIZE_MAX)
    return 0;
  *x_pages = (size_t)x;
  *y_pages = (size_t)y;
  return 1;
}

static int
cf_v2_arithmetic_image_page_plan(cf_v2_arithmetic_layout_t *layout,
                                 cf_v2_arithmetic_image_plan_t *plan)
{
  int overflow = 0;
  int64_t scaling;
  int64_t media_width;
  int64_t media_height;
  uint64_t common;
  uint64_t actual_x_pages;
  uint64_t actual_y_pages;
  long double projected_x_pages;
  long double projected_y_pages;
  long double source_width;
  long double source_height;
  unsigned emits;
  unsigned selection;
  unsigned phase;

  memset(plan, 0, sizeof(*plan));
  if (!cf_v2_arithmetic_select_page_axes(layout, &plan->x_pages,
                                         &plan->y_pages) ||
      !cf_v2_arithmetic_scalar_u32(&layout->source_ppi_x,
                                   layout->source_width,
                                   &plan->source_ppi_x) ||
      !cf_v2_arithmetic_scalar_u32(&layout->source_ppi_y,
                                   layout->source_height,
                                   &plan->source_ppi_y) ||
      !plan->source_ppi_x || !plan->source_ppi_y ||
      plan->source_ppi_x > CF_V2_ARITHMETIC_MAX_SOURCE_PPI ||
      plan->source_ppi_y > CF_V2_ARITHMETIC_MAX_SOURCE_PPI)
    return 0;
  common = plan->x_pages > plan->y_pages ? plan->x_pages : plan->y_pages;
  layout->natural_scaling.derived_value =
      common > ((uint64_t)INT_MAX + 25U) / 100U ?
          INT_MAX : (int64_t)(common * 100U - 25U);
  scaling = cf_v2_scalar_relation_value(&layout->natural_scaling);
  if (scaling <= 0 || scaling > INT_MAX)
    return 0;
  plan->natural_scaling = (int)scaling;
  source_width = (long double)layout->source_width / plan->source_ppi_x;
  source_height = (long double)layout->source_height / plan->source_ppi_y;
  layout->media_width.derived_value = 72;
  layout->media_height.derived_value = 72;
  media_width = cf_v2_scalar_relation_value(&layout->media_width);
  media_height = cf_v2_scalar_relation_value(&layout->media_height);
  if (layout->media_width.mode == CF_V2_RELATION_DERIVED)
    plan->media_width = source_width * scaling * 72.0L /
                        (100.0L * ((long double)plan->x_pages - 0.25L));
  else
    plan->media_width = media_width;
  if (layout->media_height.mode == CF_V2_RELATION_DERIVED)
    plan->media_height = source_height * scaling * 72.0L /
                         (100.0L * ((long double)plan->y_pages - 0.25L));
  else
    plan->media_height = media_height;
  if (!(plan->media_width > 0.0L) || !(plan->media_height > 0.0L) ||
      plan->media_width > CF_V2_ARITHMETIC_MAX_MEDIA_POINTS ||
      plan->media_height > CF_V2_ARITHMETIC_MAX_MEDIA_POINTS)
    return 0;
  if (!cf_v2_arithmetic_scalar_u32(&layout->output_resolution_x, 300,
                                   &plan->output_resolution_x) ||
      !cf_v2_arithmetic_scalar_u32(&layout->output_resolution_y, 300,
                                   &plan->output_resolution_y) ||
      !plan->output_resolution_x || !plan->output_resolution_y ||
      plan->output_resolution_x > 9600U ||
      plan->output_resolution_y > 9600U)
    return 0;
  projected_x_pages = source_width * scaling * 72.0L /
                      (100.0L * plan->media_width);
  projected_y_pages = source_height * scaling * 72.0L /
                      (100.0L * plan->media_height);
  if (!isfinite(projected_x_pages) || !isfinite(projected_y_pages) ||
      !(projected_x_pages > 0.0L) || !(projected_y_pages > 0.0L) ||
      projected_x_pages > (long double)(1U << 20U) ||
      projected_y_pages > (long double)(1U << 20U))
    return 0;
  actual_x_pages = (uint64_t)ceill(projected_x_pages);
  actual_y_pages = (uint64_t)ceill(projected_y_pages);
  if (!actual_x_pages || !actual_y_pages ||
      actual_x_pages > (1U << 20U) || actual_y_pages > (1U << 20U))
    return 0;
  plan->x_pages = (size_t)actual_x_pages;
  plan->y_pages = (size_t)actual_y_pages;
  cf_v2_arithmetic_apply_actions(layout, &emits, &selection, &phase);
  (void)selection;
  (void)phase;
  plan->copies = (unsigned)cf_v2_cardinality_value(&layout->copies);
  if (!plan->copies)
    plan->copies = 1U;
  if (emits && plan->copies < 4U)
    plan->copies += emits > 4U - plan->copies ? 4U - plan->copies : emits;
  plan->wide_pages = cf_v2_arithmetic_u64_product(
      plan->x_pages, plan->y_pages, &overflow);
  plan->wide_pages = cf_v2_arithmetic_u64_product(
      plan->wide_pages, plan->copies, &overflow);
  if (overflow)
    return 0;
  plan->encoded_pages = (uint32_t)plan->wide_pages;
  if ((uint64_t)plan->encoded_pages * sizeof(int) >
      CF_V2_ARITHMETIC_MAX_ROUTE_ALLOCATION)
    return 0;
#ifdef CF_V2_ARITHMETIC_DEEP
  if (plan->wide_pages > 4096U || plan->x_pages > 64U ||
      plan->y_pages > 64U || plan->natural_scaling > 10000)
    return 0;
#endif
  return 1;
}

static int
cf_v2_arithmetic_image_row_plan(cf_v2_arithmetic_layout_t *layout,
                                cf_v2_arithmetic_image_plan_t *plan)
{
  uint64_t logical_width =
      cf_v2_cardinality_value(&layout->logical_width);
  long double scaled_width;
  long double scaled_height;
  uint64_t actual_width;
  uint32_t projected_width;
  uint64_t stride_width_boundary;
  uint64_t source_depth;
  uint64_t wide_stride;
  uint32_t encoded_stride;
  int64_t requested_channels;
  int64_t requested_bits_per_pixel;
  int64_t scaling;

  memset(plan, 0, sizeof(*plan));
  layout->source_ppi_x.derived_value = 1;
  layout->source_ppi_y.derived_value = 1;
  if (!logical_width || logical_width > UINT32_MAX ||
      !cf_v2_arithmetic_scalar_u32(&layout->source_ppi_x, 1,
                                   &plan->source_ppi_x) ||
      !cf_v2_arithmetic_scalar_u32(&layout->source_ppi_y, 1,
                                   &plan->source_ppi_y) ||
      plan->source_ppi_x != 1U || plan->source_ppi_y != 1U)
    return 0;
  layout->media_width.derived_value =
      ((int64_t)layout->source_width + 1) * 72;
  layout->media_height.derived_value =
      ((int64_t)layout->source_height + 1) * 72;
  plan->media_width = cf_v2_scalar_relation_value(&layout->media_width);
  plan->media_height = cf_v2_scalar_relation_value(&layout->media_height);
  layout->natural_scaling.derived_value = 100;
  scaling = cf_v2_scalar_relation_value(&layout->natural_scaling);
  if (scaling != 100 ||
      !(plan->media_width > 0.0L) || !(plan->media_height > 0.0L) ||
      plan->media_width > CF_V2_ARITHMETIC_MAX_MEDIA_POINTS ||
      plan->media_height > CF_V2_ARITHMETIC_MAX_MEDIA_POINTS)
    return 0;
  plan->natural_scaling = (int)scaling;
  scaled_width = (long double)layout->source_width * scaling * 72.0L /
                 ((long double)plan->source_ppi_x * 100.0L);
  scaled_height = (long double)layout->source_height * scaling * 72.0L /
                  ((long double)plan->source_ppi_y * 100.0L);
  if (scaled_width > plan->media_width || scaled_height > plan->media_height)
    return 0;
  if (!cf_v2_arithmetic_scalar_u32(&layout->output_resolution_x,
                                   (int64_t)cf_v2_arithmetic_ceil_div(
                                       logical_width,
                                       layout->source_width),
                                   &plan->output_resolution_x) ||
      !cf_v2_arithmetic_scalar_u32(&layout->output_resolution_y, 1,
                                   &plan->output_resolution_y) ||
      !plan->output_resolution_x ||
      plan->output_resolution_x > INT_MAX ||
      plan->output_resolution_y != 1U)
    return 0;
  if (!cf_v2_arithmetic_image_raster_width(
          layout->source_width, plan->source_ppi_x, plan->natural_scaling,
          plan->output_resolution_x, &projected_width))
    return 0;
  actual_width = projected_width;
  requested_bits_per_pixel =
      cf_v2_scalar_relation_value(&layout->bits_per_pixel);
  requested_channels = cf_v2_scalar_relation_value(&layout->channels);
  if (!cf_v2_arithmetic_image_raster_tuple(
          layout, &plan->output_channels,
          &plan->output_bits_per_pixel) ||
      requested_bits_per_pixel != (int64_t)plan->output_bits_per_pixel ||
      requested_channels != (int64_t)plan->output_channels)
    return 0;
  stride_width_boundary =
      UINT32_MAX / (uint64_t)plan->output_bits_per_pixel + 1U;
  if (actual_width > stride_width_boundary +
                         CF_V2_ARITHMETIC_STRIDE_NEIGHBORHOOD)
    return 0;
  source_depth =
      layout->source_format == CF_V2_ARITHMETIC_SOURCE_RGB8 ? 3U : 1U;
  if (actual_width > CF_V2_ARITHMETIC_MAX_ZOOM_ROW / source_depth)
    return 0;
  wide_stride = (uint64_t)plan->output_bits_per_pixel * actual_width;
  encoded_stride = ((uint32_t)wide_stride + 7U) / 8U;
  if (layout->output_color_order == CUPS_ORDER_BANDED) {
    if (wide_stride > UINT64_MAX / (uint64_t)plan->output_channels)
      return 0;
    wide_stride *= (uint64_t)plan->output_channels;
    encoded_stride *= plan->output_channels;
  }
  if ((uint64_t)encoded_stride * 2U >
      CF_V2_ARITHMETIC_MAX_ROUTE_ALLOCATION)
    return 0;
#ifdef CF_V2_ARITHMETIC_DEEP
  if (wide_stride > UINT32_MAX || actual_width > 4096U ||
      plan->output_resolution_x > 9600U ||
      plan->output_resolution_y > 9600U)
    return 0;
#endif
  plan->copies = 1U;
  plan->x_pages = 1U;
  plan->y_pages = 1U;
  plan->wide_pages = 1U;
  plan->encoded_pages = 1U;
  plan->logical_width = actual_width;
  plan->wide_stride = wide_stride;
  plan->encoded_stride = encoded_stride;
  return 1;
}

static int
cf_v2_arithmetic_run_image(cf_v2_arithmetic_layout_t *layout)
{
  cf_v2_arithmetic_image_plan_t plan;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  uint8_t *png = NULL;
  char *ppd = NULL;
  char options[512];
  static const uint8_t title[] = "arithmetic-layout";
  size_t png_size = 0U;
  size_t ppd_size = 0U;
  int options_length;
  int ready;

#ifdef CF_V2_ARITHMETIC_IMAGE_PAGE
  ready = cf_v2_arithmetic_image_page_plan(layout, &plan);
#else
  ready = cf_v2_arithmetic_image_row_plan(layout, &plan);
#endif
  if (!ready)
    return 0;
  png = cf_v2_arithmetic_build_png(layout, plan.source_ppi_x,
                                   plan.source_ppi_y, &png_size);
  ppd = cf_v2_arithmetic_build_ppd(
      layout, plan.media_width, plan.media_height,
      plan.output_resolution_x, plan.output_resolution_y, &ppd_size);
#ifdef CF_V2_ARITHMETIC_IMAGE_ROW
  options_length = snprintf(
      options, sizeof(options),
      "PageSize=Geometry PageRegion=Geometry ColorModel=Layout "
      "Resolution=Geometry ppi=%u natural-scaling=%d copies=%u "
      "Collate=false sides=one-sided position=center "
      "orientation-requested=3 hardware-copies=false "
      "hardware-collate=false emit-jcl=false",
      plan.source_ppi_x, plan.natural_scaling, plan.copies);
#else
  options_length = snprintf(
      options, sizeof(options),
      "PageSize=Geometry PageRegion=Geometry ColorModel=Layout "
      "Resolution=Geometry natural-scaling=%d copies=%u Collate=false "
      "sides=one-sided position=center orientation-requested=3 "
      "hardware-copies=false hardware-collate=false emit-jcl=false",
      plan.natural_scaling, plan.copies);
#endif
  if (!png || !ppd || options_length < 0 ||
      (size_t)options_length >= sizeof(options))
    goto cleanup;
  memset(&job, 0, sizeof(job));
  memset(&result, 0, sizeof(result));
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_length;
  job.title = title;
  job.title_size = sizeof(title) - 1U;
  job.document = png;
  job.document_size = png_size;
  job.control.copies = (uint8_t)(plan.copies - 1U);
  job.control_bytes = (const uint8_t *)&job.control;
#ifdef CF_V2_ARITHMETIC_IMAGE_ROW
  if (getenv("CF_V2_ARITHMETIC_TRACE_OUTPUT_HEADER"))
    fprintf(stderr,
            "ARITHMETIC_IMAGE_PLAN source=%ux%u ppi=%ux%u "
            "media=%.8Lfx%.8Lf resolution=%ux%u logical_width=%llu "
            "bpc=%u bpp=%u colors=%u order=%u wide_stride=%llu "
            "encoded_stride=%u\n",
            layout->source_width, layout->source_height,
            plan.source_ppi_x, plan.source_ppi_y,
            plan.media_width, plan.media_height,
            plan.output_resolution_x, plan.output_resolution_y,
            (unsigned long long)plan.logical_width,
            layout->output_bits_per_color,
            plan.output_bits_per_pixel, plan.output_channels,
            (unsigned)layout->output_color_order,
            (unsigned long long)plan.wide_stride,
            plan.encoded_stride);
  cf_v2_arithmetic_trace_source_format = layout->source_format;
  cf_v2_arithmetic_trace_planned_product = plan.wide_stride;
  cf_v2_arithmetic_trace_planned_allocation = plan.encoded_stride;
  cf_v2_arithmetic_trace_filter_active = 1;
#endif
  cf_v2_relation_stats_register(&cf_v2_arithmetic_relation_stats,
                                CF_V2_TARGET_NAME);
  cf_v2_arithmetic_layout_record(&cf_v2_arithmetic_relation_stats, layout);
  (void)cf_v2_execute_direct_job(&job, 0, &result);
#ifdef CF_V2_ARITHMETIC_IMAGE_ROW
  cf_v2_arithmetic_trace_filter_active = 0;
#endif
  cf_v2_free_run_result(&result);
  cf_v2_release_joined_options();

cleanup:
  free(ppd);
  free(png);
  return 0;
}

static void
cf_v2_arithmetic_source_profile(const cf_v2_arithmetic_layout_t *layout,
                                cups_cspace_t *color_space,
                                uint32_t *bits_per_color,
                                uint32_t *bits_per_pixel,
                                uint32_t *colors)
{
  switch (layout->source_format) {
    case CF_V2_ARITHMETIC_SOURCE_RGB8:
      *color_space = CUPS_CSPACE_SRGB;
      *bits_per_color = 8U;
      *bits_per_pixel = 24U;
      *colors = 3U;
      break;
    case CF_V2_ARITHMETIC_SOURCE_BLACK1:
      *color_space = CUPS_CSPACE_K;
      *bits_per_color = 1U;
      *bits_per_pixel = 1U;
      *colors = 1U;
      break;
    default:
      *color_space = CUPS_CSPACE_W;
      *bits_per_color = 8U;
      *bits_per_pixel = 8U;
      *colors = 1U;
      break;
  }
}

static int
cf_v2_arithmetic_pwg_plan(cf_v2_arithmetic_layout_t *layout,
                          cf_v2_arithmetic_pwg_plan_t *plan)
{
  uint64_t line_bytes = cf_v2_cardinality_value(&layout->line_bytes);
  uint64_t desired_inline;
  uint64_t actual_inline;
  uint64_t product;
  uint64_t factor;
  uint64_t height;
  uint64_t output_line;
  int64_t output_channels;
  uint32_t input_bits_per_color;
  uint32_t input_bits_per_pixel;
  uint32_t input_colors;
  cups_cspace_t input_color_space;
  unsigned emits;
  unsigned selection;
  unsigned phase;

  memset(plan, 0, sizeof(*plan));
  if (!line_bytes || line_bytes > 512U * 1024U)
    return 0;
  plan->input_bytes_per_line = (uint32_t)line_bytes;
  cf_v2_arithmetic_source_profile(layout, &input_color_space,
                                  &input_bits_per_color,
                                  &input_bits_per_pixel, &input_colors);
  (void)input_color_space;
  (void)input_bits_per_color;
  (void)input_colors;
  if (input_bits_per_pixel == 1U) {
    if (line_bytes > UINT32_MAX / 8U)
      return 0;
    plan->input_width = (uint32_t)line_bytes * 8U;
  } else {
    uint64_t bytes_per_pixel = input_bits_per_pixel / 8U;
    plan->input_width = (uint32_t)(line_bytes / bytes_per_pixel);
    if (!plan->input_width)
      plan->input_width = 1U;
  }
  plan->input_height = 1U;
  plan->input_resolution_x = 1U;
  plan->input_resolution_y = 1U;
  plan->output_resolution_x = 1U;
  plan->output_resolution_y = 1U;
  plan->page_width = 72U;
  plan->page_height = 72U;

#if defined(CF_V2_ARITHMETIC_PWG_HORIZONTAL)
  product = cf_v2_cardinality_value(&layout->horizontal_product);
  factor = cf_v2_arithmetic_ceil_div(product, line_bytes);
  if (!factor)
    factor = 1U;
  if (factor > UINT32_MAX)
    return 0;
  layout->source_ppi_x.derived_value = 1;
  layout->output_resolution_x.derived_value = (int64_t)factor;
  if (!cf_v2_arithmetic_scalar_u32(&layout->source_ppi_x, 1,
                                   &plan->input_resolution_x) ||
      !cf_v2_arithmetic_scalar_u32(&layout->output_resolution_x,
                                   (int64_t)factor,
                                   &plan->output_resolution_x) ||
      !plan->input_resolution_x ||
      plan->output_resolution_x % plan->input_resolution_x)
    return 0;
  factor = plan->output_resolution_x / plan->input_resolution_x;
  if (!factor)
    return 0;
  plan->mathematical_product = line_bytes * factor;
  plan->encoded_allocation = (uint32_t)plan->mathematical_product;
  output_line = plan->output_resolution_x;
  if (output_line > plan->encoded_allocation)
    plan->encoded_allocation = (uint32_t)output_line;
#elif defined(CF_V2_ARITHMETIC_PWG_VERTICAL)
  if (layout->source_format == CF_V2_ARITHMETIC_SOURCE_BLACK1)
    return 0;
  product = cf_v2_cardinality_value(&layout->vertical_product);
  factor = cf_v2_arithmetic_ceil_div(product, line_bytes);
  if (!factor)
    factor = 1U;
  if (factor > UINT32_MAX)
    return 0;
  layout->source_ppi_y.derived_value = (int64_t)factor;
  layout->output_resolution_y.derived_value = 1;
  if (!cf_v2_arithmetic_scalar_u32(&layout->source_ppi_y,
                                   (int64_t)factor,
                                   &plan->input_resolution_y) ||
      !cf_v2_arithmetic_scalar_u32(&layout->output_resolution_y, 1,
                                   &plan->output_resolution_y) ||
      !plan->output_resolution_y ||
      plan->input_resolution_y % plan->output_resolution_y)
    return 0;
  factor = plan->input_resolution_y / plan->output_resolution_y;
  if (!factor)
    return 0;
  plan->mathematical_product = line_bytes * factor;
  plan->encoded_allocation = (uint32_t)plan->mathematical_product;
#else
  if (layout->output_color_order != CUPS_ORDER_PLANAR)
    return 0;
  output_channels = cf_v2_scalar_relation_value(&layout->channels);
  if (output_channels <= 1 || output_channels > 16)
    return 0;
  product = cf_v2_cardinality_value(&layout->page_product);
  desired_inline = line_bytes;
  if (product > CF_V2_ARITHMETIC_MAX_ROUTE_ALLOCATION)
    desired_inline = cf_v2_arithmetic_floor_sqrt(product);
  if (!desired_inline || desired_inline > 512U * 1024U)
    return 0;

  switch (layout->source_format) {
    case CF_V2_ARITHMETIC_SOURCE_RGB8:
      plan->input_width = (uint32_t)cf_v2_arithmetic_ceil_div(
          desired_inline, 3U);
      actual_inline = (uint64_t)plan->input_width * 3U;
      break;
    case CF_V2_ARITHMETIC_SOURCE_BLACK1:
      if (desired_inline > UINT32_MAX / 8U)
        return 0;
      plan->input_width = (uint32_t)(desired_inline * 8U);
      actual_inline = (plan->input_width + 7U) / 8U;
      break;
    default:
      plan->input_width = (uint32_t)desired_inline;
      actual_inline = plan->input_width;
      break;
  }
  if (!plan->input_width || !actual_inline ||
      actual_inline > 512U * 1024U)
    return 0;
  height = cf_v2_arithmetic_ceil_div(product, actual_inline);
  if (!height || height > UINT32_MAX)
    return 0;
  plan->input_bytes_per_line = (uint32_t)actual_inline;
  plan->page_width = plan->input_width;
  plan->page_height = (uint32_t)height;
  plan->input_resolution_x = 72U;
  plan->input_resolution_y = 72U;
  plan->output_resolution_x = 72U;
  plan->output_resolution_y = 72U;
  plan->mathematical_product = actual_inline * height;
  plan->encoded_allocation = (uint32_t)plan->mathematical_product;
#endif
  if (plan->encoded_allocation > CF_V2_ARITHMETIC_MAX_ROUTE_ALLOCATION)
    return 0;
#ifdef CF_V2_ARITHMETIC_DEEP
  if (plan->mathematical_product > UINT32_MAX ||
      plan->input_width > 4096U || plan->page_width > 4096U ||
      plan->page_height > 4096U ||
      plan->input_resolution_x > 9600U ||
      plan->input_resolution_y > 9600U ||
      plan->output_resolution_x > 9600U ||
      plan->output_resolution_y > 9600U)
    return 0;
#endif
  cf_v2_arithmetic_apply_actions(layout, &emits, &selection, &phase);
  (void)selection;
  (void)phase;
  plan->pages = (unsigned)cf_v2_cardinality_value(&layout->input_pages);
  if (emits && plan->pages < 4U)
    plan->pages += emits > 4U - plan->pages ? 4U - plan->pages : emits;
  if (plan->pages > 4U)
    plan->pages = 4U;
  if ((uint64_t)plan->pages * plan->input_bytes_per_line *
          plan->input_height > CF_V2_ARITHMETIC_MAX_RASTER)
    return 0;
  layout->row_length.base = plan->input_bytes_per_line;
  layout->payload_length.base =
      (size_t)plan->pages * plan->input_bytes_per_line *
      plan->input_height;
  return 1;
}

static uint8_t *
cf_v2_arithmetic_build_pwg(const cf_v2_arithmetic_layout_t *layout,
                           const cf_v2_arithmetic_pwg_plan_t *plan,
                           size_t *document_size)
{
  FILE *file = NULL;
  cups_raster_t *raster = NULL;
  cups_page_header2_t header;
  uint8_t *row = NULL;
  uint8_t *document = NULL;
  cups_cspace_t color_space;
  uint32_t bits_per_color;
  uint32_t bits_per_pixel;
  uint32_t colors;
  size_t relation_row = cf_v2_length_relation_value(&layout->row_length);
  size_t relation_payload =
      cf_v2_length_relation_value(&layout->payload_length);
  size_t relation_opaque =
      cf_v2_length_relation_value(&layout->opaque_length);
  size_t material_size = layout->opaque.size;
  size_t expected_payload = (size_t)plan->pages *
      plan->input_height * plan->input_bytes_per_line;
  long file_size;
  int write_fd = -1;

  if (relation_opaque < material_size)
    material_size = relation_opaque;
  cf_v2_arithmetic_source_profile(layout, &color_space, &bits_per_color,
                                  &bits_per_pixel, &colors);
  file = tmpfile();
  row = (uint8_t *)malloc(plan->input_bytes_per_line);
  if (!file || !row || (write_fd = dup(fileno(file))) < 0 ||
      !(raster = cupsRasterOpen(write_fd, CUPS_RASTER_WRITE_PWG)))
    goto cleanup;
  for (unsigned page = 0U; page < plan->pages; page ++) {
    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "Plain", sizeof("Plain"));
    memcpy(header.cupsPageSizeName, "Geometry", sizeof("Geometry"));
    header.HWResolution[0] = plan->input_resolution_x;
    header.HWResolution[1] = plan->input_resolution_y;
    header.PageSize[0] = plan->page_width;
    header.PageSize[1] = plan->page_height;
    header.ImagingBoundingBox[2] = plan->input_width;
    header.ImagingBoundingBox[3] = plan->input_height;
    header.cupsPageSize[0] = (float)plan->page_width;
    header.cupsPageSize[1] = (float)plan->page_height;
    header.cupsImagingBBox[2] = header.cupsPageSize[0];
    header.cupsImagingBBox[3] = header.cupsPageSize[1];
    header.cupsWidth = plan->input_width;
    header.cupsHeight = plan->input_height;
    header.cupsBitsPerColor = bits_per_color;
    header.cupsBitsPerPixel = bits_per_pixel;
    header.cupsBytesPerLine = plan->input_bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = colors;
    header.NumCopies = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_CrossFeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_FeedTransform] = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] = plan->input_width;
    header.cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] = plan->input_height;
    if (!cupsRasterWriteHeader2(raster, &header))
      goto cleanup;
    for (uint32_t y = 0U; y < plan->input_height; y ++) {
      for (uint32_t x = 0U; x < plan->input_bytes_per_line; x ++) {
        size_t offset = ((size_t)page * plan->input_height + y) *
                            plan->input_bytes_per_line + x;
        size_t source_offset = relation_row ?
            ((size_t)page * plan->input_height + y) * relation_row +
                x % relation_row : offset;
        row[x] = cf_v2_arithmetic_material(layout, material_size,
                                           source_offset);
      }
      if (cupsRasterWritePixels(raster, row, plan->input_bytes_per_line) !=
          plan->input_bytes_per_line)
        goto cleanup;
    }
  }
  cupsRasterClose(raster);
  raster = NULL;
  close(write_fd);
  write_fd = -1;
  if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0 ||
      (unsigned long)file_size > CF_V2_ARITHMETIC_MAX_RASTER ||
      fseek(file, 0, SEEK_SET) != 0 ||
      !(document = (uint8_t *)malloc((size_t)file_size + 4096U)) ||
      fread(document, 1U, (size_t)file_size, file) != (size_t)file_size)
    goto cleanup;
  *document_size = (size_t)file_size;
  if (relation_payload < expected_payload) {
    size_t missing = expected_payload - relation_payload;
    if (missing < *document_size)
      *document_size -= missing;
  } else if (relation_payload > expected_payload) {
    size_t extra = relation_payload - expected_payload;
    if (extra > 4096U)
      extra = 4096U;
    for (size_t index = 0U; index < extra; index ++)
      document[(*document_size) ++] =
          cf_v2_arithmetic_material(layout, material_size,
                                    expected_payload + index);
  }
  free(row);
  fclose(file);
  return document;

cleanup:
  if (raster)
    cupsRasterClose(raster);
  if (write_fd >= 0)
    close(write_fd);
  free(row);
  free(document);
  if (file)
    fclose(file);
  return NULL;
}

static int
cf_v2_arithmetic_run_pwg(cf_v2_arithmetic_layout_t *layout)
{
  cf_v2_arithmetic_pwg_plan_t plan;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  uint8_t *document = NULL;
  char *ppd = NULL;
  char options[512];
  static const uint8_t title[] = "arithmetic-layout";
  size_t document_size = 0U;
  size_t ppd_size = 0U;
  int options_length;

  if (!cf_v2_arithmetic_pwg_plan(layout, &plan))
    return 0;
  document = cf_v2_arithmetic_build_pwg(layout, &plan, &document_size);
  ppd = cf_v2_arithmetic_build_ppd(
      layout, plan.page_width, plan.page_height,
      plan.output_resolution_x, plan.output_resolution_y, &ppd_size);
  options_length = snprintf(
      options, sizeof(options),
      "PageSize=Geometry PageRegion=Geometry ColorModel=Layout "
      "Resolution=Geometry cm-calibration=true emit-jcl=false copies=1");
  if (!document || !document_size || !ppd || options_length < 0 ||
      (size_t)options_length >= sizeof(options))
    goto cleanup;
  memset(&job, 0, sizeof(job));
  memset(&result, 0, sizeof(result));
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_length;
  job.title = title;
  job.title_size = sizeof(title) - 1U;
  job.document = document;
  job.document_size = document_size;
  job.control_bytes = (const uint8_t *)&job.control;
#if defined(CF_V2_ARITHMETIC_PWG_HORIZONTAL) || \
    defined(CF_V2_ARITHMETIC_PWG_VERTICAL) || \
    defined(CF_V2_ARITHMETIC_PWG_PLANAR)
  cf_v2_arithmetic_trace_source_format = layout->source_format;
  cf_v2_arithmetic_trace_planned_product = plan.mathematical_product;
  cf_v2_arithmetic_trace_planned_allocation = plan.encoded_allocation;
  cf_v2_arithmetic_trace_filter_active = 1;
#endif
  cf_v2_relation_stats_register(&cf_v2_arithmetic_relation_stats,
                                CF_V2_TARGET_NAME);
  cf_v2_arithmetic_layout_record(&cf_v2_arithmetic_relation_stats, layout);
  (void)cf_v2_execute_direct_job(&job, 0, &result);
#if defined(CF_V2_ARITHMETIC_PWG_HORIZONTAL) || \
    defined(CF_V2_ARITHMETIC_PWG_VERTICAL) || \
    defined(CF_V2_ARITHMETIC_PWG_PLANAR)
  cf_v2_arithmetic_trace_filter_active = 0;
#endif
  cf_v2_free_run_result(&result);
  cf_v2_release_joined_options();

cleanup:
  free(ppd);
  free(document);
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  cf_v2_arithmetic_layout_t layout;

  if (size > CF_V2_ARITHMETIC_MAX_INPUT ||
      !cf_v2_arithmetic_layout_parse(data, size, &layout))
    return 0;
#if defined(CF_V2_ARITHMETIC_IMAGE_PAGE) || \
    defined(CF_V2_ARITHMETIC_IMAGE_ROW)
  return cf_v2_arithmetic_run_image(&layout);
#else
  return cf_v2_arithmetic_run_pwg(&layout);
#endif
}
