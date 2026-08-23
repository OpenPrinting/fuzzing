// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "raster_pwg_bridge.h"
#include "raster_pwg_packed_oracle.h"
#include "raster_pwg_route.h"
#include "raster_pwg_wrapper_bridge.h"
#include "pwg_filter_adapter.h"

#include "../../v2/include/control.h"

#include <cups/raster.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int cf_v3_raster_pwg_direct_pwg_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_direct_apple_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_direct_pclm_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_state_pwg_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_state_apple_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_state_pclm_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_oracle_pwg_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_oracle_apple_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_backside_pwg_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_backside_apple_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_backside_native_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_backside_manual_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_metadata_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_pwg_name_legacy(const uint8_t *, size_t);

typedef int (*cf_v3_raster_pwg_runner_t)(const uint8_t *, size_t);

static const cf_v3_raster_pwg_runner_t cf_v3_raster_pwg_runners[] =
{
  cf_v3_raster_pwg_direct_pwg_legacy,
  cf_v3_raster_pwg_direct_apple_legacy,
  cf_v3_raster_pwg_direct_pclm_legacy,
  cf_v3_raster_pwg_state_pwg_legacy,
  cf_v3_raster_pwg_state_apple_legacy,
  cf_v3_raster_pwg_state_pclm_legacy,
  cf_v3_raster_pwg_oracle_pwg_legacy,
  cf_v3_raster_pwg_oracle_apple_legacy,
  cf_v3_raster_pwg_backside_pwg_legacy,
  cf_v3_raster_pwg_backside_apple_legacy,
  cf_v3_raster_pwg_backside_native_legacy,
  cf_v3_raster_pwg_backside_manual_legacy,
  cf_v3_raster_pwg_metadata_legacy,
  cf_v3_raster_pwg_name_legacy
};

static int
cf_v3_raster_pwg_call(unsigned route, cf_v3_raster_pwg_runner_t runner,
                      const uint8_t *data, size_t size)
{
  int result;

  cf_v3_raster_pwg_wrapper_enter(route);
  result = runner(data, size);
  cf_v3_raster_pwg_wrapper_leave();
  cf_v3_pwg_filter_release();
  return result;
}

static void
cf_v3_raster_pwg_selectors(const uint8_t *header, uint8_t selector[12])
{
  static const uint8_t offsets[12] =
  {
    4U, 0U, 2U, 36U, 38U, 40U, 42U, 60U, 72U, 5U, 64U, 77U
  };
  static const uint8_t mixes[12] =
  {
    5U, 41U, 43U, 65U, 67U, 69U, 71U, 61U, 76U, 78U, 66U, 35U
  };

  for (size_t index = 0U; index < 12U; index ++)
    selector[index] = header[offsets[index]] ^ header[mixes[index]];
}

static uint8_t
cf_v3_raster_pwg_material(const uint8_t *material, size_t material_size,
                          unsigned pattern, unsigned page, size_t offset)
{
  uint8_t value = material_size
                      ? material[(offset + (size_t)page * 257U) %
                                 material_size]
                      : (uint8_t)(offset * 131U + page * 67U);

  switch (pattern % 6U)
  {
    case 0U: return value;
    case 1U: return 0U;
    case 2U: return 0xffU;
    case 3U: return offset & 1U ? 0xaaU : 0x55U;
    case 4U: return (uint8_t)offset;
    default: return (uint8_t)(value ^ (uint8_t)(offset * 29U));
  }
}

static void
cf_v3_raster_pwg_profile(cf_v2_arithmetic_source_format_t format,
                         cups_cspace_t *color_space,
                         unsigned *bits_per_color,
                         unsigned *bits_per_pixel, unsigned *num_colors)
{
  if (format == CF_V2_ARITHMETIC_SOURCE_RGB8)
  {
    *color_space = CUPS_CSPACE_SRGB;
    *bits_per_color = 8U;
    *bits_per_pixel = 24U;
    *num_colors = 3U;
  }
  else if (format == CF_V2_ARITHMETIC_SOURCE_BLACK1)
  {
    *color_space = CUPS_CSPACE_SW;
    *bits_per_color = 1U;
    *bits_per_pixel = 1U;
    *num_colors = 1U;
  }
  else
  {
    *color_space = CUPS_CSPACE_W;
    *bits_per_color = 8U;
    *bits_per_pixel = 8U;
    *num_colors = 1U;
  }
}

static uint8_t *
cf_v3_raster_pwg_document(const cf_v2_arithmetic_layout_t *layout,
                          const uint8_t selector[12],
                          const uint8_t *material, size_t material_size,
                          size_t *document_size)
{
  static const unsigned margins[] = {0U, 1U, 2U, 3U, 4U, 7U, 8U, 15U, 16U};
  cups_cspace_t color_space;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
  unsigned num_colors;
  unsigned width = layout->source_width;
  unsigned height = layout->source_height;
  unsigned left = margins[selector[3] % (sizeof(margins) / sizeof(margins[0]))];
  unsigned right = margins[selector[4] % (sizeof(margins) / sizeof(margins[0]))];
  unsigned bottom = margins[selector[5] % (sizeof(margins) / sizeof(margins[0]))];
  unsigned top = margins[selector[6] % (sizeof(margins) / sizeof(margins[0]))];
  unsigned pages = 1U + selector[7] % 4U;
  size_t bytes_per_line;
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;

  cf_v3_raster_pwg_profile(layout->source_format, &color_space,
                           &bits_per_color, &bits_per_pixel, &num_colors);
  bytes_per_line = ((size_t)width * bits_per_pixel + 7U) / 8U;
  if (!bytes_per_line || bytes_per_line > 4096U || height > 256U)
    return NULL;
  for (unsigned page = 0U; page < pages; page ++)
  {
    size_t page_bytes = (size_t)height * bytes_per_line;

    if (page_bytes > SIZE_MAX - sizeof(cups_page_header2_t) ||
        total > SIZE_MAX - sizeof(cups_page_header2_t) - page_bytes)
      return NULL;
    total += sizeof(cups_page_header2_t) + page_bytes;
  }
  document = (uint8_t *)malloc(total);
  if (!document)
    return NULL;
  memcpy(document, "3SaR", 4U);
  for (unsigned page = 0U; page < pages; page ++)
  {
    cups_page_header2_t header;
    unsigned outer_width = width + left + right;
    unsigned outer_height = height + top + bottom;
    size_t pixels = (size_t)height * bytes_per_line;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "stationery", sizeof("stationery"));
    memcpy(header.cupsPageSizeName, "Tiny", sizeof("Tiny"));
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = outer_width;
    header.PageSize[1] = outer_height;
    header.ImagingBoundingBox[0] = left;
    header.ImagingBoundingBox[1] = bottom;
    header.ImagingBoundingBox[2] = left + width;
    header.ImagingBoundingBox[3] = bottom + height;
    header.cupsPageSize[0] = (float)outer_width;
    header.cupsPageSize[1] = (float)outer_height;
    header.cupsImagingBBox[0] = (float)left;
    header.cupsImagingBBox[1] = (float)bottom;
    header.cupsImagingBBox[2] = (float)(left + width);
    header.cupsImagingBBox[3] = (float)(bottom + height);
    header.cupsWidth = width;
    header.cupsHeight = height;
    header.cupsBitsPerColor = bits_per_color;
    header.cupsBitsPerPixel = bits_per_pixel;
    header.cupsBytesPerLine = (unsigned)bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = num_colors;
    header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] = pages;
    header.NumCopies = 1U;
    header.Duplex = (selector[10] >> (page & 3U)) & 1U;
    header.Tumble = (selector[10] >> (4U + (page & 3U))) & 1U;
    header.Orientation = (cups_orient_t)((selector[11] + page) % 4U);
    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);
    for (size_t index = 0U; index < pixels; index ++)
      document[offset + index] = cf_v3_raster_pwg_material(
          material, material_size, layout->pattern, page, index);
    offset += pixels;
  }
  *document_size = total;
  return document;
}

static void
cf_v3_raster_pwg_control(const uint8_t *header, cf_v2_control_t *control)
{
  static const uint8_t offsets[CF_V2_CONTROL_SIZE] =
  {
    78U, 77U, 5U, 27U, 64U, 35U, 34U, 63U,
    37U, 39U, 76U, 7U, 72U, 66U, 68U, 70U
  };

  for (size_t index = 0U; index < CF_V2_CONTROL_SIZE; index ++)
    ((uint8_t *)control)[index] = header[offsets[index]];
}

static int
cf_v3_raster_pwg_run_direct(unsigned route,
                            const cf_v2_arithmetic_layout_t *layout,
                            const uint8_t *header, const uint8_t *material,
                            size_t material_size)
{
  uint8_t selector[12];
  uint8_t *generated = NULL;
  uint8_t *input = NULL;
  const uint8_t *document;
  size_t document_size;
  size_t input_size;
  cf_v2_control_t control;

  cf_v3_raster_pwg_selectors(header, selector);
  if (layout->option_mode == 3U)
  {
    document = material;
    document_size = material_size;
  }
  else
  {
    generated = cf_v3_raster_pwg_document(
        layout, selector, material, material_size, &document_size);
    document = generated;
  }
  if (!document || !document_size ||
      document_size > SIZE_MAX - CF_V2_CONTROL_SIZE)
    goto cleanup;
  input_size = document_size + CF_V2_CONTROL_SIZE;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    goto cleanup;
  cf_v3_raster_pwg_control(header, &control);
  memcpy(input, document, document_size);
  memcpy(input + document_size, &control, CF_V2_CONTROL_SIZE);
  (void)cf_v3_raster_pwg_call(route, cf_v3_raster_pwg_runners[route],
                              input, input_size);

cleanup:
  free(input);
  free(generated);
  return 0;
}

static int
cf_v3_raster_pwg_run_state(unsigned route, const uint8_t *header,
                           const uint8_t *material, size_t material_size)
{
  uint8_t input[8U + 8U + 4096U];
  uint8_t selector[12];

  cf_v3_raster_pwg_selectors(header, selector);
  memcpy(input, "ROSTATE1", 8U);
  memcpy(input + 8U, selector, 8U);
  memcpy(input + 16U, material, material_size);
  return cf_v3_raster_pwg_call(route, cf_v3_raster_pwg_runners[route],
                               input, 16U + material_size);
}

static int
cf_v3_raster_pwg_run_output_oracle(unsigned route, const uint8_t *header,
                                   const uint8_t *material,
                                   size_t material_size)
{
  uint8_t input[12U + 256U];
  uint8_t selector[12];

  cf_v3_raster_pwg_selectors(header, selector);
  if (material_size > 256U)
    material_size = 256U;
  memcpy(input, selector, sizeof(selector));
  memcpy(input + sizeof(selector), material, material_size);
  return cf_v3_raster_pwg_call(route, cf_v3_raster_pwg_runners[route],
                               input, sizeof(selector) + material_size);
}

static int
cf_v3_raster_pwg_run_backside(unsigned route, const uint8_t *header,
                              int faithful)
{
  uint8_t input[20U];
  uint8_t selector[12];
  unsigned actual_route = route;

  cf_v3_raster_pwg_selectors(header, selector);
  if (!faithful &&
      route == CF_V3_RASTER_PWG_ROUTE_BACKSIDE_NATIVE_BOUNDARY)
  {
    actual_route = CF_V3_RASTER_PWG_ROUTE_BACKSIDE_PWG;
    selector[0] = (uint8_t)(1U + selector[0] % 3U);
    selector[1] = 2U;
    selector[2] = 2U;
    selector[9] = 1U;
  }
  else if (!faithful &&
           route == CF_V3_RASTER_PWG_ROUTE_BACKSIDE_MANUAL_BOUNDARY)
  {
    actual_route = CF_V3_RASTER_PWG_ROUTE_BACKSIDE_APPLE;
    selector[0] = 3U;
    selector[1] = 1U;
    selector[2] = 2U;
    selector[9] = 0U;
  }
  memcpy(input, "RPWGBK01", 8U);
  memcpy(input + 8U, selector, sizeof(selector));
  return cf_v3_raster_pwg_call(
      actual_route, cf_v3_raster_pwg_runners[actual_route], input,
      sizeof(input));
}

static int
cf_v3_raster_pwg_run_metadata(unsigned route, const uint8_t *header)
{
  uint8_t input[21U];
  uint8_t selector[12];

  cf_v3_raster_pwg_selectors(header, selector);
  memcpy(input, "RPWGMETA1", 9U);
  memcpy(input + 9U, selector, sizeof(selector));
  return cf_v3_raster_pwg_call(route, cf_v3_raster_pwg_runners[route],
                               input, sizeof(input));
}

static int
cf_v3_raster_pwg_run_page_name(unsigned route, const uint8_t *header,
                               int faithful)
{
  uint8_t input[13U];
  uint8_t selector[12];

  cf_v3_raster_pwg_selectors(header, selector);
  if (!faithful)
    selector[0] %= 2U;
  memcpy(input, "RPWGNAME1", 9U);
  memcpy(input + 9U, selector, 4U);
  return cf_v3_raster_pwg_call(route, cf_v3_raster_pwg_runners[route],
                               input, sizeof(input));
}

int
cf_v3_raster_pwg_bridge(const uint8_t *data, size_t size)
{
  cf_v2_arithmetic_layout_t layout;
  const uint8_t *header;
  const uint8_t *material;
  size_t material_size;
  unsigned route;
  int faithful;

  if (!cf_v3_raster_pwg_input(data, size) ||
      !cf_v2_arithmetic_layout_parse(data, size, &layout))
    return 0;
  header = cf_v3_raster_pwg_const_header(data);
  material = data + CF_V3_RASTER_PWG_FIXED_SIZE;
  material_size = size - CF_V3_RASTER_PWG_FIXED_SIZE;
  route = cf_v3_raster_pwg_route(header);
  faithful = cf_v3_raster_pwg_faithful(header);
  if (getenv("CF_V3_TRACE_RASTER_PWG"))
    fprintf(stderr, "raster-pwg-route: route=%u faithful=%d format=%u\n",
            route, faithful, (unsigned)layout.source_format);

  if (route <= CF_V3_RASTER_PWG_ROUTE_DIRECT_PCLM)
    return cf_v3_raster_pwg_run_direct(route, &layout, header, material,
                                       material_size);
  if (route <= CF_V3_RASTER_PWG_ROUTE_STATE_PCLM)
    return cf_v3_raster_pwg_run_state(route, header, material, material_size);
  if (route <= CF_V3_RASTER_PWG_ROUTE_ORACLE_APPLE)
    return cf_v3_raster_pwg_run_output_oracle(route, header, material,
                                              material_size);
  if (route <= CF_V3_RASTER_PWG_ROUTE_BACKSIDE_MANUAL_BOUNDARY)
    return cf_v3_raster_pwg_run_backside(route, header, faithful);
  if (route == CF_V3_RASTER_PWG_ROUTE_METADATA)
    return cf_v3_raster_pwg_run_metadata(route, header);
  if (route == CF_V3_RASTER_PWG_ROUTE_PAGE_NAME)
    return cf_v3_raster_pwg_run_page_name(route, header, faithful);
  {
    uint8_t selector[12];

    cf_v3_raster_pwg_selectors(header, selector);
    return cf_v3_raster_pwg_packed_oracle(
        selector, material, material_size, faithful);
  }
}
