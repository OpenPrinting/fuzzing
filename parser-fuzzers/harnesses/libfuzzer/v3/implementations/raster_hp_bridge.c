// SPDX-License-Identifier: Apache-2.0
#include "raster_hp_bridge.h"
#include "raster_hp_route.h"
#include "raster_hp_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cups_cspace_t
cf_v3_raster_hp_color(cf_v2_arithmetic_color_space_t color)
{
  switch (color)
  {
    case CF_V2_ARITHMETIC_COLOR_RGB:
    case CF_V2_ARITHMETIC_COLOR_SRGB:
    case CF_V2_ARITHMETIC_COLOR_CMY:
      return CUPS_CSPACE_CMY;
    case CF_V2_ARITHMETIC_COLOR_CMYK:
      return CUPS_CSPACE_KCMY;
    default:
      return CUPS_CSPACE_K;
  }
}

static uint32_t
cf_v3_raster_hp_resolution(int64_t encoded)
{
  static const uint32_t values[] = {150U, 300U, 600U, 1200U};
  uint64_t magnitude = encoded < 0 ? (uint64_t)(-(encoded + 1)) + 1U :
                                      (uint64_t)encoded;

  return values[magnitude % (sizeof(values) / sizeof(values[0]))];
}

static uint32_t
cf_v3_raster_hp_page_height(int64_t encoded)
{
  static const uint32_t values[] = {
    540U, 595U, 624U, 649U, 684U, 709U, 756U,
    792U, 842U, 1008U, 1191U, 1224U
  };
  uint64_t magnitude = encoded < 0 ? (uint64_t)(-(encoded + 1)) + 1U :
                                      (uint64_t)encoded;

  return values[magnitude % (sizeof(values) / sizeof(values[0]))];
}

static unsigned
cf_v3_raster_hp_planes(cups_cspace_t color_space)
{
  if (color_space == CUPS_CSPACE_KCMY)
    return 4U;
  if (color_space == CUPS_CSPACE_CMY)
    return 3U;
  return 1U;
}

static void
cf_v3_raster_hp_safe_layout(cf_v3_raster_hp_case_t *test_case)
{
  unsigned planes;
  uint32_t plane_bytes;

  if (test_case->bits_per_color > 2U)
    test_case->bits_per_color = 1U;
#ifdef CF_V3_CUPS_HP_LEGACY_COLORBITS
  /* The frozen CRet implementation allocates every non-zero compression
   * buffer with the smaller PackBits bound, while type 1 can emit 2*N bytes.
   * CompressData's dedicated route retains type 1 with a correct harness
   * buffer; complete jobs use raw or PackBits until the production fix. */
  if (test_case->compression == 1U)
    test_case->compression = 0U;
  /* CRet model 2 only recognizes KCMY as multi-plane. Mapping CMY to KCMY
   * keeps the declared row layout and StartPage's plane count coherent. */
  if (test_case->ppd_model == 2U &&
      test_case->color_space == CUPS_CSPACE_CMY)
    test_case->color_space = CUPS_CSPACE_KCMY;
#endif
  planes = cf_v3_raster_hp_planes(test_case->color_space);
  if (planes > 1U && test_case->color_order == CUPS_ORDER_PLANAR)
    test_case->color_order = CUPS_ORDER_BANDED;

  if (test_case->bits_per_color == 2U)
  {
    int coherent = 0;

    for (unsigned attempt = 0U; attempt < 16U; attempt ++)
    {
      uint32_t bytes_per_line;
      uint32_t source_count;

      plane_bytes = (test_case->width * 2U + 7U) / 8U;
      if (test_case->color_order == CUPS_ORDER_CHUNKED)
        bytes_per_line = (test_case->width * 2U * planes + 7U) / 8U;
      else
        bytes_per_line = plane_bytes * planes;
      source_count = bytes_per_line / planes;
      if (source_count && !(source_count & 1U))
      {
        coherent = 1;
        break;
      }
      if (test_case->width < 512U)
        test_case->width ++;
      else if (test_case->width > 1U)
        test_case->width --;
      else
      {
        test_case->bits_per_color = 1U;
        break;
      }
    }
    if (!coherent)
      test_case->bits_per_color = 1U;
  }
}

static void
cf_v3_raster_hp_planar_case(cf_v3_raster_hp_case_t *test_case,
                            const uint8_t *header)
{
  static const uint32_t widths[] = {64U, 128U, 256U, 512U};

  test_case->width = widths[header[1] %
      (sizeof(widths) / sizeof(widths[0]))];
  test_case->height = 2U;
  test_case->bits_per_color = 1U;
  test_case->compression = 0U;
  switch (header[68] % 3U)
  {
    case 0U:
      test_case->color_space = CUPS_CSPACE_K;
      test_case->color_order = CUPS_ORDER_CHUNKED;
      break;
    case 1U:
      test_case->color_space = CUPS_CSPACE_KCMY;
      test_case->color_order = CUPS_ORDER_BANDED;
      break;
    default:
      test_case->color_space = CUPS_CSPACE_KCMY;
      test_case->color_order = CUPS_ORDER_PLANAR;
      break;
  }
}

int
cf_v3_raster_hp_run(const uint8_t *data, size_t size)
{
  cf_v2_arithmetic_layout_t layout;
  cf_v3_raster_hp_case_t test_case;
  const uint8_t *header;
  const uint8_t *material;
  size_t material_size;
  size_t copies;
  unsigned route;
  int faithful;
  int result;

  if (!cf_v3_raster_hp_input(data, size) ||
      !cf_v2_arithmetic_layout_parse(data, size, &layout))
    return 0;
  header = cf_v3_raster_hp_const_header(data);
  material = data + CF_V3_RASTER_HP_FIXED_SIZE;
  material_size = size - CF_V3_RASTER_HP_FIXED_SIZE;
  route = cf_v3_raster_hp_route(header);
  faithful = cf_v3_raster_hp_faithful(header);

  memset(&test_case, 0, sizeof(test_case));
  test_case.width = layout.source_width;
  test_case.height = layout.source_height;
  test_case.color_space = cf_v3_raster_hp_color(layout.output_color_space);
  test_case.bits_per_color = layout.output_bits_per_color;
  test_case.color_order = (cups_order_t)layout.output_color_order;
  test_case.compression = layout.geometry_phase % 3U;
  test_case.resolution = cf_v3_raster_hp_resolution(
      cf_v2_scalar_relation_value(&layout.output_resolution_x));
  test_case.page_height = cf_v3_raster_hp_page_height(
      cf_v2_scalar_relation_value(&layout.media_height));
  copies = cf_v2_cardinality_value(&layout.copies);
  test_case.copies = copies ? (uint32_t)copies : 1U;
  test_case.media_position = header[65] % 8U;
  test_case.media_type = header[67] % 5U;
  test_case.duplex = header[69] & 1U;
  test_case.tumble = (header[69] >> 1U) & 1U;
  test_case.ppd_model = (layout.option_mode & 1U) ? 2U : 0U;
  test_case.pattern = layout.pattern;
  test_case.material_phase = layout.material_phase;
  memcpy(test_case.selectors, header + 64U, sizeof(test_case.selectors));

  if (route == CF_V3_RASTER_HP_ROUTE_PLANAR)
    cf_v3_raster_hp_planar_case(&test_case, header);
  else if (route == CF_V3_RASTER_HP_ROUTE_ONE_BIT)
    test_case.bits_per_color = 1U;

  if (!faithful && (route == CF_V3_RASTER_HP_ROUTE_JOB ||
                    route == CF_V3_RASTER_HP_ROUTE_PLANAR ||
                    route == CF_V3_RASTER_HP_ROUTE_LAYOUT ||
                    route == CF_V3_RASTER_HP_ROUTE_ONE_BIT))
    cf_v3_raster_hp_safe_layout(&test_case);

  switch (route)
  {
    case CF_V3_RASTER_HP_ROUTE_JOB:
    case CF_V3_RASTER_HP_ROUTE_PLANAR:
    case CF_V3_RASTER_HP_ROUTE_LAYOUT:
    case CF_V3_RASTER_HP_ROUTE_ONE_BIT:
      result = cf_v3_raster_hp_run_main(&test_case, material, material_size);
      break;
    case CF_V3_RASTER_HP_ROUTE_CODEC:
      result = cf_v3_raster_hp_run_codec(&test_case, material, material_size);
      break;
    case CF_V3_RASTER_HP_ROUTE_ROW:
      result = cf_v3_raster_hp_run_row(&test_case, material, material_size);
      break;
    case CF_V3_RASTER_HP_ROUTE_PAGE:
      result = cf_v3_raster_hp_run_page(&test_case, material,
                                        material_size, 0);
      break;
    case CF_V3_RASTER_HP_ROUTE_TUMBLE:
      result = cf_v3_raster_hp_run_page(&test_case, material,
                                        material_size, faithful);
      break;
    default:
      result = 0;
      break;
  }
  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "raster_hp route=%u faithful=%d input=%zu\n",
            route, faithful, size);
  return result;
}
