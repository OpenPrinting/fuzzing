// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_ARITHMETIC_LAYOUT_H
#define CUPSFILTERS_FUZZ_V2_ARITHMETIC_LAYOUT_H

#include "relation_program.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_ARITHMETIC_LAYOUT_MAGIC "ARITHL01"
#define CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE 8U
#define CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE 80U

typedef enum cf_v2_arithmetic_source_format_e {
  CF_V2_ARITHMETIC_SOURCE_GRAY8 = 0,
  CF_V2_ARITHMETIC_SOURCE_RGB8 = 1,
  CF_V2_ARITHMETIC_SOURCE_BLACK1 = 2,
  CF_V2_ARITHMETIC_SOURCE_FORMAT_COUNT = 3
} cf_v2_arithmetic_source_format_t;

typedef enum cf_v2_arithmetic_color_space_e {
  CF_V2_ARITHMETIC_COLOR_W = 0,
  CF_V2_ARITHMETIC_COLOR_K = 1,
  CF_V2_ARITHMETIC_COLOR_RGB = 2,
  CF_V2_ARITHMETIC_COLOR_SRGB = 3,
  CF_V2_ARITHMETIC_COLOR_CMY = 4,
  CF_V2_ARITHMETIC_COLOR_CMYK = 5,
  CF_V2_ARITHMETIC_COLOR_SPACE_COUNT = 6
} cf_v2_arithmetic_color_space_t;

typedef enum cf_v2_arithmetic_axis_relation_e {
  CF_V2_ARITHMETIC_AXIS_INDEPENDENT = 0,
  CF_V2_ARITHMETIC_AXIS_Y_FOLLOWS_X = 1,
  CF_V2_ARITHMETIC_AXIS_X_FOLLOWS_Y = 2,
  CF_V2_ARITHMETIC_AXIS_SWAP = 3,
  CF_V2_ARITHMETIC_AXIS_RELATION_COUNT = 4
} cf_v2_arithmetic_axis_relation_t;

typedef struct cf_v2_arithmetic_layout_s {
  uint32_t source_width;
  uint32_t source_height;
  cf_v2_arithmetic_source_format_t source_format;
  cf_v2_arithmetic_color_space_t output_color_space;
  uint32_t output_bits_per_color;
  uint8_t output_color_order;
  cf_v2_scalar_relation_t channels;
  cf_v2_scalar_relation_t bits_per_pixel;
  cf_v2_scalar_relation_t source_ppi_x;
  cf_v2_scalar_relation_t source_ppi_y;
  cf_v2_scalar_relation_t media_width;
  cf_v2_scalar_relation_t media_height;
  cf_v2_scalar_relation_t output_resolution_x;
  cf_v2_scalar_relation_t output_resolution_y;
  cf_v2_scalar_relation_t natural_scaling;
  cf_v2_arithmetic_axis_relation_t axis_relation;
  cf_v2_cardinality_relation_t x_pages;
  cf_v2_cardinality_relation_t y_pages;
  cf_v2_cardinality_relation_t logical_width;
  cf_v2_cardinality_relation_t line_bytes;
  cf_v2_cardinality_relation_t horizontal_product;
  cf_v2_cardinality_relation_t vertical_product;
  cf_v2_cardinality_relation_t page_product;
  cf_v2_length_relation_t row_length;
  cf_v2_length_relation_t payload_length;
  cf_v2_cardinality_relation_t input_pages;
  cf_v2_cardinality_relation_t copies;
  cf_v2_action_program_t actions;
  uint8_t material_phase;
  cf_v2_relation_mode_t opaque_mode;
  cf_v2_length_relation_t opaque_length;
  uint8_t pattern;
  uint8_t geometry_phase;
  uint8_t option_mode;
  uint8_t spare;
  cf_v2_opaque_bytes_t opaque;
} cf_v2_arithmetic_layout_t;

static inline int16_t
cf_v2_arithmetic_i16(const uint8_t *data)
{
  uint16_t encoded = (uint16_t)data[0] | (uint16_t)data[1] << 8U;

  return (int16_t)encoded;
}

static inline int32_t
cf_v2_arithmetic_i32(const uint8_t *data)
{
  uint32_t encoded = (uint32_t)data[0] |
                     (uint32_t)data[1] << 8U |
                     (uint32_t)data[2] << 16U |
                     (uint32_t)data[3] << 24U;

  return (int32_t)encoded;
}

static inline uint32_t
cf_v2_arithmetic_output_channels(cf_v2_arithmetic_color_space_t color_space)
{
  switch (color_space) {
    case CF_V2_ARITHMETIC_COLOR_RGB:
    case CF_V2_ARITHMETIC_COLOR_SRGB:
    case CF_V2_ARITHMETIC_COLOR_CMY:
      return 3U;
    case CF_V2_ARITHMETIC_COLOR_CMYK:
      return 4U;
    default:
      return 1U;
  }
}

static inline int
cf_v2_arithmetic_image_raster_tuple(
    const cf_v2_arithmetic_layout_t *layout, uint32_t *channels,
    uint32_t *bits_per_pixel)
{
  uint32_t normalized_channels;
  uint64_t normalized_bits;

  if (!layout || !channels || !bits_per_pixel ||
      !layout->output_bits_per_color || layout->output_color_order > 2U)
    return 0;
  normalized_channels = cf_v2_arithmetic_output_channels(
      layout->output_color_space);
  normalized_bits = layout->output_bits_per_color;
  if (layout->output_color_order == 0U)
    normalized_bits *= normalized_channels;
  if (!normalized_bits || normalized_bits > UINT32_MAX)
    return 0;
  *channels = normalized_channels;
  *bits_per_pixel = (uint32_t)normalized_bits;
  return 1;
}

static inline int
cf_v2_arithmetic_image_raster_width(uint32_t source_width,
                                    uint32_t source_ppi,
                                    int natural_scaling,
                                    uint32_t output_resolution,
                                    uint32_t *raster_width)
{
  float inches;
  float pixels;

  if (!source_width || !source_ppi || natural_scaling <= 0 ||
      !output_resolution || !raster_width)
    return 0;
  inches = (float)source_width / (float)source_ppi;
  inches = inches * (float)natural_scaling / 100.0f;
  pixels = inches * (float)output_resolution;
  if (!(pixels >= 1.0f) || !(pixels < 4294967296.0f))
    return 0;
  *raster_width = (uint32_t)pixels;
  return *raster_width != 0U;
}

static inline size_t
cf_v2_arithmetic_source_row_bytes(uint32_t width,
                                  cf_v2_arithmetic_source_format_t format)
{
  switch (format) {
    case CF_V2_ARITHMETIC_SOURCE_RGB8:
      return (size_t)width * 3U;
    case CF_V2_ARITHMETIC_SOURCE_BLACK1:
      return ((size_t)width + 7U) / 8U;
    default:
      return width;
  }
}

static inline void
cf_v2_arithmetic_cardinality_init(cf_v2_cardinality_relation_t *relation,
                                  uint8_t class_id, uint8_t parameter,
                                  size_t boundary, size_t limit)
{
  relation->class_id = (cf_v2_cardinality_class_t)(
      class_id % CF_V2_CARDINALITY_CLASS_COUNT);
  relation->parameter = parameter;
  relation->boundary = boundary;
  relation->limit = limit;
}

static inline void
cf_v2_arithmetic_scalar_init(cf_v2_scalar_relation_t *relation,
                             uint8_t mode, int64_t derived,
                             uint8_t kind, uint8_t parameter,
                             uint64_t maximum, int allow_zero)
{
  relation->mode = cf_v2_relation_mode(mode);
  relation->derived_value = derived;
  relation->explicit_value = (int64_t)cf_v2_boundary_bounded_unsigned(
      kind, parameter, maximum);
  if (!allow_zero && relation->explicit_value < 1)
    relation->explicit_value = 1;
}

static inline size_t
cf_v2_arithmetic_add_limit(size_t value, size_t increment)
{
  return value > SIZE_MAX - increment ? SIZE_MAX : value + increment;
}

static inline int
cf_v2_arithmetic_layout_parse(const uint8_t *data, size_t size,
                              cf_v2_arithmetic_layout_t *layout)
{
  static const uint32_t bits_per_color[] = {1U, 2U, 4U, 8U, 16U};
  const uint8_t *header;
  uint32_t derived_channels;
  uint64_t derived_bpp;
  uint64_t logical_boundary;
  size_t source_row;
  size_t source_payload;

  if (!data || !layout ||
      size < CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE +
                 CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE + 1U ||
      memcmp(data, CF_V2_ARITHMETIC_LAYOUT_MAGIC,
             CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE))
    return 0;
  memset(layout, 0, sizeof(*layout));
  header = data + CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE;

  layout->source_width = (uint32_t)cf_v2_boundary_bounded_unsigned(
      header[0], header[1], 256U);
  layout->source_height = (uint32_t)cf_v2_boundary_bounded_unsigned(
      header[2], header[3], 256U);
  if (!layout->source_width)
    layout->source_width = 1U;
  if (!layout->source_height)
    layout->source_height = 1U;
  layout->source_format = (cf_v2_arithmetic_source_format_t)(
      header[4] % CF_V2_ARITHMETIC_SOURCE_FORMAT_COUNT);
  layout->output_color_space = (cf_v2_arithmetic_color_space_t)(
      header[5] % CF_V2_ARITHMETIC_COLOR_SPACE_COUNT);
  layout->output_bits_per_color = bits_per_color[
      header[6] % (sizeof(bits_per_color) / sizeof(bits_per_color[0]))];
  layout->output_color_order = header[7] % 3U;

  derived_channels = cf_v2_arithmetic_output_channels(
      layout->output_color_space);
  cf_v2_arithmetic_scalar_init(&layout->channels, header[8],
                               derived_channels, header[9], header[10],
                               6U, 0);
  derived_bpp = layout->output_color_order == 0U ?
                    (uint64_t)layout->output_bits_per_color *
                        derived_channels :
                    layout->output_bits_per_color;
  cf_v2_arithmetic_scalar_init(&layout->bits_per_pixel, header[11],
                               (int64_t)derived_bpp, header[12], header[13],
                               64U, 0);
  cf_v2_arithmetic_scalar_init(&layout->source_ppi_x, header[14], 72,
                               header[15], header[16], UINT32_MAX, 1);
  cf_v2_arithmetic_scalar_init(&layout->source_ppi_y, header[17], 72,
                               header[18], header[19], UINT32_MAX, 1);
  cf_v2_arithmetic_scalar_init(&layout->media_width, header[20], 612,
                               header[21], header[22], UINT32_MAX, 1);
  cf_v2_arithmetic_scalar_init(&layout->media_height, header[23], 792,
                               header[24], header[25], UINT32_MAX, 1);
  cf_v2_arithmetic_scalar_init(&layout->output_resolution_x, header[26], 300,
                               header[27], header[28], UINT32_MAX, 1);
  cf_v2_arithmetic_scalar_init(&layout->output_resolution_y, header[29], 300,
                               header[30], header[31], UINT32_MAX, 1);
  layout->natural_scaling.mode = cf_v2_relation_mode(header[32]);
  layout->natural_scaling.derived_value = 100;
  layout->natural_scaling.explicit_value =
      cf_v2_boundary_signed(header[33], header[34], 32U);
  layout->axis_relation = (cf_v2_arithmetic_axis_relation_t)(
      header[35] % CF_V2_ARITHMETIC_AXIS_RELATION_COUNT);

  cf_v2_arithmetic_cardinality_init(&layout->x_pages, header[36], header[37],
                                    1U << 16U, (1U << 16U) + 1U);
  cf_v2_arithmetic_cardinality_init(&layout->y_pages, header[38], header[39],
                                    1U << 16U, (1U << 16U) + 1U);
  logical_boundary = UINT32_MAX /
                     (uint64_t)(cf_v2_scalar_relation_value(
                         &layout->bits_per_pixel) > 0 ?
                         cf_v2_scalar_relation_value(&layout->bits_per_pixel) :
                         1) + 1U;
  if (logical_boundary > SIZE_MAX)
    logical_boundary = SIZE_MAX;
  cf_v2_arithmetic_cardinality_init(
      &layout->logical_width, header[40], header[41],
      (size_t)logical_boundary,
      cf_v2_arithmetic_add_limit((size_t)logical_boundary, 1U << 16U));
  cf_v2_arithmetic_cardinality_init(&layout->line_bytes, header[42], header[43],
                                    1U << 16U, 512U * 1024U);
  cf_v2_arithmetic_cardinality_init(
      &layout->horizontal_product, header[44], header[45],
      (size_t)UINT32_MAX + 1U,
      cf_v2_arithmetic_add_limit((size_t)UINT32_MAX + 1U, 1U << 20U));
  cf_v2_arithmetic_cardinality_init(
      &layout->vertical_product, header[46], header[47],
      (size_t)UINT32_MAX + 1U,
      cf_v2_arithmetic_add_limit((size_t)UINT32_MAX + 1U, 1U << 20U));
  cf_v2_arithmetic_cardinality_init(
      &layout->page_product, header[48], header[49],
      (size_t)UINT32_MAX + 1U,
      cf_v2_arithmetic_add_limit((size_t)UINT32_MAX + 1U, 1U << 20U));

  source_row = cf_v2_arithmetic_source_row_bytes(
      layout->source_width, layout->source_format);
  layout->row_length.mode = cf_v2_relation_mode(header[50]);
  layout->row_length.base = source_row;
  layout->row_length.signed_delta = cf_v2_arithmetic_i32(header + 51U);
  if (source_row > SIZE_MAX / layout->source_height)
    return 0;
  source_payload = source_row * layout->source_height;
  layout->payload_length.mode = cf_v2_relation_mode(header[55]);
  layout->payload_length.base = source_payload;
  layout->payload_length.signed_delta = cf_v2_arithmetic_i32(header + 56U);
  cf_v2_arithmetic_cardinality_init(&layout->input_pages, header[60],
                                    header[61], 2U, 4U);
  cf_v2_arithmetic_cardinality_init(&layout->copies, header[62], header[63],
                                    2U, 4U);
  cf_v2_action_program_init(&layout->actions, header + 64U, 8U);
  layout->material_phase = header[72];
  layout->opaque_mode = cf_v2_relation_mode(header[73]);
  layout->opaque = cf_v2_opaque_bytes(
      data + CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE +
          CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE,
      size - CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE -
          CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE);
  layout->opaque_length.mode = layout->opaque_mode;
  layout->opaque_length.base = layout->opaque.size;
  layout->opaque_length.signed_delta = cf_v2_arithmetic_i16(header + 74U);
  layout->pattern = header[76] & 7U;
  layout->geometry_phase = header[77] & 3U;
  layout->option_mode = header[78] & 3U;
  layout->spare = header[79];
  return 1;
}

static inline void
cf_v2_arithmetic_layout_record(cf_v2_relation_stats_t *stats,
                               const cf_v2_arithmetic_layout_t *layout)
{
  const cf_v2_scalar_relation_t *scalars[] = {
    &layout->channels, &layout->bits_per_pixel,
    &layout->source_ppi_x, &layout->source_ppi_y,
    &layout->media_width, &layout->media_height,
    &layout->output_resolution_x, &layout->output_resolution_y,
    &layout->natural_scaling,
  };
  const cf_v2_cardinality_relation_t *cardinalities[] = {
    &layout->x_pages, &layout->y_pages, &layout->logical_width,
    &layout->line_bytes, &layout->horizontal_product,
    &layout->vertical_product, &layout->page_product,
    &layout->input_pages, &layout->copies,
  };
  cf_v2_action_program_t actions;
  cf_v2_action_t action;
  size_t index;

  if (!stats || !layout)
    return;
  for (index = 0U; index < sizeof(scalars) / sizeof(scalars[0]); index ++)
    cf_v2_relation_stats_scalar(stats, scalars[index]->mode);
  cf_v2_relation_stats_scalar(stats, layout->opaque_mode);
  cf_v2_relation_stats_length(stats, layout->row_length.mode);
  cf_v2_relation_stats_length(stats, layout->payload_length.mode);
  cf_v2_relation_stats_length(stats, layout->opaque_length.mode);
  for (index = 0U;
       index < sizeof(cardinalities) / sizeof(cardinalities[0]); index ++)
    cf_v2_relation_stats_cardinality(stats, cardinalities[index]->class_id);
  actions = layout->actions;
  while (cf_v2_action_program_next(&actions, &action))
    cf_v2_relation_stats_action(stats, action.kind);
  cf_v2_relation_stats_opaque(stats, layout->opaque.size);
}

#endif
