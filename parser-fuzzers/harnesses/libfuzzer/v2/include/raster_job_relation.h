// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_RASTER_JOB_RELATION_H
#define CUPSFILTERS_FUZZ_V2_RASTER_JOB_RELATION_H

#include "relation_program.h"

#include <cups/raster.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_RASTER_JOB_MAGIC "RSTRJOB1"
#define CF_V2_RASTER_JOB_MAGIC_SIZE 8U
#define CF_V2_RASTER_JOB_HEADER_SIZE 64U

typedef struct cf_v2_raster_job_relation_s {
  uint32_t width;
  uint32_t height;
  cups_cspace_t color_space;
  uint32_t bits_per_color;
  cups_order_t color_order;
  uint32_t compression;
  cf_v2_scalar_relation_t colors;
  cf_v2_scalar_relation_t bits_per_pixel;
  cf_v2_length_relation_t bytes_per_line;
  cf_v2_relation_mode_t physical_rows_mode;
  cf_v2_cardinality_relation_t physical_rows;
  cf_v2_scalar_relation_t ppd_color_space;
  cf_v2_scalar_relation_t ppd_channels;
  cf_v2_scalar_relation_t ppd_bits_per_pixel;
  cf_v2_scalar_relation_t resolution_x;
  cf_v2_scalar_relation_t resolution_y;
  cf_v2_scalar_relation_t row_count;
  cf_v2_scalar_relation_t row_feed;
  cf_v2_scalar_relation_t row_step;
  cf_v2_scalar_relation_t column_step;
  cf_v2_cardinality_relation_t page_size_count;
  cf_v2_cardinality_relation_t page_count;
  cf_v2_scalar_relation_t page_width;
  cf_v2_scalar_relation_t page_height;
  cf_v2_cardinality_relation_t copies;
  uint8_t duplex;
  uint8_t tumble;
  uint8_t model_mode;
  uint8_t pattern;
  uint8_t material_phase;
  cf_v2_relation_mode_t opaque_mode;
  cf_v2_length_relation_t opaque_length;
  cf_v2_opaque_bytes_t opaque;
} cf_v2_raster_job_relation_t;

static const cups_cspace_t cf_v2_raster_job_color_spaces[] = {
  CUPS_CSPACE_W, CUPS_CSPACE_RGB, CUPS_CSPACE_K,
  CUPS_CSPACE_CMY, CUPS_CSPACE_CMYK, CUPS_CSPACE_KCMY,
  CUPS_CSPACE_RGBA, CUPS_CSPACE_YMC, CUPS_CSPACE_YMCK,
  CUPS_CSPACE_KCMYcm, CUPS_CSPACE_GMCK, CUPS_CSPACE_GMCS,
  CUPS_CSPACE_WHITE, CUPS_CSPACE_GOLD, CUPS_CSPACE_SILVER,
  CUPS_CSPACE_CIEXYZ, CUPS_CSPACE_CIELab, CUPS_CSPACE_RGBW,
  CUPS_CSPACE_SW, CUPS_CSPACE_SRGB, CUPS_CSPACE_ADOBERGB,
  CUPS_CSPACE_ICC1, CUPS_CSPACE_ICC2, CUPS_CSPACE_ICC3,
  CUPS_CSPACE_ICC4, CUPS_CSPACE_ICC5, CUPS_CSPACE_ICC6,
  CUPS_CSPACE_ICC7, CUPS_CSPACE_ICC8, CUPS_CSPACE_ICC9,
  CUPS_CSPACE_ICCA, CUPS_CSPACE_ICCB, CUPS_CSPACE_ICCC,
  CUPS_CSPACE_ICCD, CUPS_CSPACE_ICCE, CUPS_CSPACE_ICCF,
  CUPS_CSPACE_DEVICE1, CUPS_CSPACE_DEVICE2, CUPS_CSPACE_DEVICE3,
  CUPS_CSPACE_DEVICE4, CUPS_CSPACE_DEVICE5, CUPS_CSPACE_DEVICE6,
  CUPS_CSPACE_DEVICE7, CUPS_CSPACE_DEVICE8, CUPS_CSPACE_DEVICE9,
  CUPS_CSPACE_DEVICEA, CUPS_CSPACE_DEVICEB, CUPS_CSPACE_DEVICEC,
  CUPS_CSPACE_DEVICED, CUPS_CSPACE_DEVICEE, CUPS_CSPACE_DEVICEF,
};

static inline int16_t
cf_v2_raster_job_i16(const uint8_t *data)
{
  uint16_t encoded = (uint16_t)data[0] | (uint16_t)data[1] << 8U;

  return (int16_t)encoded;
}

static inline uint32_t
cf_v2_raster_job_channels(cups_cspace_t color_space)
{
  if (color_space >= CUPS_CSPACE_DEVICE1 &&
      color_space <= CUPS_CSPACE_DEVICEF)
    return 1U + (uint32_t)(color_space - CUPS_CSPACE_DEVICE1);
  if (color_space >= CUPS_CSPACE_ICC1 && color_space <= CUPS_CSPACE_ICCF)
    return 1U + (uint32_t)(color_space - CUPS_CSPACE_ICC1);
  switch (color_space) {
    case CUPS_CSPACE_RGB:
    case CUPS_CSPACE_CMY:
    case CUPS_CSPACE_YMC:
    case CUPS_CSPACE_CIEXYZ:
    case CUPS_CSPACE_CIELab:
    case CUPS_CSPACE_SRGB:
    case CUPS_CSPACE_ADOBERGB:
      return 3U;
    case CUPS_CSPACE_CMYK:
    case CUPS_CSPACE_KCMY:
    case CUPS_CSPACE_RGBA:
    case CUPS_CSPACE_YMCK:
    case CUPS_CSPACE_GMCK:
    case CUPS_CSPACE_GMCS:
    case CUPS_CSPACE_RGBW:
      return 4U;
    case CUPS_CSPACE_KCMYcm:
      return 6U;
    default:
      return 1U;
  }
}

static inline int
cf_v2_raster_job_parse(const uint8_t *data, size_t size,
                       cf_v2_raster_job_relation_t *job)
{
  static const uint32_t bits_per_color[] = {1U, 2U, 4U, 8U, 16U};
  static const uint32_t compressions[] = {0U, 1U, 2U, 3U, 10U};
  const uint8_t *header;
  uint64_t plane_bytes;
  uint64_t derived_bpl;
  uint64_t derived_bpp;
  uint64_t expected_rows;
  uint32_t derived_colors;
  uint32_t storage_colors;

  if (!data || !job ||
      size < CF_V2_RASTER_JOB_MAGIC_SIZE + CF_V2_RASTER_JOB_HEADER_SIZE + 1U ||
      memcmp(data, CF_V2_RASTER_JOB_MAGIC, CF_V2_RASTER_JOB_MAGIC_SIZE))
    return 0;
  memset(job, 0, sizeof(*job));
  header = data + CF_V2_RASTER_JOB_MAGIC_SIZE;
  job->width = (uint32_t)cf_v2_boundary_bounded_unsigned(
      header[0], header[1], 256U);
  job->height = (uint32_t)cf_v2_boundary_bounded_unsigned(
      header[2], header[3], 64U);
  if (!job->width)
    job->width = 1U;
  if (!job->height)
    job->height = 1U;
  job->color_space = cf_v2_raster_job_color_spaces[
      header[4] % (sizeof(cf_v2_raster_job_color_spaces) /
                   sizeof(cf_v2_raster_job_color_spaces[0]))];
  job->bits_per_color = bits_per_color[
      header[5] % (sizeof(bits_per_color) / sizeof(bits_per_color[0]))];
  job->color_order = (cups_order_t)(header[6] % 3U);
  job->compression = compressions[
      header[7] % (sizeof(compressions) / sizeof(compressions[0]))];

  derived_colors = cf_v2_raster_job_channels(job->color_space);
  job->colors.mode = cf_v2_relation_mode(header[8]);
  job->colors.derived_value = derived_colors;
  job->colors.explicit_value = (int64_t)cf_v2_boundary_bounded_unsigned(
      header[9], header[10], 15U);
  if (job->colors.explicit_value < 1)
    job->colors.explicit_value = 1;
  storage_colors = (uint32_t)cf_v2_scalar_relation_value(&job->colors);

  derived_bpp = job->color_order == CUPS_ORDER_CHUNKED ?
                    (uint64_t)job->bits_per_color * storage_colors :
                    job->bits_per_color;
  job->bits_per_pixel.mode = cf_v2_relation_mode(header[11]);
  job->bits_per_pixel.derived_value = (int64_t)derived_bpp;
  job->bits_per_pixel.explicit_value =
      (int64_t)cf_v2_boundary_bounded_unsigned(header[12], header[13], 64U);
  if (job->bits_per_pixel.explicit_value < 1)
    job->bits_per_pixel.explicit_value = 1;

  plane_bytes = ((uint64_t)job->width * job->bits_per_color + 7U) / 8U;
  if (job->color_order == CUPS_ORDER_CHUNKED)
    derived_bpl = ((uint64_t)job->width *
                   (uint64_t)cf_v2_scalar_relation_value(
                       &job->bits_per_pixel) + 7U) / 8U;
  else if (job->color_order == CUPS_ORDER_BANDED)
    derived_bpl = plane_bytes * storage_colors;
  else
    derived_bpl = plane_bytes;
  if (derived_bpl > SIZE_MAX)
    return 0;
  job->bytes_per_line.mode = cf_v2_relation_mode(header[14]);
  job->bytes_per_line.base = (size_t)derived_bpl;
  job->bytes_per_line.signed_delta = cf_v2_raster_job_i16(header + 15U);

  expected_rows = job->color_order == CUPS_ORDER_PLANAR ?
                      (uint64_t)job->height * storage_colors : job->height;
  job->physical_rows_mode = cf_v2_relation_mode(header[17]);
  job->physical_rows.class_id =
      (cf_v2_cardinality_class_t)(header[18] %
                                  CF_V2_CARDINALITY_CLASS_COUNT);
  job->physical_rows.parameter = header[19];
  job->physical_rows.boundary = expected_rows > SIZE_MAX ?
                                    SIZE_MAX : (size_t)expected_rows;
  job->physical_rows.limit = 64U * 15U;

  job->ppd_color_space.mode = cf_v2_relation_mode(header[20]);
  job->ppd_color_space.derived_value = job->color_space;
  job->ppd_color_space.explicit_value = cf_v2_raster_job_color_spaces[
      header[21] % (sizeof(cf_v2_raster_job_color_spaces) /
                    sizeof(cf_v2_raster_job_color_spaces[0]))];
  job->ppd_channels.mode = cf_v2_relation_mode(header[22]);
  job->ppd_channels.derived_value = storage_colors;
  job->ppd_channels.explicit_value =
      (int64_t)cf_v2_boundary_bounded_unsigned(header[23], header[24], 15U);
  if (job->ppd_channels.explicit_value < 1)
    job->ppd_channels.explicit_value = 1;
  job->ppd_bits_per_pixel.mode = cf_v2_relation_mode(header[25]);
  job->ppd_bits_per_pixel.derived_value =
      cf_v2_scalar_relation_value(&job->bits_per_pixel);
  job->ppd_bits_per_pixel.explicit_value =
      (int64_t)cf_v2_boundary_bounded_unsigned(header[26], header[27], 64U);
  if (job->ppd_bits_per_pixel.explicit_value < 1)
    job->ppd_bits_per_pixel.explicit_value = 1;

#define CF_V2_RASTER_SCALAR(field, mode_offset, kind_offset, parameter_offset, derived, maximum) \
  do { \
    job->field.mode = cf_v2_relation_mode(header[mode_offset]); \
    job->field.derived_value = (derived); \
    job->field.explicit_value = (int64_t)cf_v2_boundary_bounded_unsigned( \
        header[kind_offset], header[parameter_offset], (maximum)); \
  } while (0)
  CF_V2_RASTER_SCALAR(resolution_x, 28U, 29U, 30U, 300, UINT32_MAX);
  CF_V2_RASTER_SCALAR(resolution_y, 31U, 32U, 33U,
                      cf_v2_scalar_relation_value(&job->resolution_x),
                      UINT32_MAX);
  CF_V2_RASTER_SCALAR(row_count, 34U, 35U, 36U, 1, 128U);
  CF_V2_RASTER_SCALAR(row_feed, 37U, 38U, 39U, 1, 128U);
  CF_V2_RASTER_SCALAR(row_step, 40U, 41U, 42U, 1, 128U);
  CF_V2_RASTER_SCALAR(column_step, 43U, 44U, 45U, 1, 128U);
#undef CF_V2_RASTER_SCALAR

  job->page_size_count.class_id =
      (cf_v2_cardinality_class_t)(header[46] %
                                  CF_V2_CARDINALITY_CLASS_COUNT);
  job->page_size_count.parameter = header[47];
  job->page_size_count.boundary = 2U;
  job->page_size_count.limit = 4U;
  job->page_count.class_id =
      (cf_v2_cardinality_class_t)(header[48] %
                                  CF_V2_CARDINALITY_CLASS_COUNT);
  job->page_count.parameter = header[49];
  job->page_count.boundary = 2U;
  job->page_count.limit = 4U;
  job->page_width.mode = cf_v2_relation_mode(header[50]);
  job->page_width.derived_value = 612;
  job->page_width.explicit_value = (int64_t)cf_v2_boundary_unsigned(
      header[51], header[52], 32U);
  job->page_height.mode = cf_v2_relation_mode(header[53]);
  job->page_height.derived_value = 792;
  job->page_height.explicit_value = (int64_t)cf_v2_boundary_unsigned(
      header[54], header[55], 32U);
  job->copies.class_id =
      (cf_v2_cardinality_class_t)(header[56] %
                                  CF_V2_CARDINALITY_CLASS_COUNT);
  job->copies.parameter = header[57];
  job->copies.boundary = 2U;
  job->copies.limit = 4U;
  job->duplex = header[58] & 1U;
  job->tumble = (header[58] >> 1U) & 1U;
  job->model_mode = header[59] & 3U;
  job->pattern = header[60] & 7U;
  job->material_phase = header[61];
  job->opaque_mode = cf_v2_relation_mode(header[62]);
  job->opaque = cf_v2_opaque_bytes(
      data + CF_V2_RASTER_JOB_MAGIC_SIZE + CF_V2_RASTER_JOB_HEADER_SIZE,
      size - CF_V2_RASTER_JOB_MAGIC_SIZE - CF_V2_RASTER_JOB_HEADER_SIZE);
  job->opaque_length.mode = job->opaque_mode;
  job->opaque_length.base = job->opaque.size;
  job->opaque_length.signed_delta = (int8_t)header[63];
  return 1;
}

static inline size_t
cf_v2_raster_job_physical_rows(const cf_v2_raster_job_relation_t *job)
{
  if (!job)
    return 0U;
  return job->physical_rows_mode == CF_V2_RELATION_DERIVED ?
             job->physical_rows.boundary :
             cf_v2_cardinality_value(&job->physical_rows);
}

static inline void
cf_v2_raster_job_record(cf_v2_relation_stats_t *stats,
                        const cf_v2_raster_job_relation_t *job)
{
  const cf_v2_scalar_relation_t *scalars[] = {
    &job->colors, &job->bits_per_pixel, &job->ppd_color_space,
    &job->ppd_channels, &job->ppd_bits_per_pixel, &job->resolution_x,
    &job->resolution_y, &job->row_count, &job->row_feed, &job->row_step,
    &job->column_step, &job->page_width, &job->page_height,
  };
  size_t index;

  if (!stats || !job)
    return;
  for (index = 0U; index < sizeof(scalars) / sizeof(scalars[0]); index ++)
    cf_v2_relation_stats_scalar(stats, scalars[index]->mode);
  cf_v2_relation_stats_scalar(stats, job->physical_rows_mode);
  cf_v2_relation_stats_scalar(stats, job->opaque_mode);
  cf_v2_relation_stats_length(stats, job->bytes_per_line.mode);
  if (job->opaque_mode == CF_V2_RELATION_EXPLICIT)
    cf_v2_relation_stats_length(stats, job->opaque_length.mode);
  if (job->physical_rows_mode == CF_V2_RELATION_EXPLICIT)
    cf_v2_relation_stats_cardinality(stats, job->physical_rows.class_id);
  cf_v2_relation_stats_cardinality(stats, job->page_size_count.class_id);
  cf_v2_relation_stats_cardinality(stats, job->page_count.class_id);
  cf_v2_relation_stats_cardinality(stats, job->copies.class_id);
  cf_v2_relation_stats_opaque(stats, job->opaque.size);
}

#endif
