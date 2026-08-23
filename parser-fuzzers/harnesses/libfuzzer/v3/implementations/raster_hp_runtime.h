// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_HP_RUNTIME_H
#define CUPSFILTERS_FUZZ_V3_RASTER_HP_RUNTIME_H

#include <cups/raster.h>

#include <stddef.h>
#include <stdint.h>

typedef struct cf_v3_raster_hp_case_s
{
  uint32_t width;
  uint32_t height;
  cups_cspace_t color_space;
  uint32_t bits_per_color;
  cups_order_t color_order;
  uint32_t compression;
  uint32_t resolution;
  uint32_t page_height;
  uint32_t copies;
  uint32_t media_position;
  uint32_t media_type;
  uint8_t duplex;
  uint8_t tumble;
  uint8_t ppd_model;
  uint8_t pattern;
  uint8_t material_phase;
  uint8_t selectors[12];
} cf_v3_raster_hp_case_t;

int cf_v3_raster_hp_run_main(const cf_v3_raster_hp_case_t *test_case,
                             const uint8_t *material, size_t material_size);
int cf_v3_raster_hp_run_codec(const cf_v3_raster_hp_case_t *test_case,
                              const uint8_t *material, size_t material_size);
int cf_v3_raster_hp_run_row(const cf_v3_raster_hp_case_t *test_case,
                            const uint8_t *material, size_t material_size);
int cf_v3_raster_hp_run_page(const cf_v3_raster_hp_case_t *test_case,
                             const uint8_t *material, size_t material_size,
                             int spec_tumble);

#endif
