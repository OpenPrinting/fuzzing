// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_IMAGE_RASTER_STATE_H
#define CUPSFILTERS_FUZZ_V3_IMAGE_RASTER_STATE_H

#include <cups/raster.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CF_V3_IMAGE_RASTER_MAGIC "IMGV3RA1"
#define CF_V3_IMAGE_RASTER_MAGIC_SIZE 8U
#define CF_V3_IMAGE_RASTER_SELECTOR_SIZE 40U
#define CF_V3_IMAGE_RASTER_HEADER_SIZE \
  (CF_V3_IMAGE_RASTER_MAGIC_SIZE + CF_V3_IMAGE_RASTER_SELECTOR_SIZE)
#define CF_V3_IMAGE_RASTER_RAW_PNG_FLAG 0x80U
#define CF_V3_IMAGE_RASTER_STRUCTURED_MAX_MATERIAL 4096U
#define CF_V3_IMAGE_RASTER_MAX_MATERIAL (2U * 1024U * 1024U)
#define CF_V3_IMAGE_RASTER_MIN_INPUT (CF_V3_IMAGE_RASTER_HEADER_SIZE + 1U)
#define CF_V3_IMAGE_RASTER_STRUCTURED_MAX_INPUT \
  (CF_V3_IMAGE_RASTER_HEADER_SIZE + \
   CF_V3_IMAGE_RASTER_STRUCTURED_MAX_MATERIAL)
#define CF_V3_IMAGE_RASTER_MAX_INPUT \
  (CF_V3_IMAGE_RASTER_HEADER_SIZE + CF_V3_IMAGE_RASTER_MAX_MATERIAL)

typedef enum cf_v3_image_raster_profile_e {
  CF_V3_IMAGE_RASTER_LAYOUT = 0,
  CF_V3_IMAGE_RASTER_NATURAL = 1,
  CF_V3_IMAGE_RASTER_MULTIPAGE = 2,
  CF_V3_IMAGE_RASTER_CMY = 3,
  CF_V3_IMAGE_RASTER_ARITHMETIC = 4,
  CF_V3_IMAGE_RASTER_PROFILE_COUNT
} cf_v3_image_raster_profile_t;

typedef struct cf_v3_image_raster_output_s {
  cups_cspace_t color_space;
  cups_order_t color_order;
  unsigned num_colors;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
} cf_v3_image_raster_output_t;

typedef struct cf_v3_image_raster_state_s {
  cf_v3_image_raster_profile_t profile;
  bool faithful;
  bool mirror;
  bool collate;
  bool reverse;
  bool duplex;
  bool arithmetic_stride;

  unsigned format_selector;
  unsigned source_selector;
  unsigned geometry_selector;
  unsigned scale_policy;
  unsigned page_policy;
  unsigned orientation;
  unsigned orientation_requested;
  unsigned position;
  unsigned copies;
  unsigned pattern;
  unsigned phase;
  unsigned material_stride;
  unsigned xppi;
  unsigned yppi;
  unsigned output_resolution_x;
  unsigned output_resolution_y;
  unsigned explicit_width;
  unsigned explicit_height;
  unsigned topology_x;
  unsigned topology_y;
  unsigned natural_scaling;
  unsigned cmy_relation_stage;
  int cmy_threshold_delta;
  uint8_t codec_controls[4];

  double page_width;
  double page_height;
  double margin_left;
  double margin_bottom;
  double margin_right;
  double margin_top;

  cf_v3_image_raster_output_t output;
} cf_v3_image_raster_state_t;

void cf_v3_image_raster_decode_state(
    const uint8_t selectors[CF_V3_IMAGE_RASTER_SELECTOR_SIZE],
    cf_v3_image_raster_state_t *state);

void cf_v3_image_raster_normalize_layout(
    cf_v3_image_raster_state_t *state, unsigned width, unsigned height,
    unsigned source_xppi, unsigned source_yppi);

size_t cf_v3_image_raster_expected_bpl(
    const cf_v3_image_raster_output_t *output, unsigned width);

unsigned cf_v3_image_raster_plane_count(
    const cf_v3_image_raster_output_t *output);

const char *cf_v3_image_raster_position_name(unsigned position);

int cf_v3_image_raster_build_options(
    const cf_v3_image_raster_state_t *state, char *buffer,
    size_t buffer_size);

#endif
