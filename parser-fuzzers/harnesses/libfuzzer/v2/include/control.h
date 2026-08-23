// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_CONTROL_H
#define CUPSFILTERS_FUZZ_V2_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#define CF_V2_CONTROL_SIZE 16U

typedef struct cf_v2_control_s {
  uint8_t ppd_profile;
  uint8_t page_size;
  uint8_t color_model;
  uint8_t resolution;
  uint8_t sides;
  uint8_t orientation;
  uint8_t scaling;
  uint8_t copies;
  uint8_t number_up;
  uint8_t position;
  uint8_t quality;
  uint8_t output_order;
  uint8_t media_type;
  uint8_t mirror;
  uint8_t route_mode;
  uint8_t reserved;
} cf_v2_control_t;

/* Compile-time policies bind a target to one meaningful configuration while
 * leaving the remaining lightweight dimensions under fuzzer control. */
static inline void cf_v2_apply_control_policy(cf_v2_control_t *control) {
#ifdef CF_V2_FORCE_PPD_PROFILE
  control->ppd_profile = (uint8_t)CF_V2_FORCE_PPD_PROFILE;
#endif
#ifdef CF_V2_FORCE_PAGE_SIZE
  control->page_size = (uint8_t)CF_V2_FORCE_PAGE_SIZE;
#endif
#ifdef CF_V2_FORCE_COLOR_MODEL
  control->color_model = (uint8_t)CF_V2_FORCE_COLOR_MODEL;
#endif
#ifdef CF_V2_FORCE_RESOLUTION
  control->resolution = (uint8_t)CF_V2_FORCE_RESOLUTION;
#endif
#ifdef CF_V2_FORCE_SIDES
  control->sides = (uint8_t)CF_V2_FORCE_SIDES;
#endif
#ifdef CF_V2_FORCE_ORIENTATION
  control->orientation = (uint8_t)CF_V2_FORCE_ORIENTATION;
#endif
#ifdef CF_V2_FORCE_NUMBER_UP
  control->number_up = (uint8_t)CF_V2_FORCE_NUMBER_UP;
#endif
#ifdef CF_V2_FORCE_OUTPUT_ORDER
  control->output_order = (uint8_t)CF_V2_FORCE_OUTPUT_ORDER;
#endif
}

static inline int cf_v2_split_input(const uint8_t *data, size_t size,
                                    size_t max_document,
                                    const uint8_t **document,
                                    size_t *document_size,
                                    cf_v2_control_t *control) {
  const uint8_t *tail;

  if (!data || !document || !document_size || !control ||
      size <= CF_V2_CONTROL_SIZE ||
      size - CF_V2_CONTROL_SIZE > max_document) {
    return 0;
  }

  *document = data;
  *document_size = size - CF_V2_CONTROL_SIZE;
  tail = data + *document_size;
  control->ppd_profile = tail[0];
  control->page_size = tail[1];
  control->color_model = tail[2];
  control->resolution = tail[3];
  control->sides = tail[4];
  control->orientation = tail[5];
  control->scaling = tail[6];
  control->copies = tail[7];
  control->number_up = tail[8];
  control->position = tail[9];
  control->quality = tail[10];
  control->output_order = tail[11];
  control->media_type = tail[12];
  control->mirror = tail[13];
  control->route_mode = tail[14];
  control->reserved = tail[15];
  cf_v2_apply_control_policy(control);
  return 1;
}

#endif
