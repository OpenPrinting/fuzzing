// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_IMAGE_PDF_STATE_H
#define CUPSFILTERS_FUZZ_V3_IMAGE_PDF_STATE_H

#include "image_pdf_oracle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CF_V3_IMAGE_PDF_MAGIC "IMGV3PD1"
#define CF_V3_IMAGE_PDF_MAGIC_SIZE 8U
#define CF_V3_IMAGE_PDF_SELECTOR_SIZE 32U
#define CF_V3_IMAGE_PDF_HEADER_SIZE \
  (CF_V3_IMAGE_PDF_MAGIC_SIZE + CF_V3_IMAGE_PDF_SELECTOR_SIZE)
#define CF_V3_IMAGE_PDF_RAW_PNG_FLAG 0x80U
#define CF_V3_IMAGE_PDF_STRUCTURED_MAX_MATERIAL 1024U
#define CF_V3_IMAGE_PDF_MAX_MATERIAL (2U * 1024U * 1024U)
#define CF_V3_IMAGE_PDF_MIN_INPUT (CF_V3_IMAGE_PDF_HEADER_SIZE + 1U)
#define CF_V3_IMAGE_PDF_STRUCTURED_MAX_INPUT \
  (CF_V3_IMAGE_PDF_HEADER_SIZE + CF_V3_IMAGE_PDF_STRUCTURED_MAX_MATERIAL)
#define CF_V3_IMAGE_PDF_MAX_INPUT \
  (CF_V3_IMAGE_PDF_HEADER_SIZE + CF_V3_IMAGE_PDF_MAX_MATERIAL)

typedef enum cf_v3_image_pdf_profile_e {
  CF_V3_IMAGE_PDF_WRITER = 0,
  CF_V3_IMAGE_PDF_SEQUENCE = 1,
  CF_V3_IMAGE_PDF_AUTO_FIT = 2,
  CF_V3_IMAGE_PDF_CARDINALITY = 3,
} cf_v3_image_pdf_profile_t;

typedef struct cf_v3_image_pdf_state_s {
  cf_v3_image_pdf_profile_t profile;
  bool faithful;
  bool requested_collate;
  bool requested_even_duplex;
  bool collate;
  bool duplex;
  bool reverse;
  bool mirror;
  bool even_duplex;
  bool known_collate_boundary;
  bool known_even_duplex_boundary;
  unsigned format_selector;
  unsigned source_selector;
  unsigned geometry_selector;
  unsigned codec_selector;
  unsigned topology_x;
  unsigned topology_y;
  unsigned page_size;
  unsigned orientation;
  unsigned position;
  unsigned copies;
  unsigned software_copies;
  unsigned hardware_copies_policy;
  unsigned hardware_collate_policy;
  unsigned color_selector;
  unsigned ppd_profile;
  unsigned pattern;
  unsigned phase;
  unsigned stride;
  unsigned gamma;
  unsigned brightness;
  unsigned saturation;
  int hue;
  unsigned xppi;
  unsigned yppi;
  unsigned explicit_width;
  unsigned explicit_height;
  uint32_t natural_scaling;
  uint8_t codec_controls[6];
} cf_v3_image_pdf_state_t;

void cf_v3_image_pdf_decode_state(const uint8_t *selectors,
                                  cf_v3_image_pdf_state_t *state);

bool cf_v3_image_pdf_model(cf_v3_image_pdf_state_t *state, unsigned width,
                           unsigned height,
                           cf_v3_image_pdf_oracle_t *oracle);

int cf_v3_image_pdf_build_options(const cf_v3_image_pdf_state_t *state,
                                  unsigned components, char *buffer,
                                  size_t buffer_size);

#endif
