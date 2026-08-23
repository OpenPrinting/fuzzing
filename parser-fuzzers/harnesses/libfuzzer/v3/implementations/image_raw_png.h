// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_IMAGE_RAW_PNG_H
#define CUPSFILTERS_FUZZ_V3_IMAGE_RAW_PNG_H

#include <stddef.h>
#include <stdint.h>

typedef struct cf_v3_image_raw_png_info_s {
  unsigned width;
  unsigned height;
  unsigned components;
} cf_v3_image_raw_png_info_t;

int cf_v3_image_raw_png_validate(const uint8_t *data, size_t size,
                                 cf_v3_image_raw_png_info_t *info);

#endif
