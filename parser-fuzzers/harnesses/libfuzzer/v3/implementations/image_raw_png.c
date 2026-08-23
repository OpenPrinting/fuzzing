// SPDX-License-Identifier: Apache-2.0
#include "image_raw_png.h"

#include "../../v2/include/validity.h"

int cf_v3_image_raw_png_validate(const uint8_t *data, size_t size,
                                 cf_v3_image_raw_png_info_t *info) {
  unsigned color_type;

  if (!info || !cf_v2_validate_png(data, size)) {
    return 0;
  }
  info->width = cf_v2_be32(data + 16U);
  info->height = cf_v2_be32(data + 20U);
  color_type = data[25U];
  info->components = color_type == 0U ? 1U : color_type == 2U ? 3U : 4U;
  return 1;
}
