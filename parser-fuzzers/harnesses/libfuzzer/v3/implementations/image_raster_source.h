// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_IMAGE_RASTER_SOURCE_H
#define CUPSFILTERS_FUZZ_V3_IMAGE_RASTER_SOURCE_H

#include "image_pdf_formats.h"
#include "image_raster_state.h"

#include <stddef.h>
#include <stdint.h>

/* Returns 1 when a profile-specific image was built, 0 when the shared image
 * format block should be used, and -1 on construction failure. */
int cf_v3_image_raster_build_special_source(
    const cf_v3_image_raster_state_t *state, const uint8_t *material,
    size_t material_size, cf_v3_image_pdf_format_result_t *result);

#endif
