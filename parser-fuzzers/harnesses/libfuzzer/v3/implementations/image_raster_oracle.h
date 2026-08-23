// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_IMAGE_RASTER_ORACLE_H
#define CUPSFILTERS_FUZZ_V3_IMAGE_RASTER_ORACLE_H

#include "image_pdf_formats.h"
#include "image_raster_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool cf_v3_image_raster_validate(
    const uint8_t *output, size_t output_size,
    const cf_v3_image_raster_state_t *state,
    const cf_v3_image_pdf_format_result_t *image, const char **failure);

#endif
