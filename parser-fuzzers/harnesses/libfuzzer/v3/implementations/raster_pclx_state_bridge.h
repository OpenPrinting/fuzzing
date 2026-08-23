// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_PCLX_STATE_BRIDGE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_PCLX_STATE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

int cf_v3_pclx_state_run(const uint8_t *header, const uint8_t *control,
                         const uint8_t *material, size_t material_size);

#endif
