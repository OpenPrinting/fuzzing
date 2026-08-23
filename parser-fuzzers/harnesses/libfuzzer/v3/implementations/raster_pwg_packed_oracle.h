// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_PWG_PACKED_ORACLE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_PWG_PACKED_ORACLE_H

#include <stddef.h>
#include <stdint.h>

int cf_v3_raster_pwg_packed_oracle(const uint8_t selector[12],
                                    const uint8_t *material,
                                    size_t material_size, int faithful);

#endif
