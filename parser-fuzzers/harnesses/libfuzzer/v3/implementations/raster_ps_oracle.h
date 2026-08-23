// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_PS_ORACLE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_PS_ORACLE_H

#include <stddef.h>
#include <stdint.h>

int cf_v3_raster_ps_truncation_oracle(const uint8_t *header,
                                      const uint8_t *material,
                                      size_t material_size, int faithful);
int cf_v3_raster_ps_output_oracle(const uint8_t *header,
                                  const uint8_t *material,
                                  size_t material_size);

#endif
