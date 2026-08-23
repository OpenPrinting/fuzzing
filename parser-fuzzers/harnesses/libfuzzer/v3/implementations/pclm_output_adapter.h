// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PCLM_OUTPUT_ADAPTER_H
#define CUPSFILTERS_FUZZ_V3_PCLM_OUTPUT_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

void cf_v3_pclm_output_begin(const uint8_t *data, size_t size);
void cf_v3_pclm_output_end(void);

#endif
