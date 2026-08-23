// SPDX-License-Identifier: Apache-2.0
#include "pwg_raster_bridge.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  return cf_v3_pwg_raster_bridge(data, size);
}
