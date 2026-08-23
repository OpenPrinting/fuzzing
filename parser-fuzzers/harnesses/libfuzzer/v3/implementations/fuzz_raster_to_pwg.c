// SPDX-License-Identifier: Apache-2.0
#include "raster_pwg_bridge.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  return cf_v3_raster_pwg_bridge(data, size);
}
