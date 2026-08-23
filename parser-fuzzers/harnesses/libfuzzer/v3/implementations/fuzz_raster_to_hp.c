// SPDX-License-Identifier: Apache-2.0
#include "raster_hp_bridge.h"
#include "raster_hp_route.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (!cf_v3_raster_hp_input(data, size))
    return 0;
  return cf_v3_raster_hp_run(data, size);
}
