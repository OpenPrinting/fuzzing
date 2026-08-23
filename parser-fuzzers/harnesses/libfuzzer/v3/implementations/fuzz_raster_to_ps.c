// SPDX-License-Identifier: Apache-2.0
#include "raster_ps_bridge.h"
#include "raster_ps_route.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const uint8_t *header;
  const uint8_t *material;

  if (!cf_v3_raster_ps_input(data, size))
    return 0;
  header = cf_v3_raster_ps_const_header(data);
  material = data + CF_V3_RASTER_PS_FIXED_SIZE;
  return cf_v3_raster_ps_run(header, material,
                             size - CF_V3_RASTER_PS_FIXED_SIZE);
}
