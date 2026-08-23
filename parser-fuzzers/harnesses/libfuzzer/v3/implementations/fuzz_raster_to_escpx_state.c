// SPDX-License-Identifier: Apache-2.0
#include "raster_escpx_route.h"
#include "raster_escpx_state_bridge.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (!cf_v3_escpx_state_input(data, size))
    return 0;
  return cf_v3_escpx_state_run(
      cf_v3_escpx_state_const_header(data),
      cf_v3_escpx_state_const_control(data),
      data + CF_V3_ESCPX_STATE_FIXED_SIZE,
      size - CF_V3_ESCPX_STATE_FIXED_SIZE);
}
