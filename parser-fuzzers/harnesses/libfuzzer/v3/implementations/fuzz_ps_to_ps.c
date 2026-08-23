// SPDX-License-Identifier: Apache-2.0
#include "ps_route.h"
#include "ps_route_bridge.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (!cf_v3_ps_input(data, size))
    return 0;
  return cf_v3_ps_run(cf_v3_ps_const_header(data),
                      data + CF_V3_PS_FIXED_SIZE,
                      size - CF_V3_PS_FIXED_SIZE);
}
