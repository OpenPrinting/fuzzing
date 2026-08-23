// SPDX-License-Identifier: Apache-2.0
#include "pwg_route_bridge.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  return cf_v3_pwg_route_bridge(data, size);
}
