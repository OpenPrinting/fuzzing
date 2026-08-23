// SPDX-License-Identifier: Apache-2.0
#include "text_route.h"
#include "text_route_bridge.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (!cf_v3_text_input(data, size))
    return 0;
  return cf_v3_text_run(cf_v3_text_const_header(data),
                        data + CF_V3_TEXT_FIXED_SIZE,
                        size - CF_V3_TEXT_FIXED_SIZE);
}
