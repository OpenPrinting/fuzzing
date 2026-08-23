// SPDX-License-Identifier: Apache-2.0
#include "../implementations/pwg_route.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint64_t
cf_v3_pwg_next(uint64_t *state)
{
  uint64_t value = *state;

  value ^= value >> 12U;
  value ^= value << 25U;
  value ^= value >> 27U;
  *state = value;
  return value * UINT64_C(2685821657736338717);
}

static size_t
cf_v3_pwg_initialize(uint8_t *data, size_t max_size, uint64_t seed)
{
  size_t size = CF_V3_PWG_FIXED_SIZE + 8U;

  if (max_size < CF_V3_PWG_FIXED_SIZE + 1U)
    return 0U;
  if (size > max_size)
    size = max_size;
  memset(data, 0, size);
  memcpy(data, CF_V3_PWG_MAGIC, CF_V3_PWG_MAGIC_SIZE);
  data[CF_V3_PWG_MAGIC_SIZE] = (uint8_t)(seed % CF_V3_PWG_ROUTE_COUNT);
  data[CF_V3_PWG_MAGIC_SIZE + 2U] = 4U;
  data[CF_V3_PWG_MAGIC_SIZE + 3U] = 2U;
  data[CF_V3_PWG_MAGIC_SIZE + 4U] = 1U;
  data[CF_V3_PWG_MAGIC_SIZE + 5U] = 2U;
  data[CF_V3_PWG_MAGIC_SIZE + 6U] = 2U;
  data[CF_V3_PWG_MAGIC_SIZE + 8U] = 4U;
  return size;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                        unsigned int seed)
{
  uint64_t state = ((uint64_t)seed << 32U) | seed | 1U;
  uint8_t *header;

  if (!data || max_size < CF_V3_PWG_FIXED_SIZE + 1U)
    return 0U;
  if (!cf_v3_pwg_route_input(data, size))
    size = cf_v3_pwg_initialize(data, max_size, cf_v3_pwg_next(&state));
  else
  {
    size = LLVMFuzzerMutate(data, size, max_size);
    if (size < CF_V3_PWG_FIXED_SIZE + 1U)
      size = cf_v3_pwg_initialize(data, max_size, cf_v3_pwg_next(&state));
  }
  memcpy(data, CF_V3_PWG_MAGIC, CF_V3_PWG_MAGIC_SIZE);
  header = cf_v3_pwg_route_header(data);
  if ((cf_v3_pwg_next(&state) & 7U) == 0U)
    header[0] = (uint8_t)(cf_v3_pwg_next(&state) % CF_V3_PWG_ROUTE_COUNT);
  if ((cf_v3_pwg_next(&state) & 15U) == 0U)
    header[4] = (uint8_t)(cf_v3_pwg_next(&state) % 9U);
  if ((cf_v3_pwg_next(&state) & 15U) == 0U)
    header[8] = (uint8_t)(cf_v3_pwg_next(&state) % 6U);
  cf_v3_pwg_route_normalize_mutation(data, size);
  return size;
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *output, size_t max_output_size,
                          unsigned int seed)
{
  size_t size;
  size_t material1;
  size_t material2;
  size_t split1;
  size_t split2;
  uint64_t state = ((uint64_t)seed << 32U) | seed | 1U;

  if (!output || !cf_v3_pwg_route_input(data1, size1) ||
      !cf_v3_pwg_route_input(data2, size2) ||
      max_output_size < CF_V3_PWG_FIXED_SIZE + 1U)
    return 0U;
  material1 = size1 - CF_V3_PWG_FIXED_SIZE;
  material2 = size2 - CF_V3_PWG_FIXED_SIZE;
  split1 = material1 ? cf_v3_pwg_next(&state) % (material1 + 1U) : 0U;
  split2 = material2 ? cf_v3_pwg_next(&state) % (material2 + 1U) : 0U;
  size = CF_V3_PWG_FIXED_SIZE + split1 + material2 - split2;
  if (size > max_output_size)
    size = max_output_size;
  memcpy(output, data1, CF_V3_PWG_FIXED_SIZE);
  if (split1 && CF_V3_PWG_FIXED_SIZE + split1 <= size)
    memcpy(output + CF_V3_PWG_FIXED_SIZE,
           data1 + CF_V3_PWG_FIXED_SIZE, split1);
  if (size > CF_V3_PWG_FIXED_SIZE + split1)
  {
    size_t tail = size - CF_V3_PWG_FIXED_SIZE - split1;

    memcpy(output + CF_V3_PWG_FIXED_SIZE + split1,
           data2 + CF_V3_PWG_FIXED_SIZE + split2, tail);
  }
  for (size_t index = 0U; index < CF_V3_PWG_HEADER_SIZE; index ++)
    if (cf_v3_pwg_next(&state) & 1U)
      output[CF_V3_PWG_MAGIC_SIZE + index] =
          data2[CF_V3_PWG_MAGIC_SIZE + index];
  cf_v3_pwg_route_normalize_mutation(output, size);
  return size;
}
