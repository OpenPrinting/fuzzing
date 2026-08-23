// SPDX-License-Identifier: Apache-2.0
#include "../implementations/pwg_raster_route.h"

#include <stddef.h>
#include <stdint.h>

extern size_t cf_v3_pwg_raster_relation_mutator(
    uint8_t *data, size_t size, size_t max_size, unsigned int seed);
extern size_t cf_v3_pwg_raster_relation_crossover(
    const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2,
    uint8_t *output, size_t max_output_size, unsigned int seed);

static uint32_t
cf_v3_pwg_raster_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                        unsigned int seed)
{
  uint32_t state = seed;

  size = cf_v3_pwg_raster_relation_mutator(data, size, max_size, seed);
  if (!cf_v3_pwg_raster_input(data, size))
    return size;
  cf_v3_pwg_raster_normalize_mutation(data, size);
  if ((cf_v3_pwg_raster_random(&state) & 3U) == 0U)
    cf_v3_pwg_raster_set_route(
        cf_v3_pwg_raster_header(data),
        cf_v3_pwg_raster_random(&state) % CF_V3_PWG_RASTER_ROUTE_COUNT);
  return size;
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *output, size_t max_output_size,
                          unsigned int seed)
{
  size_t size = cf_v3_pwg_raster_relation_crossover(
      data1, size1, data2, size2, output, max_output_size, seed);

  if (cf_v3_pwg_raster_input(output, size))
    cf_v3_pwg_raster_normalize_mutation(output, size);
  return size;
}
