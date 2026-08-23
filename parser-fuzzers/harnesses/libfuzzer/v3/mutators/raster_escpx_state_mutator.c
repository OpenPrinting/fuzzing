// SPDX-License-Identifier: Apache-2.0
#include "../implementations/raster_escpx_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern size_t cf_v3_escpx_relation_mutator(
    uint8_t *, size_t, size_t, unsigned int);
extern size_t cf_v3_escpx_relation_crossover(
    const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *, size_t,
    unsigned int);

static uint32_t
cf_v3_escpx_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static size_t
cf_v3_escpx_to_relation(const uint8_t *input, size_t size,
                        uint8_t *relation)
{
  size_t material_size = size - CF_V3_ESCPX_STATE_FIXED_SIZE;

  memcpy(relation, "RSTRJOB1", 8U);
  memcpy(relation + 8U, cf_v3_escpx_state_const_header(input), 64U);
  memcpy(relation + 72U, input + CF_V3_ESCPX_STATE_FIXED_SIZE,
         material_size);
  return 72U + material_size;
}

static size_t
cf_v3_escpx_from_relation(uint8_t *output, size_t max_size,
                          const uint8_t *relation, size_t relation_size,
                          uint8_t control)
{
  size_t material_size;

  if (relation_size <= 72U || max_size < relation_size + 1U)
    return 0U;
  material_size = relation_size - 72U;
  memcpy(output, CF_V3_ESCPX_STATE_MAGIC, 8U);
  memcpy(output + 8U, relation + 8U, 64U);
  output[72] = control;
  memcpy(output + 73U, relation + 72U, material_size);
  return 73U + material_size;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                        unsigned int seed)
{
  uint32_t state = seed;
  uint8_t control;
  uint8_t *relation;
  size_t relation_size;

  if (!cf_v3_escpx_state_input(data, size) || max_size <= 1U)
    return size;
  control = *cf_v3_escpx_state_control(data);
  relation = (uint8_t *)malloc(max_size - 1U);
  if (!relation)
    return size;
  relation_size = cf_v3_escpx_to_relation(data, size, relation);
  relation_size = cf_v3_escpx_relation_mutator(
      relation, relation_size, max_size - 1U, seed);
  if ((cf_v3_escpx_random(&state) & 3U) == 0U)
    control = (uint8_t)(cf_v3_escpx_random(&state) %
                        CF_V3_ESCPX_STATE_ROUTE_COUNT);
#ifdef CF_V3_ESCPX_MUTATE_FAITHFUL
  control = (uint8_t)((control & CF_V3_ESCPX_FLAG_FAITHFUL) |
                      (control % CF_V3_ESCPX_STATE_ROUTE_COUNT));
#else
  control = (uint8_t)(control % CF_V3_ESCPX_STATE_ROUTE_COUNT);
#endif
  size = cf_v3_escpx_from_relation(data, max_size, relation, relation_size,
                                   control);
  free(relation);
  return size;
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *output, size_t max_size,
                          unsigned int seed)
{
  uint8_t *first;
  uint8_t *second;
  uint8_t *merged;
  size_t first_size;
  size_t second_size;
  size_t merged_size;
  uint8_t control;
  size_t result;

  if (!cf_v3_escpx_state_input(data1, size1) ||
      !cf_v3_escpx_state_input(data2, size2) || max_size <= 1U)
    return 0U;
  first = (uint8_t *)malloc(max_size - 1U);
  second = (uint8_t *)malloc(max_size - 1U);
  merged = (uint8_t *)malloc(max_size - 1U);
  if (!first || !second || !merged)
  {
    free(first);
    free(second);
    free(merged);
    return 0U;
  }
  first_size = cf_v3_escpx_to_relation(data1, size1, first);
  second_size = cf_v3_escpx_to_relation(data2, size2, second);
  merged_size = cf_v3_escpx_relation_crossover(
      first, first_size, second, second_size, merged, max_size - 1U, seed);
  control = *(seed & 1U ? cf_v3_escpx_state_const_control(data2) :
                          cf_v3_escpx_state_const_control(data1));
#ifndef CF_V3_ESCPX_MUTATE_FAITHFUL
  control &= (uint8_t)~CF_V3_ESCPX_FLAG_FAITHFUL;
#endif
  result = cf_v3_escpx_from_relation(output, max_size, merged, merged_size,
                                     control);
  free(first);
  free(second);
  free(merged);
  return result;
}
