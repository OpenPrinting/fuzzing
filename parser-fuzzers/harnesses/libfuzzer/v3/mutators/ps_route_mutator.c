// SPDX-License-Identifier: Apache-2.0
#include "../implementations/ps_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t
cf_v3_ps_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static int
cf_v3_ps_faithful_mode(void)
{
  const char *value = getenv("CF_V3_PS_MUTATE_FAITHFUL");

  if (!value || !value[0] || !strcmp(value, "0"))
    return 0;
  if (!strcmp(value, "eof"))
    return 2;
  if (!strcmp(value, "sequence"))
    return 3;
  return 1;
}

static int
cf_v3_ps_faithful_allowed(int mode, const uint8_t *header)
{
  unsigned route = cf_v3_ps_route(header);

  if (!mode)
    return 0;
  if (mode == 1)
    return 1;
  if (mode == 2)
    return route == CF_V3_PS_ROUTE_PAGE_RANGE_EOF &&
           header[2] % 8U == 7U;
  return route == CF_V3_PS_ROUTE_SEQUENCE;
}

static size_t
cf_v3_ps_route_material_limit(unsigned route)
{
  switch (route)
  {
    case CF_V3_PS_ROUTE_DSC: return 1024U;
    case CF_V3_PS_ROUTE_PAGE_RANGE_EOF: return 128U;
    case CF_V3_PS_ROUTE_SEQUENCE:
    case CF_V3_PS_ROUTE_SEQUENCE_DEEP: return 512U;
    default: return CF_V3_PS_MAX_MATERIAL;
  }
}

static size_t
cf_v3_ps_normalize(uint8_t *data, size_t size, int faithful_mode)
{
  uint8_t *header;
  uint8_t policy;
  unsigned route;
  size_t material_size;
  size_t route_limit;

  if (!cf_v3_ps_input(data, size))
    return size;
  header = cf_v3_ps_header(data);
  route = cf_v3_ps_route(header);
  policy = cf_v3_ps_faithful_allowed(faithful_mode, header) &&
                   cf_v3_ps_faithful(header)
               ? CF_V3_PS_FLAG_FAITHFUL : 0U;
  header[CF_V3_PS_ROUTE_OFFSET] = (uint8_t)(policy | route);
  material_size = size - CF_V3_PS_FIXED_SIZE;
  route_limit = cf_v3_ps_route_material_limit(route);
  if (material_size > route_limit)
    size = CF_V3_PS_FIXED_SIZE + route_limit;
  return size;
}

static size_t
cf_v3_ps_initialize(uint8_t *data, size_t max_size, uint32_t *state)
{
  size_t material_size;

  if (!data || max_size < CF_V3_PS_FIXED_SIZE + 1U)
    return 0U;
  memcpy(data, CF_V3_PS_MAGIC, CF_V3_PS_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V3_PS_HEADER_SIZE; index++)
    data[CF_V3_PS_MAGIC_SIZE + index] = (uint8_t)cf_v3_ps_random(state);
  data[CF_V3_PS_MAGIC_SIZE + CF_V3_PS_ROUTE_OFFSET] =
      (uint8_t)(cf_v3_ps_random(state) % CF_V3_PS_ROUTE_COUNT);
  material_size = 1U + cf_v3_ps_random(state) %
      (max_size - CF_V3_PS_FIXED_SIZE < 64U
           ? max_size - CF_V3_PS_FIXED_SIZE : 64U);
  for (size_t index = 0U; index < material_size; index++)
    data[CF_V3_PS_FIXED_SIZE + index] = (uint8_t)cf_v3_ps_random(state);
  return cf_v3_ps_normalize(data, CF_V3_PS_FIXED_SIZE + material_size,
                            cf_v3_ps_faithful_mode());
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  uint32_t state = seed;
  int faithful_mode = cf_v3_ps_faithful_mode();

  if (!cf_v3_ps_input(data, size))
    return cf_v3_ps_initialize(data, max_size, &state);

  if ((cf_v3_ps_random(&state) & 3U) != 0U)
  {
    uint8_t *header = cf_v3_ps_header(data);
    size_t slot = cf_v3_ps_random(&state) % CF_V3_PS_HEADER_SIZE;
    uint8_t delta = (uint8_t)(1U + (cf_v3_ps_random(&state) & 0xffU));

    if (cf_v3_ps_random(&state) & 1U)
      header[slot] ^= delta;
    else
      header[slot] += delta;
    if ((cf_v3_ps_random(&state) & 15U) == 0U)
      cf_v3_ps_set_route(header,
          cf_v3_ps_random(&state) % CF_V3_PS_ROUTE_COUNT);
    if (cf_v3_ps_faithful_allowed(faithful_mode, header) &&
        (cf_v3_ps_random(&state) & 31U) == 0U)
      header[CF_V3_PS_ROUTE_OFFSET] ^= CF_V3_PS_FLAG_FAITHFUL;
    return cf_v3_ps_normalize(data, size, faithful_mode);
  }

  {
    size_t material_size = size - CF_V3_PS_FIXED_SIZE;
    size_t mutated_size = LLVMFuzzerMutate(
        data + CF_V3_PS_FIXED_SIZE, material_size,
        max_size - CF_V3_PS_FIXED_SIZE);

    if (!mutated_size)
    {
      data[CF_V3_PS_FIXED_SIZE] = (uint8_t)cf_v3_ps_random(&state);
      mutated_size = 1U;
    }
    return cf_v3_ps_normalize(data, CF_V3_PS_FIXED_SIZE + mutated_size,
                              faithful_mode);
  }
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *output, size_t max_output_size,
                          unsigned int seed)
{
  const uint8_t *first_header;
  const uint8_t *second_header;
  const uint8_t *material;
  size_t material_size;

  if (!output || max_output_size < CF_V3_PS_FIXED_SIZE + 1U ||
      !cf_v3_ps_input(data1, size1) || !cf_v3_ps_input(data2, size2))
    return 0U;
  first_header = cf_v3_ps_const_header(data1);
  second_header = cf_v3_ps_const_header(data2);
  if (seed & 1U)
  {
    material = data2 + CF_V3_PS_FIXED_SIZE;
    material_size = size2 - CF_V3_PS_FIXED_SIZE;
  }
  else
  {
    material = data1 + CF_V3_PS_FIXED_SIZE;
    material_size = size1 - CF_V3_PS_FIXED_SIZE;
  }
  if (!material_size ||
      material_size > max_output_size - CF_V3_PS_FIXED_SIZE)
    return 0U;
  memcpy(output, CF_V3_PS_MAGIC, CF_V3_PS_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V3_PS_HEADER_SIZE; index++)
    output[CF_V3_PS_MAGIC_SIZE + index] =
        ((seed >> (index % 24U)) & 1U)
            ? second_header[index] : first_header[index];
  memcpy(output + CF_V3_PS_FIXED_SIZE, material, material_size);
  return cf_v3_ps_normalize(output,
                            CF_V3_PS_FIXED_SIZE + material_size,
                            cf_v3_ps_faithful_mode());
}
