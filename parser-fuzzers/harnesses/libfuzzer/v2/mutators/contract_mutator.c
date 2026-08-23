// SPDX-License-Identifier: Apache-2.0
#include "../include/contract_schema.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t
cf_v2_contract_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static size_t
cf_v2_contract_fixed_size(void)
{
  return cf_v2_contract_schema.magic_size +
         cf_v2_contract_schema.field_count;
}

static int
cf_v2_contract_schema_is_valid(void)
{
  size_t index;

  if (!cf_v2_contract_schema.magic || !cf_v2_contract_schema.magic_size ||
      !cf_v2_contract_schema.cardinalities ||
      !cf_v2_contract_schema.groups || !cf_v2_contract_schema.field_count)
    return 0;
  for (index = 0U; index < cf_v2_contract_schema.field_count; index ++)
    if (!cf_v2_contract_schema.cardinalities[index] ||
        cf_v2_contract_schema.cardinalities[index] > 256U)
      return 0;
  return 1;
}

static int
cf_v2_contract_input_is_valid(const uint8_t *data, size_t size)
{
  const size_t fixed_size = cf_v2_contract_fixed_size();

  return data && size >= fixed_size + cf_v2_contract_schema.min_payload &&
         !memcmp(data, cf_v2_contract_schema.magic,
                 cf_v2_contract_schema.magic_size);
}

static size_t
cf_v2_contract_initialize(uint8_t *data, size_t max_size, uint32_t *state)
{
  const size_t fixed_size = cf_v2_contract_fixed_size();
  const size_t minimum_size = fixed_size + cf_v2_contract_schema.min_payload;
  size_t index;

  if (!data || max_size < minimum_size)
    return 0U;
  memcpy(data, cf_v2_contract_schema.magic,
         cf_v2_contract_schema.magic_size);
  for (index = 0U; index < cf_v2_contract_schema.field_count; index ++)
    data[cf_v2_contract_schema.magic_size + index] =
        (uint8_t)(cf_v2_contract_random(state) %
                  cf_v2_contract_schema.cardinalities[index]);
  for (index = fixed_size; index < minimum_size; index ++)
    data[index] = (uint8_t)cf_v2_contract_random(state);
  return minimum_size;
}

static void
cf_v2_contract_normalize(uint8_t *data)
{
  size_t index;

  memcpy(data, cf_v2_contract_schema.magic,
         cf_v2_contract_schema.magic_size);
  for (index = 0U; index < cf_v2_contract_schema.field_count; index ++)
    data[cf_v2_contract_schema.magic_size + index] =
        (uint8_t)(data[cf_v2_contract_schema.magic_size + index] %
                  cf_v2_contract_schema.cardinalities[index]);
}

static void
cf_v2_contract_mutate_field(uint8_t *data, size_t field, uint32_t *state)
{
  const uint16_t cardinality =
      cf_v2_contract_schema.cardinalities[field];
  uint8_t *value = data + cf_v2_contract_schema.magic_size + field;
  const unsigned mode = cf_v2_contract_random(state) % 5U;

  if (cardinality <= 1U) {
    *value = 0U;
    return;
  }
  switch (mode) {
    case 0U:
      *value = 0U;
      break;
    case 1U:
      *value = (uint8_t)(cardinality - 1U);
      break;
    case 2U:
      *value = (uint8_t)((*value + 1U) % cardinality);
      break;
    case 3U:
      *value = (uint8_t)((*value + cardinality - 1U) % cardinality);
      break;
    default: {
      uint8_t next = (uint8_t)(cf_v2_contract_random(state) % cardinality);

      if (next == *value)
        next = (uint8_t)((next + 1U) % cardinality);
      *value = next;
      break;
    }
  }
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t fixed_size = cf_v2_contract_fixed_size();
  uint32_t state = seed;
  unsigned action;
  size_t field;

  if (!cf_v2_contract_schema_is_valid())
    return LLVMFuzzerMutate(data, size, max_size);
  if (!cf_v2_contract_input_is_valid(data, size))
    return cf_v2_contract_initialize(data, max_size, &state);

  cf_v2_contract_normalize(data);
  action = cf_v2_contract_random(&state) % 10U;
  field = cf_v2_contract_random(&state) %
          cf_v2_contract_schema.field_count;

  if (action < 6U) {
    cf_v2_contract_mutate_field(data, field, &state);
    return size;
  }
  if (action < 8U) {
    const uint8_t group = cf_v2_contract_schema.groups[field];
    size_t index;

    if (!group) {
      cf_v2_contract_mutate_field(data, field, &state);
      return size;
    }
    for (index = 0U; index < cf_v2_contract_schema.field_count; index ++)
      if (cf_v2_contract_schema.groups[index] == group)
        cf_v2_contract_mutate_field(data, index, &state);
    return size;
  }

  {
    size_t payload_size = size - fixed_size;
    size_t mutated_size = LLVMFuzzerMutate(data + fixed_size, payload_size,
                                           max_size - fixed_size);

    if (mutated_size < cf_v2_contract_schema.min_payload) {
      size_t index;

      for (index = mutated_size;
           index < cf_v2_contract_schema.min_payload; index ++)
        data[fixed_size + index] = (uint8_t)cf_v2_contract_random(&state);
      mutated_size = cf_v2_contract_schema.min_payload;
    }
    return fixed_size + mutated_size;
  }
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *out, size_t max_out_size,
                          unsigned int seed)
{
  const size_t fixed_size = cf_v2_contract_fixed_size();
  const uint8_t *payload;
  size_t payload_size;
  uint32_t state = seed;
  size_t index;
  int valid1;
  int valid2;

  if (!cf_v2_contract_schema_is_valid() || !out)
    return 0U;
  valid1 = cf_v2_contract_input_is_valid(data1, size1);
  valid2 = cf_v2_contract_input_is_valid(data2, size2);
  if (!valid1 && !valid2)
    return 0U;
  if (max_out_size < fixed_size + cf_v2_contract_schema.min_payload)
    return 0U;
  if (!valid1 || !valid2) {
    const uint8_t *source = valid1 ? data1 : data2;
    const size_t source_size = valid1 ? size1 : size2;

    if (source_size > max_out_size)
      return 0U;
    memcpy(out, source, source_size);
    cf_v2_contract_normalize(out);
    return source_size;
  }

  payload = (cf_v2_contract_random(&state) & 1U) ? data2 : data1;
  payload_size = payload == data1 ? size1 - fixed_size : size2 - fixed_size;
  if (payload_size > max_out_size - fixed_size) {
    payload = payload == data1 ? data2 : data1;
    payload_size = payload == data1 ? size1 - fixed_size : size2 - fixed_size;
  }
  if (payload_size > max_out_size - fixed_size)
    return 0U;

  memcpy(out, cf_v2_contract_schema.magic,
         cf_v2_contract_schema.magic_size);
  for (index = 0U; index < cf_v2_contract_schema.field_count; index ++) {
    const uint8_t group = cf_v2_contract_schema.groups[index];
    uint32_t choice = seed ^ (uint32_t)(index * UINT32_C(0x9e3779b9));
    const uint8_t *source;

    if (group)
      choice = seed ^ (uint32_t)(group * UINT32_C(0x85ebca6b));
    source = (choice & 1U) ? data2 : data1;
    out[cf_v2_contract_schema.magic_size + index] =
        (uint8_t)(source[cf_v2_contract_schema.magic_size + index] %
                  cf_v2_contract_schema.cardinalities[index]);
  }
  memcpy(out + fixed_size, payload + fixed_size, payload_size);
  return fixed_size + payload_size;
}
