// SPDX-License-Identifier: Apache-2.0
#include "../include/relation_mutator_schema.h"
#include "../include/relation_program.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t
cf_v2_relation_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static size_t
cf_v2_relation_fixed_size(void)
{
  return cf_v2_relation_mutator_schema.magic_size +
         cf_v2_relation_mutator_schema.header_size;
}

static int
cf_v2_relation_schema_valid(void)
{
  size_t index;

  if (!cf_v2_relation_mutator_schema.magic ||
      !cf_v2_relation_mutator_schema.magic_size ||
      !cf_v2_relation_mutator_schema.fields ||
      !cf_v2_relation_mutator_schema.field_count)
    return 0;
  for (index = 0U; index < cf_v2_relation_mutator_schema.field_count;
       index ++) {
    const cf_v2_relation_field_schema_t *field =
        cf_v2_relation_mutator_schema.fields + index;

    if (!field->width || field->width > 8U ||
        (size_t)field->offset + field->width >
            cf_v2_relation_mutator_schema.header_size ||
        (field->kind == CF_V2_RELATION_FIELD_ENUM &&
         (!field->cardinality || field->cardinality > 256U)))
      return 0;
  }
  return 1;
}

static int
cf_v2_relation_input_valid(const uint8_t *data, size_t size)
{
  size_t fixed_size = cf_v2_relation_fixed_size();

  return data &&
         size >= fixed_size + cf_v2_relation_mutator_schema.min_payload &&
         !memcmp(data, cf_v2_relation_mutator_schema.magic,
                 cf_v2_relation_mutator_schema.magic_size);
}

static void
cf_v2_relation_write_little_endian(uint8_t *field, size_t width,
                                   uint64_t value)
{
  size_t index;

  for (index = 0U; index < width; index ++) {
    field[index] = (uint8_t)value;
    value >>= 8U;
  }
}

static uint64_t
cf_v2_relation_signed_delta(uint32_t *state, unsigned bits)
{
  static const int8_t small_deltas[] = {
    0, 1, -1, 2, -2, 3, -3, 4, -4, 8, -8, 16, -16
  };
  uint32_t choice = cf_v2_relation_random(state);

  if ((choice & 3U) != 3U)
    return (uint64_t)(int64_t)small_deltas[
        choice % (sizeof(small_deltas) / sizeof(small_deltas[0]))];
  return (uint64_t)cf_v2_boundary_signed(
      (uint8_t)(choice >> 8U), (uint8_t)(choice >> 16U), bits);
}

static void
cf_v2_relation_mutate_field(uint8_t *data, size_t field_index,
                            uint32_t *state)
{
  const cf_v2_relation_field_schema_t *field =
      cf_v2_relation_mutator_schema.fields + field_index;
  uint8_t *value = data + cf_v2_relation_mutator_schema.magic_size +
                   field->offset;

  switch (field->kind) {
    case CF_V2_RELATION_FIELD_ENUM:
      if (field->cardinality <= 1U)
        value[0] = 0U;
      else {
        uint8_t next = (uint8_t)(cf_v2_relation_random(state) %
                                 field->cardinality);

        if (next == value[0])
          next = (uint8_t)((next + 1U) % field->cardinality);
        value[0] = next;
      }
      break;
    case CF_V2_RELATION_FIELD_SIGNED_DELTA:
      cf_v2_relation_write_little_endian(
          value, field->width,
          cf_v2_relation_signed_delta(state, field->width * 8U));
      break;
    case CF_V2_RELATION_FIELD_UNSIGNED_BOUNDARY:
      cf_v2_relation_write_little_endian(
          value, field->width,
          cf_v2_boundary_unsigned((uint8_t)cf_v2_relation_random(state),
                                  (uint8_t)cf_v2_relation_random(state),
                                  field->width * 8U));
      break;
    case CF_V2_RELATION_FIELD_RAW:
      (void)LLVMFuzzerMutate(value, field->width, field->width);
      break;
  }
}

static void
cf_v2_relation_normalize(uint8_t *data)
{
  size_t index;

  memcpy(data, cf_v2_relation_mutator_schema.magic,
         cf_v2_relation_mutator_schema.magic_size);
  for (index = 0U; index < cf_v2_relation_mutator_schema.field_count;
       index ++) {
    const cf_v2_relation_field_schema_t *field =
        cf_v2_relation_mutator_schema.fields + index;

    if (field->kind == CF_V2_RELATION_FIELD_ENUM)
      data[cf_v2_relation_mutator_schema.magic_size + field->offset] =
          (uint8_t)(data[cf_v2_relation_mutator_schema.magic_size +
                         field->offset] % field->cardinality);
  }
}

static size_t
cf_v2_relation_initialize(uint8_t *data, size_t max_size, uint32_t *state)
{
  size_t fixed_size = cf_v2_relation_fixed_size();
  size_t minimum_size = fixed_size +
                        cf_v2_relation_mutator_schema.min_payload;
  size_t index;

  if (!data || max_size < minimum_size)
    return 0U;
  memcpy(data, cf_v2_relation_mutator_schema.magic,
         cf_v2_relation_mutator_schema.magic_size);
  memset(data + cf_v2_relation_mutator_schema.magic_size, 0,
         cf_v2_relation_mutator_schema.header_size);
  for (index = 0U; index < cf_v2_relation_mutator_schema.field_count;
       index ++)
    if (cf_v2_relation_random(state) & 1U)
      cf_v2_relation_mutate_field(data, index, state);
  for (index = fixed_size; index < minimum_size; index ++)
    data[index] = (uint8_t)cf_v2_relation_random(state);
  cf_v2_relation_normalize(data);
  return minimum_size;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                        unsigned int seed)
{
  size_t fixed_size = cf_v2_relation_fixed_size();
  uint32_t state = seed;
  size_t field_index;
  unsigned action;

  if (!cf_v2_relation_schema_valid())
    return LLVMFuzzerMutate(data, size, max_size);
  if (!cf_v2_relation_input_valid(data, size))
    return cf_v2_relation_initialize(data, max_size, &state);
  cf_v2_relation_normalize(data);
  field_index = cf_v2_relation_random(&state) %
                cf_v2_relation_mutator_schema.field_count;
  action = cf_v2_relation_random(&state) % 10U;
  if (action < 6U) {
    cf_v2_relation_mutate_field(data, field_index, &state);
    return size;
  }
  if (action < 8U) {
    const uint8_t group =
        cf_v2_relation_mutator_schema.fields[field_index].group;
    size_t index;

    for (index = 0U; index < cf_v2_relation_mutator_schema.field_count;
         index ++)
      if (group &&
          cf_v2_relation_mutator_schema.fields[index].group == group)
        cf_v2_relation_mutate_field(data, index, &state);
    if (!group)
      cf_v2_relation_mutate_field(data, field_index, &state);
    return size;
  }
  {
    size_t payload_size = size - fixed_size;
    size_t mutated_size = LLVMFuzzerMutate(
        data + fixed_size, payload_size, max_size - fixed_size);

    if (mutated_size < cf_v2_relation_mutator_schema.min_payload) {
      size_t index;

      for (index = mutated_size;
           index < cf_v2_relation_mutator_schema.min_payload; index ++)
        data[fixed_size + index] = (uint8_t)cf_v2_relation_random(&state);
      mutated_size = cf_v2_relation_mutator_schema.min_payload;
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
  size_t fixed_size = cf_v2_relation_fixed_size();
  const uint8_t *payload_parent;
  size_t payload_size;
  size_t index;

  if (!out || !cf_v2_relation_schema_valid() ||
      !cf_v2_relation_input_valid(data1, size1) ||
      !cf_v2_relation_input_valid(data2, size2) ||
      max_out_size < fixed_size + cf_v2_relation_mutator_schema.min_payload)
    return 0U;
  payload_parent = (seed & 1U) ? data2 : data1;
  payload_size = (payload_parent == data1 ? size1 : size2) - fixed_size;
  if (payload_size > max_out_size - fixed_size)
    return 0U;
  memcpy(out, cf_v2_relation_mutator_schema.magic,
         cf_v2_relation_mutator_schema.magic_size);
  memcpy(out + cf_v2_relation_mutator_schema.magic_size,
         data1 + cf_v2_relation_mutator_schema.magic_size,
         cf_v2_relation_mutator_schema.header_size);
  for (index = 0U; index < cf_v2_relation_mutator_schema.field_count;
       index ++) {
    const cf_v2_relation_field_schema_t *field =
        cf_v2_relation_mutator_schema.fields + index;
    uint32_t choice = seed ^
        (uint32_t)((field->group ? field->group : index + 1U) *
                   UINT32_C(0x9e3779b9));
    const uint8_t *source = (choice & 1U) ? data2 : data1;

    memcpy(out + cf_v2_relation_mutator_schema.magic_size + field->offset,
           source + cf_v2_relation_mutator_schema.magic_size + field->offset,
           field->width);
  }
  memcpy(out + fixed_size, payload_parent + fixed_size, payload_size);
  cf_v2_relation_normalize(out);
  return fixed_size + payload_size;
}
