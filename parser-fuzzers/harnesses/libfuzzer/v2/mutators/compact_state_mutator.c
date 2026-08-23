// SPDX-License-Identifier: Apache-2.0
#include "../include/shared_blocks.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

#ifndef CF_V2_STATE_PREFIX_SIZE
#define CF_V2_STATE_PREFIX_SIZE 0U
#endif

#ifndef CF_V2_STATE_SELECTOR_SIZE
#error "CF_V2_STATE_SELECTOR_SIZE must name the compact state selector bytes"
#endif

#ifndef CF_V2_STATE_MIN_PAYLOAD
#define CF_V2_STATE_MIN_PAYLOAD 0U
#endif

static int
cf_v2_compact_state_shared_blocks(const uint8_t *data, size_t size,
                                  cf_v2_shared_block_set_t *blocks)
{
  const size_t state_size =
      CF_V2_STATE_PREFIX_SIZE + CF_V2_STATE_SELECTOR_SIZE;

  if (!data || !blocks || size < state_size + CF_V2_STATE_MIN_PAYLOAD)
    return 0;
  cf_v2_shared_blocks_init(blocks);
  return cf_v2_shared_blocks_add(
             blocks, CF_V2_BLOCK_SELECTORS,
             data + CF_V2_STATE_PREFIX_SIZE, CF_V2_STATE_SELECTOR_SIZE) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_PAYLOAD,
                                 data + state_size, size - state_size);
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t state_size =
      CF_V2_STATE_PREFIX_SIZE + CF_V2_STATE_SELECTOR_SIZE;
  size_t payload_size;
  size_t mutated_size;

  if (!data || size < state_size + CF_V2_STATE_MIN_PAYLOAD ||
      max_size < state_size + CF_V2_STATE_MIN_PAYLOAD)
    return LLVMFuzzerMutate(data, size, max_size);

  /* Selector bytes are total functions: every value maps to a finite state. */
  if ((seed & 3U) != 0U)
  {
    const size_t slot = CF_V2_STATE_PREFIX_SIZE +
                        ((seed >> 2U) % CF_V2_STATE_SELECTOR_SIZE);
    const uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      data[slot] ^= delta;
    else
      data[slot] += delta;
    return size;
  }

  payload_size = size - state_size;
  mutated_size = LLVMFuzzerMutate(data + state_size, payload_size,
                                  max_size - state_size);
  if (mutated_size < CF_V2_STATE_MIN_PAYLOAD)
  {
    data[state_size] = (uint8_t)seed;
    mutated_size = CF_V2_STATE_MIN_PAYLOAD;
  }
  return state_size + mutated_size;
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *out, size_t max_out_size,
                          unsigned int seed)
{
  const size_t state_size =
      CF_V2_STATE_PREFIX_SIZE + CF_V2_STATE_SELECTOR_SIZE;
  cf_v2_shared_block_set_t first;
  cf_v2_shared_block_set_t second;
  const cf_v2_shared_block_t *first_selectors;
  const cf_v2_shared_block_t *second_selectors;
  const cf_v2_shared_block_t *payload_block;
  const uint8_t *base;
  size_t index;
  int valid1;
  int valid2;

  if (!out || max_out_size < state_size + CF_V2_STATE_MIN_PAYLOAD)
    return 0U;
  valid1 = cf_v2_compact_state_shared_blocks(data1, size1, &first);
  valid2 = cf_v2_compact_state_shared_blocks(data2, size2, &second);
#if CF_V2_STATE_PREFIX_SIZE > 0
  if (valid1 && valid2 &&
      memcmp(data1, data2, CF_V2_STATE_PREFIX_SIZE) != 0)
    valid2 = 0;
#endif
  if (!valid1 && !valid2)
    return 0U;

  if (valid1 && size1 <= max_out_size && (!(seed & 1U) || !valid2))
  {
    base = data1;
  }
  else if (valid2 && size2 <= max_out_size)
  {
    base = data2;
  }
  else
    return 0U;

  first_selectors = valid1
      ? cf_v2_shared_blocks_find(&first, CF_V2_BLOCK_SELECTORS) : NULL;
  second_selectors = valid2
      ? cf_v2_shared_blocks_find(&second, CF_V2_BLOCK_SELECTORS) : NULL;
  payload_block = ((seed & 2U) && valid2)
      ? cf_v2_shared_blocks_find(&second, CF_V2_BLOCK_PAYLOAD)
      : (valid1 ? cf_v2_shared_blocks_find(&first, CF_V2_BLOCK_PAYLOAD)
                : NULL);
  if (!payload_block ||
      payload_block->size > max_out_size - state_size)
  {
    const cf_v2_shared_block_set_t *base_blocks =
        base == data1 ? &first : &second;

    payload_block =
        cf_v2_shared_blocks_find(base_blocks, CF_V2_BLOCK_PAYLOAD);
  }
  if (!payload_block || payload_block->size > max_out_size - state_size)
    return 0U;

#if CF_V2_STATE_PREFIX_SIZE > 0
  memcpy(out, base, CF_V2_STATE_PREFIX_SIZE);
#endif
  for (index = 0U; index < CF_V2_STATE_SELECTOR_SIZE; index ++)
  {
    uint32_t choice = seed ^ (uint32_t)(index * 0x9e3779b9U);
    const cf_v2_shared_block_t *source =
        (second_selectors && (choice & 1U))
            ? second_selectors : first_selectors;

    if (!source)
      source = second_selectors;
    out[CF_V2_STATE_PREFIX_SIZE + index] =
        source->data[index];
  }
  memcpy(out + state_size, payload_block->data, payload_block->size);
  return state_size + payload_block->size;
}
