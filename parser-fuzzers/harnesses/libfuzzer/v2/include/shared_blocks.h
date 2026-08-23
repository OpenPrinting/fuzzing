// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_SHARED_BLOCKS_H
#define CUPSFILTERS_FUZZ_V2_SHARED_BLOCKS_H

#include <stddef.h>
#include <stdint.h>

#define CF_V2_SHARED_BLOCK_CAPACITY 8U

typedef enum cf_v2_shared_block_role_e {
  CF_V2_BLOCK_PPD = 1,
  CF_V2_BLOCK_OPTIONS = 2,
  CF_V2_BLOCK_TITLE = 3,
  CF_V2_BLOCK_DOCUMENT = 4,
  CF_V2_BLOCK_CONTROL = 5,
  CF_V2_BLOCK_SELECTORS = 6,
  CF_V2_BLOCK_PAYLOAD = 7
} cf_v2_shared_block_role_t;

typedef struct cf_v2_shared_block_s {
  cf_v2_shared_block_role_t role;
  const uint8_t *data;
  size_t size;
} cf_v2_shared_block_t;

typedef struct cf_v2_shared_block_set_s {
  cf_v2_shared_block_t blocks[CF_V2_SHARED_BLOCK_CAPACITY];
  size_t count;
} cf_v2_shared_block_set_t;

static inline void
cf_v2_shared_blocks_init(cf_v2_shared_block_set_t *set)
{
  if (set)
    set->count = 0U;
}

static inline const cf_v2_shared_block_t *
cf_v2_shared_blocks_find(const cf_v2_shared_block_set_t *set,
                         cf_v2_shared_block_role_t role)
{
  size_t index;

  if (!set)
    return NULL;
  for (index = 0U; index < set->count; index ++)
    if (set->blocks[index].role == role)
      return set->blocks + index;
  return NULL;
}

static inline int
cf_v2_shared_blocks_add(cf_v2_shared_block_set_t *set,
                        cf_v2_shared_block_role_t role,
                        const uint8_t *data, size_t size)
{
  cf_v2_shared_block_t *block;

  if (!set || set->count >= CF_V2_SHARED_BLOCK_CAPACITY ||
      (!data && size) || cf_v2_shared_blocks_find(set, role))
    return 0;
  block = set->blocks + set->count ++;
  block->role = role;
  block->data = data;
  block->size = size;
  return 1;
}

static inline int
cf_v2_shared_blocks_replace(cf_v2_shared_block_set_t *set,
                            const cf_v2_shared_block_t *replacement)
{
  size_t index;

  if (!set || !replacement || (!replacement->data && replacement->size))
    return 0;
  for (index = 0U; index < set->count; index ++)
  {
    if (set->blocks[index].role != replacement->role)
      continue;
    set->blocks[index] = *replacement;
    return 1;
  }
  return 0;
}

#endif
