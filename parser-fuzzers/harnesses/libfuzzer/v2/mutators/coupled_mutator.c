// SPDX-License-Identifier: Apache-2.0
#include "../include/coupled.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef CF_V2_COUPLED_MAX_PPD
#define CF_V2_COUPLED_MAX_PPD (256U * 1024U)
#endif
#ifndef CF_V2_COUPLED_MAX_DOCUMENT
#define CF_V2_COUPLED_MAX_DOCUMENT (2U * 1024U * 1024U)
#endif

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t cf_v2_coupled_random(uint32_t *state) {
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);
  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  *state = value;
  return value;
}

static size_t cf_v2_mutate_region(uint8_t *data, size_t size, size_t max_size,
                                  size_t offset, size_t region_size,
                                  size_t suffix_size) {
  uint8_t *temporary;
  size_t region_max;
  size_t new_size;

  if (offset > size || region_size > size - offset ||
      suffix_size > size - offset - region_size ||
      max_size < offset + suffix_size) {
    return size;
  }
  region_max = max_size - offset - suffix_size;
  temporary = (uint8_t *)malloc(region_max ? region_max : 1U);
  if (!temporary) {
    return size;
  }
  memcpy(temporary, data + offset, region_size);
  new_size = LLVMFuzzerMutate(temporary, region_size, region_max);
  memmove(data + offset + new_size, data + offset + region_size, suffix_size);
  memcpy(data + offset, temporary, new_size);
  free(temporary);
  return offset + new_size + suffix_size;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned seed) {
  cf_v2_coupled_input_t input;
  uint32_t random_state = seed;
  size_t ppd_offset = CF_V2_COUPLED_LENGTH_SIZE;
  size_t document_offset;
  size_t next_size;
  unsigned lane;

  if (!cf_v2_parse_coupled_input(data, size, CF_V2_COUPLED_MAX_PPD,
                                 CF_V2_COUPLED_MAX_DOCUMENT, &input)) {
    return LLVMFuzzerMutate(data, size, max_size);
  }

  document_offset = ppd_offset + input.ppd_size;
  lane = cf_v2_coupled_random(&random_state) % 3U;
  if (lane == 0U) {
    size_t suffix_size = input.document_size + CF_V2_CONTROL_SIZE;
    size_t ppd_max = max_size > ppd_offset + suffix_size
                         ? max_size - ppd_offset - suffix_size
                         : 0U;
    if (ppd_max > CF_V2_COUPLED_MAX_PPD) {
      ppd_max = CF_V2_COUPLED_MAX_PPD;
    }
    next_size = cf_v2_mutate_region(data, size,
                                    ppd_offset + ppd_max + suffix_size,
                                    ppd_offset, input.ppd_size, suffix_size);
    if (next_size >= ppd_offset + suffix_size) {
      size_t next_ppd = next_size - ppd_offset - suffix_size;
      if (next_ppd < CF_V2_COUPLED_PPD_PREFIX_SIZE) {
        size_t growth = CF_V2_COUPLED_PPD_PREFIX_SIZE - next_ppd;
        memmove(data + ppd_offset + CF_V2_COUPLED_PPD_PREFIX_SIZE,
                data + ppd_offset + next_ppd, suffix_size);
        next_ppd += growth;
        next_size += growth;
      }
      memcpy(data + ppd_offset, CF_V2_COUPLED_PPD_PREFIX,
             CF_V2_COUPLED_PPD_PREFIX_SIZE);
      cf_v2_store_u32le(data, (uint32_t)next_ppd);
      return next_size;
    }
    return size;
  }
  if (lane == 1U) {
    size_t document_max = max_size > document_offset + CF_V2_CONTROL_SIZE
                              ? max_size - document_offset - CF_V2_CONTROL_SIZE
                              : 0U;
    if (document_max > CF_V2_COUPLED_MAX_DOCUMENT) {
      document_max = CF_V2_COUPLED_MAX_DOCUMENT;
    }
    return cf_v2_mutate_region(
        data, size, document_offset + document_max + CF_V2_CONTROL_SIZE,
        document_offset, input.document_size, CF_V2_CONTROL_SIZE);
  }

  data[size - CF_V2_CONTROL_SIZE +
       cf_v2_coupled_random(&random_state) % CF_V2_CONTROL_SIZE] ^=
      (uint8_t)(1U << (cf_v2_coupled_random(&random_state) % 8U));
  return size;
}

static int cf_v2_coupled_blocks_from_bytes(
    const uint8_t *data, size_t size, cf_v2_shared_block_set_t *blocks) {
  cf_v2_coupled_input_t input;

  return cf_v2_parse_coupled_input(data, size, CF_V2_COUPLED_MAX_PPD,
                                   CF_V2_COUPLED_MAX_DOCUMENT, &input) &&
         cf_v2_coupled_shared_blocks(&input, blocks);
}

static void cf_v2_coupled_take_block(
    cf_v2_shared_block_set_t *output,
    const cf_v2_shared_block_set_t *donor,
    cf_v2_shared_block_role_t role) {
  const cf_v2_shared_block_t *replacement =
      cf_v2_shared_blocks_find(donor, role);

  if (replacement)
    (void)cf_v2_shared_blocks_replace(output, replacement);
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                 const uint8_t *data2, size_t size2,
                                 uint8_t *out, size_t max_out_size,
                                 unsigned int seed) {
  cf_v2_shared_block_set_t first;
  cf_v2_shared_block_set_t second;
  cf_v2_shared_block_set_t selected;
  const cf_v2_shared_block_set_t *base;
  const cf_v2_shared_block_set_t *donor;
  uint32_t random_state = seed;
  int valid1;
  int valid2;
  size_t output_size;

  if (!out)
    return 0U;
  valid1 = cf_v2_coupled_blocks_from_bytes(data1, size1, &first);
  valid2 = cf_v2_coupled_blocks_from_bytes(data2, size2, &second);
  if (!valid1 && !valid2)
    return 0U;
  if (valid1 && size1 <= max_out_size &&
      (!valid2 || size2 > max_out_size ||
       !(cf_v2_coupled_random(&random_state) & 1U))) {
    base = &first;
    donor = valid2 ? &second : &first;
  } else if (valid2 && size2 <= max_out_size) {
    base = &second;
    donor = valid1 ? &first : &second;
  } else {
    return 0U;
  }
  selected = *base;

  switch (cf_v2_coupled_random(&random_state) % 3U) {
    case 0U:
      cf_v2_coupled_take_block(&selected, donor, CF_V2_BLOCK_PPD);
      cf_v2_coupled_take_block(&selected, donor, CF_V2_BLOCK_CONTROL);
      break;
    case 1U:
      cf_v2_coupled_take_block(&selected, donor, CF_V2_BLOCK_DOCUMENT);
      break;
    default:
      cf_v2_coupled_take_block(&selected, donor, CF_V2_BLOCK_PPD);
      cf_v2_coupled_take_block(&selected, donor, CF_V2_BLOCK_DOCUMENT);
      break;
  }
  output_size =
      cf_v2_pack_coupled_shared_blocks(out, max_out_size, &selected);
  if (output_size)
    return output_size;
  return cf_v2_pack_coupled_shared_blocks(out, max_out_size, base);
}
