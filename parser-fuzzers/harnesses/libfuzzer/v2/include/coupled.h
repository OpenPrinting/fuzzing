// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_COUPLED_H
#define CUPSFILTERS_FUZZ_V2_COUPLED_H

#include "control.h"
#include "shared_blocks.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_COUPLED_LENGTH_SIZE 4U
#define CF_V2_COUPLED_PPD_PREFIX "*PPD-Adobe:"
#define CF_V2_COUPLED_PPD_PREFIX_SIZE 11U

typedef struct cf_v2_coupled_input_s {
  const uint8_t *ppd;
  size_t ppd_size;
  const uint8_t *document;
  size_t document_size;
  const uint8_t *control_bytes;
  cf_v2_control_t control;
} cf_v2_coupled_input_t;

static inline uint32_t cf_v2_load_u32le(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static inline void cf_v2_store_u32le(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
  data[2] = (uint8_t)(value >> 16);
  data[3] = (uint8_t)(value >> 24);
}

static inline int cf_v2_parse_coupled_input(
    const uint8_t *data, size_t size, size_t max_ppd, size_t max_document,
    cf_v2_coupled_input_t *input) {
  size_t ppd_size;
  size_t document_offset;
  size_t document_size;
  const uint8_t *tail;

  if (!data || !input || size <= CF_V2_COUPLED_LENGTH_SIZE +
                                    CF_V2_CONTROL_SIZE) {
    return 0;
  }
  ppd_size = (size_t)cf_v2_load_u32le(data);
  document_offset = CF_V2_COUPLED_LENGTH_SIZE + ppd_size;
  if (ppd_size < CF_V2_COUPLED_PPD_PREFIX_SIZE || ppd_size > max_ppd ||
      document_offset > size - CF_V2_CONTROL_SIZE ||
      memcmp(data + CF_V2_COUPLED_LENGTH_SIZE, CF_V2_COUPLED_PPD_PREFIX,
             CF_V2_COUPLED_PPD_PREFIX_SIZE) != 0) {
    return 0;
  }
  document_size = size - document_offset - CF_V2_CONTROL_SIZE;
  if (!document_size || document_size > max_document) {
    return 0;
  }

  input->ppd = data + CF_V2_COUPLED_LENGTH_SIZE;
  input->ppd_size = ppd_size;
  input->document = data + document_offset;
  input->document_size = document_size;
  tail = data + size - CF_V2_CONTROL_SIZE;
  input->control_bytes = tail;
  memcpy(&input->control, tail, CF_V2_CONTROL_SIZE);
  cf_v2_apply_control_policy(&input->control);
  return 1;
}

static inline int
cf_v2_coupled_shared_blocks(const cf_v2_coupled_input_t *input,
                            cf_v2_shared_block_set_t *blocks)
{
  if (!input || !blocks || !input->control_bytes)
    return 0;
  cf_v2_shared_blocks_init(blocks);
  return cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_PPD,
                                 input->ppd, input->ppd_size) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_DOCUMENT,
                                 input->document, input->document_size) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_CONTROL,
                                 input->control_bytes, CF_V2_CONTROL_SIZE);
}

static inline size_t
cf_v2_pack_coupled_shared_blocks(uint8_t *output, size_t max_output_size,
                                 const cf_v2_shared_block_set_t *blocks)
{
  const cf_v2_shared_block_t *ppd;
  const cf_v2_shared_block_t *document;
  const cf_v2_shared_block_t *control;
  size_t output_size = CF_V2_COUPLED_LENGTH_SIZE + CF_V2_CONTROL_SIZE;
  size_t offset;

  if (!output || !blocks ||
      !(ppd = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_PPD)) ||
      !(document = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_DOCUMENT)) ||
      !(control = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_CONTROL)) ||
      control->size != CF_V2_CONTROL_SIZE ||
      ppd->size < CF_V2_COUPLED_PPD_PREFIX_SIZE ||
      ppd->size > UINT32_MAX || !document->size ||
      memcmp(ppd->data, CF_V2_COUPLED_PPD_PREFIX,
             CF_V2_COUPLED_PPD_PREFIX_SIZE) != 0 ||
      ppd->size > SIZE_MAX - output_size)
    return 0U;
  output_size += ppd->size;
  if (document->size > SIZE_MAX - output_size)
    return 0U;
  output_size += document->size;
  if (output_size > max_output_size)
    return 0U;

  cf_v2_store_u32le(output, (uint32_t)ppd->size);
  offset = CF_V2_COUPLED_LENGTH_SIZE;
  memcpy(output + offset, ppd->data, ppd->size);
  offset += ppd->size;
  memcpy(output + offset, document->data, document->size);
  offset += document->size;
  memcpy(output + offset, control->data, control->size);
  return output_size;
}

#endif
