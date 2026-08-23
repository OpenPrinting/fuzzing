// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_JOB_H
#define CUPSFILTERS_FUZZ_V2_JOB_H

#include "control.h"
#include "shared_blocks.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_JOB_LENGTH_FIELDS 4U
#define CF_V2_JOB_HEADER_SIZE (CF_V2_JOB_LENGTH_FIELDS * 4U)
#define CF_V2_JOB_FIXED_SIZE (CF_V2_JOB_HEADER_SIZE + CF_V2_CONTROL_SIZE)
#define CF_V2_JOB_PPD_PREFIX "*PPD-Adobe:"
#define CF_V2_JOB_PPD_PREFIX_SIZE 11U

typedef struct cf_v2_job_input_s {
  cf_v2_control_t control;
  const uint8_t *control_bytes;
  const uint8_t *ppd;
  size_t ppd_size;
  const uint8_t *options;
  size_t options_size;
  const uint8_t *title;
  size_t title_size;
  const uint8_t *document;
  size_t document_size;
} cf_v2_job_input_t;

static inline uint32_t cf_v2_job_load_u32le(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static inline void cf_v2_job_store_u32le(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
  data[2] = (uint8_t)(value >> 16);
  data[3] = (uint8_t)(value >> 24);
}

static inline int cf_v2_parse_job_input(
    const uint8_t *data, size_t size, size_t max_ppd, size_t max_options,
    size_t max_title, size_t max_document, cf_v2_job_input_t *input) {
  size_t lengths[CF_V2_JOB_LENGTH_FIELDS];
  size_t offset = CF_V2_JOB_FIXED_SIZE;

  if (!data || !input || size < CF_V2_JOB_FIXED_SIZE) {
    return 0;
  }
  for (size_t index = 0; index < CF_V2_JOB_LENGTH_FIELDS; index++) {
    lengths[index] = (size_t)cf_v2_job_load_u32le(data + index * 4U);
  }
  if (lengths[0] > max_ppd || lengths[1] > max_options ||
      lengths[2] > max_title || !lengths[3] || lengths[3] > max_document ||
      lengths[0] > size - offset) {
    return 0;
  }
  input->ppd = data + offset;
  input->ppd_size = lengths[0];
  offset += lengths[0];
  if (lengths[1] > size - offset) {
    return 0;
  }
  input->options = data + offset;
  input->options_size = lengths[1];
  offset += lengths[1];
  if (lengths[2] > size - offset) {
    return 0;
  }
  input->title = data + offset;
  input->title_size = lengths[2];
  offset += lengths[2];
  if (lengths[3] != size - offset) {
    return 0;
  }
  input->document = data + offset;
  input->document_size = lengths[3];

  if ((input->ppd_size &&
       (input->ppd_size < CF_V2_JOB_PPD_PREFIX_SIZE ||
        memcmp(input->ppd, CF_V2_JOB_PPD_PREFIX,
               CF_V2_JOB_PPD_PREFIX_SIZE) != 0)) ||
      (input->options_size && memchr(input->options, 0, input->options_size))) {
    return 0;
  }
  input->control_bytes = data + CF_V2_JOB_HEADER_SIZE;
  memcpy(&input->control, input->control_bytes, CF_V2_CONTROL_SIZE);
  cf_v2_apply_control_policy(&input->control);
  return 1;
}

static inline int
cf_v2_job_shared_blocks(const cf_v2_job_input_t *input,
                        cf_v2_shared_block_set_t *blocks)
{
  if (!input || !blocks || !input->control_bytes)
    return 0;
  cf_v2_shared_blocks_init(blocks);
  return cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_PPD,
                                 input->ppd, input->ppd_size) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_OPTIONS,
                                 input->options, input->options_size) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_TITLE,
                                 input->title, input->title_size) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_DOCUMENT,
                                 input->document, input->document_size) &&
         cf_v2_shared_blocks_add(blocks, CF_V2_BLOCK_CONTROL,
                                 input->control_bytes, CF_V2_CONTROL_SIZE);
}

static inline size_t
cf_v2_pack_job_shared_blocks(uint8_t *output, size_t max_output_size,
                             const cf_v2_shared_block_set_t *blocks)
{
  const cf_v2_shared_block_t *ppd;
  const cf_v2_shared_block_t *options;
  const cf_v2_shared_block_t *title;
  const cf_v2_shared_block_t *document;
  const cf_v2_shared_block_t *control;
  size_t output_size = CF_V2_JOB_FIXED_SIZE;
  size_t offset;

  if (!output || !blocks ||
      !(ppd = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_PPD)) ||
      !(options = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_OPTIONS)) ||
      !(title = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_TITLE)) ||
      !(document = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_DOCUMENT)) ||
      !(control = cf_v2_shared_blocks_find(blocks, CF_V2_BLOCK_CONTROL)) ||
      control->size != CF_V2_CONTROL_SIZE || !document->size ||
      ppd->size > UINT32_MAX || options->size > UINT32_MAX ||
      title->size > UINT32_MAX || document->size > UINT32_MAX ||
      (ppd->size &&
       (ppd->size < CF_V2_JOB_PPD_PREFIX_SIZE ||
        memcmp(ppd->data, CF_V2_JOB_PPD_PREFIX,
               CF_V2_JOB_PPD_PREFIX_SIZE) != 0)) ||
      (options->size && memchr(options->data, 0, options->size)))
    return 0U;

  if (ppd->size > SIZE_MAX - output_size)
    return 0U;
  output_size += ppd->size;
  if (options->size > SIZE_MAX - output_size)
    return 0U;
  output_size += options->size;
  if (title->size > SIZE_MAX - output_size)
    return 0U;
  output_size += title->size;
  if (document->size > SIZE_MAX - output_size)
    return 0U;
  output_size += document->size;
  if (output_size > max_output_size)
    return 0U;

  cf_v2_job_store_u32le(output, (uint32_t)ppd->size);
  cf_v2_job_store_u32le(output + 4U, (uint32_t)options->size);
  cf_v2_job_store_u32le(output + 8U, (uint32_t)title->size);
  cf_v2_job_store_u32le(output + 12U, (uint32_t)document->size);
  memcpy(output + CF_V2_JOB_HEADER_SIZE, control->data, control->size);
  offset = CF_V2_JOB_FIXED_SIZE;
  if (ppd->size)
    memcpy(output + offset, ppd->data, ppd->size);
  offset += ppd->size;
  if (options->size)
    memcpy(output + offset, options->data, options->size);
  offset += options->size;
  if (title->size)
    memcpy(output + offset, title->data, title->size);
  offset += title->size;
  memcpy(output + offset, document->data, document->size);
  return output_size;
}

#endif
