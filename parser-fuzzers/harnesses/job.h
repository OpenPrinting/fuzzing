#ifndef CUPSFILTERS_FUZZ_JOB_H
#define CUPSFILTERS_FUZZ_JOB_H

#include "control.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_FUZZ_JOB_LENGTH_FIELDS 4U
#define CF_FUZZ_JOB_HEADER_SIZE (CF_FUZZ_JOB_LENGTH_FIELDS * 4U)
#define CF_FUZZ_JOB_FIXED_SIZE (CF_FUZZ_JOB_HEADER_SIZE + CF_FUZZ_CONTROL_SIZE)
#define CF_FUZZ_JOB_PPD_PREFIX "*PPD-Adobe:"
#define CF_FUZZ_JOB_PPD_PREFIX_SIZE 11U

typedef struct cf_fuzz_job_input_s {
  cf_fuzz_control_t control;
  const uint8_t *ppd;
  size_t ppd_size;
  const uint8_t *options;
  size_t options_size;
  const uint8_t *title;
  size_t title_size;
  const uint8_t *document;
  size_t document_size;
} cf_fuzz_job_input_t;

static inline uint32_t cf_fuzz_job_load_u32le(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static inline void cf_fuzz_job_store_u32le(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
  data[2] = (uint8_t)(value >> 16);
  data[3] = (uint8_t)(value >> 24);
}

static inline int cf_fuzz_parse_job_input(
    const uint8_t *data, size_t size, size_t max_ppd, size_t max_options,
    size_t max_title, size_t max_document, cf_fuzz_job_input_t *input) {
  size_t lengths[CF_FUZZ_JOB_LENGTH_FIELDS];
  size_t offset = CF_FUZZ_JOB_FIXED_SIZE;

  if (!data || !input || size < CF_FUZZ_JOB_FIXED_SIZE) {
    return 0;
  }
  for (size_t index = 0; index < CF_FUZZ_JOB_LENGTH_FIELDS; index++) {
    lengths[index] = (size_t)cf_fuzz_job_load_u32le(data + index * 4U);
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
       (input->ppd_size < CF_FUZZ_JOB_PPD_PREFIX_SIZE ||
        memcmp(input->ppd, CF_FUZZ_JOB_PPD_PREFIX,
               CF_FUZZ_JOB_PPD_PREFIX_SIZE) != 0)) ||
      (input->options_size && memchr(input->options, 0, input->options_size))) {
    return 0;
  }
  memcpy(&input->control, data + CF_FUZZ_JOB_HEADER_SIZE, CF_FUZZ_CONTROL_SIZE);
  cf_fuzz_apply_control_policy(&input->control);
  return 1;
}

#endif
