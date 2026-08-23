// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerTestOneInput cf_v2_text_title_unused_entrypoint
#include "fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_TITLE_MAGIC "TXTTIT01"
#define CF_V2_TEXT_TITLE_MAGIC_SIZE 8U
#define CF_V2_TEXT_TITLE_SELECTORS 8U
#define CF_V2_TEXT_TITLE_MAX_PAYLOAD 64U
#define CF_V2_TEXT_TITLE_MAX_SIZE 64U

static uint8_t cf_v2_text_title_ascii(uint8_t value) {
  return (uint8_t)('!' + value % 94U);
}

static size_t cf_v2_text_title_prefix(
    uint8_t *title, const uint8_t selectors[CF_V2_TEXT_TITLE_SELECTORS],
    const uint8_t *payload, size_t payload_size) {
  const size_t prefix_size = selectors[1] % 4U;

  for (size_t index = 0; index < prefix_size; index++) {
    title[index] = cf_v2_text_title_ascii(
        payload[(index + selectors[3]) % payload_size]);
  }
  return prefix_size;
}

static size_t cf_v2_text_title_build(
    uint8_t *title, const uint8_t selectors[CF_V2_TEXT_TITLE_SELECTORS],
    const uint8_t *payload, size_t payload_size) {
  const unsigned mode = selectors[0] % 8U;
  size_t used = cf_v2_text_title_prefix(title, selectors, payload,
                                        payload_size);

  switch (mode) {
    case 0U: {
      const size_t wanted = 1U + selectors[2] % 24U;
      while (used < wanted && used < CF_V2_TEXT_TITLE_MAX_SIZE) {
        title[used] = cf_v2_text_title_ascii(
            payload[(used + selectors[4]) % payload_size]);
        used++;
      }
      break;
    }
    case 1U:
      title[used++] = (uint8_t)(0xc2U + selectors[2] % 30U);
      title[used++] = (uint8_t)(0x80U + selectors[3] % 64U);
      break;
    case 2U:
      title[used++] = (uint8_t)(0xe1U + selectors[2] % 14U);
      title[used++] = (uint8_t)(0x80U + selectors[3] % 64U);
      title[used++] = (uint8_t)(0x80U + selectors[4] % 64U);
      break;
    case 3U:
      title[used++] = (uint8_t)(0xc0U + selectors[2] % 2U);
      title[used++] = (uint8_t)(0x80U + selectors[3] % 64U);
      break;
    case 4U:
      title[used++] = (uint8_t)(0xc0U + selectors[2] % 32U);
      break;
    case 5U:
      title[used++] = (uint8_t)(0xe0U + selectors[2] % 16U);
      break;
    case 6U:
      title[used++] = (uint8_t)(0xe0U + selectors[2] % 16U);
      title[used++] = (uint8_t)(0x80U + selectors[3] % 64U);
      break;
    default:
      title[used++] = (uint8_t)(0xc0U + selectors[2] % 48U);
      title[used++] = cf_v2_text_title_ascii(selectors[3]);
      break;
  }
  return used;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t options[] = "PageSize=A4 prettyprint=true";
  const uint8_t *selectors;
  const uint8_t *payload;
  size_t payload_size;
  uint8_t title[CF_V2_TEXT_TITLE_MAX_SIZE];
  static const uint8_t document[] = "A\n";
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;

  if (!data ||
      size < CF_V2_TEXT_TITLE_MAGIC_SIZE + CF_V2_TEXT_TITLE_SELECTORS + 1U ||
      size > CF_V2_TEXT_TITLE_MAGIC_SIZE + CF_V2_TEXT_TITLE_SELECTORS +
                 CF_V2_TEXT_TITLE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_TITLE_MAGIC,
             CF_V2_TEXT_TITLE_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_TEXT_TITLE_MAGIC_SIZE;
  payload = selectors + CF_V2_TEXT_TITLE_SELECTORS;
  payload_size = size - CF_V2_TEXT_TITLE_MAGIC_SIZE -
                 CF_V2_TEXT_TITLE_SELECTORS;

  memset(&job, 0, sizeof(job));
  job.options = options;
  job.options_size = sizeof(options) - 1U;
  job.title = title;
  job.title_size = cf_v2_text_title_build(title, selectors, payload,
                                          payload_size);
  job.document = document;
  job.document_size = sizeof(document) - 1U;

#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
  cf_v2_texttopdf_active = 1;
#endif
  (void)cf_v2_execute_direct_job(&job, 0, &result);
#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
  cf_v2_release_texttopdf_lifecycle();
#endif
  cf_v2_free_run_result(&result);
  return 0;
}
