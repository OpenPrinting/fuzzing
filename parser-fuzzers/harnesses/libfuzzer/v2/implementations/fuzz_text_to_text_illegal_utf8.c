// SPDX-License-Identifier: Apache-2.0
#define CF_V2_CAPTURE_TEXT_TAIL_LOGS
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_ILLEGAL_MAGIC "TXTILL01"
#define CF_V2_TEXT_ILLEGAL_MAGIC_SIZE 8U
#define CF_V2_TEXT_ILLEGAL_SELECTORS 5U
#define CF_V2_TEXT_ILLEGAL_MAX_PAYLOAD 256U
#define CF_V2_TEXT_ILLEGAL_READ_SIZE 2048U
#define CF_V2_TEXT_ILLEGAL_MAX_DOCUMENT 4608U

typedef struct cf_v2_text_illegal_case_s
{
  const uint8_t *bytes;
  size_t size;
  const uint8_t *preserved;
  size_t preserved_size;
  unsigned incomplete_prefix_mask;
} cf_v2_text_illegal_case_t;

static const uint8_t cf_v2_illegal_80[] = {0x80U};
static const uint8_t cf_v2_illegal_c0_af[] = {0xc0U, 0xafU};
static const uint8_t cf_v2_illegal_e0_80_80[] = {0xe0U, 0x80U, 0x80U};
static const uint8_t cf_v2_illegal_ed_a0_80[] = {0xedU, 0xa0U, 0x80U};
static const uint8_t cf_v2_illegal_fe[] = {0xfeU};
static const uint8_t cf_v2_illegal_ff[] = {0xffU};
static const uint8_t cf_v2_illegal_c2_a[] = {0xc2U, 'A'};
static const uint8_t cf_v2_illegal_e2_82_a[] = {0xe2U, 0x82U, 'A'};
static const uint8_t cf_v2_illegal_f0_9f_98_a[] = {
  0xf0U, 0x9fU, 0x98U, 'A'
};
static const uint8_t cf_v2_illegal_preserved_a[] = {'A'};

static const cf_v2_text_illegal_case_t cf_v2_text_illegal_cases[] = {
  {cf_v2_illegal_80, sizeof(cf_v2_illegal_80), NULL, 0U, 0U},
  {cf_v2_illegal_c0_af, sizeof(cf_v2_illegal_c0_af), NULL, 0U, 1U << 1U},
  {cf_v2_illegal_e0_80_80, sizeof(cf_v2_illegal_e0_80_80), NULL, 0U,
   (1U << 1U) | (1U << 2U)},
  {cf_v2_illegal_ed_a0_80, sizeof(cf_v2_illegal_ed_a0_80), NULL, 0U,
   (1U << 1U) | (1U << 2U)},
  {cf_v2_illegal_fe, sizeof(cf_v2_illegal_fe), NULL, 0U, 0U},
  {cf_v2_illegal_ff, sizeof(cf_v2_illegal_ff), NULL, 0U, 0U},
  {cf_v2_illegal_c2_a, sizeof(cf_v2_illegal_c2_a),
   cf_v2_illegal_preserved_a, sizeof(cf_v2_illegal_preserved_a), 1U << 1U},
  {cf_v2_illegal_e2_82_a, sizeof(cf_v2_illegal_e2_82_a),
   cf_v2_illegal_preserved_a, sizeof(cf_v2_illegal_preserved_a),
   (1U << 1U) | (1U << 2U)},
  {cf_v2_illegal_f0_9f_98_a, sizeof(cf_v2_illegal_f0_9f_98_a),
   cf_v2_illegal_preserved_a, sizeof(cf_v2_illegal_preserved_a),
   (1U << 1U) | (1U << 2U) | (1U << 3U)},
};

static int
cf_v2_text_illegal_build(const uint8_t selectors[CF_V2_TEXT_ILLEGAL_SELECTORS],
                         const uint8_t *payload, size_t payload_size,
                         uint8_t **document_data, size_t *document_size,
                         uint8_t **expected_data, size_t *expected_size,
                         const char **encoding,
                         unsigned *expected_iconv_logs)
{
  static const char *const encodings[] = {
    "ASCII", "ISO-8859-1", "CP1252", "UTF-8"
  };
  static const size_t boundaries[] = {32U, 2048U, 4096U};
  static const int deltas[] = {-3, -2, -1, 0, 1, 2};
  static const size_t recovery_sizes[] = {1U, 17U, 64U};
  const cf_v2_text_illegal_case_t *illegal =
      &cf_v2_text_illegal_cases[
          selectors[1] % (sizeof(cf_v2_text_illegal_cases) /
                          sizeof(cf_v2_text_illegal_cases[0]))];
  const size_t boundary =
      boundaries[selectors[2] % (sizeof(boundaries) / sizeof(boundaries[0]))];
  const int delta =
      deltas[selectors[3] % (sizeof(deltas) / sizeof(deltas[0]))];
  const size_t prefix_size = (size_t)((int)boundary + delta);
  const size_t recovery_size =
      recovery_sizes[selectors[4] %
                     (sizeof(recovery_sizes) / sizeof(recovery_sizes[0]))];
  const size_t output_size =
      prefix_size + illegal->preserved_size + recovery_size + 1U;
  const size_t input_size = prefix_size + illegal->size + recovery_size;
  const size_t offset_in_read = prefix_size % CF_V2_TEXT_ILLEGAL_READ_SIZE;
  const size_t bytes_before_refill =
      offset_in_read ? CF_V2_TEXT_ILLEGAL_READ_SIZE - offset_in_read
                     : CF_V2_TEXT_ILLEGAL_READ_SIZE;
  uint8_t *document;
  uint8_t *expected;
  size_t index;
  size_t expected_offset = 0U;

  if (!payload || !payload_size || prefix_size < 1U ||
      input_size > CF_V2_TEXT_ILLEGAL_MAX_DOCUMENT)
    return 0;
  document = (uint8_t *)malloc(input_size);
  expected = (uint8_t *)malloc(output_size);
  if (!document || !expected)
  {
    free(document);
    free(expected);
    return 0;
  }

  for (index = 0U; index < prefix_size; index ++)
  {
    const uint8_t value =
        (uint8_t)('A' + (payload[index % payload_size] + index * 7U) % 26U);
    document[index] = value;
    expected[expected_offset ++] = value;
  }
  memcpy(document + prefix_size, illegal->bytes, illegal->size);
  if (illegal->preserved_size)
  {
    memcpy(expected + expected_offset, illegal->preserved,
           illegal->preserved_size);
    expected_offset += illegal->preserved_size;
  }
  for (index = 0U; index < recovery_size; index ++)
  {
    const uint8_t value = (uint8_t)(
        'a' + (payload[(index * 5U + selectors[0]) % payload_size] +
               index * 11U) % 26U);
    document[prefix_size + illegal->size + index] = value;
    expected[expected_offset ++] = value;
  }
  expected[expected_offset ++] = '\n';

  *document_data = document;
  *document_size = input_size;
  *expected_data = expected;
  *expected_size = expected_offset;
  *encoding = encodings[selectors[0] %
                       (sizeof(encodings) / sizeof(encodings[0]))];
  *expected_iconv_logs =
      1U + (bytes_before_refill < illegal->size &&
            (illegal->incomplete_prefix_mask &
             (1U << bytes_before_refill)) != 0U);
  return 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_V2_TEXT_ILLEGAL_MAGIC_SIZE + CF_V2_TEXT_ILLEGAL_SELECTORS;
  const uint8_t *selectors;
  const uint8_t *payload;
  size_t payload_size;
  uint8_t *document = NULL;
  uint8_t *expected = NULL;
  size_t document_size = 0U;
  size_t expected_size = 0U;
  const char *encoding = NULL;
  unsigned expected_iconv_logs = 0U;
  unsigned observed_iconv_logs = 0U;
  unsigned observed_incomplete_logs = 0U;
  unsigned observed_illegal_logs = 0U;
  char options[512];
  static const uint8_t title[] = "text-to-text illegal UTF-8 recovery";
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  const char *failure = NULL;
  int trap_after_cleanup = 0;
  int options_size;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_ILLEGAL_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_ILLEGAL_MAGIC,
             CF_V2_TEXT_ILLEGAL_MAGIC_SIZE) != 0)
    return 0;

  selectors = data + CF_V2_TEXT_ILLEGAL_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  if (!cf_v2_text_illegal_build(
          selectors, payload, payload_size, &document, &document_size,
          &expected, &expected_size, &encoding, &expected_iconv_logs))
    return 0;

  options_size = snprintf(
      options, sizeof(options),
      "PageWidth=8192 PageHeight=2 PageLeft=0 PageRight=0 PageTop=0 "
      "PageBottom=0 PrinterEncoding=%s OverLongLines=wrap-at-width "
      "TabWidth=8 Pagination=false SendFF=false NewlineCharacters=lf "
      "page-ranges=1-99 page-set=all OutputOrder=normal Collate=true",
      encoding);
  if (options_size < 0 || (size_t)options_size >= sizeof(options))
    goto cleanup;

  memset(&job, 0, sizeof(job));
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_size;
  job.title = title;
  job.title_size = sizeof(title) - 1U;
  job.document = document;
  job.document_size = document_size;
  memset(&result, 0, sizeof(result));

  executed = cf_v2_execute_direct_job(&job, 1, &result);
  if (!executed)
    goto cleanup;
  observed_iconv_logs = result.text_iconv_log_count;
  observed_incomplete_logs = result.text_incomplete_log_count;
  observed_illegal_logs = result.text_illegal_log_count;
  if (!result.captured)
    failure = "capture";
  else if (result.status != 0)
    failure = "filter-status";
  else if (result.text_iconv_log_count != expected_iconv_logs)
    failure = "iconv-log-count";
  else if (result.text_incomplete_log_count != 0U)
    failure = "unexpected-incomplete-log";
  else if (result.text_illegal_log_count != 0U)
    failure = "unexpected-explicit-illegal-log";
  else if (result.output_size != expected_size)
    failure = "output-size";
  else if (expected_size &&
           memcmp(result.output, expected, expected_size) != 0)
    failure = "output-bytes";
  trap_after_cleanup = failure != NULL;
  cf_v2_free_run_result(&result);

cleanup:
  free(document);
  free(expected);
  if (trap_after_cleanup)
  {
    fprintf(stderr,
            "text-illegal-utf8-oracle: %s iconv=%u/%u incomplete=%u "
            "illegal=%u\n",
            failure, observed_iconv_logs, expected_iconv_logs,
            observed_incomplete_logs, observed_illegal_logs);
    __builtin_trap();
  }
  return 0;
}
