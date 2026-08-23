// SPDX-License-Identifier: Apache-2.0
#define CF_V2_CAPTURE_TEXT_TAIL_LOGS
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_TAIL_MAGIC "TXTTAIL1"
#define CF_V2_TEXT_TAIL_MAGIC_SIZE 8U
#define CF_V2_TEXT_TAIL_SELECTORS 5U
#define CF_V2_TEXT_TAIL_MAX_PAYLOAD 256U
#define CF_V2_TEXT_TAIL_MAX_DOCUMENT 4608U

typedef struct cf_v2_text_tail_s
{
  const uint8_t *bytes;
  size_t size;
} cf_v2_text_tail_t;

static const uint8_t cf_v2_tail_c2[] = {0xc2U};
static const uint8_t cf_v2_tail_e2[] = {0xe2U};
static const uint8_t cf_v2_tail_e2_82[] = {0xe2U, 0x82U};
static const uint8_t cf_v2_tail_f0[] = {0xf0U};
static const uint8_t cf_v2_tail_f0_9f[] = {0xf0U, 0x9fU};
static const uint8_t cf_v2_tail_f0_9f_98[] = {0xf0U, 0x9fU, 0x98U};

static const cf_v2_text_tail_t cf_v2_text_tails[] = {
  {cf_v2_tail_c2, sizeof(cf_v2_tail_c2)},
  {cf_v2_tail_e2, sizeof(cf_v2_tail_e2)},
  {cf_v2_tail_e2_82, sizeof(cf_v2_tail_e2_82)},
  {cf_v2_tail_f0, sizeof(cf_v2_tail_f0)},
  {cf_v2_tail_f0_9f, sizeof(cf_v2_tail_f0_9f)},
  {cf_v2_tail_f0_9f_98, sizeof(cf_v2_tail_f0_9f_98)},
};

static int
cf_v2_text_tail_is_incomplete_prefix(const uint8_t *tail, size_t size)
{
  size_t index;

  for (index = 0U;
       index < sizeof(cf_v2_text_tails) / sizeof(cf_v2_text_tails[0]);
       index ++)
    if (size == cf_v2_text_tails[index].size &&
        memcmp(tail, cf_v2_text_tails[index].bytes, size) == 0)
      return 1;
  return 0;
}

static int
cf_v2_text_tail_build(const uint8_t selectors[CF_V2_TEXT_TAIL_SELECTORS],
                      const uint8_t *payload, size_t payload_size,
                      uint8_t **document_data, size_t *document_size,
                      uint8_t **expected_data, size_t *expected_size,
                      const char **encoding,
                      unsigned *expected_incomplete_logs)
{
  static const char *const encodings[] = {
    "ASCII", "ISO-8859-1", "CP1252", "UTF-8"
  };
  static const size_t boundaries[] = {32U, 2048U, 4096U};
  static const int deltas[] = {-3, -2, -1, 0, 1, 2};
  static const size_t line_periods[] = {17U, 31U, 63U, 79U};
  const cf_v2_text_tail_t *tail =
      &cf_v2_text_tails[selectors[3] %
                        (sizeof(cf_v2_text_tails) /
                         sizeof(cf_v2_text_tails[0]))];
  const size_t boundary =
      boundaries[selectors[1] %
                 (sizeof(boundaries) / sizeof(boundaries[0]))];
  const int delta =
      deltas[selectors[2] % (sizeof(deltas) / sizeof(deltas[0]))];
  const size_t prefix_size = (size_t)((int)boundary + delta);
  const size_t line_period =
      line_periods[selectors[4] %
                   (sizeof(line_periods) / sizeof(line_periods[0]))];
  uint8_t *document;
  uint8_t *expected;
  size_t index;
  size_t output_size = prefix_size;

  if (!payload || !payload_size || prefix_size < 1U ||
      prefix_size + tail->size > CF_V2_TEXT_TAIL_MAX_DOCUMENT ||
      !cf_v2_text_tail_is_incomplete_prefix(tail->bytes, tail->size))
    return 0;

  document = (uint8_t *)malloc(prefix_size + tail->size);
  expected = (uint8_t *)malloc(prefix_size + 1U);
  if (!document || !expected)
  {
    free(document);
    free(expected);
    return 0;
  }

  for (index = 0U; index < prefix_size; index ++)
  {
    uint8_t value;

    if ((index + 1U) % line_period == 0U)
      value = '\n';
    else
      value = (uint8_t)('A' +
                        (payload[index % payload_size] + index * 7U) % 26U);
    document[index] = value;
    expected[index] = value;
  }
  memcpy(document + prefix_size, tail->bytes, tail->size);
  if (expected[prefix_size - 1U] != '\n')
    expected[output_size ++] = '\n';

  *document_data = document;
  *document_size = prefix_size + tail->size;
  *expected_data = expected;
  *expected_size = output_size;
  *encoding = encodings[selectors[0] %
                       (sizeof(encodings) / sizeof(encodings[0]))];
  {
    const size_t read_offset = prefix_size % 2048U;
    *expected_incomplete_logs =
        read_offset > 0U && read_offset + tail->size <= 2048U ? 1U : 0U;
  }
  return 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_V2_TEXT_TAIL_MAGIC_SIZE + CF_V2_TEXT_TAIL_SELECTORS;
  const uint8_t *selectors;
  const uint8_t *payload;
  size_t payload_size;
  uint8_t *document = NULL;
  uint8_t *expected = NULL;
  size_t document_size = 0U;
  size_t expected_size = 0U;
  const char *encoding = NULL;
  unsigned expected_incomplete_logs = 0U;
  char options[512];
  static const uint8_t title[] = "text-to-text incomplete encoding tail";
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  int options_size;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_TAIL_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_TAIL_MAGIC,
             CF_V2_TEXT_TAIL_MAGIC_SIZE) != 0)
    return 0;

  selectors = data + CF_V2_TEXT_TAIL_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  if (!cf_v2_text_tail_build(selectors, payload, payload_size, &document,
                             &document_size, &expected, &expected_size,
                             &encoding, &expected_incomplete_logs))
    return 0;

  options_size = snprintf(
      options, sizeof(options),
      "PageWidth=132 PageHeight=66 PageLeft=0 PageRight=0 PageTop=0 "
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
  if (executed &&
      (!result.captured || result.status != 0 ||
       result.text_iconv_log_count == 0U ||
       result.text_incomplete_log_count != expected_incomplete_logs ||
       result.text_illegal_log_count != 0U ||
       result.output_size != expected_size ||
       (expected_size && memcmp(result.output, expected, expected_size) != 0)))
    __builtin_trap();
  cf_v2_free_run_result(&result);

cleanup:
  free(document);
  free(expected);
  return 0;
}
