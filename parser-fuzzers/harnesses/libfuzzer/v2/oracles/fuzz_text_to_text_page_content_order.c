// SPDX-License-Identifier: Apache-2.0
#define CF_V2_CAPTURE_PAGE_LOGS 1
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_PAGE_CONTENT_MAGIC "TXTORD01"
#define CF_V2_TEXT_PAGE_CONTENT_MAGIC_SIZE 8U
#define CF_V2_TEXT_PAGE_CONTENT_SELECTORS 8U
#define CF_V2_TEXT_PAGE_CONTENT_MAX_PAYLOAD 128U
#define CF_V2_TEXT_PAGE_CONTENT_MAX_PAGES 6U

typedef struct cf_v2_text_page_buffer_s
{
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v2_text_page_buffer_t;

static const char *const cf_v2_text_page_ranges[] = {
  "1-1", "1-2", "2-3", "1-4", "2-4", "1,3", "1-99", "2,4-6",
  "-2", "3-", ""
};

static const char *const cf_v2_text_page_sets[] = {"all", "odd", "even"};
static const char *const cf_v2_text_page_newline_names[] = {"lf", "cr", "crlf"};
static const char *const cf_v2_text_page_newlines[] = {"\n", "\r", "\r\n"};
static const size_t cf_v2_text_page_body_sizes[] = {
  1U, 2U, 3U, 4U, 7U, 8U, 15U, 16U
};

static int
cf_v2_text_page_append(cf_v2_text_page_buffer_t *buffer,
                       const uint8_t *data, size_t size)
{
  if (!buffer || !data || buffer->size > buffer->capacity ||
      size > buffer->capacity - buffer->size)
    return 0;
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int
cf_v2_text_page_append_byte(cf_v2_text_page_buffer_t *buffer, uint8_t value)
{
  return cf_v2_text_page_append(buffer, &value, 1U);
}

static int
cf_v2_text_page_range_selected(unsigned range, unsigned page)
{
  switch (range % 11U)
  {
    case 0U:
      return page == 1U;
    case 1U:
      return page <= 2U;
    case 2U:
      return page >= 2U && page <= 3U;
    case 3U:
      return page <= 4U;
    case 4U:
      return page >= 2U && page <= 4U;
    case 5U:
      return page == 1U || page == 3U;
    case 6U:
      return 1;
    case 7U:
      return page == 2U || (page >= 4U && page <= 6U);
    case 8U:
      return page <= 2U;
    case 9U:
      return page >= 3U;
    default:
      return 1;
  }
}

static int
cf_v2_text_page_set_selected(unsigned page_set, unsigned page)
{
  if (page_set % 3U == 1U)
    return page & 1U;
  if (page_set % 3U == 2U)
    return !(page & 1U);
  return 1;
}

static uint8_t
cf_v2_text_page_material(const uint8_t *payload, size_t payload_size,
                         unsigned pattern, unsigned page, size_t offset)
{
  const uint8_t value = payload[(offset + page * 17U + pattern * 29U) %
                                payload_size];

  switch (pattern % 6U)
  {
    case 0U:
      return (uint8_t)('a' + value % 26U);
    case 1U:
      return (uint8_t)('0' + value % 10U);
    case 2U:
      return (uint8_t)('a' + (offset + page) % 26U);
    case 3U:
      return offset & 1U ? 'x' : 'y';
    case 4U:
      return (uint8_t)('a' + (value ^ (uint8_t)offset) % 26U);
    default:
      return (uint8_t)('0' + (value + offset + page) % 10U);
  }
}

static int
cf_v2_text_page_build(const uint8_t *selector, const uint8_t *payload,
                      size_t payload_size, uint8_t **document_data,
                      size_t *document_size, uint8_t **expected_data,
                      size_t *expected_size)
{
  const unsigned range = selector[0] % 11U;
  const unsigned page_set = selector[1] % 3U;
  const unsigned newline = selector[3] % 3U;
  const unsigned pages = 1U + selector[4] % CF_V2_TEXT_PAGE_CONTENT_MAX_PAGES;
  const unsigned pattern = selector[7] % 6U;
  const size_t body_size =
      cf_v2_text_page_body_sizes[selector[6] %
                                 (sizeof(cf_v2_text_page_body_sizes) /
                                  sizeof(cf_v2_text_page_body_sizes[0]))];
  const size_t capacity = pages * (body_size + 8U);
  cf_v2_text_page_buffer_t document = {NULL, 0, capacity};
  cf_v2_text_page_buffer_t expected = {NULL, 0, capacity};
  unsigned page;

  document.data = (uint8_t *)malloc(capacity);
  expected.data = (uint8_t *)malloc(capacity);
  if (!document.data || !expected.data)
    goto fail;

  for (page = 1U; page <= pages; page ++)
  {
    const int selected =
        cf_v2_text_page_range_selected(range, page) &&
        cf_v2_text_page_set_selected(page_set, page);
    const uint8_t marker = (uint8_t)('A' + page - 1U);
    size_t index;

    if (!cf_v2_text_page_append_byte(&document, marker) ||
        !cf_v2_text_page_append_byte(&document, ':'))
      goto fail;
    if (selected &&
        (!cf_v2_text_page_append_byte(&expected, marker) ||
         !cf_v2_text_page_append_byte(&expected, ':')))
      goto fail;

    for (index = 0; index < body_size; index ++)
    {
      const uint8_t value = cf_v2_text_page_material(
          payload, payload_size, pattern, page, index);

      if (!cf_v2_text_page_append_byte(&document, value) ||
          (selected && !cf_v2_text_page_append_byte(&expected, value)))
        goto fail;
    }
    if (!cf_v2_text_page_append_byte(&document, '\n'))
      goto fail;
    if (selected &&
        (!cf_v2_text_page_append(
             &expected, (const uint8_t *)cf_v2_text_page_newlines[newline],
             strlen(cf_v2_text_page_newlines[newline])) ||
         !cf_v2_text_page_append_byte(&expected, '\f')))
      goto fail;
    if (page < pages && !cf_v2_text_page_append_byte(&document, '\f'))
      goto fail;
  }

  *document_data = document.data;
  *document_size = document.size;
  *expected_data = expected.data;
  *expected_size = expected.size;
  return 1;

fail:
  free(document.data);
  free(expected.data);
  return 0;
}

static int
cf_v2_text_page_logs_match(const cf_v2_run_result_t *result,
                           const uint8_t *selector, unsigned copies)
{
  const unsigned range = selector[0] % 11U;
  const unsigned page_set = selector[1] % 3U;
  const unsigned pages = 1U + selector[4] % CF_V2_TEXT_PAGE_CONTENT_MAX_PAGES;
  unsigned expected_index = 0;
  unsigned page;

  if (result->page_log_overflow)
    return 0;
  for (page = 1U; page <= pages; page ++)
    if (cf_v2_text_page_range_selected(range, page) &&
        cf_v2_text_page_set_selected(page_set, page))
    {
      if (expected_index >= result->page_log_count ||
          result->page_log_page[expected_index] != expected_index + 1U ||
          result->page_log_copies[expected_index] != copies)
        return 0;
      expected_index ++;
    }
  return result->page_log_count == expected_index;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_V2_TEXT_PAGE_CONTENT_MAGIC_SIZE + CF_V2_TEXT_PAGE_CONTENT_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  uint8_t *document = NULL;
  uint8_t *expected = NULL;
  size_t document_size = 0;
  size_t expected_size = 0;
  char options[512];
  static const uint8_t title[] = "text-to-text page content order oracle";
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  const unsigned range = data && size >= fixed_size ? data[8] % 11U : 0U;
  const unsigned page_set = data && size >= fixed_size ? data[9] % 3U : 0U;
  const unsigned copies = data && size >= fixed_size ? 1U + data[10] % 4U : 1U;
  const unsigned newline = data && size >= fixed_size ? data[11] % 3U : 0U;
  int options_size;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_PAGE_CONTENT_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_PAGE_CONTENT_MAGIC,
             CF_V2_TEXT_PAGE_CONTENT_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_TEXT_PAGE_CONTENT_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  if (!cf_v2_text_page_build(selector, payload, payload_size, &document,
                             &document_size, &expected, &expected_size))
    return 0;

  options_size = snprintf(
      options, sizeof(options),
      "PageWidth=132 PageHeight=8 PageLeft=0 PageRight=0 PageTop=0 "
      "PageBottom=0 PrinterEncoding=UTF-8 OverLongLines=wrap-at-width "
      "TabWidth=8 Pagination=true SendFF=true NewlineCharacters=%s "
      "page-ranges=%s page-set=%s OutputOrder=normal Collate=%s",
      cf_v2_text_page_newline_names[newline], cf_v2_text_page_ranges[range],
      cf_v2_text_page_sets[page_set],
      copies == 1U && (selector[5] & 1U) ? "true" : "false");
  if (options_size < 0 || (size_t)options_size >= sizeof(options))
    goto cleanup;

  memset(&job, 0, sizeof(job));
  job.control.copies = (uint8_t)(copies - 1U);
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_size;
  job.title = title;
  job.title_size = sizeof(title) - 1U;
  job.document = document;
  job.document_size = document_size;
  memset(&result, 0, sizeof(result));
  executed = cf_v2_execute_direct_job(&job, 1, &result);
  if (executed && result.captured &&
      (result.status != 0 || result.output_size != expected_size ||
       !cf_v2_text_page_logs_match(&result, selector, copies) ||
       (expected_size &&
        memcmp(result.output, expected, expected_size) != 0)))
    __builtin_trap();
  cf_v2_free_run_result(&result);

cleanup:
  free(document);
  free(expected);
  return 0;
}
