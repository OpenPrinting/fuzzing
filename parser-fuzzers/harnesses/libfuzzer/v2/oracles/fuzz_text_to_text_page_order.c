// SPDX-License-Identifier: Apache-2.0
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef CF_V2_TEXTTOTEXT_PAGE_ARRAY_BOUNDARY
#define CF_V2_TEXT_ORDER_MAGIC "TXTPAGE1"
#else
#define CF_V2_TEXT_ORDER_MAGIC "TXTSEL01"
#endif

#define CF_V2_TEXT_ORDER_MAGIC_SIZE 8U
#define CF_V2_TEXT_ORDER_SELECTORS 16U
#define CF_V2_TEXT_ORDER_MAX_PAYLOAD 256U
#define CF_V2_TEXT_ORDER_PAGES 4U

static int
cf_v2_text_order_range_selected(unsigned range, unsigned page)
{
  static const uint8_t selected[7][CF_V2_TEXT_ORDER_PAGES] = {
      {1, 0, 0, 0},
      {1, 1, 0, 0},
      {0, 1, 1, 0},
      {1, 1, 1, 1},
      {0, 1, 1, 1},
      {1, 0, 1, 0},
      {1, 1, 1, 1},
  };

  return page >= 1U && page <= CF_V2_TEXT_ORDER_PAGES &&
         selected[range % 7U][page - 1U];
}

static int
cf_v2_text_order_set_selected(unsigned page_set, unsigned page)
{
  if (page_set % 3U == 1U)
    return page & 1U;
  if (page_set % 3U == 2U)
    return !(page & 1U);
  return 1;
}

static uint8_t *
cf_v2_text_order_document(const uint8_t *payload, size_t payload_size,
                          size_t *document_size)
{
  const size_t capacity = CF_V2_TEXT_ORDER_PAGES * 16U;
  uint8_t *document = (uint8_t *)malloc(capacity);
  size_t used = 0;
  unsigned page;

  if (!document)
    return NULL;
  for (page = 0; page < CF_V2_TEXT_ORDER_PAGES; page ++)
  {
    const uint8_t material = payload[page % payload_size];
    const unsigned body_size = 1U + material % 6U;
    unsigned index;

    document[used ++] = (uint8_t)('A' + page);
    for (index = 0; index < body_size; index ++)
      document[used ++] =
          (uint8_t)('a' + (material + index * 7U + page * 11U) % 26U);
    document[used ++] = '\n';
    if (page + 1U < CF_V2_TEXT_ORDER_PAGES)
      document[used ++] = '\f';
  }
  *document_size = used;
  return document;
}

static void
cf_v2_text_order_control(const uint8_t *selector, cf_v2_control_t *control)
{
  memset(control, 0, sizeof(*control));
  control->page_size = 8U;
  control->sides = 0U;
  control->position = 4U;
  control->number_up = selector[0] % 7U;
  control->ppd_profile = selector[1] % 3U;
  control->mirror = selector[2] % 3U;
  control->route_mode = 3U;

#ifdef CF_V2_TEXTTOTEXT_PAGE_ARRAY_BOUNDARY
  control->number_up = 6U;
  control->ppd_profile = 0U;
  if (selector[3] & 1U)
  {
    control->copies = 0U;
    control->output_order = 1U;
    control->reserved = 0U;
  }
  else
  {
    control->copies = 1U;
    control->output_order = 0U;
    control->reserved = 1U;
  }
#endif
}

static size_t
cf_v2_text_order_expected(const uint8_t *selector, uint8_t *markers)
{
  size_t count = 0;
  unsigned page;

#ifdef CF_V2_TEXTTOTEXT_PAGE_ARRAY_BOUNDARY
  if (selector[3] & 1U)
  {
    for (page = CF_V2_TEXT_ORDER_PAGES; page >= 1U; page --)
      markers[count ++] = (uint8_t)('A' + page - 1U);
  }
  else
  {
    unsigned copy;
    for (copy = 0; copy < 2U; copy ++)
      for (page = 1U; page <= CF_V2_TEXT_ORDER_PAGES; page ++)
        markers[count ++] = (uint8_t)('A' + page - 1U);
  }
#else
  for (page = 1U; page <= CF_V2_TEXT_ORDER_PAGES; page ++)
    if (cf_v2_text_order_range_selected(selector[0], page) &&
        cf_v2_text_order_set_selected(selector[1], page))
      markers[count ++] = (uint8_t)('A' + page - 1U);
#endif
  return count;
}

static size_t
cf_v2_text_order_actual(const cf_v2_run_result_t *result, uint8_t *markers,
                        size_t capacity)
{
  size_t count = 0;
  size_t index;

  for (index = 0; index < result->output_size; index ++)
    if (result->output[index] >= 'A' && result->output[index] <= 'D')
    {
      if (count == capacity)
        return capacity + 1U;
      markers[count ++] = result->output[index];
    }
  return count;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_V2_TEXT_ORDER_MAGIC_SIZE + CF_V2_TEXT_ORDER_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  size_t document_size = 0;
  uint8_t expected[CF_V2_TEXT_ORDER_PAGES * 2U];
  uint8_t actual[CF_V2_TEXT_ORDER_PAGES * 2U];
  size_t expected_count;
  size_t actual_count;
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  uint8_t *document;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_ORDER_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_ORDER_MAGIC,
             CF_V2_TEXT_ORDER_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_TEXT_ORDER_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  document = cf_v2_text_order_document(payload, payload_size, &document_size);
  if (!document)
    return 0;

  cf_v2_text_order_control(selector, &control);
  executed =
      cf_v2_execute_direct(document, document_size, &control, 1, &result);
  if (executed && result.captured && result.status == 0)
  {
    expected_count = cf_v2_text_order_expected(selector, expected);
    actual_count = cf_v2_text_order_actual(&result, actual, sizeof(actual));
    if (actual_count != expected_count ||
        (actual_count && memcmp(actual, expected, actual_count) != 0))
      __builtin_trap();
  }

  cf_v2_free_run_result(&result);
  free(document);
  return 0;
}
