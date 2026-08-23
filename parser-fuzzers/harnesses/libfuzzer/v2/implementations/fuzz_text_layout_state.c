// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerTestOneInput cf_v2_text_layout_direct_test_one_input
#include "fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#define CF_V2_TEXT_STATE_MAGIC "TXTSTAT1"
#define CF_V2_TEXT_STATE_MAGIC_SIZE 8U
#define CF_V2_TEXT_STATE_SELECTORS 16U
#define CF_V2_TEXT_STATE_MAX_PAYLOAD 4096U

static uint8_t
cf_v2_text_material(uint8_t value, unsigned mode)
{
  static const char punctuation[] = "{}[]()<>/*#;:'\"=+-_.,!?";

  switch (mode % 4U)
  {
    case 1:
      return (uint8_t)('a' + value % 26U);
    case 2:
      return (uint8_t)('0' + value % 10U);
    case 3:
      return (uint8_t)punctuation[value % (sizeof(punctuation) - 1U)];
    default:
      return (uint8_t)(' ' + value % 95U);
  }
}

static uint8_t *
cf_v2_build_text_document(const uint8_t selector[CF_V2_TEXT_STATE_SELECTORS],
                          const uint8_t *payload, size_t payload_size,
                          size_t *document_size)
{
  const unsigned line_width = 8U + selector[0] % 25U;
  const unsigned page_lines = 2U + selector[1] % 15U;
  const unsigned mode = selector[2];
  const size_t capacity = payload_size * 3U + 64U;
  uint8_t *document = (uint8_t *)malloc(capacity);
  size_t used = 0;
  unsigned column = 0;
  unsigned line = 0;
  size_t index;

  if (!document)
    return NULL;
  document[used ++] = 'A';
  for (index = 0; index < payload_size; index ++)
  {
    uint8_t value = cf_v2_text_material(payload[index], mode);

    if ((selector[3] & 1U) && column == line_width / 2U &&
        used + 1U < capacity)
    {
      document[used ++] = '\t';
      column = (column + 8U) & ~7U;
    }
    if ((selector[3] & 2U) && column == 2U && used + 2U < capacity)
    {
      document[used ++] = '\b';
      document[used ++] = value;
    }
    else if ((selector[3] & 4U) && column == 3U && used + 2U < capacity)
    {
      document[used ++] = 0x1bU;
      document[used ++] = (uint8_t)('7' + selector[4] % 3U);
    }
    else
    {
      document[used ++] = value;
    }
    column ++;

    if (column >= line_width || payload[index] == '\n')
    {
      document[used ++] = '\n';
      column = 0;
      line ++;
      if (line >= page_lines)
      {
        document[used ++] = (selector[5] & 1U) ? '\f' : '\n';
        line = 0;
      }
    }
  }
  if (!used || document[used - 1U] != '\n')
    document[used ++] = '\n';
  if (selector[6] & 1U)
    document[used ++] = '\f';
  *document_size = used;
  return document;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  size_t document_size = 0;
  size_t direct_size;
  uint8_t *document;
  uint8_t *direct_input;

  if (!data || size < CF_V2_TEXT_STATE_MAGIC_SIZE +
                           CF_V2_TEXT_STATE_SELECTORS + 1U ||
      size > CF_V2_TEXT_STATE_MAGIC_SIZE + CF_V2_TEXT_STATE_SELECTORS +
                 CF_V2_TEXT_STATE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_STATE_MAGIC, CF_V2_TEXT_STATE_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_TEXT_STATE_MAGIC_SIZE;
  payload = selector + CF_V2_TEXT_STATE_SELECTORS;
  payload_size = size - CF_V2_TEXT_STATE_MAGIC_SIZE -
                 CF_V2_TEXT_STATE_SELECTORS;
  document = cf_v2_build_text_document(selector, payload, payload_size,
                                       &document_size);
  if (!document)
    return 0;

  direct_size = document_size + CF_V2_CONTROL_SIZE;
  direct_input = (uint8_t *)malloc(direct_size);
  if (!direct_input)
  {
    free(document);
    return 0;
  }
  memcpy(direct_input, document, document_size);
  memcpy(direct_input + document_size, selector, CF_V2_CONTROL_SIZE);
  (void)cf_v2_text_layout_direct_test_one_input(direct_input, direct_size);
  free(direct_input);
  free(document);
  return 0;
}
