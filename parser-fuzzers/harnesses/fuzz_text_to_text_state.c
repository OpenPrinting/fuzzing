#include "direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CF_FUZZ_TEXT_TO_TEXT_MAGIC "TXT2TXT1"
#define CF_FUZZ_TEXT_TO_TEXT_MAGIC_SIZE 8U
#define CF_FUZZ_TEXT_TO_TEXT_SELECTORS 16U
#define CF_FUZZ_TEXT_TO_TEXT_MAX_PAYLOAD 4096U
#define CF_FUZZ_TEXT_TO_TEXT_CHUNK_BOUNDARY 2047U

static int
cf_fuzz_text_to_text_append(uint8_t *document, size_t capacity, size_t *used,
                          const uint8_t *material, size_t material_size)
{
  if (material_size > capacity - *used)
    return 0;
  memcpy(document + *used, material, material_size);
  *used += material_size;
  return 1;
}

static int
cf_fuzz_text_to_text_append_byte(uint8_t *document, size_t capacity,
                               size_t *used, uint8_t value)
{
  return cf_fuzz_text_to_text_append(document, capacity, used, &value, 1U);
}

static void
cf_fuzz_text_to_text_control(const uint8_t *selector,
                           cf_fuzz_control_t *control)
{
  control->ppd_profile = selector[0];
  control->page_size = selector[1];
  control->color_model = selector[2];
  control->resolution = selector[3];
  control->sides = selector[4];
  control->orientation = selector[5];
  control->scaling = selector[6];
  control->copies = selector[7];
  control->number_up = selector[8];
  control->position = selector[9];
  control->quality = selector[10];
  control->output_order = selector[11];
  control->media_type = selector[12];
  control->mirror = selector[13];
  control->route_mode = selector[14];
  control->reserved = selector[15];
}

static uint8_t *
cf_fuzz_build_text_to_text_document(
    const uint8_t selector[CF_FUZZ_TEXT_TO_TEXT_SELECTORS],
    const uint8_t *payload, size_t payload_size,
    const cf_fuzz_texttotext_state_t *state, size_t *document_size)
{
  static const uint8_t euro[] = {0xe2U, 0x82U, 0xacU};
  static const uint8_t smile[] = {0xf0U, 0x9fU, 0x98U, 0x80U};
  static const uint8_t latin_e_acute[] = {0xc3U, 0xa9U};
  static const uint8_t ascii_z[] = {'Z'};
  const unsigned stream_mode = (selector[15] >> 1U) % 4U;
  const int word_wrap = strcmp(state->overlong, "word-wrap") == 0;
  const unsigned word_limit = word_wrap ? 1U :
      cf_fuzz_texttotext_min(state->text_width > 1U ? state->text_width - 1U
                                                  : 1U,
                            7U);
  const size_t capacity = payload_size * 5U + 2304U;
  uint8_t *document = (uint8_t *)malloc(capacity);
  const uint8_t *stream_character = ascii_z;
  size_t stream_character_size = sizeof(ascii_z);
  size_t used = 0;
  unsigned word_bytes = 0;
  size_t index;

  if (!document)
    return NULL;
  if (strcmp(state->encoding, "UTF-8") == 0)
  {
    stream_character = stream_mode == 2U ? smile : euro;
    stream_character_size = stream_mode == 2U ? sizeof(smile) : sizeof(euro);
  }
  else if (strcmp(state->encoding, "ISO-8859-1") == 0)
  {
    stream_character = latin_e_acute;
    stream_character_size = sizeof(latin_e_acute);
  }
  else if (strcmp(state->encoding, "CP1252") == 0)
  {
    stream_character = euro;
    stream_character_size = sizeof(euro);
  }
  if (!cf_fuzz_text_to_text_append(document, capacity, &used,
                                 (const uint8_t *)"A ", 2U))
    goto fail;

  if (stream_mode == 1U || stream_mode == 2U)
  {
    while (used < CF_FUZZ_TEXT_TO_TEXT_CHUNK_BOUNDARY)
    {
      uint8_t value = word_bytes >= word_limit ? (uint8_t)' ' :
                      (uint8_t)('a' + used % 26U);
      if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used, value))
        goto fail;
      word_bytes = value == ' ' ? 0U : word_bytes + 1U;
    }
    if (!cf_fuzz_text_to_text_append(document, capacity, &used,
                                   stream_character,
                                   stream_character_size))
      goto fail;
    word_bytes += stream_character_size;
  }

  for (index = 0; index < payload_size; index ++)
  {
    const uint8_t value = payload[index];

    if (value % 53U == 0U && state->pagination[0] == 't' &&
        used && document[used - 1U] != '\f')
    {
      if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used, '\f') ||
          !cf_fuzz_text_to_text_append(document, capacity, &used,
                                     (const uint8_t *)"P ", 2U))
        goto fail;
      word_bytes = 0;
    }
    else if (value % 31U == 0U)
    {
      /* Tab expansion can move a partial word to a fresh line and enter the
       * already-known first-word under-read. Keep tab and word-wrap as
       * separate state blocks so this lane can continue past that root. */
      if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used,
                                          word_wrap ? ' ' : '\t'))
        goto fail;
      word_bytes = 0;
    }
    else if (value % 29U == 0U)
    {
      static const uint8_t crlf[] = {'\r', '\n'};
      const uint8_t newline = selector[13] % 3U == 0U ? '\n' : '\r';

      if (selector[13] % 3U == 2U)
      {
        if (!cf_fuzz_text_to_text_append(document, capacity, &used, crlf,
                                       sizeof(crlf)))
          goto fail;
      }
      else if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used,
                                               newline))
        goto fail;
      word_bytes = 0;
    }
    else
    {
      const int use_multibyte =
          stream_mode == 3U && !word_wrap && stream_character_size > 1U &&
          (value & 7U) == 0U;

      if (word_bytes >= word_limit)
      {
        if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used, ' '))
          goto fail;
        word_bytes = 0;
      }
      if (use_multibyte)
      {
        if (!cf_fuzz_text_to_text_append(document, capacity, &used,
                                       stream_character,
                                       stream_character_size))
          goto fail;
        word_bytes += stream_character_size;
      }
      else
      {
        const uint8_t glyph = (uint8_t)('!' + value % 94U);
        if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used, glyph))
          goto fail;
        word_bytes ++;
      }
    }
  }

  if (!used || (document[used - 1U] != '\n' && document[used - 1U] != '\r'))
    if (!cf_fuzz_text_to_text_append_byte(document, capacity, &used, '\n'))
      goto fail;
  *document_size = used;
  return document;

fail:
  free(document);
  return NULL;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_FUZZ_TEXT_TO_TEXT_MAGIC_SIZE + CF_FUZZ_TEXT_TO_TEXT_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  cf_fuzz_control_t control;
  cf_fuzz_texttotext_state_t state;
  cf_fuzz_run_result_t result;
  uint8_t *document;
  size_t document_size = 0;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_FUZZ_TEXT_TO_TEXT_MAX_PAYLOAD ||
      memcmp(data, CF_FUZZ_TEXT_TO_TEXT_MAGIC,
             CF_FUZZ_TEXT_TO_TEXT_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_FUZZ_TEXT_TO_TEXT_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  cf_fuzz_text_to_text_control(selector, &control);
  cf_fuzz_decode_texttotext_state(&control, &state);
  document = cf_fuzz_build_text_to_text_document(
      selector, payload, payload_size, &state, &document_size);
  if (!document)
    return 0;

  (void)cf_fuzz_execute_direct(document, document_size, &control, 1, &result);
  cf_fuzz_free_run_result(&result);
  free(document);
  return 0;
}
