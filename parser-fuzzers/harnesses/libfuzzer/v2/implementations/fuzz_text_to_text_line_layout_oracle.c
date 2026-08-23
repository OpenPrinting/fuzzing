// SPDX-License-Identifier: Apache-2.0
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_LINE_MAGIC "TXTLAY01"
#define CF_V2_TEXT_LINE_MAGIC_SIZE 8U
#define CF_V2_TEXT_LINE_SELECTORS 8U
#define CF_V2_TEXT_LINE_MAX_PAYLOAD 256U

typedef struct cf_v2_text_line_buffer_s
{
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v2_text_line_buffer_t;

typedef enum cf_v2_text_line_mode_e
{
  CF_V2_TEXT_LINE_TRUNCATE,
  CF_V2_TEXT_LINE_WORD_WRAP,
  CF_V2_TEXT_LINE_WRAP_AT_WIDTH
} cf_v2_text_line_mode_t;

typedef struct cf_v2_text_line_model_s
{
  cf_v2_text_line_buffer_t output;
  uint8_t line[128];
  size_t line_size;
  size_t width;
  size_t left_margin;
  size_t tab_width;
  const uint8_t *newline;
  size_t newline_size;
  cf_v2_text_line_mode_t mode;
  int line_started;
  int skip_rest_of_line;
  int skip_spaces;
} cf_v2_text_line_model_t;

static int
cf_v2_text_line_reserve(cf_v2_text_line_buffer_t *buffer, size_t extra)
{
  size_t capacity;
  uint8_t *replacement;

  if (!buffer || extra > SIZE_MAX - buffer->size)
    return 0;
  if (buffer->size + extra <= buffer->capacity)
    return 1;
  capacity = buffer->capacity ? buffer->capacity : 256U;
  while (capacity < buffer->size + extra)
  {
    if (capacity > SIZE_MAX / 2U)
      return 0;
    capacity *= 2U;
  }
  replacement = (uint8_t *)realloc(buffer->data, capacity);
  if (!replacement)
    return 0;
  buffer->data = replacement;
  buffer->capacity = capacity;
  return 1;
}

static int
cf_v2_text_line_append(cf_v2_text_line_buffer_t *buffer,
                       const uint8_t *data, size_t size)
{
  if (!size)
    return 1;
  if (!data || !cf_v2_text_line_reserve(buffer, size))
    return 0;
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int
cf_v2_text_line_append_byte(cf_v2_text_line_buffer_t *buffer, uint8_t value)
{
  return cf_v2_text_line_append(buffer, &value, 1U);
}

static int
cf_v2_text_line_emit(cf_v2_text_line_model_t *model)
{
  static const uint8_t spaces[16] = {
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
  };
  size_t content_size;

  if (!model)
    return 0;
  content_size = model->line_size;
  while (content_size && model->line[content_size - 1U] == ' ')
    content_size --;
  if (content_size &&
      (!cf_v2_text_line_append(&model->output, spaces, model->left_margin) ||
       !cf_v2_text_line_append(&model->output, model->line, content_size)))
    return 0;
  if (!cf_v2_text_line_append(&model->output, model->newline,
                              model->newline_size))
    return 0;
  model->line_size = 0;
  model->line_started = 0;
  return 1;
}

static int
cf_v2_text_line_wrap_before(cf_v2_text_line_model_t *model, uint8_t current)
{
  size_t split;
  size_t prefix_size;
  size_t carry_start;
  size_t carry_size;
  uint8_t carry[128];

  if (model->line_size < model->width)
    return 1;
  if (model->mode == CF_V2_TEXT_LINE_TRUNCATE)
  {
    model->skip_rest_of_line = 1;
    return 1;
  }
  if (model->mode != CF_V2_TEXT_LINE_WORD_WRAP)
    return cf_v2_text_line_emit(model);

  if (current <= ' ')
  {
    model->skip_spaces = 1;
    return cf_v2_text_line_emit(model);
  }

  split = model->line_size;
  while (split && model->line[split - 1U] != ' ')
    split --;
  if (!split || split == model->line_size)
    return cf_v2_text_line_emit(model);

  prefix_size = split - 1U;
  while (prefix_size && model->line[prefix_size - 1U] == ' ')
    prefix_size --;
  if (!prefix_size)
    return cf_v2_text_line_emit(model);

  carry_start = split;
  carry_size = model->line_size - carry_start;
  memcpy(carry, model->line + carry_start, carry_size);
  model->line_size = prefix_size;
  if (!cf_v2_text_line_emit(model))
    return 0;
  memcpy(model->line, carry, carry_size);
  model->line_size = carry_size;
  model->skip_spaces = 0;
  return 1;
}

static int
cf_v2_text_line_regular(cf_v2_text_line_model_t *model, uint8_t value)
{
  if (!cf_v2_text_line_wrap_before(model, value))
    return 0;
  model->line_started = 1;
  if (model->skip_rest_of_line)
    return 1;
  if (model->line_size >= sizeof(model->line))
    return 0;
  model->line[model->line_size ++] = value;
  model->skip_spaces = 0;
  return 1;
}

static int
cf_v2_text_line_space(cf_v2_text_line_model_t *model)
{
  if (!cf_v2_text_line_wrap_before(model, ' '))
    return 0;
  model->line_started = 1;
  if (model->skip_rest_of_line || model->skip_spaces)
    return 1;
  if (model->line_size >= sizeof(model->line))
    return 0;
  model->line[model->line_size ++] = ' ';
  return 1;
}

static int
cf_v2_text_line_tab(cf_v2_text_line_model_t *model)
{
  if (!cf_v2_text_line_wrap_before(model, '\t'))
    return 0;
  model->line_started = 1;
  if (model->skip_rest_of_line || model->skip_spaces)
    return 1;
  if (model->line_size >= sizeof(model->line))
    return 0;
  model->line[model->line_size ++] = ' ';
  while (model->line_size % model->tab_width != 0U &&
         model->line_size < model->width)
  {
    if (model->line_size >= sizeof(model->line))
      return 0;
    model->line[model->line_size ++] = ' ';
  }
  return 1;
}

static int
cf_v2_text_line_break(cf_v2_text_line_model_t *model)
{
  model->line_started = 1;
  if (!cf_v2_text_line_emit(model))
    return 0;
  model->skip_rest_of_line = 0;
  model->skip_spaces = 0;
  return 1;
}

static int
cf_v2_text_line_reference(const uint8_t *document, size_t document_size,
                          size_t width, size_t left_margin, size_t tab_width,
                          cf_v2_text_line_mode_t mode, const uint8_t *newline,
                          size_t newline_size, uint8_t **expected,
                          size_t *expected_size)
{
  cf_v2_text_line_model_t model;
  size_t index;

  memset(&model, 0, sizeof(model));
  model.width = width;
  model.left_margin = left_margin;
  model.tab_width = tab_width;
  model.newline = newline;
  model.newline_size = newline_size;
  model.mode = mode;

  for (index = 0; index < document_size; index ++)
  {
    const uint8_t value = document[index];

    if (value == '\r' || value == '\n')
    {
      if (value == '\n' && index && document[index - 1U] == '\r')
      {
        model.line_started = 1;
        continue;
      }
      if (!cf_v2_text_line_break(&model))
        goto fail;
    }
    else if (value == '\t')
    {
      if (!cf_v2_text_line_tab(&model))
        goto fail;
    }
    else if (value == ' ')
    {
      if (!cf_v2_text_line_space(&model))
        goto fail;
    }
    else if (value > ' ')
    {
      if (!cf_v2_text_line_regular(&model, value))
        goto fail;
    }
  }
  if (model.line_size && !cf_v2_text_line_emit(&model))
    goto fail;
  if (model.line_started && left_margin)
  {
    static const uint8_t spaces[16] = {
      ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
      ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
    };

    if (!cf_v2_text_line_append(&model.output, spaces, left_margin))
      goto fail;
  }
  *expected = model.output.data;
  *expected_size = model.output.size;
  return 1;

fail:
  free(model.output.data);
  return 0;
}

static int
cf_v2_text_line_source_break(cf_v2_text_line_buffer_t *document,
                             unsigned int style, size_t ordinal)
{
  static const uint8_t lf[] = {'\n'};
  static const uint8_t cr[] = {'\r'};
  static const uint8_t crlf[] = {'\r', '\n'};

  if (style == 0U || (style == 3U && ordinal % 3U == 0U))
    return cf_v2_text_line_append(document, lf, sizeof(lf));
  if (style == 1U || (style == 3U && ordinal % 3U == 1U))
    return cf_v2_text_line_append(document, cr, sizeof(cr));
  return cf_v2_text_line_append(document, crlf, sizeof(crlf));
}

static int
cf_v2_text_line_build_document(const uint8_t *selector,
                               const uint8_t *payload, size_t payload_size,
                               size_t width, cf_v2_text_line_mode_t mode,
                               uint8_t **document_data, size_t *document_size)
{
  static const uint8_t prefix0[] = "one two three four five";
  static const uint8_t prefix1[] = "\talpha\tbeta\tgamma";
  static const uint8_t prefix2[] = "abcdefghijklmnopqrstuv";
  static const uint8_t prefix3[] = "  lead   middle   tail  ";
  static const uint8_t prefix4[] = "x y z longword0123456789";
  static const uint8_t prefix5[] = "tab\tend  ";
  static const struct
  {
    const uint8_t *data;
    size_t size;
  } prefixes[] = {
    {prefix0, sizeof(prefix0) - 1U},
    {prefix1, sizeof(prefix1) - 1U},
    {prefix2, sizeof(prefix2) - 1U},
    {prefix3, sizeof(prefix3) - 1U},
    {prefix4, sizeof(prefix4) - 1U},
    {prefix5, sizeof(prefix5) - 1U},
  };
  static const uint8_t a[] = "a";
  static const uint8_t bc[] = "bc";
  static const uint8_t word[] = "word";
  static const uint8_t longtoken[] = "longtoken";
  static const uint8_t two_spaces[] = "  ";
  static const uint8_t spaced[] = "x y ";
  static const uint8_t digits[] = "0123456789";
  cf_v2_text_line_buffer_t document;
  size_t index;
  size_t newline_ordinal = 0;
  const size_t prefix_index = selector[7] %
      (sizeof(prefixes) / sizeof(prefixes[0]));
  const unsigned int source_style = selector[6] % 4U;

  memset(&document, 0, sizeof(document));
#ifdef CF_V2_TEXT_LINE_CONTINUATION
  if (mode == CF_V2_TEXT_LINE_WORD_WRAP)
  {
    static const uint8_t safe_prefix[] = "aa bb cc dd";

    (void)width;
    if (!cf_v2_text_line_append(&document, safe_prefix,
                                sizeof(safe_prefix) - 1U) ||
        !cf_v2_text_line_source_break(&document, source_style,
                                      newline_ordinal ++))
      goto fail;
    for (index = 0; index < payload_size; index ++)
    {
      const size_t word_size = 1U + (payload[index] + selector[7]) % 3U;
      size_t word_index;

      for (word_index = 0; word_index < word_size; word_index ++)
        if (!cf_v2_text_line_append_byte(
                &document,
                (uint8_t)('a' + (payload[index] + word_index) % 26U)))
          goto fail;
      if (!cf_v2_text_line_append_byte(&document, ' '))
        goto fail;
      if (payload[index] % 11U == 0U &&
          !cf_v2_text_line_source_break(&document, source_style,
                                        newline_ordinal ++))
        goto fail;
    }
    if ((selector[7] & 1U) == 0U &&
        !cf_v2_text_line_source_break(&document, source_style,
                                      newline_ordinal))
      goto fail;
    *document_data = document.data;
    *document_size = document.size;
    return 1;
  }
#else
  (void)width;
  (void)mode;
#endif
  if (!cf_v2_text_line_append(&document, prefixes[prefix_index].data,
                              prefixes[prefix_index].size) ||
      !cf_v2_text_line_source_break(&document, source_style,
                                    newline_ordinal ++))
    goto fail;

  for (index = 0; index < payload_size; index ++)
  {
    switch ((payload[index] + selector[7] + index * 5U) % 12U)
    {
      case 0:
        if (!cf_v2_text_line_append(&document, a, sizeof(a) - 1U))
          goto fail;
        break;
      case 1:
        if (!cf_v2_text_line_append(&document, bc, sizeof(bc) - 1U))
          goto fail;
        break;
      case 2:
        if (!cf_v2_text_line_append(&document, word, sizeof(word) - 1U))
          goto fail;
        break;
      case 3:
        if (!cf_v2_text_line_append(&document, longtoken,
                                    sizeof(longtoken) - 1U))
          goto fail;
        break;
      case 4:
        if (!cf_v2_text_line_append_byte(&document, ' '))
          goto fail;
        break;
      case 5:
        if (!cf_v2_text_line_append(&document, two_spaces,
                                    sizeof(two_spaces) - 1U))
          goto fail;
        break;
      case 6:
        if (!cf_v2_text_line_append_byte(&document, '\t'))
          goto fail;
        break;
      case 7:
      case 11:
        if (!cf_v2_text_line_source_break(&document, source_style,
                                          newline_ordinal ++))
          goto fail;
        break;
      case 8:
        if (!cf_v2_text_line_append(&document, spaced,
                                    sizeof(spaced) - 1U))
          goto fail;
        break;
      case 9:
        if (!cf_v2_text_line_append(&document, digits,
                                    sizeof(digits) - 1U))
          goto fail;
        break;
      case 10:
        if (!cf_v2_text_line_append_byte(&document, 'Z'))
          goto fail;
        break;
    }
  }
  if ((selector[7] & 1U) == 0U &&
      !cf_v2_text_line_source_break(&document, source_style,
                                    newline_ordinal))
    goto fail;
  *document_data = document.data;
  *document_size = document.size;
  return 1;

fail:
  free(document.data);
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static const size_t widths[] = {8U, 9U, 12U, 16U, 23U, 31U};
  static const size_t margins[] = {0U, 1U, 2U, 4U};
  static const size_t tabs[] = {2U, 3U, 4U, 8U};
  static const char *const modes[] = {
    "truncate", "word-wrap", "wrap-at-width"
  };
  static const char *const newline_names[] = {"lf", "cr", "crlf"};
  static const uint8_t newline_lf[] = {'\n'};
  static const uint8_t newline_cr[] = {'\r'};
  static const uint8_t newline_crlf[] = {'\r', '\n'};
  static const struct
  {
    const uint8_t *data;
    size_t size;
  } newlines[] = {
    {newline_lf, sizeof(newline_lf)},
    {newline_cr, sizeof(newline_cr)},
    {newline_crlf, sizeof(newline_crlf)},
  };
  const size_t fixed_size =
      CF_V2_TEXT_LINE_MAGIC_SIZE + CF_V2_TEXT_LINE_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  size_t width;
  size_t left_margin;
  size_t right_margin;
  size_t tab_width;
  size_t mode_index;
  size_t newline_index;
  size_t page_width;
  uint8_t *document = NULL;
  size_t document_size = 0;
  uint8_t *expected = NULL;
  size_t expected_size = 0;
  char options[512];
  int options_size;
  static const uint8_t title[] = "text-to-text line layout oracle";
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_LINE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_LINE_MAGIC, CF_V2_TEXT_LINE_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_TEXT_LINE_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  width = widths[selector[0] % (sizeof(widths) / sizeof(widths[0]))];
  left_margin = margins[selector[1] % (sizeof(margins) / sizeof(margins[0]))];
  right_margin = margins[selector[2] % (sizeof(margins) / sizeof(margins[0]))];
  tab_width = tabs[selector[3] % (sizeof(tabs) / sizeof(tabs[0]))];
  mode_index = selector[4] % (sizeof(modes) / sizeof(modes[0]));
  newline_index = selector[5] %
      (sizeof(newline_names) / sizeof(newline_names[0]));
  page_width = width + left_margin + right_margin;

  if (!cf_v2_text_line_build_document(selector, payload, payload_size,
                                      width,
                                      (cf_v2_text_line_mode_t)mode_index,
                                      &document, &document_size) ||
      !cf_v2_text_line_reference(
          document, document_size, width, left_margin, tab_width,
          (cf_v2_text_line_mode_t)mode_index, newlines[newline_index].data,
          newlines[newline_index].size, &expected, &expected_size))
    goto cleanup;

  options_size = snprintf(
      options, sizeof(options),
      "PageWidth=%u PageHeight=1024 PageLeft=%u PageRight=%u PageTop=0 "
      "PageBottom=0 PrinterEncoding=ASCII OverLongLines=%s TabWidth=%u "
      "Pagination=false SendFF=false NewlineCharacters=%s "
      "page-ranges=1-99 page-set=all OutputOrder=normal Collate=true",
      (unsigned int)page_width, (unsigned int)left_margin,
      (unsigned int)right_margin, modes[mode_index],
      (unsigned int)tab_width, newline_names[newline_index]);
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
  if (executed && result.captured &&
      (result.status != 0 || result.output_size != expected_size ||
       (expected_size && memcmp(result.output, expected, expected_size) != 0)))
  {
    __builtin_trap();
  }
  cf_v2_free_run_result(&result);

cleanup:
  free(document);
  free(expected);
  return 0;
}
