// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_text_direction_unused_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <math.h>
#include <pdfio.h>
#include <stdbool.h>

#define CF_V2_TEXT_DIRECTION_MAGIC "TXTDIR01"
#define CF_V2_TEXT_DIRECTION_MAGIC_SIZE 8U
#define CF_V2_TEXT_DIRECTION_SELECTORS 10U
#define CF_V2_TEXT_DIRECTION_INPUT_SIZE 18U
#define CF_V2_TEXT_DIRECTION_MAX_DOCUMENT 512U
#define CF_V2_TEXT_DIRECTION_MAX_OUTPUT (2U * 1024U * 1024U)
#define CF_V2_TEXT_DIRECTION_MAX_EVENTS 32U
#define CF_V2_TEXT_DIRECTION_MAX_TOKENS 4096U

enum {
  CF_V2_TEXT_DIRECTION_STYLE_NORMAL = 0,
  CF_V2_TEXT_DIRECTION_STYLE_BOLD = 1,
  CF_V2_TEXT_DIRECTION_STYLE_UNDERLINE = 2,
  CF_V2_TEXT_DIRECTION_STYLE_RAISED = 3,
  CF_V2_TEXT_DIRECTION_STYLE_LOWERED = 4
};

typedef struct cf_v2_text_direction_state_s {
  unsigned shape;
  unsigned run_length;
  unsigned latin_phase;
  unsigned hebrew_phase;
  unsigned start_column;
  unsigned row;
  unsigned page_size;
  unsigned orientation;
  unsigned cpi_index;
  unsigned lpi_index;
  unsigned style;
} cf_v2_text_direction_state_t;

typedef struct cf_v2_text_direction_char_s {
  uint16_t codepoint;
  unsigned font_index;
  bool space;
} cf_v2_text_direction_char_t;

typedef struct cf_v2_text_direction_expected_s {
  unsigned font_index;
  unsigned glyph_count;
  unsigned rtl_group;
} cf_v2_text_direction_expected_t;

typedef struct cf_v2_text_direction_event_s {
  double x;
  double y;
  double font_size;
  char font[16];
  unsigned glyph_count;
  bool all_glyphs_nonzero;
} cf_v2_text_direction_event_t;

typedef struct cf_v2_text_direction_parse_s {
  cf_v2_text_direction_event_t events[CF_V2_TEXT_DIRECTION_MAX_EVENTS];
  size_t event_count;
  size_t token_count;
  unsigned stroke_count;
  int graphics_depth;
  int text_depth;
  double current_x;
  double current_y;
  double current_font_size;
  char current_font[16];
  bool have_position;
  bool have_font;
} cf_v2_text_direction_parse_t;

typedef struct cf_v2_text_direction_error_s {
  bool saw_error;
} cf_v2_text_direction_error_t;

static bool cf_v2_text_direction_fail(const char **failure,
                                      const char *reason) {
  if (failure && !*failure) {
    *failure = reason;
  }
  return false;
}

static bool cf_v2_text_direction_pdf_error(pdfio_file_t *pdf,
                                            const char *message, void *data) {
  cf_v2_text_direction_error_t *error =
      (cf_v2_text_direction_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static pdfio_dict_t *cf_v2_text_direction_dict(pdfio_dict_t *parent,
                                                const char *key) {
  pdfio_valtype_t type;

  if (!parent) {
    return NULL;
  }
  type = pdfioDictGetType(parent, key);
  if (type == PDFIO_VALTYPE_DICT) {
    return pdfioDictGetDict(parent, key);
  }
  if (type == PDFIO_VALTYPE_INDIRECT) {
    pdfio_obj_t *object = pdfioDictGetObj(parent, key);
    return object ? pdfioObjGetDict(object) : NULL;
  }
  return NULL;
}

static void cf_v2_text_direction_decode(
    const uint8_t selectors[CF_V2_TEXT_DIRECTION_SELECTORS],
    cf_v2_text_direction_state_t *state) {
  static const unsigned run_lengths[] = {1U, 2U, 4U, 8U};
  static const unsigned start_columns[] = {0U, 1U, 4U, 8U, 16U};
  static const unsigned rows[] = {0U, 1U, 2U, 4U};
  unsigned combined = selectors[9] % 20U;

  state->shape = selectors[0] % 8U;
  state->run_length = run_lengths[selectors[1] % 4U];
  state->latin_phase = selectors[2] % 8U;
  state->hebrew_phase = selectors[3] % 8U;
  state->start_column = start_columns[selectors[4] % 5U];
  state->row = rows[selectors[5] % 4U];
  state->page_size = selectors[6] % 2U;
  state->orientation = selectors[7] % 4U;
  state->cpi_index = selectors[8] % 5U;
  state->style = combined % 5U;
  state->lpi_index = combined / 5U;
}

static bool cf_v2_text_direction_append_char(
    cf_v2_text_direction_char_t *line, size_t *line_size,
    uint16_t codepoint, unsigned font_index, bool space) {
  if (*line_size >= 24U) {
    return false;
  }
  line[*line_size].codepoint = codepoint;
  line[*line_size].font_index = font_index;
  line[*line_size].space = space;
  (*line_size)++;
  return true;
}

static bool cf_v2_text_direction_append_run(
    cf_v2_text_direction_char_t *line, size_t *line_size,
    const cf_v2_text_direction_state_t *state, bool rtl) {
  static const uint16_t latin[] = {'A', 'b', 'C', 'd', 'E', 'f', 'G', 'h'};
  static const uint16_t hebrew[] = {
      0x05d0U, 0x05d1U, 0x05d2U, 0x05d3U,
      0x05d4U, 0x05d5U, 0x05d6U, 0x05d7U};

  for (unsigned index = 0; index < state->run_length; index++) {
    unsigned phase = rtl ? state->hebrew_phase : state->latin_phase;
    uint16_t codepoint = rtl ? hebrew[(phase + index) % 8U]
                             : latin[(phase + index) % 8U];
    if (!cf_v2_text_direction_append_char(line, line_size, codepoint,
                                          rtl ? 1U : 0U, false)) {
      return false;
    }
  }
  return true;
}

static bool cf_v2_text_direction_build_line(
    const cf_v2_text_direction_state_t *state,
    cf_v2_text_direction_char_t *line, size_t *line_size) {
  *line_size = 0U;
  switch (state->shape) {
    case 0U:
      return cf_v2_text_direction_append_run(line, line_size, state, false);
    case 1U:
      return cf_v2_text_direction_append_run(line, line_size, state, true);
    case 2U:
      return cf_v2_text_direction_append_run(line, line_size, state, false) &&
             cf_v2_text_direction_append_run(line, line_size, state, true);
    case 3U:
      return cf_v2_text_direction_append_run(line, line_size, state, true) &&
             cf_v2_text_direction_append_run(line, line_size, state, false);
    case 4U:
      return cf_v2_text_direction_append_run(line, line_size, state, false) &&
             cf_v2_text_direction_append_char(line, line_size, ' ', 0U,
                                              true) &&
             cf_v2_text_direction_append_run(line, line_size, state, true);
    case 5U:
      return cf_v2_text_direction_append_run(line, line_size, state, true) &&
             cf_v2_text_direction_append_char(line, line_size, '.', 0U,
                                              false) &&
             cf_v2_text_direction_append_run(line, line_size, state, false);
    case 6U:
      return cf_v2_text_direction_append_run(line, line_size, state, false) &&
             cf_v2_text_direction_append_run(line, line_size, state, true) &&
             cf_v2_text_direction_append_char(line, line_size, '!', 0U,
                                              false);
    default:
      return cf_v2_text_direction_append_run(line, line_size, state, true) &&
             cf_v2_text_direction_append_char(line, line_size, ' ', 0U,
                                              true) &&
             cf_v2_text_direction_append_run(line, line_size, state, false);
  }
}

static bool cf_v2_text_direction_put_byte(uint8_t *document, size_t *used,
                                           uint8_t value) {
  if (*used >= CF_V2_TEXT_DIRECTION_MAX_DOCUMENT) {
    return false;
  }
  document[(*used)++] = value;
  return true;
}

static bool cf_v2_text_direction_put_codepoint(uint8_t *document,
                                                size_t *used,
                                                uint16_t codepoint) {
  if (codepoint < 0x80U) {
    return cf_v2_text_direction_put_byte(document, used,
                                         (uint8_t)codepoint);
  }
  return cf_v2_text_direction_put_byte(
             document, used, (uint8_t)(0xc0U | (codepoint >> 6U))) &&
         cf_v2_text_direction_put_byte(
             document, used, (uint8_t)(0x80U | (codepoint & 0x3fU)));
}

static bool cf_v2_text_direction_put_line(
    uint8_t *document, size_t *used,
    const cf_v2_text_direction_state_t *state,
    const cf_v2_text_direction_char_t *line, size_t line_size,
    bool overlay) {
  for (unsigned index = 0; index < state->start_column; index++) {
    if (!cf_v2_text_direction_put_byte(document, used, ' ')) {
      return false;
    }
  }
  for (size_t index = 0; index < line_size; index++) {
    uint16_t codepoint = line[index].codepoint;
    if (overlay) {
      codepoint = line[index].space ? ' ' : '_';
    }
    if (!cf_v2_text_direction_put_codepoint(document, used, codepoint)) {
      return false;
    }
  }
  return true;
}

static bool cf_v2_text_direction_build_document(
    const cf_v2_text_direction_state_t *state,
    const cf_v2_text_direction_char_t *line, size_t line_size,
    uint8_t document[CF_V2_TEXT_DIRECTION_MAX_DOCUMENT],
    size_t *document_size) {
  size_t used = 0U;

  for (unsigned row = 0; row < state->row; row++) {
    if (!cf_v2_text_direction_put_byte(document, &used, '\n')) {
      return false;
    }
  }
  if (state->style == CF_V2_TEXT_DIRECTION_STYLE_RAISED ||
      state->style == CF_V2_TEXT_DIRECTION_STYLE_LOWERED) {
    if (!cf_v2_text_direction_put_byte(document, &used, 0x1bU) ||
        !cf_v2_text_direction_put_byte(
            document, &used,
            state->style == CF_V2_TEXT_DIRECTION_STYLE_RAISED ? '8' : '9')) {
      return false;
    }
  }
  if (state->style == CF_V2_TEXT_DIRECTION_STYLE_UNDERLINE) {
    if (!cf_v2_text_direction_put_line(document, &used, state, line,
                                       line_size, true) ||
        !cf_v2_text_direction_put_byte(document, &used, '\r')) {
      return false;
    }
  }
  if (!cf_v2_text_direction_put_line(document, &used, state, line,
                                     line_size, false)) {
    return false;
  }
  if (state->style == CF_V2_TEXT_DIRECTION_STYLE_BOLD) {
    if (!cf_v2_text_direction_put_byte(document, &used, '\r') ||
        !cf_v2_text_direction_put_line(document, &used, state, line,
                                       line_size, false)) {
      return false;
    }
  }
  if (!cf_v2_text_direction_put_byte(document, &used, '\n')) {
    return false;
  }
  *document_size = used;
  return true;
}

static bool cf_v2_text_direction_expected_append(
    cf_v2_text_direction_expected_t *expected, size_t *expected_count,
    unsigned font_index, unsigned glyph_count, unsigned rtl_group) {
  if (*expected_count >= CF_V2_TEXT_DIRECTION_MAX_EVENTS || !glyph_count) {
    return false;
  }
  expected[*expected_count].font_index = font_index;
  expected[*expected_count].glyph_count = glyph_count;
  expected[*expected_count].rtl_group = rtl_group;
  (*expected_count)++;
  return true;
}

static bool cf_v2_text_direction_expected_rtl(
    cf_v2_text_direction_expected_t *expected, size_t *expected_count,
    unsigned length, bool punctuation) {
  for (unsigned index = 0; index < length; index++) {
    if (!cf_v2_text_direction_expected_append(expected, expected_count, 1U,
                                              1U, 1U)) {
      return false;
    }
  }
  return !punctuation ||
         cf_v2_text_direction_expected_append(expected, expected_count, 0U,
                                              1U, 1U);
}

static bool cf_v2_text_direction_build_expected(
    const cf_v2_text_direction_state_t *state,
    cf_v2_text_direction_expected_t *expected, size_t *expected_count) {
  bool space_joins_ltr =
      state->style == CF_V2_TEXT_DIRECTION_STYLE_NORMAL ||
      state->style == CF_V2_TEXT_DIRECTION_STYLE_RAISED ||
      state->style == CF_V2_TEXT_DIRECTION_STYLE_LOWERED;

  *expected_count = 0U;
  switch (state->shape) {
    case 0U:
      return cf_v2_text_direction_expected_append(
          expected, expected_count, 0U, state->run_length, 0U);
    case 1U:
      return cf_v2_text_direction_expected_rtl(
          expected, expected_count, state->run_length, false);
    case 2U:
      return cf_v2_text_direction_expected_append(
                 expected, expected_count, 0U, state->run_length, 0U) &&
             cf_v2_text_direction_expected_rtl(
                 expected, expected_count, state->run_length, false);
    case 3U:
      return cf_v2_text_direction_expected_rtl(
                 expected, expected_count, state->run_length, false) &&
             cf_v2_text_direction_expected_append(
                 expected, expected_count, 0U, state->run_length, 0U);
    case 4U:
      return cf_v2_text_direction_expected_append(
                 expected, expected_count, 0U,
                 state->run_length + (space_joins_ltr ? 1U : 0U), 0U) &&
             cf_v2_text_direction_expected_rtl(
                 expected, expected_count, state->run_length, false);
    case 5U:
      return cf_v2_text_direction_expected_rtl(
                 expected, expected_count, state->run_length, true) &&
             cf_v2_text_direction_expected_append(
                 expected, expected_count, 0U, state->run_length, 0U);
    case 6U:
      return cf_v2_text_direction_expected_append(
                 expected, expected_count, 0U, state->run_length, 0U) &&
             cf_v2_text_direction_expected_rtl(
                 expected, expected_count, state->run_length, true);
    default:
      return cf_v2_text_direction_expected_rtl(
                 expected, expected_count, state->run_length, false) &&
             cf_v2_text_direction_expected_append(
                 expected, expected_count, 0U, state->run_length, 0U);
  }
}

static bool cf_v2_text_direction_number(const char *token, double *value) {
  char *end = NULL;

  *value = strtod(token, &end);
  return end && *end == '\0' && end != token && isfinite(*value);
}

static int cf_v2_text_direction_hex_value(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

static bool cf_v2_text_direction_hex_glyphs(const char *token,
                                             unsigned *glyph_count,
                                             bool *all_nonzero) {
  size_t length = strlen(token);
  size_t end = length;

  if (length < 5U || token[0] != '<' || token[1] == '<') {
    return false;
  }
  if (token[length - 1U] == '>') {
    end--;
  }
  if (end <= 1U || (end - 1U) % 4U != 0U) {
    return false;
  }
  *glyph_count = 0U;
  *all_nonzero = true;
  for (size_t index = 1U; index < end; index += 4U) {
    unsigned glyph = 0U;
    for (size_t digit = 0U; digit < 4U; digit++) {
      int value = cf_v2_text_direction_hex_value(token[index + digit]);
      if (value < 0) {
        return false;
      }
      glyph = (glyph << 4U) | (unsigned)value;
    }
    if (!glyph) {
      *all_nonzero = false;
    }
    (*glyph_count)++;
  }
  return true;
}

static bool cf_v2_text_direction_is_operator(const char *token) {
  static const char *const operators[] = {
      "q", "Q", "g", "w", "m", "l", "S", "BT", "ET",
      "Td", "Tz", "Tf", "Tj"};

  for (size_t index = 0; index < sizeof(operators) / sizeof(operators[0]);
       index++) {
    if (strcmp(token, operators[index]) == 0) {
      return true;
    }
  }
  return false;
}

static bool cf_v2_text_direction_process_operator(
    cf_v2_text_direction_parse_t *parse, const char *token,
    char operands[4][128], size_t operand_count, const char **failure) {
  double first;
  double second;

  if (strcmp(token, "q") == 0) {
    if (operand_count || ++parse->graphics_depth > 8) {
      return cf_v2_text_direction_fail(failure, "graphics-q");
    }
  } else if (strcmp(token, "Q") == 0) {
    if (operand_count || parse->graphics_depth-- <= 0) {
      return cf_v2_text_direction_fail(failure, "graphics-Q");
    }
  } else if (strcmp(token, "BT") == 0) {
    if (operand_count || parse->text_depth != 0) {
      return cf_v2_text_direction_fail(failure, "text-BT");
    }
    parse->text_depth = 1;
    parse->have_position = false;
    parse->have_font = false;
  } else if (strcmp(token, "ET") == 0) {
    if (operand_count || parse->text_depth != 1) {
      return cf_v2_text_direction_fail(failure, "text-ET");
    }
    parse->text_depth = 0;
  } else if (strcmp(token, "Td") == 0) {
    if (parse->text_depth != 1 || operand_count != 2U ||
        !cf_v2_text_direction_number(operands[0], &first) ||
        !cf_v2_text_direction_number(operands[1], &second)) {
      return cf_v2_text_direction_fail(failure, "text-Td");
    }
    parse->current_x = first;
    parse->current_y = second;
    parse->have_position = true;
  } else if (strcmp(token, "Tf") == 0) {
    if (parse->text_depth != 1 || operand_count != 2U ||
        operands[0][0] != '/' ||
        strlen(operands[0] + 1U) >= sizeof(parse->current_font) ||
        !cf_v2_text_direction_number(operands[1], &second) ||
        second <= 0.0) {
      return cf_v2_text_direction_fail(failure, "text-Tf");
    }
    strcpy(parse->current_font, operands[0] + 1U);
    parse->current_font_size = second;
    parse->have_font = true;
  } else if (strcmp(token, "Tj") == 0) {
    cf_v2_text_direction_event_t *event;
    if (parse->text_depth != 1 || operand_count != 1U ||
        !parse->have_position || !parse->have_font ||
        parse->event_count >= CF_V2_TEXT_DIRECTION_MAX_EVENTS) {
      return cf_v2_text_direction_fail(failure, "text-Tj-state");
    }
    event = &parse->events[parse->event_count];
    if (!cf_v2_text_direction_hex_glyphs(
            operands[0], &event->glyph_count,
            &event->all_glyphs_nonzero)) {
      return cf_v2_text_direction_fail(failure, "text-Tj-hex");
    }
    event->x = parse->current_x;
    event->y = parse->current_y;
    event->font_size = parse->current_font_size;
    strcpy(event->font, parse->current_font);
    parse->event_count++;
  } else if (strcmp(token, "g") == 0 || strcmp(token, "w") == 0 ||
             strcmp(token, "Tz") == 0) {
    if (operand_count != 1U ||
        !cf_v2_text_direction_number(operands[0], &first)) {
      return cf_v2_text_direction_fail(failure, "unary-number-operator");
    }
  } else if (strcmp(token, "m") == 0 || strcmp(token, "l") == 0) {
    if (operand_count != 2U ||
        !cf_v2_text_direction_number(operands[0], &first) ||
        !cf_v2_text_direction_number(operands[1], &second)) {
      return cf_v2_text_direction_fail(failure, "path-coordinate");
    }
  } else if (strcmp(token, "S") == 0) {
    if (operand_count) {
      return cf_v2_text_direction_fail(failure, "path-stroke-operands");
    }
    parse->stroke_count++;
  } else {
    return cf_v2_text_direction_fail(failure, "unknown-operator");
  }
  return true;
}

static bool cf_v2_text_direction_parse_stream(
    pdfio_obj_t *page, cf_v2_text_direction_parse_t *parse,
    const char **failure) {
  pdfio_stream_t *stream;
  char token[4096];
  char operands[4][128];
  size_t operand_count = 0U;
  bool valid = true;

  if (pdfioPageGetNumStreams(page) != 1U ||
      !(stream = pdfioPageOpenStream(page, 0U, true))) {
    return cf_v2_text_direction_fail(failure, "content-stream");
  }
  while (pdfioStreamGetToken(stream, token, sizeof(token))) {
    if (++parse->token_count > CF_V2_TEXT_DIRECTION_MAX_TOKENS) {
      cf_v2_text_direction_fail(failure, "content-token-budget");
      valid = false;
      break;
    }
    if (cf_v2_text_direction_is_operator(token)) {
      if (!cf_v2_text_direction_process_operator(
              parse, token, operands, operand_count, failure)) {
        valid = false;
        break;
      }
      operand_count = 0U;
    } else {
      size_t length = strlen(token);
      if (operand_count >= 4U || length >= sizeof(operands[0])) {
        cf_v2_text_direction_fail(failure, "content-operand-budget");
        valid = false;
        break;
      }
      memcpy(operands[operand_count], token, length + 1U);
      operand_count++;
    }
  }
  if (valid && (operand_count || parse->text_depth != 0 ||
                parse->graphics_depth != 0)) {
    cf_v2_text_direction_fail(failure, "content-balance");
    valid = false;
  }
  if (!pdfioStreamClose(stream)) {
    cf_v2_text_direction_fail(failure, "content-close");
    valid = false;
  }
  return valid;
}

static bool cf_v2_text_direction_validate_events(
    pdfio_dict_t *fonts, const cf_v2_text_direction_state_t *state,
    const cf_v2_text_direction_expected_t *expected, size_t expected_count,
    const cf_v2_text_direction_parse_t *parse, const char **failure) {
  const char *prefix =
      state->style == CF_V2_TEXT_DIRECTION_STYLE_BOLD ? "FB" : "FN";

  if (parse->event_count != expected_count) {
    return cf_v2_text_direction_fail(failure, "text-event-count");
  }
  if (parse->stroke_count !=
      (state->style == CF_V2_TEXT_DIRECTION_STYLE_UNDERLINE
           ? expected_count
           : 0U)) {
    return cf_v2_text_direction_fail(failure, "underline-stroke-count");
  }
  for (size_t index = 0U; index < expected_count; index++) {
    const cf_v2_text_direction_event_t *event = &parse->events[index];
    char expected_font[16];
    pdfio_dict_t *font;

    snprintf(expected_font, sizeof(expected_font), "%s%02x", prefix,
             expected[index].font_index);
    if (strcmp(event->font, expected_font) != 0 ||
        event->glyph_count != expected[index].glyph_count ||
        !event->all_glyphs_nonzero || !isfinite(event->x) ||
        !isfinite(event->y) || !isfinite(event->font_size) ||
        event->font_size <= 0.0) {
      return cf_v2_text_direction_fail(failure, "text-event-value");
    }
    font = cf_v2_text_direction_dict(fonts, event->font);
    if (!font || !pdfioDictGetName(font, "Type") ||
        strcmp(pdfioDictGetName(font, "Type"), "Font") != 0) {
      return cf_v2_text_direction_fail(failure, "font-resource-binding");
    }
    if (index > 0U && expected[index].rtl_group &&
        expected[index - 1U].rtl_group &&
        !(event->x < parse->events[index - 1U].x - 0.001)) {
      return cf_v2_text_direction_fail(failure, "rtl-coordinate-order");
    }
    if (index > 0U && fabs(event->y - parse->events[0].y) > 0.001) {
      return cf_v2_text_direction_fail(failure, "text-row-coordinate");
    }
  }
  return true;
}

static bool cf_v2_text_direction_validate_file(
    const char *path, const cf_v2_text_direction_state_t *state,
    const cf_v2_text_direction_expected_t *expected, size_t expected_count,
    const char **failure) {
  cf_v2_text_direction_error_t error = {false};
  cf_v2_text_direction_parse_t parse;
  pdfio_file_t *pdf = NULL;
  bool valid = false;

  memset(&parse, 0, sizeof(parse));
  *failure = NULL;
  pdf = pdfioFileOpen(path, NULL, NULL, cf_v2_text_direction_pdf_error,
                      &error);
  if (!pdf || error.saw_error || pdfioFileGetNumPages(pdf) != 1U) {
    cf_v2_text_direction_fail(failure, "pdf-page-count");
    goto done;
  }
  {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, 0U);
    pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
    pdfio_dict_t *resources =
        cf_v2_text_direction_dict(page_dict, "Resources");
    pdfio_dict_t *fonts = cf_v2_text_direction_dict(resources, "Font");

    if (!page || !page_dict || !resources || !fonts ||
        !cf_v2_text_direction_parse_stream(page, &parse, failure) ||
        !cf_v2_text_direction_validate_events(
            fonts, state, expected, expected_count, &parse, failure)) {
      goto done;
    }
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v2_text_direction_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_text_direction_state_t state;
  cf_v2_text_direction_char_t line[24];
  cf_v2_text_direction_expected_t
      expected[CF_V2_TEXT_DIRECTION_MAX_EVENTS];
  size_t line_size = 0U;
  size_t expected_count = 0U;
  uint8_t document[CF_V2_TEXT_DIRECTION_MAX_DOCUMENT];
  size_t document_size = 0U;
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-text-direction.XXXXXX";
  const char *failure = NULL;
  int output_fd = -1;
  int executed;
  bool trap_after_cleanup = false;

  if (!data || size != CF_V2_TEXT_DIRECTION_INPUT_SIZE ||
      memcmp(data, CF_V2_TEXT_DIRECTION_MAGIC,
             CF_V2_TEXT_DIRECTION_MAGIC_SIZE) != 0) {
    return 0;
  }
  memset(&result, 0, sizeof(result));
  cf_v2_text_direction_decode(data + CF_V2_TEXT_DIRECTION_MAGIC_SIZE,
                              &state);
  if (!cf_v2_text_direction_build_line(&state, line, &line_size) ||
      !cf_v2_text_direction_build_document(
          &state, line, line_size, document, &document_size) ||
      !cf_v2_text_direction_build_expected(
          &state, expected, &expected_count)) {
    return 0;
  }

  memset(&control, 0, sizeof(control));
  control.page_size = (uint8_t)state.page_size;
  control.orientation = (uint8_t)state.orientation;
  control.scaling = 1U;
  control.number_up = 0U;
  control.quality = (uint8_t)state.cpi_index;
  control.reserved = (uint8_t)state.lpi_index;
  control.route_mode = 0U;

  cf_v2_texttopdf_active = 1;
  executed = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &result);
  cf_v2_release_texttopdf_lifecycle();
  if (executed && result.status == 0) {
    if (!result.captured || !result.output_size ||
        result.output_size > CF_V2_TEXT_DIRECTION_MAX_OUTPUT) {
      failure = "captured-output-bounds";
      trap_after_cleanup = true;
    } else if ((output_fd = mkstemp(output_path)) >= 0 &&
               cf_v2_write_all(output_fd, result.output,
                               result.output_size) == 0 &&
               close(output_fd) == 0) {
      output_fd = -1;
      trap_after_cleanup = !cf_v2_text_direction_validate_file(
          output_path, &state, expected, expected_count, &failure);
    } else {
      failure = "oracle-tempfile";
      trap_after_cleanup = true;
    }
  }

  if (output_fd >= 0) {
    close(output_fd);
  }
  unlink(output_path);
  cf_v2_free_run_result(&result);
  if (trap_after_cleanup) {
    fprintf(stderr, "text-direction-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
