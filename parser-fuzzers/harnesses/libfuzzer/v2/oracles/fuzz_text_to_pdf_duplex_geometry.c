// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#ifndef CF_V2_TEXTTOPDF_PARAMETERS
#error "TXTDUP01 requires the text-to-PDF parameter capsule"
#endif
#ifndef CF_V2_TEXTTOPDF_LEAK_GUARD
#error "TXTDUP01 requires the audited persistent-process cleanup guard"
#endif
#ifndef CF_V2_CHARSET
#error "TXTDUP01 must be built with CF_V2_CHARSET=\"us-ascii\""
#endif

#define LLVMFuzzerTestOneInput cf_v2_text_duplex_unused_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <math.h>
#include <pdfio.h>
#include <stdbool.h>

#define CF_V2_TEXT_DUPLEX_MAGIC "TXTDUP01"
#define CF_V2_TEXT_DUPLEX_MAGIC_SIZE 8U
#define CF_V2_TEXT_DUPLEX_SELECTOR_COUNT 10U
#define CF_V2_TEXT_DUPLEX_INPUT_SIZE 18U
#define CF_V2_TEXT_DUPLEX_MAX_DOCUMENT 1024U
#define CF_V2_TEXT_DUPLEX_MAX_PPD (16U * 1024U)
#define CF_V2_TEXT_DUPLEX_MAX_OPTIONS 512U
#define CF_V2_TEXT_DUPLEX_MAX_OUTPUT (2U * 1024U * 1024U)
#define CF_V2_TEXT_DUPLEX_MAX_TOKENS 128U
#define CF_V2_TEXT_DUPLEX_TOLERANCE 0.002

typedef struct cf_v2_text_duplex_state_s {
  unsigned media;
  unsigned orientation;
  unsigned sides;
  unsigned margin_profile;
  unsigned page_count;
  unsigned cpi;
  unsigned lpi;
  unsigned marker_column;
  unsigned marker_row;
  unsigned transition;
} cf_v2_text_duplex_state_t;

typedef struct cf_v2_text_duplex_geometry_s {
  double width;
  double height;
  double media_box_width;
  double media_box_height;
  double left;
  double bottom;
  double right;
  double top;
  unsigned size_lines;
} cf_v2_text_duplex_geometry_t;

typedef struct cf_v2_text_duplex_event_s {
  double x;
  double y;
  double font_size;
  char font[32];
  uint8_t marker[2];
} cf_v2_text_duplex_event_t;

typedef struct cf_v2_text_duplex_parse_s {
  cf_v2_text_duplex_event_t event;
  size_t token_count;
  unsigned q_count;
  unsigned Q_count;
  unsigned bt_count;
  unsigned et_count;
  unsigned td_count;
  unsigned tz_count;
  unsigned tf_count;
  unsigned tj_count;
  int graphics_depth;
  int text_depth;
  double current_x;
  double current_y;
  double current_font_size;
  char current_font[32];
  bool have_position;
  bool have_font;
} cf_v2_text_duplex_parse_t;

typedef struct cf_v2_text_duplex_error_s {
  bool saw_error;
} cf_v2_text_duplex_error_t;

static char cf_v2_text_duplex_detail[256];

static const unsigned cf_v2_text_duplex_cardinalities[] = {
    2U,
#ifdef CF_V2_TEXT_DUPLEX_SAFE_CONTINUATION
    2U,
#else
    4U,
#endif
    2U, 4U, 3U, 4U, 4U, 5U, 4U, 2U};

static bool cf_v2_text_duplex_fail(const char **failure,
                                   const char *reason) {
  if (failure && !*failure) {
    *failure = reason;
  }
  return false;
}

static void cf_v2_text_duplex_decode(
    const uint8_t selectors[CF_V2_TEXT_DUPLEX_SELECTOR_COUNT],
    cf_v2_text_duplex_state_t *state) {
#ifdef CF_V2_TEXT_DUPLEX_SAFE_CONTINUATION
  static const unsigned orientations[] = {3U, 4U};
#else
  static const unsigned orientations[] = {3U, 4U, 5U, 6U};
#endif
  static const unsigned page_counts[] = {2U, 3U, 4U};
  static const unsigned cpi[] = {6U, 10U, 12U, 15U};
  static const unsigned lpi[] = {4U, 6U, 8U, 10U};
  static const unsigned columns[] = {0U, 1U, 4U, 8U, 16U};
  static const unsigned rows[] = {0U, 1U, 2U, 4U};

  state->media = selectors[0] % 2U;
  state->orientation = orientations[
      selectors[1] %
      (sizeof(orientations) / sizeof(orientations[0]))];
  state->sides = selectors[2] % 2U;
  state->margin_profile = selectors[3] % 4U;
  state->page_count = page_counts[selectors[4] % 3U];
  state->cpi = cpi[selectors[5] % 4U];
  state->lpi = lpi[selectors[6] % 4U];
  state->marker_column = columns[selectors[7] % 5U];
  state->marker_row = rows[selectors[8] % 4U];
  state->transition = selectors[9] % 2U;
}

static unsigned cf_v2_text_duplex_pwg_units(double points) {
  return (unsigned)floor(points * 2540.0 / 72.0 + 0.5);
}

static double cf_v2_text_duplex_points(unsigned pwg_units) {
  return (double)pwg_units * 72.0 / 2540.0;
}

static void cf_v2_text_duplex_geometry(
    const cf_v2_text_duplex_state_t *state,
    cf_v2_text_duplex_geometry_t *geometry) {
  static const unsigned media_pwg[][2] = {
      {21000U, 29700U}, {21590U, 27940U}};
  static const double ppd_media[][2] = {
      {595.0, 842.0}, {612.0, 792.0}};
  static const double margins[][4] = {
      {12.0, 24.0, 36.0, 48.0},
      {18.0, 42.0, 54.0, 30.0},
      {54.0, 18.0, 30.0, 42.0},
      {30.0, 54.0, 18.0, 24.0}};
  const double ppd_width = ppd_media[state->media][0];
  const double ppd_height = ppd_media[state->media][1];
  const double ppd_left = margins[state->margin_profile][0];
  const double ppd_bottom = margins[state->margin_profile][1];
  const double ppd_right =
      ppd_width - margins[state->margin_profile][2];
  const double ppd_top =
      ppd_height - margins[state->margin_profile][3];
  const double width =
      cf_v2_text_duplex_points(media_pwg[state->media][0]);
  const double height =
      cf_v2_text_duplex_points(media_pwg[state->media][1]);
  const double header_left = cf_v2_text_duplex_points(
      cf_v2_text_duplex_pwg_units(ppd_left));
  const double header_bottom = cf_v2_text_duplex_points(
      cf_v2_text_duplex_pwg_units(ppd_bottom));
  const double header_right = width - cf_v2_text_duplex_points(
      cf_v2_text_duplex_pwg_units(ppd_width - ppd_right));
  const double header_top = height - cf_v2_text_duplex_points(
      cf_v2_text_duplex_pwg_units(ppd_height - ppd_top));
  double page_width = width;
  double page_length = height;
  double page_left = header_left;
  double page_bottom = header_bottom;
  double page_right = header_right;
  double page_top = header_top;
  const unsigned rotations[] = {0U, 1U, 3U, 2U};
  const unsigned rotation_count = rotations[state->orientation - 3U];

  /* Model the layout state machine, including its integer temporaries. */
  for (unsigned rotation = 0U; rotation < rotation_count; rotation++) {
    int temp;

    page_top = page_length - page_top;
    page_right = page_width - page_right;
    temp = (int)page_width;
    page_width = page_length;
    page_length = (double)temp;
    temp = (int)page_left;
    page_left = page_bottom;
    page_bottom = page_right;
    page_right = page_top;
    page_top = (double)temp;
    page_top = page_length - page_top;
    page_right = page_width - page_right;
  }

  geometry->width = page_width;
  geometry->height = page_length;
  geometry->left = page_left;
  geometry->bottom = page_bottom;
  geometry->right = page_width - page_right;
  geometry->top = page_length - page_top;
  geometry->media_box_width =
      state->orientation == 4U || state->orientation == 5U ? height : width;
  geometry->media_box_height =
      state->orientation == 4U || state->orientation == 5U ? width : height;
  geometry->size_lines = (unsigned)(
      (geometry->height - geometry->top - geometry->bottom) *
      (double)state->lpi / 72.0);
}

static void cf_v2_text_duplex_expected_position(
    const cf_v2_text_duplex_state_t *state,
    const cf_v2_text_duplex_geometry_t *geometry, unsigned page,
    double *x, double *y) {
  const bool back = state->sides && (page & 1U) == 0U;

  *x = (back ? geometry->right : geometry->left) +
       (double)state->marker_column * 72.0 / (double)state->cpi;
  *y = geometry->height - geometry->top -
       ((double)state->marker_row + 0.843) * 72.0 /
           (double)state->lpi;
}

static bool cf_v2_text_duplex_extent_is_valid(
    const cf_v2_text_duplex_state_t *state,
    const cf_v2_text_duplex_geometry_t *geometry) {
  const double line_height = 72.0 / (double)state->lpi;
  const double front_x = geometry->left +
      (double)state->marker_column * 72.0 / (double)state->cpi;
  const double back_x = geometry->right +
      (double)state->marker_column * 72.0 / (double)state->cpi;
  const double right_edge = geometry->width - geometry->right;
  const double marker_width = 2.0 * 72.0 / (double)state->cpi;
  const double cell_top = geometry->height - geometry->top -
      (double)state->marker_row * line_height;
  const double cell_bottom = cell_top - line_height;

  return geometry->size_lines > state->marker_row &&
         front_x >= geometry->left && back_x >= geometry->right &&
         front_x + marker_width <= right_edge + CF_V2_TEXT_DUPLEX_TOLERANCE &&
         back_x + marker_width <= right_edge + CF_V2_TEXT_DUPLEX_TOLERANCE &&
         cell_top <= geometry->height - geometry->top +
                         CF_V2_TEXT_DUPLEX_TOLERANCE &&
         cell_bottom >= geometry->bottom - CF_V2_TEXT_DUPLEX_TOLERANCE;
}

static bool cf_v2_text_duplex_append(uint8_t *document, size_t *used,
                                     uint8_t value) {
  if (*used >= CF_V2_TEXT_DUPLEX_MAX_DOCUMENT) {
    return false;
  }
  document[(*used)++] = value;
  return true;
}

static bool cf_v2_text_duplex_build_document(
    const cf_v2_text_duplex_state_t *state,
    const cf_v2_text_duplex_geometry_t *geometry, uint8_t *document,
    size_t *document_size) {
  size_t used = 0U;

  for (unsigned page = 1U; page <= state->page_count; page++) {
    for (unsigned row = 0U; row < state->marker_row; row++) {
      if (!cf_v2_text_duplex_append(document, &used, '\n')) {
        return false;
      }
    }
    for (unsigned column = 0U; column < state->marker_column; column++) {
      if (!cf_v2_text_duplex_append(document, &used, ' ')) {
        return false;
      }
    }
    if (!cf_v2_text_duplex_append(document, &used, 'P') ||
        !cf_v2_text_duplex_append(document, &used,
                                  (uint8_t)('0' + page))) {
      return false;
    }
    if (state->transition == 0U) {
      if (!cf_v2_text_duplex_append(document, &used, '\f')) {
        return false;
      }
    } else {
      for (unsigned line = state->marker_row;
           line < geometry->size_lines; line++) {
        if (!cf_v2_text_duplex_append(document, &used, '\n')) {
          return false;
        }
      }
    }
  }
  *document_size = used;
  return used > 0U && used <= CF_V2_TEXT_DUPLEX_MAX_DOCUMENT;
}

static bool cf_v2_text_duplex_build_ppd(
    const cf_v2_text_duplex_state_t *state, uint8_t *ppd,
    size_t *ppd_size) {
  static const unsigned media[][2] = {{595U, 842U}, {612U, 792U}};
  static const unsigned margins[][4] = {
      {12U, 24U, 36U, 48U}, {18U, 42U, 54U, 30U},
      {54U, 18U, 30U, 42U}, {30U, 54U, 18U, 24U}};
  const char *name = state->media ? "Letter" : "A4";
  const unsigned width = media[state->media][0];
  const unsigned height = media[state->media][1];
  const unsigned left = margins[state->margin_profile][0];
  const unsigned bottom = margins[state->margin_profile][1];
  const unsigned right = width - margins[state->margin_profile][2];
  const unsigned top = height - margins[state->margin_profile][3];
  int length = snprintf(
      (char *)ppd, CF_V2_TEXT_DUPLEX_MAX_PPD,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"2.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"TXTDUP01 asymmetric geometry\"\n"
      "*ShortNickName: \"TXTDUP01\"\n"
      "*NickName: \"TXTDUP01 asymmetric geometry\"\n"
      "*PCFileName: \"TXTDUP01.PPD\"\n"
      "*Product: \"(TXTDUP01)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 2.0\n"
      "*cupsModelNumber: 0\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"text/plain 0 %s\"\n"
      "*OpenUI *PageSize: PickOne\n"
      "*DefaultPageSize: %s\n"
      "*PageSize %s/%s: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*DefaultImageableArea: %s\n"
      "*ImageableArea %s: \"%u %u %u %u\"\n"
      "*DefaultPaperDimension: %s\n"
      "*PaperDimension %s: \"%u %u\"\n"
      "*OpenUI *ColorModel: PickOne\n"
      "*DefaultColorModel: Gray\n"
      "*ColorModel Gray/Gray: \"<</cupsColorSpace 18/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *Resolution: PickOne\n"
      "*DefaultResolution: 300dpi\n"
      "*Resolution 300dpi/300 dpi: \"<</HWResolution[300 300]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n",
      CF_V2_TARGET_NAME, name, name, name, width, height, name, name,
      left, bottom, right, top, name, name, width, height);

  if (length < 0 || (size_t)length >= CF_V2_TEXT_DUPLEX_MAX_PPD) {
    return false;
  }
  *ppd_size = (size_t)length;
  return true;
}

static bool cf_v2_text_duplex_build_options(
    const cf_v2_text_duplex_state_t *state, uint8_t *options,
    size_t *options_size) {
  const char *media = state->media ? "Letter" : "A4";
  const char *sides = state->sides ? "two-sided-long-edge" : "one-sided";
  int length = snprintf(
      (char *)options, CF_V2_TEXT_DUPLEX_MAX_OPTIONS,
      "PageSize=%s ColorModel=Gray Resolution=300dpi "
      "sides=%s orientation-requested=%u columns=1 cpi=%u lpi=%u "
      "wrap=true prettyprint=false number-up=1 charset=us-ascii "
      "content-type=text/plain",
      media, sides, state->orientation, state->cpi, state->lpi);

  if (length < 0 || (size_t)length >= CF_V2_TEXT_DUPLEX_MAX_OPTIONS) {
    return false;
  }
  *options_size = (size_t)length;
  return true;
}

static bool cf_v2_text_duplex_pdf_error(pdfio_file_t *pdf,
                                        const char *message, void *data) {
  cf_v2_text_duplex_error_t *error = (cf_v2_text_duplex_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static bool cf_v2_text_duplex_name_is(pdfio_dict_t *dict, const char *key,
                                      const char *expected) {
  const char *value = dict ? pdfioDictGetName(dict, key) : NULL;

  return value && strcmp(value, expected) == 0;
}

static pdfio_dict_t *cf_v2_text_duplex_dict(pdfio_dict_t *parent,
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

static bool cf_v2_text_duplex_number(const char *token, double *value) {
  char *end = NULL;

  *value = strtod(token, &end);
  return end && end != token && *end == '\0' && isfinite(*value);
}

static int cf_v2_text_duplex_hex_value(char value) {
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

static bool cf_v2_text_duplex_decode_marker(const char *token,
                                            uint8_t marker[2]) {
  size_t length = strlen(token);
  size_t end = length;

  if (length < 5U || token[0] != '<' || token[1] == '<') {
    return false;
  }
  if (token[length - 1U] == '>') {
    end--;
  }
  if (end != 5U) {
    return false;
  }
  for (size_t index = 0U; index < 2U; index++) {
    int high = cf_v2_text_duplex_hex_value(token[1U + index * 2U]);
    int low = cf_v2_text_duplex_hex_value(token[2U + index * 2U]);

    if (high < 0 || low < 0) {
      return false;
    }
    marker[index] = (uint8_t)((high << 4) | low);
  }
  return true;
}

static bool cf_v2_text_duplex_is_operator(const char *token) {
  static const char *const operators[] = {
      "q", "Q", "g", "BT", "ET", "Td", "Tz", "Tf", "Tj"};

  for (size_t index = 0U;
       index < sizeof(operators) / sizeof(operators[0]); index++) {
    if (strcmp(token, operators[index]) == 0) {
      return true;
    }
  }
  return false;
}

static bool cf_v2_text_duplex_process_operator(
    cf_v2_text_duplex_parse_t *parse, const char *token,
    char operands[4][128], size_t operand_count, const char **failure) {
  double first;
  double second;

  if (strcmp(token, "q") == 0) {
    if (operand_count || parse->graphics_depth != 0) {
      return cf_v2_text_duplex_fail(failure, "graphics-q");
    }
    parse->graphics_depth = 1;
    parse->q_count++;
  } else if (strcmp(token, "Q") == 0) {
    if (operand_count || parse->graphics_depth != 1 || parse->text_depth) {
      return cf_v2_text_duplex_fail(failure, "graphics-Q");
    }
    parse->graphics_depth = 0;
    parse->Q_count++;
  } else if (strcmp(token, "BT") == 0) {
    if (operand_count || parse->text_depth != 0 ||
        parse->graphics_depth != 1) {
      return cf_v2_text_duplex_fail(failure, "text-BT");
    }
    parse->text_depth = 1;
    parse->have_position = false;
    parse->have_font = false;
    parse->bt_count++;
  } else if (strcmp(token, "ET") == 0) {
    if (operand_count || parse->text_depth != 1) {
      return cf_v2_text_duplex_fail(failure, "text-ET");
    }
    parse->text_depth = 0;
    parse->et_count++;
  } else if (strcmp(token, "Td") == 0) {
    if (parse->text_depth != 1 || operand_count != 2U ||
        parse->td_count ||
        !cf_v2_text_duplex_number(operands[0], &first) ||
        !cf_v2_text_duplex_number(operands[1], &second)) {
      return cf_v2_text_duplex_fail(failure, "text-Td");
    }
    parse->current_x = first;
    parse->current_y = second;
    parse->have_position = true;
    parse->td_count++;
  } else if (strcmp(token, "Tz") == 0) {
    if (parse->text_depth != 1 || operand_count != 1U ||
        parse->tz_count ||
        !cf_v2_text_duplex_number(operands[0], &first) || first <= 0.0) {
      return cf_v2_text_duplex_fail(failure, "text-Tz");
    }
    parse->tz_count++;
  } else if (strcmp(token, "Tf") == 0) {
    if (parse->text_depth != 1 || operand_count != 2U ||
        parse->tf_count || operands[0][0] != '/' ||
        strlen(operands[0] + 1U) >= sizeof(parse->current_font) ||
        !cf_v2_text_duplex_number(operands[1], &second) || second <= 0.0) {
      return cf_v2_text_duplex_fail(failure, "text-Tf");
    }
    strcpy(parse->current_font, operands[0] + 1U);
    parse->current_font_size = second;
    parse->have_font = true;
    parse->tf_count++;
  } else if (strcmp(token, "Tj") == 0) {
    if (parse->text_depth != 1 || operand_count != 1U ||
        parse->tj_count || !parse->have_position || !parse->have_font ||
        !cf_v2_text_duplex_decode_marker(operands[0],
                                         parse->event.marker)) {
      return cf_v2_text_duplex_fail(failure, "text-Tj");
    }
    parse->event.x = parse->current_x;
    parse->event.y = parse->current_y;
    parse->event.font_size = parse->current_font_size;
    strcpy(parse->event.font, parse->current_font);
    parse->tj_count++;
  } else if (strcmp(token, "g") == 0) {
    if (operand_count != 1U ||
        !cf_v2_text_duplex_number(operands[0], &first)) {
      return cf_v2_text_duplex_fail(failure, "gray-operator");
    }
  } else {
    return cf_v2_text_duplex_fail(failure, "unknown-operator");
  }
  return true;
}

static bool cf_v2_text_duplex_parse_stream(
    pdfio_obj_t *page, cf_v2_text_duplex_parse_t *parse,
    const char **failure) {
  pdfio_stream_t *stream;
  char token[4096];
  char operands[4][128];
  size_t operand_count = 0U;
  bool valid = true;

  memset(parse, 0, sizeof(*parse));
  if (pdfioPageGetNumStreams(page) != 1U ||
      !(stream = pdfioPageOpenStream(page, 0U, true))) {
    return cf_v2_text_duplex_fail(failure, "content-stream");
  }
  while (pdfioStreamGetToken(stream, token, sizeof(token))) {
    if (++parse->token_count > CF_V2_TEXT_DUPLEX_MAX_TOKENS) {
      cf_v2_text_duplex_fail(failure, "content-token-budget");
      valid = false;
      break;
    }
    if (cf_v2_text_duplex_is_operator(token)) {
      if (!cf_v2_text_duplex_process_operator(
              parse, token, operands, operand_count, failure)) {
        valid = false;
        break;
      }
      operand_count = 0U;
    } else {
      size_t length = strlen(token);

      if (operand_count >= 4U || length >= sizeof(operands[0])) {
        cf_v2_text_duplex_fail(failure, "content-operand-budget");
        valid = false;
        break;
      }
      memcpy(operands[operand_count], token, length + 1U);
      operand_count++;
    }
  }
  if (valid &&
      (operand_count || parse->graphics_depth != 0 ||
       parse->text_depth != 0 || parse->q_count != 1U ||
       parse->Q_count != 1U || parse->bt_count != 1U ||
       parse->et_count != 1U || parse->td_count != 1U ||
       parse->tz_count != 1U || parse->tf_count != 1U ||
       parse->tj_count != 1U)) {
    cf_v2_text_duplex_fail(failure, "content-lifecycle");
    valid = false;
  }
  if (!pdfioStreamClose(stream)) {
    cf_v2_text_duplex_fail(failure, "content-close");
    valid = false;
  }
  return valid;
}

static bool cf_v2_text_duplex_close(double actual, double expected) {
  return isfinite(actual) &&
         fabs(actual - expected) <= CF_V2_TEXT_DUPLEX_TOLERANCE;
}

static double cf_v2_text_duplex_media_box_value(double value) {
  return floor(value + 0.5);
}

static bool cf_v2_text_duplex_validate_page(
    pdfio_obj_t *page, unsigned page_number,
    const cf_v2_text_duplex_state_t *state,
    const cf_v2_text_duplex_geometry_t *geometry, const char **failure) {
  pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
  pdfio_dict_t *resources =
      cf_v2_text_duplex_dict(page_dict, "Resources");
  pdfio_dict_t *fonts = cf_v2_text_duplex_dict(resources, "Font");
  cf_v2_text_duplex_parse_t parse;
  pdfio_rect_t media_box;
  pdfio_dict_t *font;
  double expected_x;
  double expected_y;
  double expected_width =
      cf_v2_text_duplex_media_box_value(geometry->media_box_width);
  double expected_height =
      cf_v2_text_duplex_media_box_value(geometry->media_box_height);

  if (!page || !page_dict) {
    snprintf(cf_v2_text_duplex_detail, sizeof(cf_v2_text_duplex_detail),
             "page=%u object=%s dict=%s", page_number,
             page ? "yes" : "no", page_dict ? "yes" : "no");
    return cf_v2_text_duplex_fail(failure, "page-object");
  }
  if (!cf_v2_text_duplex_name_is(page_dict, "Type", "Page")) {
    const char *type = pdfioDictGetName(page_dict, "Type");

    snprintf(cf_v2_text_duplex_detail, sizeof(cf_v2_text_duplex_detail),
             "page=%u type=%s", page_number, type ? type : "(null)");
    return cf_v2_text_duplex_fail(failure, "page-type");
  }
  if (!resources || !fonts) {
    snprintf(cf_v2_text_duplex_detail, sizeof(cf_v2_text_duplex_detail),
             "page=%u resources=%s fonts=%s", page_number,
             resources ? "yes" : "no", fonts ? "yes" : "no");
    return cf_v2_text_duplex_fail(failure, "page-resources");
  }
  if (!pdfioPageGetRect(page, "MediaBox", &media_box)) {
    snprintf(cf_v2_text_duplex_detail, sizeof(cf_v2_text_duplex_detail),
             "page=%u MediaBox=missing", page_number);
    return cf_v2_text_duplex_fail(failure, "page-media-box");
  }
  if (!cf_v2_text_duplex_close(media_box.x1, 0.0) ||
      !cf_v2_text_duplex_close(media_box.y1, 0.0) ||
      !cf_v2_text_duplex_close(media_box.x2, expected_width) ||
      !cf_v2_text_duplex_close(media_box.y2, expected_height)) {
    snprintf(cf_v2_text_duplex_detail, sizeof(cf_v2_text_duplex_detail),
             "page=%u actual=[%.6f %.6f %.6f %.6f] "
             "expected=[0 0 %.6f %.6f] orientation=%u",
             page_number, media_box.x1, media_box.y1, media_box.x2,
             media_box.y2, expected_width, expected_height,
             state->orientation);
    return cf_v2_text_duplex_fail(failure, "page-media-box");
  }
  if (!cf_v2_text_duplex_parse_stream(page, &parse, failure)) {
    return false;
  }
  if (parse.event.marker[0] != 'P' ||
      parse.event.marker[1] != (uint8_t)('0' + page_number) ||
      !isfinite(parse.event.font_size) || parse.event.font_size <= 0.0) {
    return cf_v2_text_duplex_fail(failure, "page-marker");
  }
  cf_v2_text_duplex_expected_position(state, geometry, page_number,
                                      &expected_x, &expected_y);
  if (!cf_v2_text_duplex_close(parse.event.x, expected_x) ||
      !cf_v2_text_duplex_close(parse.event.y, expected_y)) {
    snprintf(cf_v2_text_duplex_detail, sizeof(cf_v2_text_duplex_detail),
             "page=%u actual=(%.6f,%.6f) expected=(%.6f,%.6f) "
             "orientation=%u sides=%u margins=%u",
             page_number, parse.event.x, parse.event.y, expected_x,
             expected_y, state->orientation, state->sides,
             state->margin_profile);
    return cf_v2_text_duplex_fail(failure, "duplex-coordinate");
  }
  font = cf_v2_text_duplex_dict(fonts, parse.event.font);
  if (!font || !cf_v2_text_duplex_name_is(font, "Type", "Font")) {
    return cf_v2_text_duplex_fail(failure, "font-resource-binding");
  }
  return true;
}

static bool cf_v2_text_duplex_validate_file(
    const char *path, const cf_v2_text_duplex_state_t *state,
    const cf_v2_text_duplex_geometry_t *geometry, const char **failure) {
  cf_v2_text_duplex_error_t error = {false};
  pdfio_file_t *pdf = NULL;
  bool valid = false;

  *failure = NULL;
  pdf = pdfioFileOpen(path, NULL, NULL, cf_v2_text_duplex_pdf_error, &error);
  if (!pdf || error.saw_error) {
    cf_v2_text_duplex_fail(failure, "pdf-open");
    goto done;
  }
  if (!cf_v2_text_duplex_name_is(pdfioFileGetCatalog(pdf), "Type",
                                 "Catalog") ||
      pdfioFileGetNumPages(pdf) != state->page_count) {
    cf_v2_text_duplex_fail(failure, "pdf-page-count");
    goto done;
  }
  for (unsigned index = 0U; index < state->page_count; index++) {
    if (!cf_v2_text_duplex_validate_page(
            pdfioFileGetPage(pdf, index), index + 1U, state, geometry,
            failure)) {
      goto done;
    }
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v2_text_duplex_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const uint8_t title[] = "TXTDUP01 geometry job";
  cf_v2_text_duplex_state_t state;
  cf_v2_text_duplex_geometry_t geometry;
  uint8_t ppd[CF_V2_TEXT_DUPLEX_MAX_PPD];
  uint8_t options[CF_V2_TEXT_DUPLEX_MAX_OPTIONS];
  uint8_t document[CF_V2_TEXT_DUPLEX_MAX_DOCUMENT];
  size_t ppd_size = 0U;
  size_t options_size = 0U;
  size_t document_size = 0U;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-text-duplex.XXXXXX";
  const char *failure = NULL;
  int output_fd = -1;
  int executed = 0;
  bool trap_after_cleanup = false;

  if (!data || size != CF_V2_TEXT_DUPLEX_INPUT_SIZE ||
      memcmp(data, CF_V2_TEXT_DUPLEX_MAGIC,
             CF_V2_TEXT_DUPLEX_MAGIC_SIZE) != 0) {
    return 0;
  }
  memset(&result, 0, sizeof(result));
  memset(&job, 0, sizeof(job));
  cf_v2_text_duplex_detail[0] = '\0';
  cf_v2_text_duplex_decode(data + CF_V2_TEXT_DUPLEX_MAGIC_SIZE, &state);
  cf_v2_text_duplex_geometry(&state, &geometry);
  if (!cf_v2_text_duplex_extent_is_valid(&state, &geometry) ||
      !cf_v2_text_duplex_build_ppd(&state, ppd, &ppd_size) ||
      !cf_v2_text_duplex_build_options(&state, options, &options_size) ||
      !cf_v2_text_duplex_build_document(
          &state, &geometry, document, &document_size)) {
    failure = "generated-job-contract";
    trap_after_cleanup = true;
    goto cleanup;
  }

  job.ppd = ppd;
  job.ppd_size = ppd_size;
  job.options = options;
  job.options_size = options_size;
  job.title = title;
  job.title_size = sizeof(title) - 1U;
  job.document = document;
  job.document_size = document_size;
  job.control.copies = 0U;

  cf_v2_texttopdf_active = 1;
  executed = cf_v2_execute_direct_job(&job, 1, &result);
  cf_v2_release_texttopdf_lifecycle();
  if (!executed || result.status != 0) {
    failure = "filter-route-status";
    trap_after_cleanup = true;
    goto cleanup;
  }
  if (!result.captured || !result.output_size ||
      result.output_size > CF_V2_TEXT_DUPLEX_MAX_OUTPUT) {
    failure = "captured-output-bounds";
    trap_after_cleanup = true;
    goto cleanup;
  }
  output_fd = mkstemp(output_path);
  if (output_fd < 0 ||
      cf_v2_write_all(output_fd, result.output, result.output_size) != 0) {
    failure = "oracle-tempfile-write";
    trap_after_cleanup = true;
    goto cleanup;
  }
  if (close(output_fd) != 0) {
    output_fd = -1;
    failure = "oracle-tempfile-close";
    trap_after_cleanup = true;
    goto cleanup;
  }
  output_fd = -1;
  if (!cf_v2_text_duplex_validate_file(output_path, &state, &geometry,
                                       &failure)) {
    trap_after_cleanup = true;
  }

cleanup:
  cf_v2_texttopdf_active = 0;
  cf_v2_release_texttopdf_lifecycle();
  if (output_fd >= 0) {
    close(output_fd);
  }
  unlink(output_path);
  cf_v2_free_run_result(&result);
  if (trap_after_cleanup) {
    fprintf(stderr, "text-duplex-geometry-oracle: %s%s%s\n",
            failure ? failure : "unspecified",
            cf_v2_text_duplex_detail[0] ? ": " : "",
            cf_v2_text_duplex_detail);
    __builtin_trap();
  }
  return 0;
}

static uint64_t cf_v2_text_duplex_random(uint64_t *state) {
  uint64_t value = *state;

  value ^= value >> 12U;
  value ^= value << 25U;
  value ^= value >> 27U;
  *state = value;
  return value * UINT64_C(2685821657736338717);
}

static void cf_v2_text_duplex_canonicalize(uint8_t *data) {
  memcpy(data, CF_V2_TEXT_DUPLEX_MAGIC, CF_V2_TEXT_DUPLEX_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V2_TEXT_DUPLEX_SELECTOR_COUNT;
       index++) {
    data[CF_V2_TEXT_DUPLEX_MAGIC_SIZE + index] %=
        cf_v2_text_duplex_cardinalities[index];
  }
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  uint64_t random = ((uint64_t)seed << 32U) ^ UINT64_C(0x5458544455503031);
  unsigned changes;

  if (!data || max_size < CF_V2_TEXT_DUPLEX_INPUT_SIZE) {
    return 0U;
  }
  if (size != CF_V2_TEXT_DUPLEX_INPUT_SIZE ||
      memcmp(data, CF_V2_TEXT_DUPLEX_MAGIC,
             CF_V2_TEXT_DUPLEX_MAGIC_SIZE) != 0) {
    memcpy(data, CF_V2_TEXT_DUPLEX_MAGIC, CF_V2_TEXT_DUPLEX_MAGIC_SIZE);
    for (size_t index = 0U; index < CF_V2_TEXT_DUPLEX_SELECTOR_COUNT;
         index++) {
      data[CF_V2_TEXT_DUPLEX_MAGIC_SIZE + index] =
          (uint8_t)cf_v2_text_duplex_random(&random);
    }
  }
  cf_v2_text_duplex_canonicalize(data);
  changes = 1U + (unsigned)(cf_v2_text_duplex_random(&random) % 4U);
  for (unsigned change = 0U; change < changes; change++) {
    size_t field = (size_t)(cf_v2_text_duplex_random(&random) %
                            CF_V2_TEXT_DUPLEX_SELECTOR_COUNT);
    unsigned cardinality = cf_v2_text_duplex_cardinalities[field];
    uint8_t *value = data + CF_V2_TEXT_DUPLEX_MAGIC_SIZE + field;
    unsigned delta = 1U + (unsigned)(cf_v2_text_duplex_random(&random) %
                                     (cardinality - 1U));

    *value = (uint8_t)((*value + delta) % cardinality);
  }
  return CF_V2_TEXT_DUPLEX_INPUT_SIZE;
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                 const uint8_t *data2, size_t size2,
                                 uint8_t *out, size_t max_out_size,
                                 unsigned int seed) {
  uint64_t random = ((uint64_t)seed << 32U) ^ UINT64_C(0x4455504c45585044);
  bool valid1 = data1 && size1 == CF_V2_TEXT_DUPLEX_INPUT_SIZE &&
      memcmp(data1, CF_V2_TEXT_DUPLEX_MAGIC,
             CF_V2_TEXT_DUPLEX_MAGIC_SIZE) == 0;
  bool valid2 = data2 && size2 == CF_V2_TEXT_DUPLEX_INPUT_SIZE &&
      memcmp(data2, CF_V2_TEXT_DUPLEX_MAGIC,
             CF_V2_TEXT_DUPLEX_MAGIC_SIZE) == 0;

  if (!out || max_out_size < CF_V2_TEXT_DUPLEX_INPUT_SIZE) {
    return 0U;
  }
  memcpy(out, CF_V2_TEXT_DUPLEX_MAGIC, CF_V2_TEXT_DUPLEX_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V2_TEXT_DUPLEX_SELECTOR_COUNT;
       index++) {
    unsigned cardinality = cf_v2_text_duplex_cardinalities[index];
    uint8_t first = valid1
        ? data1[CF_V2_TEXT_DUPLEX_MAGIC_SIZE + index] % cardinality
        : (uint8_t)(cf_v2_text_duplex_random(&random) % cardinality);
    uint8_t second = valid2
        ? data2[CF_V2_TEXT_DUPLEX_MAGIC_SIZE + index] % cardinality
        : (uint8_t)(cf_v2_text_duplex_random(&random) % cardinality);

    out[CF_V2_TEXT_DUPLEX_MAGIC_SIZE + index] =
        (cf_v2_text_duplex_random(&random) & 1U) ? first : second;
  }
  return CF_V2_TEXT_DUPLEX_INPUT_SIZE;
}
