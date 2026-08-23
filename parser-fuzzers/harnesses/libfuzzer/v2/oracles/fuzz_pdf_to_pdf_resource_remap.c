// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * P2PRES01 prototype: exercise the public cfFilterPDFToPDF full-layout route
 * with valid, generated PDFs whose page resources collide.
 *
 * This first implementation deliberately covers only Font and Form XObject.
 * The resource descriptor table and tag resolver are the extension points for
 * ExtGState, ColorSpace, Pattern, Shading, Properties, and ProcSet.  It also
 * fixes the page shape at two input pages and 2-up, and emits one Contents
 * stream per page.  Those are honest prototype limits, not claimed coverage
 * of the full P2PRES01 audit matrix.
 *
 * The output oracle does not search for rewritten byte strings.  It lexes PDF
 * content itself, excludes names inside literal strings and comments, resolves
 * true Tf/Do operands through the output page's Resources dictionary, and
 * checks harness-authored semantic tags.  This makes a wrong-but-existing
 * remap observable.  Literal strings are compared after independent PDF
 * escape decoding.  Comments remain lexical noise but are not a correctness
 * oracle because a PDF producer may legally discard or rewrite them.
 */

#ifndef CF_V2_TARGET_NAME
#define CF_V2_TARGET_NAME                                                   \
  "fuzz_v2_cupsfilters_pdf_to_pdf_resource_remap_oracle"
#endif
#define CF_V2_FILTER_FUNCTION cfFilterPDFToPDF
#define CF_V2_INPUT_MIME "application/pdf"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_FILTER_OPTIONS_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v2_pdf_res_unused_direct_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <ctype.h>
#include <math.h>
#include <pdfio.h>
#include <stdbool.h>
#include <zlib.h>

#ifndef CF_V2_PDF_RES_MAGIC
#define CF_V2_PDF_RES_MAGIC "P2PRES01"
#endif
#define CF_V2_PDF_RES_MAGIC_SIZE 8U
#define CF_V2_PDF_RES_SELECTOR_SIZE 10U
#define CF_V2_PDF_RES_HEADER_SIZE 18U
#define CF_V2_PDF_RES_MIN_INPUT 19U
#define CF_V2_PDF_RES_MAX_MATERIAL 256U
#define CF_V2_PDF_RES_MAX_INPUT                                         \
  (CF_V2_PDF_RES_HEADER_SIZE + CF_V2_PDF_RES_MAX_MATERIAL)
#define CF_V2_PDF_RES_PAGES 2U
#define CF_V2_PDF_RES_CLASSES 2U
#define CF_V2_PDF_RES_MAX_SPEC_NAME 127U
#define CF_V2_PDF_RES_MAX_NAME 254U
#define CF_V2_PDF_RES_MAX_ENCODED_NAME (3U * CF_V2_PDF_RES_MAX_NAME)
#define CF_V2_PDF_RES_MAX_DECOY 4096U
#define CF_V2_PDF_RES_MAX_CONTENT (72U * 1024U)
#define CF_V2_PDF_RES_MAX_GENERATED (512U * 1024U)
#define CF_V2_PDF_RES_MAX_DECODED (2U * 1024U * 1024U)
#define CF_V2_PDF_RES_MAX_OBJECTS 256U

#define CF_V2_PDF_RES_LANE_DISCOVERY 0U
#define CF_V2_PDF_RES_LANE_CONTINUATION 1U
#define CF_V2_PDF_RES_LANE_LEXICAL_BOUNDARY 2U
#define CF_V2_PDF_RES_LANE_LONG_NAME_BOUNDARY 3U
#define CF_V2_PDF_RES_LANE_REFILL_ORACLE 4U
#ifndef CF_V2_PDF_RES_LANE
#define CF_V2_PDF_RES_LANE CF_V2_PDF_RES_LANE_DISCOVERY
#endif
#if CF_V2_PDF_RES_LANE > CF_V2_PDF_RES_LANE_REFILL_ORACLE
#error "invalid PDF resource-remap lane"
#endif

enum {
  CF_V2_PDF_RES_FONT = 0,
  CF_V2_PDF_RES_XOBJECT = 1,
};

typedef struct cf_v2_pdf_res_error_s {
  bool saw_error;
} cf_v2_pdf_res_error_t;

typedef struct cf_v2_pdf_res_bytes_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
  size_t limit;
} cf_v2_pdf_res_bytes_t;

typedef struct cf_v2_pdf_res_text_s {
  char bytes[CF_V2_PDF_RES_MAX_DECOY];
  size_t length;
} cf_v2_pdf_res_text_t;

typedef struct cf_v2_pdf_res_expect_s {
  bool active[CF_V2_PDF_RES_CLASSES];
  unsigned collision_recipe;
  size_t refill_cut;
  char key[CF_V2_PDF_RES_PAGES][CF_V2_PDF_RES_CLASSES]
          [CF_V2_PDF_RES_MAX_NAME + 1U];
  char encoded[CF_V2_PDF_RES_PAGES][CF_V2_PDF_RES_CLASSES]
              [CF_V2_PDF_RES_MAX_ENCODED_NAME + 1U];
  char tag[CF_V2_PDF_RES_PAGES][CF_V2_PDF_RES_CLASSES][32];
  cf_v2_pdf_res_text_t string_decoy[CF_V2_PDF_RES_PAGES];
  cf_v2_pdf_res_text_t comment_decoy[CF_V2_PDF_RES_PAGES];
} cf_v2_pdf_res_expect_t;

typedef struct cf_v2_pdf_res_scan_s {
  const cf_v2_pdf_res_expect_t *expect;
  pdfio_dict_t *resources;
  const char **failure;
  int current_cell;
  char last_name[CF_V2_PDF_RES_MAX_NAME + 3U];
  bool have_last_name;
  unsigned marker_count[CF_V2_PDF_RES_PAGES];
  unsigned binding_count[CF_V2_PDF_RES_PAGES][CF_V2_PDF_RES_CLASSES];
  unsigned string_count[CF_V2_PDF_RES_PAGES];
  unsigned comment_count[CF_V2_PDF_RES_PAGES];
  char observed_name[CF_V2_PDF_RES_PAGES][CF_V2_PDF_RES_CLASSES]
                    [CF_V2_PDF_RES_MAX_NAME + 3U];
} cf_v2_pdf_res_scan_t;

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

/* Optional -Wl,--wrap=fprintf keeps current upstream's unconditional DEBUG
 * tracing from dominating fuzzing I/O.  It does not alter errors or sanitizer
 * reporting and is not required for semantic correctness. */
int __wrap_fprintf(FILE *stream, const char *format, ...) {
  va_list arguments;
  int result;

  if (stream == stderr && format && strncmp(format, "DEBUG:", 6U) == 0) {
    return 0;
  }
  va_start(arguments, format);
  result = vfprintf(stream, format, arguments);
  va_end(arguments);
  return result;
}

static bool cf_v2_pdf_res_fail(const char **failure, const char *message) {
  if (failure && !*failure) {
    *failure = message;
  }
  return false;
}

static bool cf_v2_pdf_res_error(pdfio_file_t *pdf, const char *message,
                                void *data) {
  cf_v2_pdf_res_error_t *error = (cf_v2_pdf_res_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static bool cf_v2_pdf_res_reserve(cf_v2_pdf_res_bytes_t *bytes,
                                  size_t extra) {
  size_t needed;
  size_t capacity;
  uint8_t *replacement;

  if (!bytes || extra > bytes->limit - bytes->size) {
    return false;
  }
  needed = bytes->size + extra;
  if (needed <= bytes->capacity) {
    return true;
  }
  capacity = bytes->capacity ? bytes->capacity : 1024U;
  while (capacity < needed) {
    if (capacity > bytes->limit / 2U) {
      capacity = bytes->limit;
      break;
    }
    capacity *= 2U;
  }
  replacement = (uint8_t *)realloc(bytes->data, capacity);
  if (!replacement) {
    return false;
  }
  bytes->data = replacement;
  bytes->capacity = capacity;
  return true;
}

static bool cf_v2_pdf_res_append(cf_v2_pdf_res_bytes_t *bytes,
                                 const void *data, size_t size) {
  if (!cf_v2_pdf_res_reserve(bytes, size)) {
    return false;
  }
  memcpy(bytes->data + bytes->size, data, size);
  bytes->size += size;
  return true;
}

static bool cf_v2_pdf_res_puts(cf_v2_pdf_res_bytes_t *bytes,
                               const char *text) {
  return cf_v2_pdf_res_append(bytes, text, strlen(text));
}

static bool cf_v2_pdf_res_repeat(cf_v2_pdf_res_bytes_t *bytes, uint8_t value,
                                 size_t count) {
  if (!cf_v2_pdf_res_reserve(bytes, count)) {
    return false;
  }
  memset(bytes->data + bytes->size, value, count);
  bytes->size += count;
  return true;
}

static bool cf_v2_pdf_res_printf(cf_v2_pdf_res_bytes_t *bytes,
                                 const char *format, ...) {
  char buffer[CF_V2_PDF_RES_MAX_DECOY + 512U];
  va_list arguments;
  int length;

  va_start(arguments, format);
  length = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  return length >= 0 && (size_t)length < sizeof(buffer) &&
         cf_v2_pdf_res_append(bytes, buffer, (size_t)length);
}

static bool cf_v2_pdf_res_is_delimiter(uint8_t ch) {
  return isspace(ch) || strchr("()<>[]{}/%{}", ch) != NULL;
}

static int cf_v2_pdf_res_hex(uint8_t ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  return -1;
}

static bool cf_v2_pdf_res_encode_name(const char *name, unsigned mode,
                                      char *encoded, size_t encoded_size) {
  static const char hex[] = "0123456789ABCDEF";
  size_t out = 0;

  for (size_t index = 0; name[index]; index++) {
    const uint8_t ch = (uint8_t)name[index];
    const bool escape = mode == 2U || (mode == 1U && (index & 1U));

    if (escape) {
      if (out + 3U >= encoded_size) {
        return false;
      }
      encoded[out++] = '#';
      encoded[out++] = hex[ch >> 4];
      encoded[out++] = hex[ch & 15U];
    } else {
      if (out + 1U >= encoded_size) {
        return false;
      }
      encoded[out++] = (char)ch;
    }
  }
  encoded[out] = '\0';
  return true;
}

static bool cf_v2_pdf_res_decode_name(const uint8_t *raw, size_t raw_size,
                                      char *decoded, size_t decoded_size) {
  size_t out = 0;

  for (size_t index = 0; index < raw_size;) {
    int high;
    int low;

    if (raw[index] == '#' && index + 2U < raw_size &&
        (high = cf_v2_pdf_res_hex(raw[index + 1U])) >= 0 &&
        (low = cf_v2_pdf_res_hex(raw[index + 2U])) >= 0) {
      if (out + 1U >= decoded_size || !(decoded[out++] =
                                           (char)((high << 4) | low))) {
        return false;
      }
      index += 3U;
    } else {
      if (out + 1U >= decoded_size || raw[index] == 0U) {
        return false;
      }
      decoded[out++] = (char)raw[index++];
    }
  }
  decoded[out] = '\0';
  return out > 0U;
}

static bool cf_v2_pdf_res_format_decoys(cf_v2_pdf_res_expect_t *expect,
                                        size_t page, unsigned mode) {
  const char *font = expect->encoded[page][CF_V2_PDF_RES_FONT];
  const char *xobject = expect->encoded[page][CF_V2_PDF_RES_XOBJECT];
  cf_v2_pdf_res_text_t *string = &expect->string_decoy[page];
  cf_v2_pdf_res_text_t *comment = &expect->comment_decoy[page];
  int length;

  if (mode == 1U || mode == 3U) {
    if (expect->active[CF_V2_PDF_RES_FONT] &&
        expect->active[CF_V2_PDF_RES_XOBJECT]) {
      length = snprintf(string->bytes, sizeof(string->bytes),
                        "(P2PRES-STRING-C%zu /%s (nested /%s) "
                        "\\(escaped\\))",
                        page, font, xobject);
    } else {
      const char *name = expect->active[CF_V2_PDF_RES_FONT] ? font : xobject;
      length = snprintf(string->bytes, sizeof(string->bytes),
                        "(P2PRES-STRING-C%zu /%s (nested /%s) "
                        "\\(escaped\\))",
                        page, name, name);
    }
    if (length < 0 || (size_t)length >= sizeof(string->bytes)) {
      return false;
    }
    string->length = (size_t)length;
  }

  if (mode == 2U || mode == 3U) {
    if (expect->active[CF_V2_PDF_RES_FONT] &&
        expect->active[CF_V2_PDF_RES_XOBJECT]) {
      length = snprintf(comment->bytes, sizeof(comment->bytes),
                        "%%P2PRES-COMMENT-C%zu /%s /%s", page, font,
                        xobject);
    } else {
      const char *name = expect->active[CF_V2_PDF_RES_FONT] ? font : xobject;
      length = snprintf(comment->bytes, sizeof(comment->bytes),
                        "%%P2PRES-COMMENT-C%zu /%s", page, name);
    }
    if (length < 0 || (size_t)length >= sizeof(comment->bytes)) {
      return false;
    }
    comment->length = (size_t)length;
  }
  return true;
}

static bool cf_v2_pdf_res_model(
    const uint8_t selectors[CF_V2_PDF_RES_SELECTOR_SIZE],
    const uint8_t *material, size_t material_size,
    cf_v2_pdf_res_expect_t *expect) {
  static const size_t lengths[] = {1U, 2U, 31U, 127U, 254U};
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const size_t alphabet_size = sizeof(alphabet) - 1U;
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
  const size_t name_length = 2U;
#else
  const size_t name_length = lengths[selectors[4] % 5U];
#endif
  const unsigned resource_mask = 1U + selectors[1] % 3U;
  const unsigned encoding = selectors[5] % 3U;

  (void)selectors[0]; /* Prototype page shape is intentionally fixed at 2/2. */
  memset(expect, 0, sizeof(*expect));
  expect->active[CF_V2_PDF_RES_FONT] = (resource_mask & 1U) != 0U;
  expect->active[CF_V2_PDF_RES_XOBJECT] = (resource_mask & 2U) != 0U;
  expect->collision_recipe = selectors[3] % 3U;
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
  expect->refill_cut = 1U + selectors[8] % 5U;
#endif

  for (size_t resource = 0; resource < CF_V2_PDF_RES_CLASSES; resource++) {
    char *first = expect->key[0][resource];
    char *second = expect->key[1][resource];

    first[0] = resource == CF_V2_PDF_RES_FONT ? 'F' : 'X';
    for (size_t index = 1U; index < name_length; index++) {
      first[index] = alphabet[(material[(index + 37U * resource) %
                                        material_size] +
                               index + 11U * resource) %
                              alphabet_size];
    }
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
    first[1] = '1';
#endif
    first[name_length] = '\0';
    memcpy(second, first, name_length + 1U);
    if (expect->collision_recipe == 0U) {
      const size_t index = name_length - 1U;
      second[index] = alphabet[((unsigned char)second[index] + 17U) %
                               alphabet_size];
      if (second[index] == first[index]) {
        second[index] = resource == CF_V2_PDF_RES_FONT ? 'G' : 'Y';
      }
    }
    if (!cf_v2_pdf_res_encode_name(first, encoding,
                                    expect->encoded[0][resource],
                                    sizeof(expect->encoded[0][resource])) ||
        !cf_v2_pdf_res_encode_name(second, encoding,
                                    expect->encoded[1][resource],
                                    sizeof(expect->encoded[1][resource]))) {
      return false;
    }
  }

  snprintf(expect->tag[0][CF_V2_PDF_RES_FONT],
           sizeof(expect->tag[0][CF_V2_PDF_RES_FONT]), "Helvetica");
  snprintf(expect->tag[1][CF_V2_PDF_RES_FONT],
           sizeof(expect->tag[1][CF_V2_PDF_RES_FONT]), "%s",
           expect->collision_recipe == 1U ? "Helvetica" : "Courier");
  snprintf(expect->tag[0][CF_V2_PDF_RES_XOBJECT],
           sizeof(expect->tag[0][CF_V2_PDF_RES_XOBJECT]), "P2P-X0-%02X",
           material[0]);
  snprintf(expect->tag[1][CF_V2_PDF_RES_XOBJECT],
           sizeof(expect->tag[1][CF_V2_PDF_RES_XOBJECT]), "%s",
           expect->collision_recipe == 1U
               ? expect->tag[0][CF_V2_PDF_RES_XOBJECT]
               : "P2P-X1");

  return cf_v2_pdf_res_format_decoys(expect, 0U, selectors[6] % 4U) &&
         cf_v2_pdf_res_format_decoys(expect, 1U, selectors[6] % 4U);
}

static bool cf_v2_pdf_res_build_content(
    const uint8_t selectors[CF_V2_PDF_RES_SELECTOR_SIZE],
    const cf_v2_pdf_res_expect_t *expect, size_t page,
    cf_v2_pdf_res_bytes_t *content) {
  static const size_t refill_offsets[] = {0U, 65534U, 65535U, 65536U};
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
  const size_t operator_prefix =
      expect->active[CF_V2_PDF_RES_FONT] ? 3U : 2U;
  const size_t refill = 65536U - operator_prefix - expect->refill_cut;
#else
  const size_t refill = refill_offsets[selectors[8] % 4U];
#endif

  memset(content, 0, sizeof(*content));
  content->limit = CF_V2_PDF_RES_MAX_CONTENT;
  if (!cf_v2_pdf_res_printf(content, "%%P2PRES-CELL:%zu\n", page)) {
    return false;
  }
  if (expect->comment_decoy[page].length &&
      (!cf_v2_pdf_res_append(content, expect->comment_decoy[page].bytes,
                             expect->comment_decoy[page].length) ||
       !cf_v2_pdf_res_puts(content, "\n"))) {
    return false;
  }
  if (expect->string_decoy[page].length &&
      !expect->active[CF_V2_PDF_RES_FONT] &&
      (!cf_v2_pdf_res_puts(content, "BX ") ||
       !cf_v2_pdf_res_append(content, expect->string_decoy[page].bytes,
                             expect->string_decoy[page].length) ||
       !cf_v2_pdf_res_puts(content, " P2PRESnoop EX\n"))) {
    return false;
  }
  if (refill && content->size + 2U < refill) {
    const size_t padding = refill - content->size;

    if (!cf_v2_pdf_res_puts(content, "%") ||
        !cf_v2_pdf_res_repeat(content, 'R', padding - 2U) ||
        !cf_v2_pdf_res_puts(content, "\n") || content->size != refill) {
      return false;
    }
  }
  if (expect->active[CF_V2_PDF_RES_FONT]) {
    if (!cf_v2_pdf_res_printf(
            content, "BT /%s 12 Tf 18 24 Td ",
            expect->encoded[page][CF_V2_PDF_RES_FONT])) {
      return false;
    }
    if (expect->string_decoy[page].length) {
      if (!cf_v2_pdf_res_append(content, expect->string_decoy[page].bytes,
                                expect->string_decoy[page].length)) {
        return false;
      }
    } else if (!cf_v2_pdf_res_printf(content, "(P2PRES-TEXT-C%zu)", page)) {
      return false;
    }
    if (!cf_v2_pdf_res_puts(content, " Tj ET\n")) {
      return false;
    }
  }
  if (expect->active[CF_V2_PDF_RES_XOBJECT] &&
      !cf_v2_pdf_res_printf(content, "q /%s Do Q\n",
                            expect->encoded[page][CF_V2_PDF_RES_XOBJECT])) {
    return false;
  }
  return content->size > 0U;
}

static pdfio_dict_t *cf_v2_pdf_res_child_dict(pdfio_dict_t *dict,
                                               const char *key) {
  pdfio_obj_t *object;

  if (!dict) {
    return NULL;
  }
  if (pdfioDictGetType(dict, key) == PDFIO_VALTYPE_DICT) {
    return pdfioDictGetDict(dict, key);
  }
  if (pdfioDictGetType(dict, key) == PDFIO_VALTYPE_INDIRECT &&
      (object = pdfioDictGetObj(dict, key)) != NULL) {
    return pdfioObjGetDict(object);
  }
  return NULL;
}

static pdfio_dict_t *cf_v2_pdf_res_page_resources(pdfio_obj_t *page) {
  return page ? cf_v2_pdf_res_child_dict(pdfioObjGetDict(page), "Resources")
              : NULL;
}

static pdfio_obj_t *cf_v2_pdf_res_resolve(pdfio_dict_t *resources,
                                          size_t resource,
                                          const char *name) {
  const char *class_name =
      resource == CF_V2_PDF_RES_FONT ? "Font" : "XObject";
  pdfio_dict_t *class_dict =
      cf_v2_pdf_res_child_dict(resources, class_name);

  return class_dict &&
                 pdfioDictGetType(class_dict, name) == PDFIO_VALTYPE_INDIRECT
             ? pdfioDictGetObj(class_dict, name)
             : NULL;
}

static const char *cf_v2_pdf_res_object_tag(pdfio_obj_t *object,
                                            size_t resource) {
  pdfio_dict_t *dict = object ? pdfioObjGetDict(object) : NULL;

  if (!dict) {
    return NULL;
  }
  return resource == CF_V2_PDF_RES_FONT
             ? pdfioDictGetName(dict, "BaseFont")
             : pdfioDictGetString(dict, "P2PResourceTag");
}

static bool cf_v2_pdf_res_check_binding(cf_v2_pdf_res_scan_t *scan,
                                        size_t resource) {
  pdfio_obj_t *object;
  const char *tag;
  const size_t cell = (size_t)scan->current_cell;

  if (scan->current_cell < 0 || cell >= CF_V2_PDF_RES_PAGES ||
      !scan->expect->active[resource] || !scan->have_last_name) {
    return cf_v2_pdf_res_fail(scan->failure, "operand-state");
  }
  object = cf_v2_pdf_res_resolve(scan->resources, resource,
                                 scan->last_name);
  tag = cf_v2_pdf_res_object_tag(object, resource);
  if (!tag || strcmp(tag, scan->expect->tag[cell][resource]) != 0) {
    return cf_v2_pdf_res_fail(scan->failure, "resource-binding");
  }
  if (++scan->binding_count[cell][resource] != 1U) {
    return cf_v2_pdf_res_fail(scan->failure, "resource-multiplicity");
  }
  snprintf(scan->observed_name[cell][resource],
           sizeof(scan->observed_name[cell][resource]), "%s",
           scan->last_name);
  scan->have_last_name = false;
  return true;
}

static int cf_v2_pdf_res_exact_cell(const uint8_t *token, size_t token_size,
                                    const cf_v2_pdf_res_text_t text[2]) {
  for (size_t cell = 0; cell < CF_V2_PDF_RES_PAGES; cell++) {
    if (text[cell].length == token_size && token_size &&
        memcmp(token, text[cell].bytes, token_size) == 0) {
      return (int)cell;
    }
  }
  return -1;
}

static bool cf_v2_pdf_res_decoded_append(cf_v2_pdf_res_text_t *decoded,
                                         uint8_t value) {
  if (!decoded || decoded->length >= sizeof(decoded->bytes)) {
    return false;
  }
  decoded->bytes[decoded->length++] = (char)value;
  return true;
}

static bool cf_v2_pdf_res_decode_string(const uint8_t *token,
                                        size_t token_size,
                                        cf_v2_pdf_res_text_t *decoded) {
  size_t index = 1U;
  unsigned depth = 1U;

  if (!token || token_size < 2U || token[0] != '(' || !decoded) {
    return false;
  }
  memset(decoded, 0, sizeof(*decoded));
  while (index < token_size) {
    uint8_t ch = token[index++];

    if (ch == '\\') {
      unsigned value;
      unsigned digits;

      if (index >= token_size) {
        return false;
      }
      ch = token[index++];
      if (ch == '\r' || ch == '\n') {
        if (ch == '\r' && index < token_size && token[index] == '\n') {
          index++;
        }
        continue;
      }
      if (ch >= '0' && ch <= '7') {
        value = ch - '0';
        for (digits = 1U; digits < 3U && index < token_size &&
                         token[index] >= '0' && token[index] <= '7';
             digits++) {
          value = (value << 3) | (unsigned)(token[index++] - '0');
        }
        if (!cf_v2_pdf_res_decoded_append(decoded, (uint8_t)value)) {
          return false;
        }
        continue;
      }
      switch (ch) {
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        default: break;
      }
      if (!cf_v2_pdf_res_decoded_append(decoded, ch)) {
        return false;
      }
    } else if (ch == '(') {
      depth++;
      if (!cf_v2_pdf_res_decoded_append(decoded, ch)) {
        return false;
      }
    } else if (ch == ')') {
      if (!--depth) {
        return index == token_size;
      }
      if (!cf_v2_pdf_res_decoded_append(decoded, ch)) {
        return false;
      }
    } else {
      if (ch == '\r') {
        if (index < token_size && token[index] == '\n') {
          index++;
        }
        ch = '\n';
      }
      if (!cf_v2_pdf_res_decoded_append(decoded, ch)) {
        return false;
      }
    }
  }
  return false;
}

static int cf_v2_pdf_res_semantic_string_cell(
    const uint8_t *token, size_t token_size,
    const cf_v2_pdf_res_text_t text[2]) {
  cf_v2_pdf_res_text_t observed;

  if (!cf_v2_pdf_res_decode_string(token, token_size, &observed)) {
    return -1;
  }
  for (size_t cell = 0; cell < CF_V2_PDF_RES_PAGES; cell++) {
    cf_v2_pdf_res_text_t expected;

    if (text[cell].length &&
        cf_v2_pdf_res_decode_string((const uint8_t *)text[cell].bytes,
                                    text[cell].length, &expected) &&
        expected.length == observed.length &&
        memcmp(expected.bytes, observed.bytes, observed.length) == 0) {
      return (int)cell;
    }
  }
  return -1;
}

static bool cf_v2_pdf_res_scan_content(cf_v2_pdf_res_scan_t *scan,
                                       const uint8_t *data, size_t size) {
  size_t index = 0;

  while (index < size) {
    const uint8_t ch = data[index];

    if (isspace(ch)) {
      index++;
      continue;
    }
    if (ch == '%') {
      const size_t start = index++;
      int cell;

      while (index < size && data[index] != '\r' && data[index] != '\n') {
        index++;
      }
      if (index - start == strlen("%P2PRES-CELL:0") &&
          memcmp(data + start, "%P2PRES-CELL:",
                 strlen("%P2PRES-CELL:")) == 0 &&
          data[index - 1U] >= '0' && data[index - 1U] < '0' + 2) {
        cell = data[index - 1U] - '0';
        scan->current_cell = cell;
        scan->marker_count[cell]++;
      }
      cell = cf_v2_pdf_res_exact_cell(
          data + start, index - start, scan->expect->comment_decoy);
      if (cell >= 0) {
        scan->comment_count[cell]++;
      }
      continue;
    }
    if (ch == '(') {
      const size_t start = index++;
      unsigned depth = 1U;
      int cell;

      while (index < size && depth) {
        if (data[index] == '\\') {
          index += index + 1U < size ? 2U : 1U;
        } else if (data[index] == '(') {
          depth++;
          index++;
        } else if (data[index] == ')') {
          depth--;
          index++;
        } else {
          index++;
        }
      }
      if (depth) {
        return cf_v2_pdf_res_fail(scan->failure, "unterminated-string");
      }
      cell = cf_v2_pdf_res_semantic_string_cell(
          data + start, index - start, scan->expect->string_decoy);
      if (cell >= 0) {
        scan->string_count[cell]++;
      }
      continue;
    }
    if (ch == '/') {
      const size_t start = ++index;

      while (index < size && !cf_v2_pdf_res_is_delimiter(data[index])) {
        index++;
      }
      if (!cf_v2_pdf_res_decode_name(data + start, index - start,
                                     scan->last_name,
                                     sizeof(scan->last_name))) {
        return cf_v2_pdf_res_fail(scan->failure, "invalid-name-token");
      }
      scan->have_last_name = true;
      continue;
    }
    if (ch == '<' && index + 1U < size && data[index + 1U] != '<') {
      index++;
      while (index < size && data[index] != '>') {
        index++;
      }
      if (index == size) {
        return cf_v2_pdf_res_fail(scan->failure, "unterminated-hex-string");
      }
      index++;
      continue;
    }
    if (strchr("<>[]{}/{}", ch)) {
      index++;
      continue;
    }
    {
      const size_t start = index;
      size_t token_size;

      while (index < size && !cf_v2_pdf_res_is_delimiter(data[index])) {
        index++;
      }
      token_size = index - start;
      if (token_size == 2U && memcmp(data + start, "Tf", 2U) == 0) {
        if (!cf_v2_pdf_res_check_binding(scan, CF_V2_PDF_RES_FONT)) {
          return false;
        }
      } else if (token_size == 2U && memcmp(data + start, "Do", 2U) == 0) {
        if (!cf_v2_pdf_res_check_binding(scan, CF_V2_PDF_RES_XOBJECT)) {
          return false;
        }
      }
    }
  }
  return true;
}

#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
static bool cf_v2_pdf_res_check_refill_geometry(
    pdfio_obj_t *page, const cf_v2_pdf_res_expect_t *expect,
    cf_v2_pdf_res_error_t *error, const char **failure) {
  static const size_t refill_size = 65536U;
  const char *operand =
      expect->active[CF_V2_PDF_RES_FONT] ? "/F#31" : "/X#31";
  const size_t operand_size = 5U;
  const size_t cut = expect->refill_cut;
  uint8_t *first = NULL;
  uint8_t second[32];
  pdfio_stream_t *stream = NULL;
  ssize_t first_count;
  ssize_t second_count;
  bool valid = false;

  if (!page || cut < 1U || cut > operand_size ||
      pdfioPageGetNumStreams(page) != 1U ||
      !(stream = pdfioPageOpenStream(page, 0U, true)) ||
      !(first = (uint8_t *)malloc(refill_size))) {
    cf_v2_pdf_res_fail(failure, "refill-open");
    goto done;
  }
  first_count = pdfioStreamRead(stream, first, refill_size);
  second_count = pdfioStreamRead(stream, second, sizeof(second));
  if (first_count != (ssize_t)refill_size || second_count < 0 ||
      (size_t)second_count < operand_size - cut + 1U || error->saw_error) {
    cf_v2_pdf_res_fail(failure, "refill-read-shape");
    goto done;
  }
  if (memcmp(first + refill_size - cut, operand, cut) != 0 ||
      memcmp(second, operand + cut, operand_size - cut) != 0 ||
      second[operand_size - cut] != ' ') {
    cf_v2_pdf_res_fail(failure, "refill-token-cut");
    goto done;
  }
  valid = true;

done:
  free(first);
  if (stream && !pdfioStreamClose(stream)) {
    cf_v2_pdf_res_fail(failure, "refill-close");
    valid = false;
  }
  return valid && !error->saw_error;
}
#endif

static bool cf_v2_pdf_res_read_page(pdfio_obj_t *page,
                                    cf_v2_pdf_res_bytes_t *decoded,
                                    size_t *decoded_total,
                                    cf_v2_pdf_res_error_t *error,
                                    const char **failure) {
  const size_t streams = pdfioPageGetNumStreams(page);

  if (!streams || streams > 8U) {
    return cf_v2_pdf_res_fail(failure, "contents-count");
  }
  memset(decoded, 0, sizeof(*decoded));
  decoded->limit = CF_V2_PDF_RES_MAX_DECODED;
  for (size_t stream_index = 0; stream_index < streams; stream_index++) {
    pdfio_stream_t *stream = pdfioPageOpenStream(page, stream_index, true);
    uint8_t buffer[4096];
    ssize_t count;
    bool valid = true;

    if (!stream) {
      free(decoded->data);
      memset(decoded, 0, sizeof(*decoded));
      return cf_v2_pdf_res_fail(failure, "contents-open");
    }
    while ((count = pdfioStreamRead(stream, buffer, sizeof(buffer))) > 0) {
      if ((size_t)count > CF_V2_PDF_RES_MAX_DECODED - *decoded_total ||
          !cf_v2_pdf_res_append(decoded, buffer, (size_t)count)) {
        valid = false;
        cf_v2_pdf_res_fail(failure, "decoded-budget");
        break;
      }
      *decoded_total += (size_t)count;
    }
    if (count < 0 || error->saw_error) {
      valid = false;
      cf_v2_pdf_res_fail(failure, "contents-read");
    }
    if (!pdfioStreamClose(stream)) {
      valid = false;
      cf_v2_pdf_res_fail(failure, "contents-close");
    }
    if (!valid || !cf_v2_pdf_res_puts(decoded, "\n")) {
      free(decoded->data);
      memset(decoded, 0, sizeof(*decoded));
      return false;
    }
  }
  return true;
}

static bool cf_v2_pdf_res_validate_path(
    const char *path, const cf_v2_pdf_res_expect_t *expect, bool input,
    const char **failure) {
  cf_v2_pdf_res_error_t error = {false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_pdf_res_error, &error);
  cf_v2_pdf_res_scan_t scan;
  size_t decoded_total = 0;
  bool valid = false;
  const size_t wanted_pages = input ? CF_V2_PDF_RES_PAGES : 1U;

  memset(&scan, 0, sizeof(scan));
  scan.expect = expect;
  scan.failure = failure;
  scan.current_cell = -1;
  if (!pdf || error.saw_error) {
    cf_v2_pdf_res_fail(failure, "strict-reopen");
    goto done;
  }
  if (pdfioFileGetNumPages(pdf) != wanted_pages ||
      pdfioFileGetNumObjs(pdf) > CF_V2_PDF_RES_MAX_OBJECTS) {
    cf_v2_pdf_res_fail(failure, "document-shape");
    goto done;
  }
  {
    pdfio_dict_t *catalog = pdfioFileGetCatalog(pdf);
    pdfio_obj_t *pages_obj = catalog ? pdfioDictGetObj(catalog, "Pages") : NULL;
    pdfio_dict_t *pages = pages_obj ? pdfioObjGetDict(pages_obj) : NULL;

    if (!catalog || !pages ||
        strcmp(pdfioDictGetName(catalog, "Type") ?: "", "Catalog") != 0 ||
        strcmp(pdfioDictGetName(pages, "Type") ?: "", "Pages") != 0 ||
        pdfioDictGetNumber(pages, "Count") != (double)wanted_pages) {
      cf_v2_pdf_res_fail(failure, "page-tree");
      goto done;
    }
  }
  for (size_t page_index = 0; page_index < wanted_pages; page_index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, page_index);
    pdfio_rect_t box;
    cf_v2_pdf_res_bytes_t decoded;

    scan.resources = cf_v2_pdf_res_page_resources(page);
    scan.current_cell = -1;
    scan.have_last_name = false;
    if (!page || !scan.resources || !pdfioPageGetRect(page, "MediaBox", &box) ||
        !isfinite(box.x1) || !isfinite(box.y1) || !isfinite(box.x2) ||
        !isfinite(box.y2) || box.x2 <= box.x1 || box.y2 <= box.y1 ||
        !cf_v2_pdf_res_read_page(page, &decoded, &decoded_total, &error,
                                 failure)) {
      goto done;
    }
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
    if (input && !cf_v2_pdf_res_check_refill_geometry(
                     page, expect, &error, failure)) {
      goto done;
    }
#endif
    if (!cf_v2_pdf_res_scan_content(&scan, decoded.data, decoded.size)) {
      free(decoded.data);
      goto done;
    }
    free(decoded.data);
    if (input && (scan.current_cell < 0 ||
                  (size_t)scan.current_cell != page_index)) {
      cf_v2_pdf_res_fail(failure, "input-cell-order");
      goto done;
    }
  }

  for (size_t cell = 0; cell < CF_V2_PDF_RES_PAGES; cell++) {
    if (scan.marker_count[cell] != 1U ||
        scan.string_count[cell] !=
            (expect->string_decoy[cell].length ? 1U : 0U)) {
      cf_v2_pdf_res_fail(failure, "lexical-decoy");
      goto done;
    }
    for (size_t resource = 0; resource < CF_V2_PDF_RES_CLASSES;
         resource++) {
      const unsigned wanted = expect->active[resource] ? 1U : 0U;

      if (scan.binding_count[cell][resource] != wanted) {
        cf_v2_pdf_res_fail(failure, "binding-count");
        goto done;
      }
    }
  }
  if (!input && expect->collision_recipe == 2U) {
    for (size_t resource = 0; resource < CF_V2_PDF_RES_CLASSES; resource++) {
      if (expect->active[resource] &&
          strcmp(scan.observed_name[0][resource],
                 scan.observed_name[1][resource]) == 0) {
        cf_v2_pdf_res_fail(failure, "collision-not-remapped");
        goto done;
      }
    }
  }
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_LONG_NAME_BOUNDARY
  if (!input) {
    for (size_t cell = 0; cell < CF_V2_PDF_RES_PAGES; cell++) {
      for (size_t resource = 0; resource < CF_V2_PDF_RES_CLASSES;
           resource++) {
        if (expect->active[resource] &&
            strlen(scan.observed_name[cell][resource]) >
                CF_V2_PDF_RES_MAX_SPEC_NAME) {
          cf_v2_pdf_res_fail(failure, "resource-name-length");
          goto done;
        }
      }
    }
  }
#endif
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v2_pdf_res_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

enum {
  CF_V2_PDF_RES_OBJ_CATALOG = 1,
  CF_V2_PDF_RES_OBJ_PAGES = 2,
  CF_V2_PDF_RES_OBJ_PAGE0 = 3,
  CF_V2_PDF_RES_OBJ_CONTENT0 = 4,
  CF_V2_PDF_RES_OBJ_PAGE1 = 5,
  CF_V2_PDF_RES_OBJ_CONTENT1 = 6,
  CF_V2_PDF_RES_OBJ_FONT0 = 7,
  CF_V2_PDF_RES_OBJ_FONT1 = 8,
  CF_V2_PDF_RES_OBJ_XOBJECT0 = 9,
  CF_V2_PDF_RES_OBJ_XOBJECT1 = 10,
  CF_V2_PDF_RES_OBJ_FONT_CLASS0 = 11,
  CF_V2_PDF_RES_OBJ_XOBJECT_CLASS0 = 12,
  CF_V2_PDF_RES_OBJ_RESOURCES0 = 13,
  CF_V2_PDF_RES_OBJ_FONT_CLASS1 = 14,
  CF_V2_PDF_RES_OBJ_XOBJECT_CLASS1 = 15,
  CF_V2_PDF_RES_OBJ_RESOURCES1 = 16,
  CF_V2_PDF_RES_OBJECT_COUNT = 16,
};

static bool cf_v2_pdf_res_make_stream(cf_v2_pdf_res_bytes_t *object,
                                      const char *dictionary_entries,
                                      const uint8_t *data, size_t size,
                                      bool flate) {
  uint8_t *compressed = NULL;
  const uint8_t *payload = data;
  size_t payload_size = size;
  uLongf compressed_size;
  bool valid;

  memset(object, 0, sizeof(*object));
  object->limit = CF_V2_PDF_RES_MAX_GENERATED;
  if (flate) {
    compressed_size = compressBound((uLong)size);
    compressed = (uint8_t *)malloc((size_t)compressed_size);
    if (!compressed ||
        compress2(compressed, &compressed_size, data, (uLong)size,
                  Z_BEST_SPEED) != Z_OK) {
      free(compressed);
      return false;
    }
    payload = compressed;
    payload_size = (size_t)compressed_size;
  }
  valid = cf_v2_pdf_res_printf(
              object, "<< /Length %zu%s%s >>\nstream\n", payload_size,
              flate ? " /Filter /FlateDecode" : "",
              dictionary_entries ? dictionary_entries : "") &&
          cf_v2_pdf_res_append(object, payload, payload_size) &&
          cf_v2_pdf_res_puts(object, "\nendstream");
  free(compressed);
  return valid;
}

static unsigned cf_v2_pdf_res_value_object(
    const cf_v2_pdf_res_expect_t *expect, size_t page, size_t resource) {
  const unsigned first = resource == CF_V2_PDF_RES_FONT
                             ? CF_V2_PDF_RES_OBJ_FONT0
                             : CF_V2_PDF_RES_OBJ_XOBJECT0;

  if (!page || expect->collision_recipe == 1U) {
    return first;
  }
  return first + 1U;
}

static bool cf_v2_pdf_res_append_class(
    cf_v2_pdf_res_bytes_t *bytes, const cf_v2_pdf_res_expect_t *expect,
    size_t page, size_t resource) {
  return cf_v2_pdf_res_printf(
      bytes, "<< /%s %u 0 R >>", expect->key[page][resource],
      cf_v2_pdf_res_value_object(expect, page, resource));
}

static unsigned cf_v2_pdf_res_class_object(size_t page, size_t resource) {
  if (!page) {
    return resource == CF_V2_PDF_RES_FONT
               ? CF_V2_PDF_RES_OBJ_FONT_CLASS0
               : CF_V2_PDF_RES_OBJ_XOBJECT_CLASS0;
  }
  return resource == CF_V2_PDF_RES_FONT
             ? CF_V2_PDF_RES_OBJ_FONT_CLASS1
             : CF_V2_PDF_RES_OBJ_XOBJECT_CLASS1;
}

static bool cf_v2_pdf_res_append_resources(
    cf_v2_pdf_res_bytes_t *bytes, const cf_v2_pdf_res_expect_t *expect,
    size_t page, bool class_indirect) {
  static const char *const class_name[] = {"Font", "XObject"};

  if (!cf_v2_pdf_res_puts(bytes, "<<")) {
    return false;
  }
  for (size_t resource = 0; resource < CF_V2_PDF_RES_CLASSES; resource++) {
    if (!expect->active[resource] ||
        !cf_v2_pdf_res_printf(bytes, " /%s ", class_name[resource])) {
      if (!expect->active[resource]) {
        continue;
      }
      return false;
    }
    if (class_indirect) {
      if (!cf_v2_pdf_res_printf(
              bytes, "%u 0 R",
              cf_v2_pdf_res_class_object(page, resource))) {
        return false;
      }
    } else if (!cf_v2_pdf_res_append_class(bytes, expect, page, resource)) {
      return false;
    }
  }
  return cf_v2_pdf_res_puts(bytes, " >>");
}

static bool cf_v2_pdf_res_make_objects(
    const uint8_t selectors[CF_V2_PDF_RES_SELECTOR_SIZE],
    const cf_v2_pdf_res_expect_t *expect,
    cf_v2_pdf_res_bytes_t objects[CF_V2_PDF_RES_OBJECT_COUNT + 1U]) {
  static const int boxes[][4] = {
      {0, 0, 595, 842},
      {0, 0, 612, 792},
      {0, 0, 842, 595},
      {18, 18, 594, 774},
  };
  static const char form_data[] = "q 0 0 8 8 re f Q\n";
  const bool flate = (selectors[7] & 1U) != 0U;

  for (size_t object = 0; object <= CF_V2_PDF_RES_OBJECT_COUNT; object++) {
    memset(&objects[object], 0, sizeof(objects[object]));
    objects[object].limit = CF_V2_PDF_RES_MAX_GENERATED;
  }
  if (!cf_v2_pdf_res_puts(&objects[CF_V2_PDF_RES_OBJ_CATALOG],
                          "<< /Type /Catalog /Pages 2 0 R >>") ||
      !cf_v2_pdf_res_puts(&objects[CF_V2_PDF_RES_OBJ_PAGES],
                          "<< /Type /Pages /Kids [3 0 R 5 0 R] "
                          "/Count 2 >>") ||
      !cf_v2_pdf_res_puts(&objects[CF_V2_PDF_RES_OBJ_FONT0],
                          "<< /Type /Font /Subtype /Type1 "
                          "/BaseFont /Helvetica >>") ||
      !cf_v2_pdf_res_puts(&objects[CF_V2_PDF_RES_OBJ_FONT1],
                          "<< /Type /Font /Subtype /Type1 "
                          "/BaseFont /Courier >>")) {
    return false;
  }

  for (size_t page = 0; page < CF_V2_PDF_RES_PAGES; page++) {
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
    const bool root_indirect = false;
    const bool class_indirect = false;
#else
    const unsigned container_mode = (selectors[2] + page) % 6U;
    const bool root_indirect =
        container_mode == 1U || container_mode == 3U ||
        (container_mode == 4U && page != 0U);
    const bool class_indirect =
        container_mode == 2U || container_mode == 3U ||
        (container_mode == 5U && page != 0U);
#endif
    const unsigned page_object = page ? CF_V2_PDF_RES_OBJ_PAGE1
                                      : CF_V2_PDF_RES_OBJ_PAGE0;
    const unsigned content_object = page ? CF_V2_PDF_RES_OBJ_CONTENT1
                                         : CF_V2_PDF_RES_OBJ_CONTENT0;
    const unsigned root_object = page ? CF_V2_PDF_RES_OBJ_RESOURCES1
                                      : CF_V2_PDF_RES_OBJ_RESOURCES0;
    const int *box = boxes[(selectors[9] + page) % 4U];
    cf_v2_pdf_res_bytes_t content;

    if (!cf_v2_pdf_res_build_content(selectors, expect, page, &content) ||
        !cf_v2_pdf_res_make_stream(&objects[content_object], NULL,
                                   content.data, content.size, flate)) {
      free(content.data);
      return false;
    }
    free(content.data);

    for (size_t resource = 0; resource < CF_V2_PDF_RES_CLASSES; resource++) {
      const unsigned class_object =
          cf_v2_pdf_res_class_object(page, resource);

      if (!cf_v2_pdf_res_append_class(&objects[class_object], expect, page,
                                      resource)) {
        return false;
      }
    }
    if (!cf_v2_pdf_res_append_resources(&objects[root_object], expect, page,
                                        class_indirect) ||
        !cf_v2_pdf_res_printf(
            &objects[page_object],
            "<< /Type /Page /Parent 2 0 R "
            "/MediaBox [%d %d %d %d] /CropBox [%d %d %d %d] "
            "/Resources ",
            box[0], box[1], box[2], box[3], box[0], box[1], box[2],
            box[3])) {
      return false;
    }
    if ((root_indirect &&
         !cf_v2_pdf_res_printf(&objects[page_object], "%u 0 R",
                               root_object)) ||
        (!root_indirect &&
         !cf_v2_pdf_res_append_resources(&objects[page_object], expect, page,
                                         class_indirect)) ||
        !cf_v2_pdf_res_printf(&objects[page_object],
                              " /Contents %u 0 R >>", content_object)) {
      return false;
    }
  }

  {
    char dictionary[160];

    snprintf(dictionary, sizeof(dictionary),
             " /Type /XObject /Subtype /Form /BBox [0 0 16 16] "
             "/Resources << >> /P2PResourceTag (%s)",
             expect->tag[0][CF_V2_PDF_RES_XOBJECT]);
    if (!cf_v2_pdf_res_make_stream(
            &objects[CF_V2_PDF_RES_OBJ_XOBJECT0], dictionary,
            (const uint8_t *)form_data, sizeof(form_data) - 1U, flate)) {
      return false;
    }
    snprintf(dictionary, sizeof(dictionary),
             " /Type /XObject /Subtype /Form /BBox [0 0 16 16] "
             "/Resources << >> /P2PResourceTag (%s)",
             expect->tag[1][CF_V2_PDF_RES_XOBJECT]);
    if (!cf_v2_pdf_res_make_stream(
            &objects[CF_V2_PDF_RES_OBJ_XOBJECT1], dictionary,
            (const uint8_t *)form_data, sizeof(form_data) - 1U, flate)) {
      return false;
    }
  }
  return true;
}

static uint8_t *cf_v2_pdf_res_build_document(
    const uint8_t selectors[CF_V2_PDF_RES_SELECTOR_SIZE],
    const cf_v2_pdf_res_expect_t *expect, size_t *document_size) {
  cf_v2_pdf_res_bytes_t objects[CF_V2_PDF_RES_OBJECT_COUNT + 1U];
  cf_v2_pdf_res_bytes_t document = {NULL, 0U, 0U,
                                    CF_V2_PDF_RES_MAX_GENERATED};
  size_t offsets[CF_V2_PDF_RES_OBJECT_COUNT + 1U] = {0};
  size_t xref_offset;
  char path[] = "/tmp/cupsfilters-v2-p2pres-input.XXXXXX";
  int fd = -1;
  const char *preflight_failure = NULL;
  bool valid = false;

  memset(objects, 0, sizeof(objects));
  if (!cf_v2_pdf_res_make_objects(selectors, expect, objects) ||
      !cf_v2_pdf_res_puts(&document, "%PDF-1.4\n%\323\364\314\341\n")) {
    goto done;
  }
  for (size_t object = 1U; object <= CF_V2_PDF_RES_OBJECT_COUNT; object++) {
    offsets[object] = document.size;
    if (!cf_v2_pdf_res_printf(&document, "%zu 0 obj\n", object) ||
        !cf_v2_pdf_res_append(&document, objects[object].data,
                              objects[object].size) ||
        !cf_v2_pdf_res_puts(&document, "\nendobj\n")) {
      goto done;
    }
  }
  xref_offset = document.size;
  if (!cf_v2_pdf_res_printf(
          &document, "xref\n0 %u\n0000000000 65535 f \n",
          CF_V2_PDF_RES_OBJECT_COUNT + 1U)) {
    goto done;
  }
  for (size_t object = 1U; object <= CF_V2_PDF_RES_OBJECT_COUNT; object++) {
    if (offsets[object] > 9999999999ULL ||
        !cf_v2_pdf_res_printf(&document, "%010zu 00000 n \n",
                              offsets[object])) {
      goto done;
    }
  }
  if (!cf_v2_pdf_res_printf(
          &document,
          "trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n%zu\n%%%%EOF\n",
          CF_V2_PDF_RES_OBJECT_COUNT + 1U, xref_offset)) {
    goto done;
  }

  fd = mkstemp(path);
  if (fd < 0 || cf_v2_write_all(fd, document.data, document.size) != 0 ||
      close(fd) != 0) {
    goto done;
  }
  fd = -1;
  valid = cf_v2_pdf_res_validate_path(path, expect, true,
                                      &preflight_failure);

done:
  if (fd >= 0) {
    close(fd);
  }
  unlink(path);
  for (size_t object = 0U; object <= CF_V2_PDF_RES_OBJECT_COUNT; object++) {
    free(objects[object].data);
  }
  if (!valid) {
    free(document.data);
    document.data = NULL;
    document.size = 0U;
  }
  *document_size = document.size;
  return document.data;
}

static char *cf_v2_pdf_res_build_ppd(const cf_v2_control_t *control,
                                     size_t *ppd_size) {
  char *ppd = NULL;
  FILE *stream = open_memstream(&ppd, ppd_size);
  int write_status;
  int close_status;

  if (!stream) {
    return NULL;
  }
  write_status = cf_v2_write_ppd(stream, control, CF_V2_TARGET_NAME);
  close_status = fclose(stream);
  if (write_status != 0 || close_status != 0) {
    free(ppd);
    return NULL;
  }
  return ppd;
}

static int cf_v2_pdf_res_options(
    char *buffer, size_t buffer_size,
    const uint8_t selectors[CF_V2_PDF_RES_SELECTOR_SIZE]) {
  static const unsigned orientations[] = {3U, 4U, 5U, 6U};
  static const char *const scaling[] = {"fit", "fill"};
  int length = snprintf(
      buffer, buffer_size,
      "number-up=2 orientation-requested=%u print-scaling=%s "
      "page-border=%s mirror=%s sides=one-sided copies=1 "
      "output-order=normal multiple-document-handling=single-document "
      "job-sheets=none emit-jcl=false",
      orientations[selectors[9] % 4U], scaling[(selectors[9] >> 2) & 1U],
      selectors[9] & 0x08U ? "single" : "none",
      selectors[9] & 0x10U ? "true" : "false");

  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}

static uint32_t cf_v2_pdf_res_random(uint32_t *state) {
  uint32_t value = *state ? *state : 0x9e3779b9U;

  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  *state = value;
  return value;
}

static void cf_v2_pdf_res_apply_lane(
    const uint8_t input[CF_V2_PDF_RES_SELECTOR_SIZE],
    uint8_t output[CF_V2_PDF_RES_SELECTOR_SIZE]) {
  memcpy(output, input, CF_V2_PDF_RES_SELECTOR_SIZE);

#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_CONTINUATION
  /* Keep collision/remap, encoding, container, Flate, refill, and layout
   * mutable while continuing beyond the two current deterministic stops. */
  if (output[3] % 3U != 0U) {
    output[4] %= 4U;
    output[6] = 0U;
  }
#elif CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_LEXICAL_BOUNDARY
  /* Render the string through Tj so rewriting is observably semantic. */
  output[1] = 2U;
  output[3] = 2U;
  output[4] %= 4U;
  output[6] = (uint8_t)(1U + 2U * (output[6] % 2U));
#elif CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_LONG_NAME_BOUNDARY
  /* A valid 127-byte name must not become a 128-byte name after remap. */
  output[3] = 2U;
  output[4] = 3U;
  output[6] = 0U;
#elif CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
  /* One true resource operand crosses one of the five decoded token cuts. */
  output[1] = input[0] & 1U;
  output[2] = 0U;
  output[3] = 2U;
  output[4] = 1U;
  output[5] = 1U;
  output[6] = 0U;
  output[7] = input[2] & 1U;
  output[8] = input[1] % 5U;
  output[9] = input[3];
#endif
}

static size_t cf_v2_pdf_res_initialize(uint8_t *data, size_t max_size,
                                       uint32_t *state) {
  if (!data || max_size < CF_V2_PDF_RES_MIN_INPUT) {
    return 0;
  }
  memcpy(data, CF_V2_PDF_RES_MAGIC, CF_V2_PDF_RES_MAGIC_SIZE);
  for (size_t index = 0; index < CF_V2_PDF_RES_SELECTOR_SIZE; index++) {
    data[CF_V2_PDF_RES_MAGIC_SIZE + index] =
        (uint8_t)cf_v2_pdf_res_random(state);
  }
  data[CF_V2_PDF_RES_HEADER_SIZE] =
      (uint8_t)cf_v2_pdf_res_random(state);
  return CF_V2_PDF_RES_MIN_INPUT;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  const size_t limit = max_size < CF_V2_PDF_RES_MAX_INPUT
                           ? max_size
                           : CF_V2_PDF_RES_MAX_INPUT;
  uint32_t state = seed;

  if (!data || limit < CF_V2_PDF_RES_MIN_INPUT ||
      size < CF_V2_PDF_RES_MIN_INPUT ||
      memcmp(data, CF_V2_PDF_RES_MAGIC, CF_V2_PDF_RES_MAGIC_SIZE) != 0) {
    return cf_v2_pdf_res_initialize(data, limit, &state);
  }
  if (size > limit) {
    size = limit;
  }
  memcpy(data, CF_V2_PDF_RES_MAGIC, CF_V2_PDF_RES_MAGIC_SIZE);
  if (cf_v2_pdf_res_random(&state) % 4U != 3U) {
    const size_t selector =
        CF_V2_PDF_RES_MAGIC_SIZE +
        cf_v2_pdf_res_random(&state) % CF_V2_PDF_RES_SELECTOR_SIZE;
    data[selector] ^=
        (uint8_t)(1U + cf_v2_pdf_res_random(&state) % 255U);
  } else {
    size_t material_size = size - CF_V2_PDF_RES_HEADER_SIZE;

    material_size = LLVMFuzzerMutate(
        data + CF_V2_PDF_RES_HEADER_SIZE, material_size,
        limit - CF_V2_PDF_RES_HEADER_SIZE);
    if (!material_size) {
      data[CF_V2_PDF_RES_HEADER_SIZE] =
          (uint8_t)cf_v2_pdf_res_random(&state);
      material_size = 1U;
    }
    size = CF_V2_PDF_RES_HEADER_SIZE + material_size;
  }
  return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  uint8_t mapped_selectors[CF_V2_PDF_RES_SELECTOR_SIZE];
  const uint8_t *material;
  size_t material_size;
  cf_v2_pdf_res_expect_t expect;
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  size_t ppd_size = 0;
  uint8_t *document = NULL;
  size_t document_size = 0;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-pdf-res.XXXXXX";
  int output_fd = -1;
  int executed;
  bool trap_after_cleanup = false;
  const char *failure = NULL;

  if (!data || size < CF_V2_PDF_RES_MIN_INPUT ||
      size > CF_V2_PDF_RES_MAX_INPUT ||
      memcmp(data, CF_V2_PDF_RES_MAGIC, CF_V2_PDF_RES_MAGIC_SIZE) != 0) {
    return 0;
  }
  cf_v2_pdf_res_apply_lane(data + CF_V2_PDF_RES_MAGIC_SIZE,
                           mapped_selectors);
  selectors = mapped_selectors;
  material = data + CF_V2_PDF_RES_HEADER_SIZE;
  material_size = size - CF_V2_PDF_RES_HEADER_SIZE;
  if (!cf_v2_pdf_res_model(selectors, material, material_size, &expect) ||
      cf_v2_pdf_res_options(options, sizeof(options), selectors) != 0) {
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
    fprintf(stderr, "pdf-resource-refill-oracle: total-map-model\n");
    __builtin_trap();
#else
    return 0;
#endif
  }
  document = cf_v2_pdf_res_build_document(selectors, &expect, &document_size);
  if (!document || document_size > CF_V2_PDF_RES_MAX_GENERATED) {
    free(document);
#if CF_V2_PDF_RES_LANE == CF_V2_PDF_RES_LANE_REFILL_ORACLE
    fprintf(stderr, "pdf-resource-refill-oracle: generated-input-preflight\n");
    __builtin_trap();
#else
    return 0;
#endif
  }

  memset(&control, 0, sizeof(control));
  control.ppd_profile = selectors[9] % 4U;
  control.page_size = selectors[9] % 2U;
  control.orientation = selectors[9] % 4U;
  control.scaling = 1U + ((selectors[9] >> 2) & 1U);
  control.number_up = 1U;
  control.mirror = (selectors[9] >> 4) & 1U;
  ppd = cf_v2_pdf_res_build_ppd(&control, &ppd_size);
  if (!ppd) {
    free(document);
    return 0;
  }

  memset(&job, 0, sizeof(job));
  memset(&result, 0, sizeof(result));
  job.control = control;
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = (const uint8_t *)CF_V2_TARGET_NAME;
  job.title_size = strlen(CF_V2_TARGET_NAME);
  job.document = document;
  job.document_size = document_size;

  executed = cf_v2_execute_direct_job(&job, 1, &result);
  if (!executed) {
    trap_after_cleanup = true;
    failure = "route-not-executed";
  } else {
    if (result.status != 0) {
      trap_after_cleanup = true;
      failure = "filter-status";
    } else if (!result.captured || result.output_size < 5U ||
               result.output_size > CF_V2_CAPTURE_LIMIT ||
               memcmp(result.output, "%PDF-", 5U) != 0) {
      trap_after_cleanup = true;
      failure = "success-output-contract";
    } else if ((output_fd = mkstemp(output_path)) >= 0) {
      const int write_status =
          cf_v2_write_all(output_fd, result.output, result.output_size);
      const int close_status = close(output_fd);

      output_fd = -1;
      if (write_status == 0 && close_status == 0) {
        trap_after_cleanup = !cf_v2_pdf_res_validate_path(
            output_path, &expect, false, &failure);
      } else {
        trap_after_cleanup = true;
        failure = "output-write";
      }
    } else {
      trap_after_cleanup = true;
      failure = "output-tempfile";
    }
  }
  cf_v2_release_filter_options();

  if (output_fd >= 0) {
    close(output_fd);
  }
  unlink(output_path);
  cf_v2_free_run_result(&result);
  free(ppd);
  free(document);
  if (trap_after_cleanup) {
    fprintf(stderr, "pdf-resource-remap-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
