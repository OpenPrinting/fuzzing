// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * P2PVAL01: exercise the four value-type arms of pdftopdf.c's
 * resource_dict_cb through the public cfFilterPDFToPDF full-layout route.
 *
 * Two generated pages are imposed 2-up.  Each page owns one ColorSpace or
 * ExtGState entry whose value is an ARRAY, DICT, NAME, or INDIRECT object.
 * The output oracle lexes the copied content, resolves the true cs/gs
 * operand through the merged Resources dictionary, validates the value, and
 * checks the type-specific collision multiplicity.  No comment is treated as
 * semantic evidence and no upstream source or sanitizer setting is changed.
 */

#ifndef CF_V2_TARGET_NAME
#define CF_V2_TARGET_NAME \
  "fuzz_v2_cupsfilters_pdf_to_pdf_resource_value_oracle"
#endif
#define CF_V2_FILTER_FUNCTION cfFilterPDFToPDF
#define CF_V2_INPUT_MIME "application/pdf"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_FILTER_OPTIONS_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v2_pdf_value_unused_direct_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <ctype.h>
#include <math.h>
#include <pdfio.h>
#include <stdbool.h>
#include <zlib.h>

#ifndef CF_V2_PDF_VALUE_MAGIC
#define CF_V2_PDF_VALUE_MAGIC "P2PVAL01"
#endif
#ifndef CF_V2_PDF_VALUE_CROSS_TYPE
#define CF_V2_PDF_VALUE_CROSS_TYPE 0
#endif
#define CF_V2_PDF_VALUE_MAGIC_SIZE 8U
#define CF_V2_PDF_VALUE_SELECTOR_SIZE 8U
#define CF_V2_PDF_VALUE_HEADER_SIZE 16U
#define CF_V2_PDF_VALUE_MIN_INPUT 17U
#define CF_V2_PDF_VALUE_MAX_MATERIAL 128U
#define CF_V2_PDF_VALUE_MAX_INPUT \
  (CF_V2_PDF_VALUE_HEADER_SIZE + CF_V2_PDF_VALUE_MAX_MATERIAL)
#define CF_V2_PDF_VALUE_PAGES 2U
#define CF_V2_PDF_VALUE_MAX_NAME 63U
#define CF_V2_PDF_VALUE_MAX_ENCODED_NAME (3U * CF_V2_PDF_VALUE_MAX_NAME)
#define CF_V2_PDF_VALUE_OBJECT_COUNT 12U
#define CF_V2_PDF_VALUE_MAX_GENERATED (512U * 1024U)
#define CF_V2_PDF_VALUE_MAX_DECODED (2U * 1024U * 1024U)

typedef enum cf_v2_pdf_value_kind_e {
  CF_V2_PDF_VALUE_ARRAY = 0,
  CF_V2_PDF_VALUE_DICT,
  CF_V2_PDF_VALUE_NAME,
  CF_V2_PDF_VALUE_INDIRECT,
  CF_V2_PDF_VALUE_KIND_COUNT
} cf_v2_pdf_value_kind_t;

typedef enum cf_v2_pdf_value_collision_e {
  CF_V2_PDF_VALUE_UNIQUE = 0,
  CF_V2_PDF_VALUE_SAME_KEY_SAME_VALUE,
  CF_V2_PDF_VALUE_SAME_KEY_DIFFERENT_VALUE,
  CF_V2_PDF_VALUE_COLLISION_COUNT
} cf_v2_pdf_value_collision_t;

typedef struct cf_v2_pdf_value_bytes_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
  size_t limit;
} cf_v2_pdf_value_bytes_t;

typedef struct cf_v2_pdf_value_error_s {
  bool saw_error;
} cf_v2_pdf_value_error_t;

typedef struct cf_v2_pdf_value_model_s {
  cf_v2_pdf_value_kind_t kind;
  cf_v2_pdf_value_kind_t second_kind;
  cf_v2_pdf_value_collision_t collision;
  unsigned root_mode;
  unsigned class_mode;
  unsigned flate;
  unsigned layout;
  unsigned variant[CF_V2_PDF_VALUE_PAGES];
  char key[CF_V2_PDF_VALUE_PAGES][CF_V2_PDF_VALUE_MAX_NAME + 1U];
  char encoded[CF_V2_PDF_VALUE_PAGES]
              [CF_V2_PDF_VALUE_MAX_ENCODED_NAME + 1U];
} cf_v2_pdf_value_model_t;

typedef struct cf_v2_pdf_value_scan_s {
  const cf_v2_pdf_value_model_t *model;
  pdfio_dict_t *class_dict;
  const char **failure;
  int current_cell;
  char last_name[CF_V2_PDF_VALUE_MAX_NAME + 4U];
  bool have_last_name;
  unsigned marker_count[CF_V2_PDF_VALUE_PAGES];
  unsigned binding_count[CF_V2_PDF_VALUE_PAGES];
  unsigned order[CF_V2_PDF_VALUE_PAGES];
  unsigned order_count;
  char observed_name[CF_V2_PDF_VALUE_PAGES]
                    [CF_V2_PDF_VALUE_MAX_NAME + 4U];
} cf_v2_pdf_value_scan_t;

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

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

static bool cf_v2_pdf_value_fail(const char **failure,
                                 const char *message) {
  if (failure && !*failure) {
    *failure = message;
  }
  return false;
}

static bool cf_v2_pdf_value_error(pdfio_file_t *pdf, const char *message,
                                  void *data) {
  cf_v2_pdf_value_error_t *error = (cf_v2_pdf_value_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static bool cf_v2_pdf_value_reserve(cf_v2_pdf_value_bytes_t *bytes,
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

static bool cf_v2_pdf_value_append(cf_v2_pdf_value_bytes_t *bytes,
                                   const void *data, size_t size) {
  if (!cf_v2_pdf_value_reserve(bytes, size)) {
    return false;
  }
  memcpy(bytes->data + bytes->size, data, size);
  bytes->size += size;
  return true;
}

static bool cf_v2_pdf_value_puts(cf_v2_pdf_value_bytes_t *bytes,
                                 const char *text) {
  return cf_v2_pdf_value_append(bytes, text, strlen(text));
}

static bool cf_v2_pdf_value_printf(cf_v2_pdf_value_bytes_t *bytes,
                                   const char *format, ...) {
  char buffer[1024];
  va_list arguments;
  int length;

  va_start(arguments, format);
  length = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  return length >= 0 && (size_t)length < sizeof(buffer) &&
         cf_v2_pdf_value_append(bytes, buffer, (size_t)length);
}

static int cf_v2_pdf_value_hex(uint8_t ch) {
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

static bool cf_v2_pdf_value_is_delimiter(uint8_t ch) {
  return isspace(ch) || strchr("()<>[]{}/%{}", ch) != NULL;
}

static bool cf_v2_pdf_value_encode_name(const char *name, unsigned mode,
                                        char *encoded,
                                        size_t encoded_size) {
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

static bool cf_v2_pdf_value_decode_name(const uint8_t *raw, size_t raw_size,
                                        char *decoded,
                                        size_t decoded_size) {
  size_t out = 0;

  for (size_t index = 0; index < raw_size;) {
    int high;
    int low;

    if (raw[index] == '#' && index + 2U < raw_size &&
        (high = cf_v2_pdf_value_hex(raw[index + 1U])) >= 0 &&
        (low = cf_v2_pdf_value_hex(raw[index + 2U])) >= 0) {
      if (out + 1U >= decoded_size ||
          (decoded[out++] = (char)((high << 4) | low)) == '\0') {
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

static unsigned cf_v2_pdf_value_variant_count(
    cf_v2_pdf_value_kind_t kind) {
  return kind == CF_V2_PDF_VALUE_NAME ? 3U : 4U;
}

static cf_v2_pdf_value_kind_t cf_v2_pdf_value_page_kind(
    const cf_v2_pdf_value_model_t *model, size_t page) {
  return page ? model->second_kind : model->kind;
}

static bool cf_v2_pdf_value_is_colorspace(
    cf_v2_pdf_value_kind_t kind) {
  return kind == CF_V2_PDF_VALUE_ARRAY || kind == CF_V2_PDF_VALUE_NAME;
}

static bool cf_v2_pdf_value_model_init(
    cf_v2_pdf_value_model_t *model,
    const uint8_t selectors[CF_V2_PDF_VALUE_SELECTOR_SIZE],
    const uint8_t *material, size_t material_size) {
  static const size_t lengths[] = {1U, 2U, 31U, 63U};
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const size_t alphabet_size = sizeof(alphabet) - 1U;
  const size_t length = lengths[selectors[4] % 4U];
  const unsigned encoding = selectors[5] % 3U;
  unsigned variants;

  if (!model || !material || !material_size) {
    return false;
  }
  memset(model, 0, sizeof(*model));
#if CF_V2_PDF_VALUE_CROSS_TYPE
  {
    static const cf_v2_pdf_value_kind_t pairs[][2] = {
        {CF_V2_PDF_VALUE_ARRAY, CF_V2_PDF_VALUE_NAME},
        {CF_V2_PDF_VALUE_NAME, CF_V2_PDF_VALUE_ARRAY},
        {CF_V2_PDF_VALUE_DICT, CF_V2_PDF_VALUE_INDIRECT},
        {CF_V2_PDF_VALUE_INDIRECT, CF_V2_PDF_VALUE_DICT},
    };
    const unsigned pair = selectors[0] % 4U;

    model->kind = pairs[pair][0];
    model->second_kind = pairs[pair][1];
  }
#else
  model->kind =
      (cf_v2_pdf_value_kind_t)(selectors[0] % CF_V2_PDF_VALUE_KIND_COUNT);
  model->second_kind = model->kind;
#endif
  model->collision = (cf_v2_pdf_value_collision_t)(
      selectors[1] % CF_V2_PDF_VALUE_COLLISION_COUNT);
#if CF_V2_PDF_VALUE_CROSS_TYPE
  model->collision = CF_V2_PDF_VALUE_SAME_KEY_DIFFERENT_VALUE;
#endif
  model->root_mode = selectors[2] % 3U;
  model->class_mode = selectors[3] % 3U;
  model->flate = selectors[6] % 2U;
  model->layout = selectors[7];
  variants = cf_v2_pdf_value_variant_count(model->kind);
  model->variant[0] = material[0] % variants;
#if CF_V2_PDF_VALUE_CROSS_TYPE
  variants = cf_v2_pdf_value_variant_count(model->second_kind);
  model->variant[1] = material[material_size - 1U] % variants;
#else
  model->variant[1] =
      model->collision == CF_V2_PDF_VALUE_SAME_KEY_SAME_VALUE
          ? model->variant[0]
          : (model->variant[0] + 1U + material[material_size - 1U] %
                                         (variants - 1U)) %
                variants;
#endif

  for (size_t page = 0; page < CF_V2_PDF_VALUE_PAGES; page++) {
    char *key = model->key[page];

    key[0] = cf_v2_pdf_value_is_colorspace(model->kind) ? 'C' : 'G';
    for (size_t index = 1U; index < length; index++) {
      key[index] = alphabet[(material[(index + page * 17U) % material_size] +
                              index * 7U) %
                             alphabet_size];
    }
    key[length] = '\0';
  }
  if (model->collision == CF_V2_PDF_VALUE_UNIQUE) {
    const size_t last = length - 1U;

    model->key[1][last] = model->key[0][last] == 'Z' ? 'Y' : 'Z';
    if (model->key[1][last] == model->key[0][last]) {
      model->key[1][last] = 'Q';
    }
  } else {
    memcpy(model->key[1], model->key[0], length + 1U);
  }
  return cf_v2_pdf_value_encode_name(
             model->key[0], encoding, model->encoded[0],
             sizeof(model->encoded[0])) &&
         cf_v2_pdf_value_encode_name(
             model->key[1], encoding, model->encoded[1],
             sizeof(model->encoded[1]));
}

static const char *cf_v2_pdf_value_class_name(
    const cf_v2_pdf_value_model_t *model) {
  return cf_v2_pdf_value_is_colorspace(model->kind) ? "ColorSpace"
                                                     : "ExtGState";
}

static bool cf_v2_pdf_value_indirect_for_page(unsigned mode, size_t page) {
  return mode == 1U || (mode == 2U && page != 0U);
}

static const uint8_t *cf_v2_pdf_value_lookup(unsigned variant,
                                             size_t *length,
                                             unsigned *hival) {
  static const uint8_t values[][12] = {
      {0x00, 0x00, 0x00, 0xff, 0x00, 0x00},
      {0xff, 0xff, 0xff, 0x00, 0x00, 0xff},
      {0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00},
      {0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00,
       0x00, 0x00, 0xff},
  };
  static const size_t lengths[] = {6U, 6U, 9U, 12U};
  static const unsigned hivals[] = {1U, 1U, 2U, 3U};

  variant %= 4U;
  *length = lengths[variant];
  *hival = hivals[variant];
  return values[variant];
}

static void cf_v2_pdf_value_alpha(unsigned variant, double *stroke,
                                  double *fill, const char **stroke_text,
                                  const char **fill_text) {
  static const double stroke_values[] = {0.25, 0.75, 1.0, 0.5};
  static const double fill_values[] = {0.5, 0.125, 0.0, 0.875};
  static const char *const stroke_strings[] = {".25", ".75", "1", ".5"};
  static const char *const fill_strings[] = {".5", ".125", "0", ".875"};

  variant %= 4U;
  *stroke = stroke_values[variant];
  *fill = fill_values[variant];
  *stroke_text = stroke_strings[variant];
  *fill_text = fill_strings[variant];
}

static const char *cf_v2_pdf_value_device_name(unsigned variant) {
  static const char *const names[] = {
      "DeviceGray", "DeviceRGB", "DeviceCMYK"};

  return names[variant % 3U];
}

static bool cf_v2_pdf_value_append_hex(cf_v2_pdf_value_bytes_t *bytes,
                                       const uint8_t *data, size_t size) {
  static const char hex[] = "0123456789ABCDEF";
  char encoded[24];

  if (size * 2U > sizeof(encoded)) {
    return false;
  }
  for (size_t index = 0; index < size; index++) {
    encoded[index * 2U] = hex[data[index] >> 4];
    encoded[index * 2U + 1U] = hex[data[index] & 15U];
  }
  return cf_v2_pdf_value_append(bytes, encoded, size * 2U);
}

static bool cf_v2_pdf_value_append_value(cf_v2_pdf_value_bytes_t *bytes,
                                         const cf_v2_pdf_value_model_t *model,
                                         size_t page) {
  const cf_v2_pdf_value_kind_t kind =
      cf_v2_pdf_value_page_kind(model, page);

  if (kind == CF_V2_PDF_VALUE_ARRAY) {
    size_t length;
    unsigned hival;
    const uint8_t *lookup =
        cf_v2_pdf_value_lookup(model->variant[page], &length, &hival);

    return cf_v2_pdf_value_printf(bytes, "[/Indexed /DeviceRGB %u <",
                                  hival) &&
           cf_v2_pdf_value_append_hex(bytes, lookup, length) &&
           cf_v2_pdf_value_puts(bytes, ">]");
  }
  if (kind == CF_V2_PDF_VALUE_NAME) {
    return cf_v2_pdf_value_printf(
        bytes, "/%s", cf_v2_pdf_value_device_name(model->variant[page]));
  }
  if (kind == CF_V2_PDF_VALUE_DICT) {
    double stroke;
    double fill;
    const char *stroke_text;
    const char *fill_text;

    cf_v2_pdf_value_alpha(model->variant[page], &stroke, &fill,
                          &stroke_text, &fill_text);
    (void)stroke;
    (void)fill;
    return cf_v2_pdf_value_printf(
        bytes, "<< /Type /ExtGState /CA %s /ca %s >>", stroke_text,
        fill_text);
  }
  return cf_v2_pdf_value_printf(
      bytes, "%u 0 R",
      page &&
              model->collision != CF_V2_PDF_VALUE_SAME_KEY_SAME_VALUE
          ? 8U
          : 7U);
}

static bool cf_v2_pdf_value_append_class(
    cf_v2_pdf_value_bytes_t *bytes, const cf_v2_pdf_value_model_t *model,
    size_t page) {
  return cf_v2_pdf_value_printf(bytes, "<< /%s ", model->encoded[page]) &&
         cf_v2_pdf_value_append_value(bytes, model, page) &&
         cf_v2_pdf_value_puts(bytes, " >>");
}

static bool cf_v2_pdf_value_append_resources(
    cf_v2_pdf_value_bytes_t *bytes, const cf_v2_pdf_value_model_t *model,
    size_t page) {
  if (!cf_v2_pdf_value_printf(bytes, "<< /%s ",
                              cf_v2_pdf_value_class_name(model))) {
    return false;
  }
  if (cf_v2_pdf_value_indirect_for_page(model->class_mode, page)) {
    if (!cf_v2_pdf_value_printf(bytes, "%u 0 R", page ? 10U : 9U)) {
      return false;
    }
  } else if (!cf_v2_pdf_value_append_class(bytes, model, page)) {
    return false;
  }
  return cf_v2_pdf_value_puts(bytes, " >>");
}

static bool cf_v2_pdf_value_make_content(
    cf_v2_pdf_value_bytes_t *content,
    const cf_v2_pdf_value_model_t *model, size_t page) {
  const cf_v2_pdf_value_kind_t kind =
      cf_v2_pdf_value_page_kind(model, page);
  const char *device;

  memset(content, 0, sizeof(*content));
  content->limit = 4096U;
  if (!cf_v2_pdf_value_printf(content,
                              "BX (P2PVAL-CELL-%zu) P2PValCell EX\n",
                              page)) {
    return false;
  }
  if (kind == CF_V2_PDF_VALUE_ARRAY) {
    return cf_v2_pdf_value_printf(content, "/%s cs 1 sc\n",
                                  model->encoded[page]);
  }
  if (kind == CF_V2_PDF_VALUE_NAME) {
    device = cf_v2_pdf_value_device_name(model->variant[page]);
    if (!cf_v2_pdf_value_printf(content, "/%s cs ",
                                model->encoded[page])) {
      return false;
    }
    if (!strcmp(device, "DeviceGray")) {
      return cf_v2_pdf_value_puts(content, "0 sc\n");
    }
    if (!strcmp(device, "DeviceRGB")) {
      return cf_v2_pdf_value_puts(content, "0 0 0 sc\n");
    }
    return cf_v2_pdf_value_puts(content, "0 0 0 1 sc\n");
  }
  return cf_v2_pdf_value_printf(content, "q /%s gs Q\n",
                                model->encoded[page]);
}

static bool cf_v2_pdf_value_make_stream(cf_v2_pdf_value_bytes_t *object,
                                        const uint8_t *data, size_t size,
                                        bool flate) {
  uint8_t *compressed = NULL;
  const uint8_t *payload = data;
  size_t payload_size = size;
  uLongf compressed_size;
  bool valid;

  memset(object, 0, sizeof(*object));
  object->limit = CF_V2_PDF_VALUE_MAX_GENERATED;
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
  valid = cf_v2_pdf_value_printf(
              object, "<< /Length %zu%s >>\nstream\n", payload_size,
              flate ? " /Filter /FlateDecode" : "") &&
          cf_v2_pdf_value_append(object, payload, payload_size) &&
          cf_v2_pdf_value_puts(object, "\nendstream");
  free(compressed);
  return valid;
}

static bool cf_v2_pdf_value_make_objects(
    const cf_v2_pdf_value_model_t *model,
    cf_v2_pdf_value_bytes_t objects[CF_V2_PDF_VALUE_OBJECT_COUNT + 1U]) {
  static const int boxes[][4] = {
      {0, 0, 595, 842}, {0, 0, 612, 792},
      {0, 0, 842, 595}, {18, 18, 594, 774}};

  for (size_t object = 0; object <= CF_V2_PDF_VALUE_OBJECT_COUNT;
       object++) {
    memset(&objects[object], 0, sizeof(objects[object]));
    objects[object].limit = CF_V2_PDF_VALUE_MAX_GENERATED;
  }
  if (!cf_v2_pdf_value_puts(&objects[1],
                            "<< /Type /Catalog /Pages 2 0 R >>") ||
      !cf_v2_pdf_value_puts(&objects[2],
                            "<< /Type /Pages /Kids [3 0 R 5 0 R] "
                            "/Count 2 >>")) {
    return false;
  }
  for (size_t page = 0; page < CF_V2_PDF_VALUE_PAGES; page++) {
    double stroke;
    double fill;
    const char *stroke_text;
    const char *fill_text;
    const unsigned value_object = page ? 8U : 7U;
    const unsigned class_object = page ? 10U : 9U;
    const unsigned root_object = page ? 12U : 11U;
    const unsigned page_object = page ? 5U : 3U;
    const unsigned content_object = page ? 6U : 4U;
    const int *box = boxes[(model->layout + page) % 4U];
    cf_v2_pdf_value_bytes_t content;

    cf_v2_pdf_value_alpha(model->variant[page], &stroke, &fill,
                          &stroke_text, &fill_text);
    (void)stroke;
    (void)fill;
    if (!cf_v2_pdf_value_printf(
            &objects[value_object],
            "<< /Type /ExtGState /CA %s /ca %s >>", stroke_text,
            fill_text) ||
        !cf_v2_pdf_value_append_class(&objects[class_object], model,
                                      page) ||
        !cf_v2_pdf_value_append_resources(&objects[root_object], model,
                                          page) ||
        !cf_v2_pdf_value_make_content(&content, model, page) ||
        !cf_v2_pdf_value_make_stream(&objects[content_object], content.data,
                                     content.size, model->flate != 0U)) {
      free(content.data);
      return false;
    }
    free(content.data);
    if (!cf_v2_pdf_value_printf(
            &objects[page_object],
            "<< /Type /Page /Parent 2 0 R "
            "/MediaBox [%d %d %d %d] /CropBox [%d %d %d %d] "
            "/Resources ",
            box[0], box[1], box[2], box[3], box[0], box[1], box[2],
            box[3])) {
      return false;
    }
    if (cf_v2_pdf_value_indirect_for_page(model->root_mode, page)) {
      if (!cf_v2_pdf_value_printf(&objects[page_object], "%u 0 R",
                                  root_object)) {
        return false;
      }
    } else if (!cf_v2_pdf_value_append_resources(&objects[page_object],
                                                 model, page)) {
      return false;
    }
    if (!cf_v2_pdf_value_printf(&objects[page_object],
                                " /Contents %u 0 R >>",
                                content_object)) {
      return false;
    }
  }
  return true;
}

static uint8_t *cf_v2_pdf_value_build_document(
    const cf_v2_pdf_value_model_t *model, size_t *document_size) {
  cf_v2_pdf_value_bytes_t objects[CF_V2_PDF_VALUE_OBJECT_COUNT + 1U];
  cf_v2_pdf_value_bytes_t document = {
      NULL, 0U, 0U, CF_V2_PDF_VALUE_MAX_GENERATED};
  size_t offsets[CF_V2_PDF_VALUE_OBJECT_COUNT + 1U] = {0};
  size_t xref_offset;
  bool valid = false;

  memset(objects, 0, sizeof(objects));
  if (!cf_v2_pdf_value_make_objects(model, objects) ||
      !cf_v2_pdf_value_puts(&document, "%PDF-1.4\n%\323\364\314\341\n")) {
    goto done;
  }
  for (size_t object = 1U; object <= CF_V2_PDF_VALUE_OBJECT_COUNT;
       object++) {
    offsets[object] = document.size;
    if (!cf_v2_pdf_value_printf(&document, "%zu 0 obj\n", object) ||
        !cf_v2_pdf_value_append(&document, objects[object].data,
                                objects[object].size) ||
        !cf_v2_pdf_value_puts(&document, "\nendobj\n")) {
      goto done;
    }
  }
  xref_offset = document.size;
  if (!cf_v2_pdf_value_printf(
          &document, "xref\n0 %u\n0000000000 65535 f \n",
          CF_V2_PDF_VALUE_OBJECT_COUNT + 1U)) {
    goto done;
  }
  for (size_t object = 1U; object <= CF_V2_PDF_VALUE_OBJECT_COUNT;
       object++) {
    if (offsets[object] > 9999999999ULL ||
        !cf_v2_pdf_value_printf(&document, "%010zu 00000 n \n",
                                offsets[object])) {
      goto done;
    }
  }
  valid = cf_v2_pdf_value_printf(
      &document,
      "trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n%zu\n%%%%EOF\n",
      CF_V2_PDF_VALUE_OBJECT_COUNT + 1U, xref_offset);

done:
  for (size_t object = 0; object <= CF_V2_PDF_VALUE_OBJECT_COUNT;
       object++) {
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

static pdfio_dict_t *cf_v2_pdf_value_child_dict(pdfio_dict_t *dict,
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

static pdfio_dict_t *cf_v2_pdf_value_class_dict(
    pdfio_obj_t *page, const cf_v2_pdf_value_model_t *model) {
  pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
  pdfio_dict_t *resources =
      cf_v2_pdf_value_child_dict(page_dict, "Resources");

  return cf_v2_pdf_value_child_dict(
      resources, cf_v2_pdf_value_class_name(model));
}

static bool cf_v2_pdf_value_close(double left, double right) {
  return fabs(left - right) < 0.000001;
}

static bool cf_v2_pdf_value_validate_binding(
    pdfio_dict_t *class_dict, const cf_v2_pdf_value_model_t *model,
    size_t cell, const char *name, const char **failure) {
  const cf_v2_pdf_value_kind_t kind =
      cf_v2_pdf_value_page_kind(model, cell);
  const unsigned variant = model->variant[cell];

  if (!class_dict || !name) {
    return cf_v2_pdf_value_fail(failure, "resource-class");
  }
  if (kind == CF_V2_PDF_VALUE_ARRAY) {
    pdfio_array_t *array;
    size_t expected_length;
    size_t observed_length = 0;
    unsigned hival;
    const uint8_t *expected =
        cf_v2_pdf_value_lookup(variant, &expected_length, &hival);
    const uint8_t *observed;

    if (pdfioDictGetType(class_dict, name) != PDFIO_VALTYPE_ARRAY ||
        !(array = pdfioDictGetArray(class_dict, name)) ||
        pdfioArrayGetSize(array) != 4U ||
        strcmp(pdfioArrayGetName(array, 0) ?: "", "Indexed") != 0 ||
        strcmp(pdfioArrayGetName(array, 1) ?: "", "DeviceRGB") != 0 ||
        !cf_v2_pdf_value_close(pdfioArrayGetNumber(array, 2),
                               (double)hival) ||
        !(observed = pdfioArrayGetBinary(array, 3, &observed_length)) ||
        observed_length != expected_length ||
        memcmp(observed, expected, expected_length) != 0) {
      return cf_v2_pdf_value_fail(failure, "array-value");
    }
    return true;
  }
  if (kind == CF_V2_PDF_VALUE_NAME) {
    const char *observed = pdfioDictGetName(class_dict, name);

    return (observed &&
            strcmp(observed, cf_v2_pdf_value_device_name(variant)) == 0) ||
           cf_v2_pdf_value_fail(failure, "name-value");
  }
  {
    pdfio_dict_t *dict = NULL;
    double stroke;
    double fill;
    const char *stroke_text;
    const char *fill_text;

    if (kind == CF_V2_PDF_VALUE_DICT) {
      if (pdfioDictGetType(class_dict, name) != PDFIO_VALTYPE_DICT) {
        return cf_v2_pdf_value_fail(failure, "dict-type");
      }
      dict = pdfioDictGetDict(class_dict, name);
    } else {
      pdfio_obj_t *object;

      if (pdfioDictGetType(class_dict, name) != PDFIO_VALTYPE_INDIRECT ||
          !(object = pdfioDictGetObj(class_dict, name))) {
        return cf_v2_pdf_value_fail(failure, "indirect-type");
      }
      dict = pdfioObjGetDict(object);
    }
    cf_v2_pdf_value_alpha(variant, &stroke, &fill, &stroke_text,
                          &fill_text);
    (void)stroke_text;
    (void)fill_text;
    return (dict &&
            strcmp(pdfioDictGetName(dict, "Type") ?: "", "ExtGState") ==
                0 &&
            cf_v2_pdf_value_close(pdfioDictGetNumber(dict, "CA"), stroke) &&
            cf_v2_pdf_value_close(pdfioDictGetNumber(dict, "ca"), fill)) ||
           cf_v2_pdf_value_fail(failure, "graphics-state-value");
  }
}

static bool cf_v2_pdf_value_marker(const uint8_t *token, size_t size,
                                   unsigned *cell) {
  static const char prefix[] = "P2PVAL-CELL-";

  if (!token || size != sizeof(prefix) + 2U || token[0] != '(' ||
      token[size - 1U] != ')' ||
      memcmp(token + 1U, prefix, sizeof(prefix) - 1U) != 0 ||
      token[size - 2U] < '0' || token[size - 2U] > '1') {
    return false;
  }
  *cell = token[size - 2U] - '0';
  return true;
}

static bool cf_v2_pdf_value_check_operator(cf_v2_pdf_value_scan_t *scan,
                                           const uint8_t *token,
                                           size_t size) {
  const bool wanted_cs =
      scan->current_cell >= 0 &&
      cf_v2_pdf_value_is_colorspace(cf_v2_pdf_value_page_kind(
          scan->model, (size_t)scan->current_cell));
  const bool matches =
      (wanted_cs && size == 2U && memcmp(token, "cs", 2U) == 0) ||
      (!wanted_cs && size == 2U && memcmp(token, "gs", 2U) == 0);
  size_t cell;

  if (!matches) {
    return true;
  }
  if (scan->current_cell < 0 || !scan->have_last_name) {
    return cf_v2_pdf_value_fail(scan->failure, "operand-state");
  }
  cell = (size_t)scan->current_cell;
  if (!cf_v2_pdf_value_validate_binding(scan->class_dict, scan->model,
                                        cell, scan->last_name,
                                        scan->failure) ||
      ++scan->binding_count[cell] != 1U) {
    return false;
  }
  snprintf(scan->observed_name[cell], sizeof(scan->observed_name[cell]),
           "%s", scan->last_name);
  scan->have_last_name = false;
  return true;
}

static bool cf_v2_pdf_value_scan_content(cf_v2_pdf_value_scan_t *scan,
                                         const uint8_t *data, size_t size) {
  size_t index = 0;

  while (index < size) {
    const uint8_t ch = data[index];

    if (isspace(ch)) {
      index++;
      continue;
    }
    if (ch == '%') {
      while (index < size && data[index] != '\r' && data[index] != '\n') {
        index++;
      }
      continue;
    }
    if (ch == '(') {
      const size_t start = index++;
      unsigned depth = 1U;
      unsigned cell;

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
        return cf_v2_pdf_value_fail(scan->failure,
                                    "unterminated-string");
      }
      if (cf_v2_pdf_value_marker(data + start, index - start, &cell)) {
        scan->current_cell = (int)cell;
        scan->marker_count[cell]++;
        if (scan->order_count >= CF_V2_PDF_VALUE_PAGES) {
          return cf_v2_pdf_value_fail(scan->failure, "marker-count");
        }
        scan->order[scan->order_count++] = cell;
        scan->have_last_name = false;
      }
      continue;
    }
    if (ch == '/') {
      const size_t start = ++index;

      while (index < size && !cf_v2_pdf_value_is_delimiter(data[index])) {
        index++;
      }
      if (!cf_v2_pdf_value_decode_name(data + start, index - start,
                                       scan->last_name,
                                       sizeof(scan->last_name))) {
        return cf_v2_pdf_value_fail(scan->failure, "name-token");
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
        return cf_v2_pdf_value_fail(scan->failure,
                                    "unterminated-hex-string");
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

      while (index < size && !cf_v2_pdf_value_is_delimiter(data[index])) {
        index++;
      }
      if (!cf_v2_pdf_value_check_operator(scan, data + start,
                                          index - start)) {
        return false;
      }
      if (index == start) {
        index++;
      }
    }
  }
  return true;
}

static bool cf_v2_pdf_value_read_page(pdfio_obj_t *page,
                                      cf_v2_pdf_value_bytes_t *decoded,
                                      size_t *decoded_total,
                                      cf_v2_pdf_value_error_t *error,
                                      const char **failure) {
  const size_t streams = pdfioPageGetNumStreams(page);

  if (!streams || streams > 8U) {
    return cf_v2_pdf_value_fail(failure, "contents-count");
  }
  memset(decoded, 0, sizeof(*decoded));
  decoded->limit = CF_V2_PDF_VALUE_MAX_DECODED;
  for (size_t stream_index = 0; stream_index < streams; stream_index++) {
    pdfio_stream_t *stream = pdfioPageOpenStream(page, stream_index, true);
    uint8_t buffer[4096];
    ssize_t count;
    bool valid = stream != NULL;

    if (!stream) {
      free(decoded->data);
      memset(decoded, 0, sizeof(*decoded));
      return cf_v2_pdf_value_fail(failure, "contents-open");
    }
    while ((count = pdfioStreamRead(stream, buffer, sizeof(buffer))) > 0) {
      if ((size_t)count > CF_V2_PDF_VALUE_MAX_DECODED - *decoded_total ||
          !cf_v2_pdf_value_append(decoded, buffer, (size_t)count)) {
        valid = false;
        cf_v2_pdf_value_fail(failure, "decoded-budget");
        break;
      }
      *decoded_total += (size_t)count;
    }
    if (count < 0 || error->saw_error) {
      valid = false;
      cf_v2_pdf_value_fail(failure, "contents-read");
    }
    if (!pdfioStreamClose(stream)) {
      valid = false;
      cf_v2_pdf_value_fail(failure, "contents-close");
    }
    if (!valid || !cf_v2_pdf_value_puts(decoded, "\n")) {
      free(decoded->data);
      memset(decoded, 0, sizeof(*decoded));
      return false;
    }
  }
  return true;
}

static unsigned cf_v2_pdf_value_expected_entries(
    const cf_v2_pdf_value_model_t *model) {
#if CF_V2_PDF_VALUE_CROSS_TYPE
  (void)model;
  return 2U;
#else
  return model->kind == CF_V2_PDF_VALUE_NAME &&
                 model->collision == CF_V2_PDF_VALUE_SAME_KEY_SAME_VALUE
             ? 1U
             : 2U;
#endif
}

static unsigned cf_v2_pdf_value_expected_total_entries(
    const cf_v2_pdf_value_model_t *model) {
  const unsigned defaults =
      cf_v2_pdf_value_is_colorspace(model->kind) ? 3U : 0U;

  return cf_v2_pdf_value_expected_entries(model) + defaults;
}

static bool cf_v2_pdf_value_validate_path(
    const char *path, const cf_v2_pdf_value_model_t *model,
    bool input_document, const char **failure) {
  cf_v2_pdf_value_error_t error = {false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_pdf_value_error, &error);
  cf_v2_pdf_value_scan_t scan;
  size_t decoded_total = 0;
  size_t output_resource_entries = 0;
  bool valid = false;

  memset(&scan, 0, sizeof(scan));
  scan.model = model;
  scan.failure = failure;
  scan.current_cell = -1;
  const size_t wanted_pages =
      input_document ? CF_V2_PDF_VALUE_PAGES : 1U;

  if (!pdf || error.saw_error ||
      pdfioFileGetNumPages(pdf) != wanted_pages ||
      pdfioFileGetNumObjs(pdf) > 128U) {
    cf_v2_pdf_value_fail(failure, "strict-reopen");
    goto done;
  }
  for (size_t page_index = 0; page_index < wanted_pages; page_index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, page_index);
    pdfio_rect_t box;
    cf_v2_pdf_value_bytes_t decoded;
    const unsigned wanted_entries =
        input_document ? 1U
                       : cf_v2_pdf_value_expected_total_entries(model);

    scan.class_dict = cf_v2_pdf_value_class_dict(page, model);
    if (!page) {
      cf_v2_pdf_value_fail(failure, "output-page");
      goto done;
    }
    if (!scan.class_dict) {
      cf_v2_pdf_value_fail(failure, "output-resource-class");
      goto done;
    }
    if (!input_document) {
      output_resource_entries = pdfioDictGetNumPairs(scan.class_dict);
    }
    if (pdfioDictGetNumPairs(scan.class_dict) != wanted_entries) {
#if CF_V2_PDF_VALUE_CROSS_TYPE
      if (input_document)
#endif
      {
        fprintf(stderr,
                "pdf-resource-value-count: got=%zu expected=%u kind=%u "
                "collision=%u\n",
                pdfioDictGetNumPairs(scan.class_dict),
                wanted_entries,
                (unsigned)model->kind, (unsigned)model->collision);
        cf_v2_pdf_value_fail(failure, "resource-entry-count");
        goto done;
      }
    }
    if (!input_document &&
        cf_v2_pdf_value_is_colorspace(model->kind) &&
        (pdfioDictGetType(scan.class_dict, "DefaultGray") ==
             PDFIO_VALTYPE_NONE ||
         pdfioDictGetType(scan.class_dict, "DefaultRGB") ==
             PDFIO_VALTYPE_NONE ||
         pdfioDictGetType(scan.class_dict, "DefaultCMYK") ==
             PDFIO_VALTYPE_NONE)) {
      cf_v2_pdf_value_fail(failure, "default-colorspaces");
      goto done;
    }
    if (!pdfioPageGetRect(page, "MediaBox", &box) ||
        !isfinite(box.x1) || !isfinite(box.y1) || !isfinite(box.x2) ||
        !isfinite(box.y2) || box.x2 <= box.x1 || box.y2 <= box.y1) {
      cf_v2_pdf_value_fail(failure, "page-box");
      goto done;
    }
    if (!cf_v2_pdf_value_read_page(page, &decoded, &decoded_total, &error,
                                   failure)) {
      goto done;
    }
    valid = cf_v2_pdf_value_scan_content(&scan, decoded.data, decoded.size);
    free(decoded.data);
    if (!valid) {
      goto done;
    }
  }
  for (size_t cell = 0; cell < CF_V2_PDF_VALUE_PAGES; cell++) {
    if (scan.marker_count[cell] != 1U || scan.binding_count[cell] != 1U ||
        scan.order[cell] != cell) {
      cf_v2_pdf_value_fail(failure, "cell-contract");
      goto done;
    }
  }
  if (scan.order_count != CF_V2_PDF_VALUE_PAGES) {
    cf_v2_pdf_value_fail(failure, "cell-order-count");
    goto done;
  }
#if CF_V2_PDF_VALUE_CROSS_TYPE
  if (!input_document &&
      output_resource_entries !=
          cf_v2_pdf_value_expected_total_entries(model)) {
    cf_v2_pdf_value_fail(failure, "resource-entry-count");
    goto done;
  }
#endif
  if (input_document) {
    for (size_t cell = 0; cell < CF_V2_PDF_VALUE_PAGES; cell++) {
      if (strcmp(scan.observed_name[cell], model->key[cell]) != 0) {
        cf_v2_pdf_value_fail(failure, "input-resource-name");
        goto done;
      }
    }
  } else if (cf_v2_pdf_value_expected_entries(model) == 1U) {
    if (strcmp(scan.observed_name[0], scan.observed_name[1]) != 0) {
      cf_v2_pdf_value_fail(failure, "name-dedup");
      goto done;
    }
  } else if (strcmp(scan.observed_name[0], scan.observed_name[1]) == 0) {
    cf_v2_pdf_value_fail(failure, "collision-not-remapped");
    goto done;
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v2_pdf_value_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

static bool cf_v2_pdf_value_validate_bytes(
    const uint8_t *data, size_t size,
    const cf_v2_pdf_value_model_t *model, bool input_document,
    const char **failure) {
  char path[] = "/tmp/cupsfilters-v2-pdf-value-preflight.XXXXXX";
  int fd = mkstemp(path);
  bool valid = false;

  if (fd < 0) {
    return cf_v2_pdf_value_fail(failure, "preflight-tempfile");
  }
  if (cf_v2_write_all(fd, data, size) == 0 && close(fd) == 0) {
    fd = -1;
    valid = cf_v2_pdf_value_validate_path(path, model, input_document,
                                          failure);
  } else {
    cf_v2_pdf_value_fail(failure, "preflight-write");
  }
  if (fd >= 0) {
    close(fd);
  }
  unlink(path);
  return valid;
}

static char *cf_v2_pdf_value_build_ppd(const cf_v2_control_t *control,
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

static int cf_v2_pdf_value_options(
    char *buffer, size_t buffer_size,
    const cf_v2_pdf_value_model_t *model) {
  static const unsigned orientations[] = {3U, 4U, 5U, 6U};
  int length = snprintf(
      buffer, buffer_size,
      "number-up=2 orientation-requested=%u print-scaling=%s "
      "page-border=%s mirror=%s sides=one-sided copies=1 "
      "output-order=normal multiple-document-handling=single-document "
      "job-sheets=none emit-jcl=false",
      orientations[model->layout % 4U],
      model->layout & 4U ? "fill" : "fit",
      model->layout & 8U ? "single" : "none",
      model->layout & 16U ? "true" : "false");

  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}

static uint32_t cf_v2_pdf_value_random(uint32_t *state) {
  uint32_t value = *state ? *state : 0x9e3779b9U;

  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  *state = value;
  return value;
}

static size_t cf_v2_pdf_value_initialize(uint8_t *data, size_t max_size,
                                         uint32_t *state) {
  if (!data || max_size < CF_V2_PDF_VALUE_MIN_INPUT) {
    return 0;
  }
  memcpy(data, CF_V2_PDF_VALUE_MAGIC, CF_V2_PDF_VALUE_MAGIC_SIZE);
  for (size_t index = 0; index < CF_V2_PDF_VALUE_SELECTOR_SIZE; index++) {
    data[CF_V2_PDF_VALUE_MAGIC_SIZE + index] =
        (uint8_t)cf_v2_pdf_value_random(state);
  }
  data[CF_V2_PDF_VALUE_HEADER_SIZE] =
      (uint8_t)cf_v2_pdf_value_random(state);
  return CF_V2_PDF_VALUE_MIN_INPUT;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  const size_t limit = max_size < CF_V2_PDF_VALUE_MAX_INPUT
                           ? max_size
                           : CF_V2_PDF_VALUE_MAX_INPUT;
  uint32_t state = seed;

  if (!data || limit < CF_V2_PDF_VALUE_MIN_INPUT ||
      size < CF_V2_PDF_VALUE_MIN_INPUT ||
      memcmp(data, CF_V2_PDF_VALUE_MAGIC,
             CF_V2_PDF_VALUE_MAGIC_SIZE) != 0) {
    return cf_v2_pdf_value_initialize(data, limit, &state);
  }
  if (size > limit) {
    size = limit;
  }
  memcpy(data, CF_V2_PDF_VALUE_MAGIC, CF_V2_PDF_VALUE_MAGIC_SIZE);
  if (cf_v2_pdf_value_random(&state) % 4U != 3U) {
    const size_t selector =
        CF_V2_PDF_VALUE_MAGIC_SIZE +
        cf_v2_pdf_value_random(&state) % CF_V2_PDF_VALUE_SELECTOR_SIZE;
    data[selector] ^=
        (uint8_t)(1U + cf_v2_pdf_value_random(&state) % 255U);
  } else {
    size_t material_size = size - CF_V2_PDF_VALUE_HEADER_SIZE;

    material_size = LLVMFuzzerMutate(
        data + CF_V2_PDF_VALUE_HEADER_SIZE, material_size,
        limit - CF_V2_PDF_VALUE_HEADER_SIZE);
    if (!material_size) {
      data[CF_V2_PDF_VALUE_HEADER_SIZE] =
          (uint8_t)cf_v2_pdf_value_random(&state);
      material_size = 1U;
    }
    size = CF_V2_PDF_VALUE_HEADER_SIZE + material_size;
  }
  return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  cf_v2_pdf_value_model_t model;
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  size_t ppd_size = 0;
  uint8_t *document = NULL;
  size_t document_size = 0;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-pdf-value.XXXXXX";
  int output_fd = -1;
  int executed;
  bool trap_after_cleanup = false;
  const char *failure = NULL;

  if (!data || size < CF_V2_PDF_VALUE_MIN_INPUT ||
      size > CF_V2_PDF_VALUE_MAX_INPUT ||
      memcmp(data, CF_V2_PDF_VALUE_MAGIC,
             CF_V2_PDF_VALUE_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_PDF_VALUE_MAGIC_SIZE;
  material = data + CF_V2_PDF_VALUE_HEADER_SIZE;
  material_size = size - CF_V2_PDF_VALUE_HEADER_SIZE;
  if (!cf_v2_pdf_value_model_init(&model, selectors, material,
                                  material_size) ||
      cf_v2_pdf_value_options(options, sizeof(options), &model) != 0) {
    return 0;
  }
  document = cf_v2_pdf_value_build_document(&model, &document_size);
  if (!document || document_size > CF_V2_PDF_VALUE_MAX_GENERATED) {
    free(document);
    return 0;
  }
  {
    const char *input_failure = NULL;

    if (!cf_v2_pdf_value_validate_bytes(document, document_size, &model,
                                        true, &input_failure)) {
      free(document);
      return 0;
    }
  }

  memset(&control, 0, sizeof(control));
  control.ppd_profile = model.layout % 4U;
  control.page_size = model.layout % 2U;
  control.orientation = model.layout % 4U;
  control.scaling = 1U + ((model.layout >> 2) & 1U);
  control.number_up = 1U;
  control.mirror = (model.layout >> 4) & 1U;
  ppd = cf_v2_pdf_value_build_ppd(&control, &ppd_size);
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
  } else if (result.status != 0) {
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
      trap_after_cleanup =
          !cf_v2_pdf_value_validate_path(output_path, &model, false,
                                         &failure);
    } else {
      trap_after_cleanup = true;
      failure = "output-write";
    }
  } else {
    trap_after_cleanup = true;
    failure = "output-tempfile";
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
    fprintf(stderr, "pdf-resource-value-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
