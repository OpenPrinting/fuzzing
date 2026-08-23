// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <config.h>

#include <cupsfilters/pdf.h>
#include <math.h>
#include <pdfio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#define CF_V2_BANNER_OBJECT_CONTRACT "BNROBJ01"
#define CF_V2_BANNER_OBJECT_SELECTORS 10U
#define CF_V2_BANNER_OBJECT_MAX_MATERIAL 64U
#define CF_V2_BANNER_OBJECT_MAX_STREAMS 4U
#define CF_V2_BANNER_OBJECT_MAX_STREAM_BYTES 65537U
#define CF_V2_BANNER_OBJECT_MAX_CONTENT \
  (64U + CF_V2_BANNER_OBJECT_MAX_STREAMS * \
             CF_V2_BANNER_OBJECT_MAX_STREAM_BYTES)
#define CF_V2_BANNER_OBJECT_MAX_OUTPUT (4U * 1024U * 1024U)
#define CF_V2_BANNER_OBJECT_MAX_OBJECTS 256U
#define CF_V2_BANNER_OBJECT_RAW_OBJECTS 32U

typedef struct cf_v2_banner_object_case_s {
  unsigned media_box;
  unsigned target_box;
  unsigned resources;
  unsigned font_content;
  unsigned contents;
  unsigned compression;
  unsigned length;
  unsigned pattern;
  unsigned copies;
  unsigned extra_resource;
  unsigned stream_count;
  size_t stream_length;
  bool indirect_contents;
  bool valid_media_box;
  pdfio_rect_t source_box;
  pdfio_rect_t destination_box;
  const uint8_t *material;
  size_t material_size;
} cf_v2_banner_object_case_t;

typedef struct cf_v2_banner_object_raw_s {
  FILE *file;
  long offsets[CF_V2_BANNER_OBJECT_RAW_OBJECTS];
  unsigned object_count;
  bool failed;
} cf_v2_banner_object_raw_t;

typedef struct cf_v2_banner_object_error_s {
  bool saw_error;
} cf_v2_banner_object_error_t;

int __wrap_fprintf(FILE *stream, const char *format, ...) {
  va_list arguments;
  int result;

  if (stream == stderr && format && strncmp(format, "DEBUG: ", 7U) == 0) {
    return 0;
  }
  va_start(arguments, format);
  result = vfprintf(stream, format, arguments);
  va_end(arguments);
  return result;
}

static uint8_t cf_v2_banner_object_selector(const uint8_t *data, size_t size,
                                             size_t index,
                                             uint8_t fallback) {
  return data && index < size ? data[index] : fallback;
}

static void cf_v2_banner_object_decode(
    const uint8_t *data, size_t size, cf_v2_banner_object_case_t *test_case) {
  static const pdfio_rect_t source_boxes[] = {
      {0.0, 0.0, 595.0, 842.0}, {0.0, 0.0, 612.0, 792.0},
      {0.0, 0.0, 842.0, 595.0}, {10.0, 20.0, 605.0, 862.0},
      {0.0, 0.0, 1440.0, 720.0},
  };
  static const pdfio_rect_t target_boxes[] = {
      {0.0, 0.0, 595.0, 842.0}, {0.0, 0.0, 595.0, 842.0},
      {0.0, 0.0, 612.0, 792.0}, {0.0, 0.0, 842.0, 595.0},
      {0.0, 0.0, 288.0, 432.0}, {0.0, 0.0, 1440.0, 720.0},
  };
  static const unsigned stream_counts[] = {0U, 1U, 1U, 2U, 4U, 2U};
  static const size_t stream_lengths[] = {
      0U, 1U, 63U, 4095U, 65535U, 65536U, 65537U,
  };
  static const unsigned copy_counts[] = {1U, 2U, 4U, 8U};
  size_t material_offset = size < CF_V2_BANNER_OBJECT_SELECTORS
                               ? size
                               : CF_V2_BANNER_OBJECT_SELECTORS;

  memset(test_case, 0, sizeof(*test_case));
  test_case->media_box =
      cf_v2_banner_object_selector(data, size, 0U, 0U) % 8U;
  test_case->target_box =
      cf_v2_banner_object_selector(data, size, 1U, 0U) % 6U;
  test_case->resources =
      cf_v2_banner_object_selector(data, size, 2U, 2U) % 6U;
  test_case->font_content =
      cf_v2_banner_object_selector(data, size, 3U, 1U) % 5U;
  test_case->contents =
      cf_v2_banner_object_selector(data, size, 4U, 1U) % 6U;
  test_case->compression =
      cf_v2_banner_object_selector(data, size, 5U, 0U) % 3U;
  test_case->length =
      cf_v2_banner_object_selector(data, size, 6U, 2U) % 7U;
  test_case->pattern =
      cf_v2_banner_object_selector(data, size, 7U, 2U) % 5U;
  test_case->copies = copy_counts[
      cf_v2_banner_object_selector(data, size, 8U, 0U) % 4U];
  test_case->extra_resource =
      cf_v2_banner_object_selector(data, size, 9U, 0U) % 4U;
  test_case->stream_count = stream_counts[test_case->contents];
  test_case->stream_length = stream_lengths[test_case->length];
  test_case->indirect_contents = test_case->contents == 5U;
  test_case->valid_media_box = test_case->media_box < 5U;
  test_case->source_box = source_boxes[
      test_case->valid_media_box ? test_case->media_box : 0U];
  test_case->destination_box = target_boxes[test_case->target_box];
  if (test_case->target_box == 0U && test_case->valid_media_box) {
    test_case->destination_box.x2 =
        test_case->source_box.x2 - test_case->source_box.x1;
    test_case->destination_box.y2 =
        test_case->source_box.y2 - test_case->source_box.y1;
  }
  test_case->material = data ? data + material_offset : NULL;
  test_case->material_size = size - material_offset;
  if (test_case->material_size > CF_V2_BANNER_OBJECT_MAX_MATERIAL) {
    test_case->material_size = CF_V2_BANNER_OBJECT_MAX_MATERIAL;
  }
}

static bool cf_v2_banner_object_raw_write(
    cf_v2_banner_object_raw_t *raw, const void *bytes, size_t count) {
  if (!raw || raw->failed || !raw->file ||
      (count && fwrite(bytes, 1, count, raw->file) != count)) {
    if (raw) {
      raw->failed = true;
    }
    return false;
  }
  return true;
}

static bool cf_v2_banner_object_raw_printf(cf_v2_banner_object_raw_t *raw,
                                            const char *format, ...) {
  va_list arguments;
  int result;

  if (!raw || raw->failed || !raw->file) {
    return false;
  }
  va_start(arguments, format);
  result = vfprintf(raw->file, format, arguments);
  va_end(arguments);
  if (result < 0) {
    raw->failed = true;
    return false;
  }
  return true;
}

static bool cf_v2_banner_object_begin(cf_v2_banner_object_raw_t *raw,
                                      unsigned object) {
  long offset;

  if (!raw || object == 0U || object >= CF_V2_BANNER_OBJECT_RAW_OBJECTS ||
      (offset = ftell(raw->file)) < 0) {
    if (raw) {
      raw->failed = true;
    }
    return false;
  }
  raw->offsets[object] = offset;
  return cf_v2_banner_object_raw_printf(raw, "%u 0 obj\n", object);
}

static void cf_v2_banner_object_font_entries(
    cf_v2_banner_object_raw_t *raw,
    const cf_v2_banner_object_case_t *test_case) {
  switch (test_case->font_content) {
    case 1U:
      cf_v2_banner_object_raw_printf(raw, "/F0 4 0 R ");
      break;
    case 2U:
      cf_v2_banner_object_raw_printf(raw, "/bannertopdf-font 4 0 R ");
      break;
    case 3U:
      cf_v2_banner_object_raw_printf(
          raw, "/F0 4 0 R /bannertopdf-font 4 0 R ");
      break;
    case 4U:
      cf_v2_banner_object_raw_printf(raw, "/F0 4 0 R /Alias 4 0 R ");
      break;
    default:
      break;
  }
}

static void cf_v2_banner_object_extra_resource(
    cf_v2_banner_object_raw_t *raw,
    const cf_v2_banner_object_case_t *test_case, unsigned xobject) {
  switch (test_case->extra_resource) {
    case 1U:
      cf_v2_banner_object_raw_printf(raw, "/ProcSet [/PDF /Text] ");
      break;
    case 2U:
      cf_v2_banner_object_raw_printf(
          raw, "/ExtGState << /GS0 << /Type /ExtGState /ca 1 >> >> ");
      break;
    case 3U:
      cf_v2_banner_object_raw_printf(raw, "/XObject << /XO0 %u 0 R >> ",
                                     xobject);
      break;
    default:
      break;
  }
}

static void cf_v2_banner_object_resources(
    cf_v2_banner_object_raw_t *raw,
    const cf_v2_banner_object_case_t *test_case, unsigned fonts,
    unsigned xobject) {
  if (test_case->resources == 0U) {
    return;
  }
  cf_v2_banner_object_raw_printf(raw, "/Resources << ");
  cf_v2_banner_object_extra_resource(raw, test_case, xobject);
  switch (test_case->resources) {
    case 2U:
      cf_v2_banner_object_raw_printf(raw, "/Font << ");
      cf_v2_banner_object_font_entries(raw, test_case);
      cf_v2_banner_object_raw_printf(raw, ">> ");
      break;
    case 3U:
      cf_v2_banner_object_raw_printf(raw, "/Font %u 0 R ", fonts);
      break;
    case 4U:
      cf_v2_banner_object_raw_printf(raw, "/Font /Wrong ");
      break;
    case 5U:
      cf_v2_banner_object_raw_printf(
          raw, "/Font << /F0 4 0 R /bannertopdf-font 4 0 R ");
      if (test_case->font_content == 4U) {
        cf_v2_banner_object_raw_printf(raw, "/Alias 4 0 R ");
      }
      cf_v2_banner_object_raw_printf(raw, ">> ");
      break;
    default:
      break;
  }
  cf_v2_banner_object_raw_printf(raw, ">> ");
}

static uint8_t cf_v2_banner_object_pattern_byte(
    const cf_v2_banner_object_case_t *test_case, unsigned stream,
    size_t index) {
  unsigned value;

  switch (test_case->pattern) {
    case 0U:
      return 0U;
    case 1U:
      return 0xffU;
    case 2U:
      return (uint8_t)('!' + (stream * 17U + index * 13U) % 94U);
    case 3U:
      return (uint8_t)((stream * 67U + index) & 0xffU);
    default:
      value = test_case->material_size
                  ? test_case->material[(stream * 11U + index * 7U) %
                                        test_case->material_size]
                  : stream * 29U + (unsigned)index * 31U;
      return (uint8_t)(value ^ (unsigned)(index >> 8U));
  }
}

static bool cf_v2_banner_object_write_stream(
    cf_v2_banner_object_raw_t *raw,
    const cf_v2_banner_object_case_t *test_case, unsigned object,
    unsigned stream_index, uint8_t *decoded) {
  bool use_flate = test_case->compression == 1U ||
                   (test_case->compression == 2U && (stream_index & 1U));
  uint8_t *stored = decoded;
  size_t stored_size = test_case->stream_length;
  uLongf compressed_size = 0;

  for (size_t index = 0; index < test_case->stream_length; index++) {
    decoded[index] =
        cf_v2_banner_object_pattern_byte(test_case, stream_index, index);
  }
  if (use_flate) {
    compressed_size = compressBound((uLong)test_case->stream_length);
    stored = (uint8_t *)malloc((size_t)compressed_size);
    if (!stored || compress2(stored, &compressed_size, decoded,
                             (uLong)test_case->stream_length,
                             Z_BEST_SPEED) != Z_OK) {
      free(stored);
      return false;
    }
    stored_size = (size_t)compressed_size;
  }

  if (!cf_v2_banner_object_begin(raw, object) ||
      !cf_v2_banner_object_raw_printf(
          raw, "<< /Length %zu%s >>\nstream\n", stored_size,
          use_flate ? " /Filter /FlateDecode" : "") ||
      !cf_v2_banner_object_raw_write(raw, stored, stored_size) ||
      !cf_v2_banner_object_raw_printf(raw, "\nendstream\nendobj\n")) {
    if (use_flate) {
      free(stored);
    }
    return false;
  }
  if (use_flate) {
    free(stored);
  }
  return true;
}

static bool cf_v2_banner_object_build_template(
    const cf_v2_banner_object_case_t *test_case, char path[1024],
    uint8_t *expected, size_t expected_capacity, size_t *expected_length) {
  static const uint8_t prefix[] = "q 1 0 0 1 0 0 cm\n";
  char filename[] = "/tmp/cf-v2-banner-object-input-XXXXXX";
  cf_v2_banner_object_raw_t raw;
  unsigned next_object = 5U;
  unsigned fonts_object = 0U;
  unsigned xobject = 0U;
  unsigned stream_objects[CF_V2_BANNER_OBJECT_MAX_STREAMS] = {0U};
  unsigned contents_array = 0U;
  long xref_offset;
  int fd = -1;
  bool valid = false;

  memset(&raw, 0, sizeof(raw));
  *expected_length = 0U;
  if (sizeof(prefix) - 1U > expected_capacity) {
    return false;
  }
  memcpy(expected, prefix, sizeof(prefix) - 1U);
  *expected_length = sizeof(prefix) - 1U;

  if (test_case->resources == 3U) {
    fonts_object = next_object++;
  }
  if (test_case->resources != 0U && test_case->extra_resource == 3U) {
    xobject = next_object++;
  }
  for (unsigned index = 0; index < test_case->stream_count; index++) {
    stream_objects[index] = next_object++;
  }
  if (test_case->indirect_contents) {
    contents_array = next_object++;
  }
  raw.object_count = next_object - 1U;
  if (raw.object_count >= CF_V2_BANNER_OBJECT_RAW_OBJECTS ||
      *expected_length + test_case->stream_count * test_case->stream_length >
          expected_capacity) {
    return false;
  }

  fd = mkstemp(filename);
  if (fd < 0 || !(raw.file = fdopen(fd, "wb"))) {
    if (fd >= 0) {
      close(fd);
      unlink(filename);
    }
    return false;
  }
  fd = -1;
  cf_v2_banner_object_raw_write(&raw, "%PDF-1.4\n%\xd0\xd4\xc5\xd8\n", 15U);

  cf_v2_banner_object_begin(&raw, 1U);
  cf_v2_banner_object_raw_printf(
      &raw, "<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  cf_v2_banner_object_begin(&raw, 2U);
  cf_v2_banner_object_raw_printf(
      &raw, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
  cf_v2_banner_object_begin(&raw, 3U);
  cf_v2_banner_object_raw_printf(&raw, "<< /Type /Page /Parent 2 0 R ");
  switch (test_case->media_box) {
    case 5U:
      break;
    case 6U:
      cf_v2_banner_object_raw_printf(&raw, "/MediaBox [0 0 595] ");
      break;
    case 7U:
      cf_v2_banner_object_raw_printf(&raw,
                                     "/MediaBox [0 0 /Bad 842] ");
      break;
    default:
      cf_v2_banner_object_raw_printf(
          &raw, "/MediaBox [%.3f %.3f %.3f %.3f] "
                "/CropBox [%.3f %.3f %.3f %.3f] ",
          test_case->source_box.x1, test_case->source_box.y1,
          test_case->source_box.x2, test_case->source_box.y2,
          test_case->source_box.x1, test_case->source_box.y1,
          test_case->source_box.x2, test_case->source_box.y2);
      break;
  }
  cf_v2_banner_object_resources(&raw, test_case, fonts_object, xobject);
  if (test_case->stream_count) {
    if (test_case->contents == 1U) {
      cf_v2_banner_object_raw_printf(&raw, "/Contents %u 0 R ",
                                     stream_objects[0]);
    } else if (test_case->indirect_contents) {
      cf_v2_banner_object_raw_printf(&raw, "/Contents %u 0 R ",
                                     contents_array);
    } else {
      cf_v2_banner_object_raw_printf(&raw, "/Contents [");
      for (unsigned index = 0; index < test_case->stream_count; index++) {
        cf_v2_banner_object_raw_printf(&raw, "%u 0 R ",
                                       stream_objects[index]);
      }
      cf_v2_banner_object_raw_printf(&raw, "] ");
    }
  }
  cf_v2_banner_object_raw_printf(&raw, ">>\nendobj\n");

  cf_v2_banner_object_begin(&raw, 4U);
  cf_v2_banner_object_raw_printf(
      &raw, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
            "endobj\n");
  if (fonts_object) {
    cf_v2_banner_object_begin(&raw, fonts_object);
    cf_v2_banner_object_raw_printf(&raw, "<< ");
    cf_v2_banner_object_font_entries(&raw, test_case);
    cf_v2_banner_object_raw_printf(&raw, ">>\nendobj\n");
  }
  if (xobject) {
    cf_v2_banner_object_begin(&raw, xobject);
    cf_v2_banner_object_raw_printf(
        &raw, "<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] "
              "/Length 0 >>\nstream\n\nendstream\nendobj\n");
  }
  for (unsigned index = 0; index < test_case->stream_count; index++) {
    uint8_t *decoded = expected + *expected_length;
    if (!cf_v2_banner_object_write_stream(&raw, test_case,
                                          stream_objects[index], index,
                                          decoded)) {
      goto done;
    }
    *expected_length += test_case->stream_length;
  }
  if (contents_array) {
    cf_v2_banner_object_begin(&raw, contents_array);
    cf_v2_banner_object_raw_printf(&raw, "[");
    for (unsigned index = 0; index < test_case->stream_count; index++) {
      cf_v2_banner_object_raw_printf(&raw, "%u 0 R ",
                                     stream_objects[index]);
    }
    cf_v2_banner_object_raw_printf(&raw, "]\nendobj\n");
  }

  xref_offset = ftell(raw.file);
  if (xref_offset < 0 ||
      !cf_v2_banner_object_raw_printf(&raw, "xref\n0 %u\n",
                                      raw.object_count + 1U) ||
      !cf_v2_banner_object_raw_printf(&raw, "0000000000 65535 f \n")) {
    goto done;
  }
  for (unsigned object = 1U; object <= raw.object_count; object++) {
    if (raw.offsets[object] <= 0 ||
        !cf_v2_banner_object_raw_printf(&raw, "%010ld 00000 n \n",
                                        raw.offsets[object])) {
      goto done;
    }
  }
  if (!cf_v2_banner_object_raw_printf(
          &raw,
          "trailer\n<< /Size %u /Root 1 0 R >>\nstartxref\n%ld\n%%%%EOF\n",
          raw.object_count + 1U, xref_offset)) {
    goto done;
  }
  valid = !raw.failed;

done:
  if (raw.file && fclose(raw.file) != 0) {
    valid = false;
  }
  if (valid) {
    snprintf(path, 1024U, "%s", filename);
  } else {
    unlink(filename);
  }
  return valid;
}

static bool cf_v2_banner_object_pdf_error(pdfio_file_t *pdf,
                                           const char *message, void *data) {
  cf_v2_banner_object_error_t *error =
      (cf_v2_banner_object_error_t *)data;
  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static pdfio_dict_t *cf_v2_banner_object_dict(pdfio_dict_t *parent,
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

static bool cf_v2_banner_object_rect_equal(const pdfio_rect_t *left,
                                            const pdfio_rect_t *right) {
  const double epsilon = 0.001;
  return fabs(left->x1 - right->x1) < epsilon &&
         fabs(left->y1 - right->y1) < epsilon &&
         fabs(left->x2 - right->x2) < epsilon &&
         fabs(left->y2 - right->y2) < epsilon;
}

static bool cf_v2_banner_object_read_content(pdfio_obj_t *page,
                                              uint8_t *buffer,
                                              size_t capacity,
                                              size_t *length) {
  pdfio_stream_t *stream;
  ssize_t count = 0;

  *length = 0U;
  if (pdfioPageGetNumStreams(page) != 1U ||
      !(stream = pdfioPageOpenStream(page, 0U, true))) {
    return false;
  }
  while (*length < capacity &&
         (count = pdfioStreamRead(stream, buffer + *length,
                                  capacity - *length)) > 0) {
    *length += (size_t)count;
  }
  if (*length == capacity) {
    uint8_t extra;
    count = pdfioStreamRead(stream, &extra, 1U);
    if (count != 0) {
      pdfioStreamClose(stream);
      return false;
    }
  } else if (count < 0) {
    pdfioStreamClose(stream);
    return false;
  }
  return pdfioStreamClose(stream);
}

static bool cf_v2_banner_object_expect_f0(
    const cf_v2_banner_object_case_t *test_case) {
  if (test_case->resources == 5U) {
    return true;
  }
  return (test_case->resources == 2U || test_case->resources == 3U) &&
         (test_case->font_content == 1U ||
          test_case->font_content == 3U ||
          test_case->font_content == 4U);
}

static bool cf_v2_banner_object_validate(
    const char *path, const cf_v2_banner_object_case_t *test_case,
    const uint8_t *expected, size_t expected_length, const char **failure) {
  cf_v2_banner_object_error_t error = {false};
  pdfio_file_t *pdf = pdfioFileOpen(path, NULL, NULL,
                                    cf_v2_banner_object_pdf_error, &error);
  uint8_t *actual = NULL;
  bool valid = false;

#define CF_V2_BANNER_OBJECT_REQUIRE(condition, reason) \
  do {                                                   \
    if (!(condition)) {                                  \
      *failure = (reason);                               \
      goto done;                                         \
    }                                                    \
  } while (0)

  CF_V2_BANNER_OBJECT_REQUIRE(pdf && !error.saw_error, "strict-reopen");
  CF_V2_BANNER_OBJECT_REQUIRE(
      pdfioFileGetNumObjs(pdf) <= CF_V2_BANNER_OBJECT_MAX_OBJECTS,
      "object-budget");
  CF_V2_BANNER_OBJECT_REQUIRE(
      pdfioFileGetNumPages(pdf) == test_case->copies, "page-count");
  actual = (uint8_t *)malloc(expected_length + 1U);
  CF_V2_BANNER_OBJECT_REQUIRE(actual, "oracle-buffer");

  for (unsigned page_index = 0U; page_index < test_case->copies;
       page_index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, page_index);
    pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
    pdfio_dict_t *resources =
        cf_v2_banner_object_dict(page_dict, "Resources");
    pdfio_dict_t *fonts = cf_v2_banner_object_dict(resources, "Font");
    pdfio_dict_t *banner_font =
        cf_v2_banner_object_dict(fonts, "bannertopdf-font");
    pdfio_rect_t media_box, crop_box, trim_box, bleed_box, art_box;
    size_t actual_length = 0U;

    CF_V2_BANNER_OBJECT_REQUIRE(page && page_dict, "page-object");
    CF_V2_BANNER_OBJECT_REQUIRE(
        pdfioPageGetRect(page, "MediaBox", &media_box) &&
            cf_v2_banner_object_rect_equal(&media_box,
                                           &test_case->source_box),
        "media-box");
    CF_V2_BANNER_OBJECT_REQUIRE(
        pdfioPageGetRect(page, "CropBox", &crop_box) &&
            pdfioPageGetRect(page, "TrimBox", &trim_box) &&
            pdfioPageGetRect(page, "BleedBox", &bleed_box) &&
            pdfioPageGetRect(page, "ArtBox", &art_box) &&
            cf_v2_banner_object_rect_equal(&crop_box,
                                           &test_case->destination_box) &&
            cf_v2_banner_object_rect_equal(&trim_box,
                                           &test_case->destination_box) &&
            cf_v2_banner_object_rect_equal(&bleed_box,
                                           &test_case->destination_box) &&
            cf_v2_banner_object_rect_equal(&art_box,
                                           &test_case->destination_box),
        "destination-boxes");
    CF_V2_BANNER_OBJECT_REQUIRE(
        banner_font && pdfioDictGetName(banner_font, "Type") &&
            strcmp(pdfioDictGetName(banner_font, "Type"), "Font") == 0 &&
            pdfioDictGetName(banner_font, "Subtype") &&
            strcmp(pdfioDictGetName(banner_font, "Subtype"), "Type1") == 0 &&
            pdfioDictGetName(banner_font, "BaseFont") &&
            strcmp(pdfioDictGetName(banner_font, "BaseFont"), "Courier") == 0,
        "banner-font");
    if (cf_v2_banner_object_expect_f0(test_case)) {
      pdfio_dict_t *f0 = cf_v2_banner_object_dict(fonts, "F0");
      CF_V2_BANNER_OBJECT_REQUIRE(
          f0 && pdfioDictGetName(f0, "BaseFont") &&
              strcmp(pdfioDictGetName(f0, "BaseFont"), "Helvetica") == 0,
          "preserved-f0");
      if (test_case->font_content == 4U) {
        pdfio_obj_t *f0_object = pdfioDictGetObj(fonts, "F0");
        pdfio_obj_t *alias_object = pdfioDictGetObj(fonts, "Alias");

        CF_V2_BANNER_OBJECT_REQUIRE(
            f0_object && alias_object &&
                pdfioObjGetNumber(f0_object) ==
                    pdfioObjGetNumber(alias_object) &&
                pdfioObjGetGeneration(f0_object) ==
                    pdfioObjGetGeneration(alias_object),
            "font-alias");
      }
    }
    if (test_case->resources != 0U && test_case->extra_resource == 1U) {
      pdfio_array_t *procset = pdfioDictGetArray(resources, "ProcSet");
      CF_V2_BANNER_OBJECT_REQUIRE(
          procset && pdfioArrayGetSize(procset) == 2U &&
              pdfioArrayGetName(procset, 0U) &&
              strcmp(pdfioArrayGetName(procset, 0U), "PDF") == 0 &&
              pdfioArrayGetName(procset, 1U) &&
              strcmp(pdfioArrayGetName(procset, 1U), "Text") == 0,
          "procset-resource");
    } else if (test_case->resources != 0U &&
               test_case->extra_resource == 2U) {
      pdfio_dict_t *states =
          cf_v2_banner_object_dict(resources, "ExtGState");
      pdfio_dict_t *gs0 = cf_v2_banner_object_dict(states, "GS0");
      CF_V2_BANNER_OBJECT_REQUIRE(
          gs0 && pdfioDictGetName(gs0, "Type") &&
              strcmp(pdfioDictGetName(gs0, "Type"), "ExtGState") == 0,
          "extgstate-resource");
    } else if (test_case->resources != 0U &&
               test_case->extra_resource == 3U) {
      pdfio_dict_t *xobjects =
          cf_v2_banner_object_dict(resources, "XObject");
      pdfio_dict_t *xo0 = cf_v2_banner_object_dict(xobjects, "XO0");
      CF_V2_BANNER_OBJECT_REQUIRE(
          xo0 && pdfioDictGetName(xo0, "Subtype") &&
              strcmp(pdfioDictGetName(xo0, "Subtype"), "Form") == 0,
          "xobject-resource");
    }
    CF_V2_BANNER_OBJECT_REQUIRE(
        cf_v2_banner_object_read_content(page, actual,
                                         expected_length + 1U,
                                         &actual_length),
        "content-stream");
    CF_V2_BANNER_OBJECT_REQUIRE(
        actual_length == expected_length &&
            memcmp(actual, expected, expected_length) == 0,
        "decoded-content");
  }
  valid = !error.saw_error;

done:
  free(actual);
  if (pdf && !pdfioFileClose(pdf)) {
    *failure = "output-close";
    valid = false;
  }
  return valid && !error.saw_error;
#undef CF_V2_BANNER_OBJECT_REQUIRE
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_banner_object_case_t test_case;
  uint8_t *expected = NULL;
  size_t expected_length = 0U;
  char template_path[1024] = "";
  char output_path[] = "/tmp/cf-v2-banner-object-output-XXXXXX";
  int output_fd = -1;
  FILE *output_file = NULL;
  cf_pdf_t *input_doc = NULL;
  cf_pdf_t *output_doc = NULL;
  iterate_data_t iterate_helper = {0};
  struct stat output_stat;
  float scale = 0.0f;
  float expected_scale;
  const char *failure = NULL;
  bool pipeline_started = false;
  bool expected_rejection = false;

  cf_v2_banner_object_decode(data, size, &test_case);
  expected = (uint8_t *)malloc(CF_V2_BANNER_OBJECT_MAX_CONTENT);
  if (!expected || !cf_v2_banner_object_build_template(
                       &test_case, template_path, expected,
                       CF_V2_BANNER_OBJECT_MAX_CONTENT, &expected_length)) {
    goto done;
  }
  output_fd = mkstemp(output_path);
  if (output_fd < 0 || !(output_file = fdopen(output_fd, "wb+"))) {
    goto done;
  }
  output_fd = -1;
  input_doc = cfPDFLoadTemplate(template_path);
  if (!input_doc || !(output_doc = cfCopyPDFdoc(input_doc, output_file,
                                                &iterate_helper))) {
    goto done;
  }
  pipeline_started = true;

  if (cfPDFResizePage1(output_doc, &iterate_helper, 1U,
                       (float)test_case.destination_box.x2,
                       (float)test_case.destination_box.y2, &scale) != 0) {
    if (!test_case.valid_media_box) {
      expected_rejection = true;
      goto done;
    }
    failure = "page-scale-reject";
    goto done;
  }
  if (!test_case.valid_media_box) {
    failure = "invalid-media-accepted";
    goto done;
  }
  expected_scale =
      (float)(test_case.destination_box.x2 /
              (test_case.source_box.x2 - test_case.source_box.x1));
  {
    float height_scale =
        (float)(test_case.destination_box.y2 /
                (test_case.source_box.y2 - test_case.source_box.y1));
    if (height_scale < expected_scale) {
      expected_scale = height_scale;
    }
  }
  if (!isfinite(scale) || fabsf(scale - expected_scale) > 0.0001f) {
    failure = "page-scale";
    goto done;
  }
  if (cfPDFAddType1Font1(output_doc, &iterate_helper, 1U, "Courier") != 0) {
    failure = "font-injection";
    goto done;
  }
  if (cfPDFPrependStream1(input_doc, &iterate_helper, 1U,
                          (const char *)expected,
                          sizeof("q 1 0 0 1 0 0 cm\n") - 1U) != 0) {
    failure = "stream-copy";
    goto done;
  }
  if (test_case.copies > 1U &&
      cfPDFDuplicatePage(output_doc, 1U, test_case.copies - 1U) != 0) {
    failure = "page-duplicate";
    goto done;
  }

done:
  if (input_doc) {
    cfPDFFree(input_doc);
  }
  if (output_doc) {
    cfPDFFree(output_doc);
  }
  if (output_file) {
    if (fflush(output_file) != 0 || fclose(output_file) != 0) {
      failure = failure ? failure : "output-flush";
    }
  } else if (output_fd >= 0) {
    close(output_fd);
  }

  if (!failure && pipeline_started && !expected_rejection &&
      (stat(output_path, &output_stat) != 0 || output_stat.st_size <= 0 ||
       (size_t)output_stat.st_size > CF_V2_BANNER_OBJECT_MAX_OUTPUT)) {
    failure = "output-budget";
  }
  if (!failure && pipeline_started && !expected_rejection &&
      !cf_v2_banner_object_validate(output_path, &test_case, expected,
                                    expected_length, &failure)) {
    /* failure is set by the independent output oracle. */
  }
  if (template_path[0]) {
    unlink(template_path);
  }
  unlink(output_path);
  free(expected);

  if (failure) {
    fprintf(stderr, "%s: %s\n", CF_V2_BANNER_OBJECT_CONTRACT, failure);
    __builtin_trap();
  }
  return 0;
}
