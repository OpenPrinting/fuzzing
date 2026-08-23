// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#ifndef CF_V2_TARGET_NAME
#define CF_V2_TARGET_NAME                                                   \
  "fuzz_v2_cupsfilters_pdf_to_pdf_nup_order_oracle"
#endif
#define CF_V2_FILTER_FUNCTION cfFilterPDFToPDF
#define CF_V2_INPUT_MIME "application/pdf"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_FILTER_OPTIONS_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v2_pdf_nup_unused_direct_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <math.h>
#include <pdfio-content.h>
#include <pdfio.h>
#include <stdbool.h>

#define CF_V2_PDF_NUP_MAGIC "P2PNUP01"
#define CF_V2_PDF_NUP_MAGIC_SIZE 8U
#define CF_V2_PDF_NUP_SELECTOR_SIZE 8U
#define CF_V2_PDF_NUP_HEADER_SIZE 16U
#define CF_V2_PDF_NUP_MIN_INPUT 17U
#define CF_V2_PDF_NUP_MAX_MATERIAL 256U
#define CF_V2_PDF_NUP_MAX_INPUT                                         \
  (CF_V2_PDF_NUP_HEADER_SIZE + CF_V2_PDF_NUP_MAX_MATERIAL)
#define CF_V2_PDF_NUP_MAX_INPUT_PAGES 32U
#define CF_V2_PDF_NUP_MAX_OUTPUT_PAGES 96U
#define CF_V2_PDF_NUP_MAX_GENERATED (256U * 1024U)
#define CF_V2_PDF_NUP_MAX_DECODED_INPUT (256U * 1024U)
#define CF_V2_PDF_NUP_MAX_DECODED_OUTPUT (2U * 1024U * 1024U)
#define CF_V2_PDF_NUP_MAX_OBJECTS 1024U
#define CF_V2_PDF_NUP_MAX_PAGE_STREAMS 16U
#define CF_V2_PDF_NUP_MARKER_PREFIX "%P2PNUP:"
#define CF_V2_PDF_NUP_MARKER_PREFIX_SIZE 8U
#define CF_V2_PDF_NUP_MARKER_SIZE 10U

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

typedef struct cf_v2_pdf_nup_error_s {
  bool saw_error;
} cf_v2_pdf_nup_error_t;

typedef struct cf_v2_pdf_nup_expect_s {
  size_t input_pages;
  size_t selected_count;
  size_t number_up;
  size_t pages_per_copy;
  size_t copies;
  size_t total_pages;
  bool reverse;
  bool selected[CF_V2_PDF_NUP_MAX_INPUT_PAGES + 1U];
  uint8_t marker_count[CF_V2_PDF_NUP_MAX_OUTPUT_PAGES];
  uint8_t markers[CF_V2_PDF_NUP_MAX_OUTPUT_PAGES][16];
} cf_v2_pdf_nup_expect_t;

typedef struct cf_v2_pdf_nup_line_s {
  uint8_t bytes[CF_V2_PDF_NUP_MARKER_SIZE + 1U];
  size_t length;
  bool overflow;
} cf_v2_pdf_nup_line_t;

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

static bool cf_v2_pdf_nup_error(pdfio_file_t *pdf, const char *message,
                                 void *data) {
  cf_v2_pdf_nup_error_t *error = (cf_v2_pdf_nup_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static bool cf_v2_pdf_nup_fail(const char **failure, const char *message) {
  if (failure) {
    *failure = message;
  }
  return false;
}

static bool cf_v2_pdf_nup_range_contains(size_t page, size_t page_count,
                                         unsigned shape) {
  const size_t half = page_count / 2U;

  switch (shape % 8U) {
    case 0U:
      return true;
    case 1U:
      return page <= 2U;
    case 2U:
      return page >= page_count - 1U;
    case 3U:
      return page <= half;
    case 4U:
      return page > half;
    case 5U:
      return page == half || page == half + 1U;
    case 6U:
      return page <= 2U || page == page_count;
    default:
      return page == 1U || page >= page_count - 1U;
  }
}

static bool cf_v2_pdf_nup_page_set_contains(size_t page,
                                            unsigned page_set) {
  switch (page_set % 3U) {
    case 1U:
      return (page & 1U) != 0U;
    case 2U:
      return (page & 1U) == 0U;
    default:
      return true;
  }
}

static bool cf_v2_pdf_nup_model(const uint8_t selectors[8],
                                cf_v2_pdf_nup_expect_t *expect) {
  static const size_t page_counts[] = {4U, 5U, 8U, 9U, 16U, 17U, 32U};
  static const size_t number_up[] = {1U, 2U, 3U, 4U, 6U, 8U,
                                     9U, 10U, 12U, 15U, 16U};
  uint8_t selected_pages[CF_V2_PDF_NUP_MAX_INPUT_PAGES];
  size_t selected_count = 0;
  size_t output_index = 0;

  memset(expect, 0, sizeof(*expect));
  expect->input_pages = page_counts[selectors[0] % 7U];
  expect->number_up = number_up[selectors[1] % 11U];
  expect->copies = 1U + selectors[4] % 3U;
  expect->reverse = (selectors[5] & 1U) != 0U;

  for (size_t page = 1U; page <= expect->input_pages; page++) {
    if (cf_v2_pdf_nup_range_contains(page, expect->input_pages,
                                     selectors[2]) &&
        cf_v2_pdf_nup_page_set_contains(page, selectors[3])) {
      expect->selected[page] = true;
      selected_pages[selected_count++] = (uint8_t)page;
    }
  }
  if (!selected_count) {
    return false;
  }

  expect->selected_count = selected_count;
  expect->pages_per_copy =
      (selected_count + expect->number_up - 1U) / expect->number_up;
  expect->total_pages = expect->pages_per_copy * expect->copies;
  if (!expect->pages_per_copy || expect->pages_per_copy > 32U ||
      expect->total_pages > CF_V2_PDF_NUP_MAX_OUTPUT_PAGES) {
    return false;
  }

  for (size_t copy = 0; copy < expect->copies; copy++) {
    for (size_t position = 0; position < expect->pages_per_copy; position++) {
      const size_t logical_page =
          expect->reverse ? expect->pages_per_copy - position - 1U : position;
      const size_t first = logical_page * expect->number_up;
      size_t count = selected_count - first;

      if (count > expect->number_up) {
        count = expect->number_up;
      }
      for (size_t cell = 0; cell < count; cell++) {
        expect->markers[output_index][cell] = selected_pages[first + cell];
      }
      expect->marker_count[output_index] = (uint8_t)count;
      output_index++;
    }
  }
  return output_index == expect->total_pages;
}

static int cf_v2_pdf_nup_range_text(char *buffer, size_t buffer_size,
                                    size_t page_count, unsigned shape) {
  int length;
  const size_t half = page_count / 2U;

  switch (shape % 8U) {
    case 0U:
      length = snprintf(buffer, buffer_size, "1-%zu", page_count);
      break;
    case 1U:
      length = snprintf(buffer, buffer_size, "1-2");
      break;
    case 2U:
      length = snprintf(buffer, buffer_size, "%zu-%zu", page_count - 1U,
                        page_count);
      break;
    case 3U:
      length = snprintf(buffer, buffer_size, "1-%zu", half);
      break;
    case 4U:
      length = snprintf(buffer, buffer_size, "%zu-%zu", half + 1U,
                        page_count);
      break;
    case 5U:
      length = snprintf(buffer, buffer_size, "%zu-%zu", half, half + 1U);
      break;
    case 6U:
      length = snprintf(buffer, buffer_size, "1-2,%zu", page_count);
      break;
    default:
      length = snprintf(buffer, buffer_size, "1,%zu-%zu", page_count - 1U,
                        page_count);
      break;
  }
  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}

static int cf_v2_pdf_nup_options(
    char *buffer, size_t buffer_size, const uint8_t selectors[8],
    const cf_v2_pdf_nup_expect_t *expect) {
  static const char *const page_sets[] = {"all", "odd", "even"};
  char range[48];
  int length;

  if (cf_v2_pdf_nup_range_text(range, sizeof(range), expect->input_pages,
                               selectors[2]) != 0) {
    return -1;
  }
  length = snprintf(
      buffer, buffer_size,
      "number-up=%zu page-ranges=%s "
      "page-set=%s copies=%zu output-order=%s "
      "multiple-document-handling=single-document "
      "sides=one-sided print-scaling=fit page-border=none "
      "mirror=false output-bin=face-down "
      "page-delivery=same-order-face-down job-sheets=none emit-jcl=false",
      expect->number_up, range, page_sets[selectors[3] % 3U], expect->copies,
      expect->reverse ? "reverse" : "normal");
  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}

static char *cf_v2_pdf_nup_build_ppd(const cf_v2_control_t *control,
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

static uint8_t *cf_v2_pdf_nup_read_file(const char *path,
                                         size_t *document_size) {
  FILE *file = fopen(path, "rb");
  uint8_t *document = NULL;
  long length;

  if (!file || fseek(file, 0, SEEK_END) != 0 ||
      (length = ftell(file)) <= 0 ||
      (unsigned long)length > CF_V2_PDF_NUP_MAX_GENERATED ||
      fseek(file, 0, SEEK_SET) != 0 ||
      !(document = (uint8_t *)malloc((size_t)length)) ||
      fread(document, 1U, (size_t)length, file) != (size_t)length) {
    free(document);
    document = NULL;
  }
  if (file) {
    fclose(file);
  }
  if (document) {
    *document_size = (size_t)length;
  }
  return document;
}

static bool cf_v2_pdf_nup_write_literal(pdfio_stream_t *stream,
                                         const uint8_t *material,
                                         size_t material_size, size_t page) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;-_";
  const size_t alphabet_size = sizeof(alphabet) - 1U;

  if (!pdfioStreamPutChar(stream, '(')) {
    return false;
  }
  for (size_t index = 0; index < material_size; index++) {
    const int ch = alphabet[(material[index] + page + index) % alphabet_size];

    if (!pdfioStreamPutChar(stream, ch)) {
      return false;
    }
  }
  return pdfioStreamPuts(stream, ") Tj\n");
}

static bool cf_v2_pdf_nup_write_octal_literal(pdfio_stream_t *stream,
                                               const uint8_t *material,
                                               size_t material_size,
                                               size_t page) {
  if (!pdfioStreamPutChar(stream, '(')) {
    return false;
  }
  for (size_t index = 0; index < material_size; index++) {
    if (!pdfioStreamPrintf(stream, "\\%03o",
                           (unsigned)((material[index] + page) & 255U))) {
      return false;
    }
  }
  return pdfioStreamPuts(stream, ") Tj\n");
}

static bool cf_v2_pdf_nup_write_hex(pdfio_stream_t *stream,
                                     const uint8_t *material,
                                     size_t material_size, size_t limit,
                                     size_t page) {
  static const char digits[] = "0123456789ABCDEF";
  const size_t count = material_size < limit ? material_size : limit;

  for (size_t index = 0; index < count; index++) {
    uint8_t value = (uint8_t)(material[index] + page + index);
    char pair[2] = {digits[value >> 4], digits[value & 15U]};

    if (!pdfioStreamWrite(stream, pair, sizeof(pair))) {
      return false;
    }
  }
  return true;
}

static bool cf_v2_pdf_nup_write_material(pdfio_stream_t *stream,
                                          const uint8_t *material,
                                          size_t material_size, size_t page,
                                          unsigned recipe) {
  const unsigned first = material[page % material_size];
  const unsigned second = material[(page * 3U + 1U) % material_size];

  switch (recipe % 6U) {
    case 0U:
      return pdfioStreamPuts(stream, "q 0 0 m 1 1 l S Q\n");
    case 1U:
      return pdfioStreamPuts(stream, "BT /F0 10 Tf 18 24 Td ") &&
             cf_v2_pdf_nup_write_literal(stream, material, material_size,
                                          page) &&
             pdfioStreamPuts(stream, "ET\n");
    case 2U:
      return pdfioStreamPuts(stream, "BT /F0 9 Tf 18 36 Td ") &&
             cf_v2_pdf_nup_write_octal_literal(
                 stream, material, material_size, page) &&
             pdfioStreamPuts(stream, "ET\n");
    case 3U:
      if (!pdfioStreamPuts(stream, "/N")) {
        return false;
      }
      return cf_v2_pdf_nup_write_hex(stream, material, material_size, 48U,
                                      page) &&
             pdfioStreamPuts(stream, " BMC EMC\n");
    case 4U:
      for (size_t offset = 0; offset < material_size; offset += 16U) {
        size_t count = material_size - offset;

        if (count > 16U) {
          count = 16U;
        }
        if (!pdfioStreamPuts(stream, "%M:") ||
            !cf_v2_pdf_nup_write_hex(stream, material + offset, count,
                                      count, page) ||
            !pdfioStreamPutChar(stream, '\n')) {
          return false;
        }
      }
      return true;
    default:
      return pdfioStreamPrintf(stream,
                               "q %u %u %u %u re W n 0 G 1 w S Q\n",
                               first % 64U, second % 64U,
                               1U + first % 128U, 1U + second % 128U) &&
             pdfioStreamPuts(stream, "/Mixed BMC\nBT /F0 8 Tf 12 18 Td ") &&
             cf_v2_pdf_nup_write_literal(stream, material, material_size,
                                          page) &&
             pdfioStreamPuts(stream, "ET\nEMC\n");
  }
}

static uint8_t *cf_v2_pdf_nup_build_document(
    const uint8_t selectors[8], const uint8_t *material,
    size_t material_size, const cf_v2_pdf_nup_expect_t *expect,
    size_t *document_size) {
  static const pdfio_rect_t boxes[] = {
      {0.0, 0.0, 595.0, 842.0},
      {0.0, 0.0, 612.0, 792.0},
      {0.0, 0.0, 842.0, 595.0},
      {0.0, 0.0, 792.0, 612.0},
  };
  cf_v2_pdf_nup_error_t error = {false};
  char path[1024] = "";
  pdfio_file_t *pdf = NULL;
  pdfio_obj_t *font = NULL;
  uint8_t *document = NULL;
  bool valid = false;
  const pdfio_rect_t *box = boxes + selectors[7] % 4U;

  pdf = pdfioFileCreateTemporary(path, sizeof(path), "1.4", NULL, NULL,
                                 cf_v2_pdf_nup_error, &error);
  if (!pdf || error.saw_error ||
      !(font = pdfioFileCreateFontObjFromBase(pdf, "Helvetica"))) {
    goto done;
  }
  for (size_t page = 1U; page <= expect->input_pages; page++) {
    pdfio_dict_t *dict = pdfioDictCreate(pdf);
    pdfio_stream_t *stream;

    if (!dict || !pdfioDictSetRect(dict, "MediaBox", (pdfio_rect_t *)box) ||
        !pdfioDictSetRect(dict, "CropBox", (pdfio_rect_t *)box) ||
        !pdfioPageDictAddFont(dict, "F0", font) ||
        !(stream = pdfioFileCreatePage(pdf, dict)) ||
        !pdfioStreamPuts(stream, "\n" CF_V2_PDF_NUP_MARKER_PREFIX) ||
        !pdfioStreamPrintf(stream, "%02u\n", (unsigned)page) ||
        !cf_v2_pdf_nup_write_material(stream, material, material_size, page,
                                      selectors[6]) ||
        !pdfioStreamClose(stream)) {
      goto done;
    }
  }
  valid = true;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    valid = false;
  }
  if (valid && !error.saw_error) {
    document = cf_v2_pdf_nup_read_file(path, document_size);
  }
  if (path[0]) {
    unlink(path);
  }
  return document;
}

static bool cf_v2_pdf_nup_finish_line(cf_v2_pdf_nup_line_t *line,
                                      uint8_t markers[16],
                                      size_t *marker_count,
                                      size_t input_pages,
                                      const char **failure) {
  size_t length = line->length;

  if (length && line->bytes[length - 1U] == '\r') {
    length--;
  }
  if (!line->overflow && length >= CF_V2_PDF_NUP_MARKER_PREFIX_SIZE &&
      memcmp(line->bytes, CF_V2_PDF_NUP_MARKER_PREFIX,
             CF_V2_PDF_NUP_MARKER_PREFIX_SIZE) == 0) {
    size_t page;

    if (length != CF_V2_PDF_NUP_MARKER_SIZE || line->bytes[8] < '0' ||
        line->bytes[8] > '9' || line->bytes[9] < '0' ||
        line->bytes[9] > '9') {
      return cf_v2_pdf_nup_fail(failure, "malformed-page-marker");
    }
    page = (size_t)(line->bytes[8] - '0') * 10U +
           (size_t)(line->bytes[9] - '0');
    if (!page || page > input_pages || *marker_count >= 16U) {
      return cf_v2_pdf_nup_fail(failure, "page-marker-bounds");
    }
    markers[(*marker_count)++] = (uint8_t)page;
  }
  memset(line, 0, sizeof(*line));
  return true;
}

static bool cf_v2_pdf_nup_scan_page(pdfio_obj_t *page,
                                    uint8_t markers[16],
                                    size_t *marker_count,
                                    size_t input_pages,
                                    size_t *decoded_total,
                                    cf_v2_pdf_nup_error_t *error,
                                    const char **failure) {
  const size_t stream_count = pdfioPageGetNumStreams(page);

  *marker_count = 0;
  if (!stream_count || stream_count > CF_V2_PDF_NUP_MAX_PAGE_STREAMS) {
    return cf_v2_pdf_nup_fail(failure, "page-stream-count");
  }
  for (size_t stream_index = 0; stream_index < stream_count; stream_index++) {
    pdfio_stream_t *stream =
        pdfioPageOpenStream(page, stream_index, true);
    cf_v2_pdf_nup_line_t line = {{0}, 0U, false};
    uint8_t buffer[4096];
    ssize_t count;
    bool valid = true;

    if (!stream) {
      return cf_v2_pdf_nup_fail(failure, "page-stream-open");
    }
    while ((count = pdfioStreamRead(stream, buffer, sizeof(buffer))) > 0) {
      *decoded_total += (size_t)count;
      if (*decoded_total > CF_V2_PDF_NUP_MAX_DECODED_OUTPUT) {
        cf_v2_pdf_nup_fail(failure, "decoded-output-budget");
        valid = false;
        break;
      }
      for (ssize_t index = 0; index < count; index++) {
        const uint8_t ch = buffer[index];

        if (ch == '\n') {
          if (!cf_v2_pdf_nup_finish_line(&line, markers, marker_count,
                                          input_pages, failure)) {
            valid = false;
            break;
          }
        } else if (line.length < sizeof(line.bytes)) {
          line.bytes[line.length++] = ch;
        } else {
          line.overflow = true;
        }
      }
      if (!valid) {
        break;
      }
    }
    if (valid && count >= 0 && line.length &&
        !cf_v2_pdf_nup_finish_line(&line, markers, marker_count, input_pages,
                                    failure)) {
      valid = false;
    }
    if (count < 0 || error->saw_error) {
      cf_v2_pdf_nup_fail(failure, "page-stream-read");
      valid = false;
    }
    if (!pdfioStreamClose(stream)) {
      cf_v2_pdf_nup_fail(failure, "page-stream-close");
      valid = false;
    }
    if (!valid) {
      return false;
    }
  }
  return true;
}

static bool cf_v2_pdf_nup_validate_output(
    const char *path, const cf_v2_pdf_nup_expect_t *expect,
    const char **failure) {
  cf_v2_pdf_nup_error_t error = {false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_pdf_nup_error, &error);
  size_t observed[CF_V2_PDF_NUP_MAX_INPUT_PAGES + 1U] = {0};
  size_t decoded_total = 0;
  bool valid = false;

  if (!pdf || error.saw_error) {
    cf_v2_pdf_nup_fail(failure, "strict-reopen");
    goto done;
  }
  if (pdfioFileGetNumObjs(pdf) > CF_V2_PDF_NUP_MAX_OBJECTS) {
    cf_v2_pdf_nup_fail(failure, "object-budget");
    goto done;
  }
  {
    pdfio_dict_t *catalog = pdfioFileGetCatalog(pdf);
    pdfio_obj_t *pages_obj = catalog ? pdfioDictGetObj(catalog, "Pages") : NULL;
    pdfio_dict_t *pages = pages_obj ? pdfioObjGetDict(pages_obj) : NULL;
    pdfio_array_t *kids = pages ? pdfioDictGetArray(pages, "Kids") : NULL;
    const char *catalog_type = catalog ? pdfioDictGetName(catalog, "Type") : NULL;
    const char *pages_type = pages ? pdfioDictGetName(pages, "Type") : NULL;

    if (!catalog_type || strcmp(catalog_type, "Catalog") != 0 ||
        !pages_type || strcmp(pages_type, "Pages") != 0 || !kids ||
        pdfioFileGetNumPages(pdf) != expect->total_pages ||
        pdfioArrayGetSize(kids) != expect->total_pages ||
        pdfioDictGetNumber(pages, "Count") != (double)expect->total_pages) {
      cf_v2_pdf_nup_fail(failure, "page-tree");
      goto done;
    }
  }

  for (size_t index = 0; index < expect->total_pages; index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, index);
    pdfio_rect_t box;
    uint8_t markers[16] = {0};
    size_t marker_count = 0;

    if (!page || !pdfioPageGetRect(page, "MediaBox", &box) ||
        !isfinite(box.x1) || !isfinite(box.y1) || !isfinite(box.x2) ||
        !isfinite(box.y2) || box.x2 <= box.x1 || box.y2 <= box.y1) {
      cf_v2_pdf_nup_fail(failure, "page-box");
      goto done;
    }
    if (!cf_v2_pdf_nup_scan_page(page, markers, &marker_count,
                                  expect->input_pages, &decoded_total, &error,
                                  failure)) {
      goto done;
    }
    if (marker_count != expect->marker_count[index] ||
        memcmp(markers, expect->markers[index], marker_count) != 0) {
      fprintf(stderr,
              "pdf-nup-order-oracle: output-page=%zu actual-count=%zu "
              "expected-count=%u first-actual=%u first-expected=%u\n",
              index + 1U, marker_count,
              (unsigned)expect->marker_count[index], (unsigned)markers[0],
              (unsigned)expect->markers[index][0]);
      cf_v2_pdf_nup_fail(failure, "page-marker-order");
      goto done;
    }
    for (size_t marker = 0; marker < marker_count; marker++) {
      observed[markers[marker]]++;
    }
  }

  for (size_t page = 1U; page <= expect->input_pages; page++) {
    const size_t wanted = expect->selected[page] ? expect->copies : 0U;

    if (observed[page] != wanted) {
      cf_v2_pdf_nup_fail(failure, "page-marker-multiplicity");
      goto done;
    }
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v2_pdf_nup_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

static uint32_t cf_v2_pdf_nup_random(uint32_t *state) {
  uint32_t value = *state ? *state : 0x9e3779b9U;

  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  *state = value;
  return value;
}

static size_t cf_v2_pdf_nup_initialize(uint8_t *data, size_t max_size,
                                        uint32_t *state) {
  if (!data || max_size < CF_V2_PDF_NUP_MIN_INPUT) {
    return 0;
  }
  memcpy(data, CF_V2_PDF_NUP_MAGIC, CF_V2_PDF_NUP_MAGIC_SIZE);
  memset(data + CF_V2_PDF_NUP_MAGIC_SIZE, 0,
         CF_V2_PDF_NUP_SELECTOR_SIZE);
  data[CF_V2_PDF_NUP_HEADER_SIZE] =
      (uint8_t)cf_v2_pdf_nup_random(state);
  return CF_V2_PDF_NUP_MIN_INPUT;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  const size_t limit = max_size < CF_V2_PDF_NUP_MAX_INPUT
                           ? max_size
                           : CF_V2_PDF_NUP_MAX_INPUT;
  uint32_t state = seed;

  if (!data || limit < CF_V2_PDF_NUP_MIN_INPUT ||
      size < CF_V2_PDF_NUP_MIN_INPUT ||
      memcmp(data, CF_V2_PDF_NUP_MAGIC, CF_V2_PDF_NUP_MAGIC_SIZE) != 0) {
    return cf_v2_pdf_nup_initialize(data, limit, &state);
  }
  if (size > limit) {
    size = limit;
  }
  memcpy(data, CF_V2_PDF_NUP_MAGIC, CF_V2_PDF_NUP_MAGIC_SIZE);

  if (cf_v2_pdf_nup_random(&state) % 4U != 3U) {
    const size_t selector =
        CF_V2_PDF_NUP_MAGIC_SIZE +
        cf_v2_pdf_nup_random(&state) % CF_V2_PDF_NUP_SELECTOR_SIZE;
    uint8_t replacement = (uint8_t)cf_v2_pdf_nup_random(&state);

    if (replacement == data[selector]) {
      replacement++;
    }
    data[selector] = replacement;
  } else {
    size_t material_size = size - CF_V2_PDF_NUP_HEADER_SIZE;

    material_size = LLVMFuzzerMutate(
        data + CF_V2_PDF_NUP_HEADER_SIZE, material_size,
        limit - CF_V2_PDF_NUP_HEADER_SIZE);
    if (!material_size) {
      data[CF_V2_PDF_NUP_HEADER_SIZE] =
          (uint8_t)cf_v2_pdf_nup_random(&state);
      material_size = 1U;
    }
    size = CF_V2_PDF_NUP_HEADER_SIZE + material_size;
  }
  return size;
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                 const uint8_t *data2, size_t size2,
                                 uint8_t *out, size_t max_out_size,
                                 unsigned int seed) {
  const size_t limit = max_out_size < CF_V2_PDF_NUP_MAX_INPUT
                           ? max_out_size
                           : CF_V2_PDF_NUP_MAX_INPUT;
  const bool valid1 = data1 && size1 >= CF_V2_PDF_NUP_MIN_INPUT &&
                      memcmp(data1, CF_V2_PDF_NUP_MAGIC,
                             CF_V2_PDF_NUP_MAGIC_SIZE) == 0;
  const bool valid2 = data2 && size2 >= CF_V2_PDF_NUP_MIN_INPUT &&
                      memcmp(data2, CF_V2_PDF_NUP_MAGIC,
                             CF_V2_PDF_NUP_MAGIC_SIZE) == 0;
  const uint8_t *selector_source = (seed & 1U) && valid2 ? data2 : data1;
  const uint8_t *material_source = (seed & 1U) && valid1 ? data1 : data2;
  size_t material_source_size = (seed & 1U) && valid1 ? size1 : size2;
  uint32_t state = seed;
  size_t material_size;

  if (!out || limit < CF_V2_PDF_NUP_MIN_INPUT) {
    return 0;
  }
  if ((!valid1 && !valid2) ||
      (selector_source == data1 && !valid1) ||
      (selector_source == data2 && !valid2)) {
    return cf_v2_pdf_nup_initialize(out, limit, &state);
  }
  memcpy(out, CF_V2_PDF_NUP_MAGIC, CF_V2_PDF_NUP_MAGIC_SIZE);
  memcpy(out + CF_V2_PDF_NUP_MAGIC_SIZE,
         selector_source + CF_V2_PDF_NUP_MAGIC_SIZE,
         CF_V2_PDF_NUP_SELECTOR_SIZE);

  if ((material_source == data1 && valid1) ||
      (material_source == data2 && valid2)) {
    material_size = material_source_size - CF_V2_PDF_NUP_HEADER_SIZE;
    if (material_size > limit - CF_V2_PDF_NUP_HEADER_SIZE) {
      material_size = limit - CF_V2_PDF_NUP_HEADER_SIZE;
    }
    memcpy(out + CF_V2_PDF_NUP_HEADER_SIZE,
           material_source + CF_V2_PDF_NUP_HEADER_SIZE, material_size);
  } else {
    material_size = 0U;
  }
  if (!material_size) {
    out[CF_V2_PDF_NUP_HEADER_SIZE] =
        (uint8_t)cf_v2_pdf_nup_random(&state);
    material_size = 1U;
  }
  return CF_V2_PDF_NUP_HEADER_SIZE + material_size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  cf_v2_pdf_nup_expect_t expect;
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  size_t ppd_size = 0;
  uint8_t *document = NULL;
  size_t document_size = 0;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-pdf-nup.XXXXXX";
  int output_fd = -1;
  int executed;
  bool trap_after_cleanup = false;
  const char *failure = NULL;

  if (!data || size < CF_V2_PDF_NUP_MIN_INPUT ||
      size > CF_V2_PDF_NUP_MAX_INPUT ||
      memcmp(data, CF_V2_PDF_NUP_MAGIC,
             CF_V2_PDF_NUP_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_PDF_NUP_MAGIC_SIZE;
  material = data + CF_V2_PDF_NUP_HEADER_SIZE;
  material_size = size - CF_V2_PDF_NUP_HEADER_SIZE;
  if (!cf_v2_pdf_nup_model(selectors, &expect)) {
    return 0;
  }
  document = cf_v2_pdf_nup_build_document(
      selectors, material, material_size, &expect, &document_size);
  if (!document || document_size > CF_V2_PDF_NUP_MAX_GENERATED ||
      document_size > CF_V2_PDF_NUP_MAX_DECODED_INPUT ||
      cf_v2_pdf_nup_options(options, sizeof(options), selectors, &expect) !=
          0) {
    free(document);
    return 0;
  }

  memset(&control, 0, sizeof(control));
  control.ppd_profile = selectors[7] % 4U;
  control.page_size = selectors[7] % 2U;
  control.sides = 0U;
  control.scaling = 1U;
  control.copies = (uint8_t)(expect.copies - 1U);
  control.number_up = 0U;
  control.output_order = expect.reverse ? 1U : 0U;
  ppd = cf_v2_pdf_nup_build_ppd(&control, &ppd_size);
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
  if (executed) {
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
        trap_after_cleanup =
            !cf_v2_pdf_nup_validate_output(output_path, &expect, &failure);
      }
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
    fprintf(stderr, "pdf-nup-order-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
