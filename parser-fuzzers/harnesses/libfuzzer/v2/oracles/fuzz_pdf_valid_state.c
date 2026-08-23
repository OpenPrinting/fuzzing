// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define CF_V2_FILTER_FUNCTION cfFilterPDFToPDF
#define CF_V2_INPUT_MIME "application/pdf"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_FILTER_OPTIONS_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v2_pdf_unused_direct_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <math.h>
#include <pdfio-content.h>
#include <pdfio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

extern int __real_fputs(const char *text, FILE *stream);

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

int __wrap_fputs(const char *text, FILE *stream) {
  if (stream == stderr && text && strncmp(text, "DEBUG:", 6U) == 0) {
    return 0;
  }
  return __real_fputs(text, stream);
}

#define CF_V2_PDF_STATE_MAGIC_SIZE 8U
#define CF_V2_PDF_STATE_SELECTORS 24U
#define CF_V2_PDF_STATE_HEADER_SIZE                                           \
  (CF_V2_PDF_STATE_MAGIC_SIZE + CF_V2_PDF_STATE_SELECTORS)
#define CF_V2_PDF_STATE_MAX_PAYLOAD 4096U
#define CF_V2_PDF_STATE_MAX_INPUT                                             \
  (CF_V2_PDF_STATE_HEADER_SIZE + CF_V2_PDF_STATE_MAX_PAYLOAD)
#define CF_V2_PDF_STATE_MAX_GENERATED (2U * 1024U * 1024U)
#define CF_V2_PDF_STATE_MAX_DECODED (4U * 1024U * 1024U)
#define CF_V2_PDF_STATE_MAX_OUTPUT_PAGES 256U

#if defined(CF_V2_PDF_OBJECT_VALID)
static const uint8_t cf_v2_pdf_state_magic[CF_V2_PDF_STATE_MAGIC_SIZE] =
    "P2POBJ01";
#elif defined(CF_V2_PDF_PAGE_LAYOUT_VALID)
static const uint8_t cf_v2_pdf_state_magic[CF_V2_PDF_STATE_MAGIC_SIZE] =
    "P2PLAY01";
#else
#error "Select one PDF valid-state grammar"
#endif

typedef struct cf_v2_pdf_state_error_s {
  bool saw_error;
} cf_v2_pdf_state_error_t;

typedef struct cf_v2_pdf_state_expect_s {
  size_t input_pages;
  size_t expected_pages;
  bool duplex;
} cf_v2_pdf_state_expect_t;

static bool cf_v2_pdf_state_error(pdfio_file_t *pdf, const char *message,
                                  void *data) {
  cf_v2_pdf_state_error_t *error = (cf_v2_pdf_state_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static char *cf_v2_pdf_state_build_ppd(const cf_v2_control_t *control,
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

static uint8_t *cf_v2_pdf_state_read_file(const char *path, size_t *size_out) {
  FILE *file = fopen(path, "rb");
  uint8_t *data = NULL;
  long length;

  if (!file || fseek(file, 0, SEEK_END) != 0 ||
      (length = ftell(file)) <= 0 ||
      (unsigned long)length > CF_V2_PDF_STATE_MAX_GENERATED ||
      fseek(file, 0, SEEK_SET) != 0 ||
      !(data = (uint8_t *)malloc((size_t)length)) ||
      fread(data, 1U, (size_t)length, file) != (size_t)length) {
    free(data);
    data = NULL;
  }
  if (file) {
    fclose(file);
  }
  if (data) {
    *size_out = (size_t)length;
  }
  return data;
}

static bool cf_v2_pdf_state_close_scalar(pdfio_obj_t *object) {
  return object && pdfioObjClose(object);
}

static bool cf_v2_pdf_state_add_aux_objects(
    pdfio_file_t *pdf, const uint8_t selectors[CF_V2_PDF_STATE_SELECTORS],
    const uint8_t *payload, size_t payload_size) {
  static const size_t object_counts[] = {8U, 16U, 32U, 64U};
  size_t count = object_counts[selectors[18] % 4U];

  for (size_t index = 0; index < count; index++) {
    pdfio_obj_t *object = NULL;
    char text[96];

    snprintf(text, sizeof(text), "P2PAUX%03zu-%02x-%02x", index,
             payload[index % payload_size], selectors[index % 24U]);
    switch ((selectors[9] + index) % 5U) {
      case 0U:
        object = pdfioFileCreateStringObj(pdf, text);
        break;
      case 1U:
        object = pdfioFileCreateNameObj(pdf, text);
        break;
      case 2U:
        object = pdfioFileCreateNumberObj(
            pdf, (double)((int)payload[index % payload_size] - 128));
        break;
      case 3U: {
        pdfio_array_t *array = pdfioArrayCreate(pdf);
        if (!array || !pdfioArrayAppendString(array, text) ||
            !pdfioArrayAppendNumber(array, (double)index) ||
            !pdfioArrayAppendBoolean(array, (index & 1U) != 0U)) {
          return false;
        }
        object = pdfioFileCreateArrayObj(pdf, array);
        break;
      }
      default: {
        pdfio_dict_t *dict = pdfioDictCreate(pdf);
        if (!dict || !pdfioDictSetName(dict, "Type", "P2PState") ||
            !pdfioDictSetString(dict, "Value", text) ||
            !pdfioDictSetNumber(dict, "Index", (double)index)) {
          return false;
        }
        object = pdfioFileCreateObj(pdf, dict);
        break;
      }
    }
    if (!cf_v2_pdf_state_close_scalar(object)) {
      return false;
    }
  }

  {
    pdfio_dict_t *dict = pdfioDictCreate(pdf);
    pdfio_obj_t *object;
    pdfio_stream_t *stream;
    pdfio_filter_t filter =
        selectors[5] & 1U ? PDFIO_FILTER_FLATE : PDFIO_FILTER_NONE;
    size_t stream_size = payload_size < 1024U ? payload_size : 1024U;

    if (!dict || !pdfioDictSetName(dict, "Type", "P2PStream") ||
        !(object = pdfioFileCreateObj(pdf, dict)) ||
        !(stream = pdfioObjCreateStream(object, filter)) ||
        !pdfioStreamPuts(stream, "P2PAUXSTREAM\n") ||
        !pdfioStreamWrite(stream, payload, stream_size) ||
        !pdfioStreamClose(stream)) {
      return false;
    }
  }
  return true;
}

static bool cf_v2_pdf_state_write_pages(
    pdfio_file_t *pdf, pdfio_obj_t *font_a, pdfio_obj_t *font_b,
    size_t page_count,
    const uint8_t selectors[CF_V2_PDF_STATE_SELECTORS],
    const uint8_t *payload, size_t payload_size) {
  static const pdfio_rect_t boxes[] = {
      {0.0, 0.0, 595.0, 842.0},
      {0.0, 0.0, 612.0, 792.0},
      {0.0, 0.0, 842.0, 595.0},
      {18.0, 18.0, 594.0, 774.0},
  };

  for (size_t page = 0; page < page_count; page++) {
    pdfio_dict_t *dict = pdfioDictCreate(pdf);
    pdfio_stream_t *stream;
    pdfio_rect_t box = boxes[(selectors[11] + page) % 4U];
    pdfio_obj_t *font =
        selectors[20] % 3U == 2U && (page & 1U) ? font_b : font_a;
    uint8_t material = payload[(page + selectors[22]) % payload_size];

    if (!dict || !pdfioDictSetRect(dict, "MediaBox", &box) ||
        !pdfioPageDictAddFont(dict, "F0", font) ||
        !(stream = pdfioFileCreatePage(pdf, dict)) ||
        !pdfioStreamPrintf(stream,
                           "q BT /F0 12 Tf 36 72 Td (P2P%04u-%02X) Tj ET Q\n",
                           (unsigned)(page + 1U), (unsigned)material) ||
        !pdfioStreamClose(stream)) {
      return false;
    }
  }
  return true;
}

static uint8_t *cf_v2_pdf_state_build_document(
    const uint8_t selectors[CF_V2_PDF_STATE_SELECTORS],
    const uint8_t *payload, size_t payload_size,
    cf_v2_pdf_state_expect_t *expect, size_t *document_size) {
#if defined(CF_V2_PDF_OBJECT_VALID)
  static const char *const versions[] = {"1.4", "1.5", "1.7"};
  static const size_t page_counts[] = {1U, 2U, 4U, 8U, 16U};
  const char *version = versions[selectors[1] % 3U];
  size_t page_count = page_counts[selectors[3] % 5U];
#else
  static const size_t page_counts[] = {1U, 2U, 3U, 4U, 5U,
                                       8U, 16U, 32U, 64U};
  const char *version = selectors[1] & 1U ? "1.7" : "1.4";
  size_t page_count = page_counts[selectors[0] % 9U];
#endif
  cf_v2_pdf_state_error_t error = {false};
  char path[1024];
  pdfio_file_t *pdf = NULL;
  pdfio_obj_t *font_a = NULL;
  pdfio_obj_t *font_b = NULL;
  uint8_t *document = NULL;
  bool valid = false;

  expect->input_pages = page_count;
  pdf = pdfioFileCreateTemporary(path, sizeof(path), version, NULL, NULL,
                                 cf_v2_pdf_state_error, &error);
  if (!pdf || error.saw_error ||
      !(font_a = pdfioFileCreateFontObjFromBase(pdf, "Helvetica")) ||
      !(font_b = pdfioFileCreateFontObjFromBase(pdf, "Courier"))) {
    goto done;
  }
#if defined(CF_V2_PDF_OBJECT_VALID)
  if (!cf_v2_pdf_state_add_aux_objects(pdf, selectors, payload,
                                       payload_size)) {
    goto done;
  }
#endif
  if (!cf_v2_pdf_state_write_pages(pdf, font_a, font_b, page_count, selectors,
                                   payload, payload_size)) {
    goto done;
  }
  valid = true;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    valid = false;
  }
  if (valid && !error.saw_error) {
    document = cf_v2_pdf_state_read_file(path, document_size);
  }
  if (pdf) {
    unlink(path);
  }
  return document;
}

static int cf_v2_pdf_state_build_options(
    char *buffer, size_t buffer_size,
    const uint8_t selectors[CF_V2_PDF_STATE_SELECTORS],
    cf_v2_pdf_state_expect_t *expect) {
#if defined(CF_V2_PDF_OBJECT_VALID)
  bool full_layout = (selectors[16] & 1U) != 0U;
  int length = snprintf(
      buffer, buffer_size,
      "number-up=1 orientation-requested=%u print-scaling=%s "
      "page-border=%s mirror=%s sides=one-sided OutputOrder=Normal "
      "emit-jcl=false",
      full_layout ? 3U : 7U, full_layout ? "fit" : "none",
      full_layout ? "single" : "none", full_layout ? "true" : "false");

  expect->expected_pages = expect->input_pages;
  expect->duplex = false;
#else
  static const unsigned number_up[] = {1U, 2U, 3U, 4U, 6U, 8U,
                                       9U, 10U, 12U, 15U, 16U};
  static const unsigned orientations[] = {3U, 4U, 5U, 6U, 7U};
  static const char *const scaling[] = {"auto", "auto-fit", "fill", "fit",
                                        "none"};
  static const char *const sides[] = {"one-sided", "two-sided-long-edge",
                                      "two-sided-short-edge"};
  static const char *const borders[] = {"none", "single", "single-thick",
                                        "double", "double-thick"};
  unsigned nup = number_up[selectors[2] % 11U];
  const char *side = sides[selectors[8] % 3U];
  int length = snprintf(
      buffer, buffer_size,
      "number-up=%u orientation-requested=%u print-scaling=%s "
      "page-border=%s mirror=%s sides=%s OutputOrder=%s emit-jcl=false",
      nup, orientations[selectors[3] % 5U], scaling[selectors[4] % 5U],
      borders[selectors[12] % 5U], selectors[13] & 1U ? "true" : "false",
      side, selectors[9] & 1U ? "Reverse" : "Normal");

  expect->expected_pages = (expect->input_pages + nup - 1U) / nup;
  expect->duplex = strcmp(side, "one-sided") != 0;
#endif
  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}

static bool cf_v2_pdf_state_scan_stream(pdfio_obj_t *object,
                                        size_t *decoded_total,
                                        size_t input_pages,
                                        bool marker_seen[64]) {
  pdfio_stream_t *stream;
  uint8_t buffer[4096U + 8U];
  size_t carry = 0;
  ssize_t bytes;

  if (!object) {
    return true;
  }
  (void)pdfioObjGetDict(object);
  if (pdfioObjGetLength(object) == 0U) {
    return true;
  }
  if (!(stream = pdfioObjOpenStream(object, true))) {
    return false;
  }
  while ((bytes = pdfioStreamRead(stream, buffer + carry, 4096U)) > 0) {
    size_t available = carry + (size_t)bytes;
    *decoded_total += (size_t)bytes;
    if (*decoded_total > CF_V2_PDF_STATE_MAX_DECODED) {
      pdfioStreamClose(stream);
      return false;
    }
    for (size_t offset = 0; offset + 7U <= available; offset++) {
      size_t page_id;

      if (memcmp(buffer + offset, "P2P", 3U) != 0 ||
          buffer[offset + 3U] < '0' || buffer[offset + 3U] > '9' ||
          buffer[offset + 4U] < '0' || buffer[offset + 4U] > '9' ||
          buffer[offset + 5U] < '0' || buffer[offset + 5U] > '9' ||
          buffer[offset + 6U] < '0' || buffer[offset + 6U] > '9') {
        continue;
      }
      page_id = (size_t)(buffer[offset + 3U] - '0') * 1000U +
                (size_t)(buffer[offset + 4U] - '0') * 100U +
                (size_t)(buffer[offset + 5U] - '0') * 10U +
                (size_t)(buffer[offset + 6U] - '0');
      if (page_id >= 1U && page_id <= input_pages) {
        marker_seen[page_id - 1U] = true;
      }
    }
    carry = available < 7U ? available : 6U;
    memmove(buffer, buffer + available - carry, carry);
  }
  return bytes >= 0 && pdfioStreamClose(stream);
}

static bool cf_v2_pdf_state_validate_output(
    const char *path, const cf_v2_pdf_state_expect_t *expect,
    const char **failure) {
  cf_v2_pdf_state_error_t error = {false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_pdf_state_error, &error);
  bool valid = false;
  size_t pages;
  size_t decoded_total = 0;
  bool marker_seen[64] = {false};

  if (!pdf || error.saw_error) {
    *failure = "strict-reopen";
    goto done;
  }
  pages = pdfioFileGetNumPages(pdf);
  if (!pages || pages > CF_V2_PDF_STATE_MAX_OUTPUT_PAGES ||
      pages < expect->expected_pages ||
      pages > expect->expected_pages + (expect->duplex ? 1U : 0U)) {
    *failure = "page-count";
    goto done;
  }
  {
    pdfio_dict_t *catalog = pdfioFileGetCatalog(pdf);
    pdfio_obj_t *pages_object = catalog ? pdfioDictGetObj(catalog, "Pages") : NULL;
    pdfio_dict_t *pages_dict =
        pages_object ? pdfioObjGetDict(pages_object) : NULL;

    if (!catalog || !pages_dict ||
        strcmp(pdfioDictGetName(catalog, "Type") ?: "", "Catalog") != 0 ||
        strcmp(pdfioDictGetName(pages_dict, "Type") ?: "", "Pages") != 0 ||
        pdfioDictGetNumber(pages_dict, "Count") != (double)pages) {
      *failure = "page-tree";
      goto done;
    }
  }
  for (size_t index = 0; index < pages; index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, index);
    pdfio_rect_t box;

    if (!page || !pdfioPageGetRect(page, "MediaBox", &box) ||
        !isfinite(box.x1) || !isfinite(box.y1) || !isfinite(box.x2) ||
        !isfinite(box.y2) || box.x2 <= box.x1 || box.y2 <= box.y1) {
      *failure = "page-box";
      goto done;
    }
  }
  for (size_t index = 0; index < pdfioFileGetNumObjs(pdf); index++) {
    if (!cf_v2_pdf_state_scan_stream(pdfioFileGetObj(pdf, index),
                                     &decoded_total, expect->input_pages,
                                     marker_seen)) {
      *failure = "stream-decode";
      goto done;
    }
  }
  for (size_t page = 0; page < expect->input_pages; page++) {
    if (!marker_seen[page]) {
      *failure = "page-marker-loss";
      goto done;
    }
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    valid = false;
    *failure = "pdf-close";
  }
  return valid && !error.saw_error;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  const uint8_t *payload;
  size_t payload_size;
  cf_v2_pdf_state_expect_t expect = {0};
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  size_t ppd_size = 0;
  uint8_t *document = NULL;
  size_t document_size = 0;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-pdf-state.XXXXXX";
  int output_fd = -1;
  bool trap_after_cleanup = false;
  const char *failure = NULL;

  if (!data || size <= CF_V2_PDF_STATE_HEADER_SIZE ||
      size > CF_V2_PDF_STATE_MAX_INPUT ||
      memcmp(data, cf_v2_pdf_state_magic, CF_V2_PDF_STATE_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_PDF_STATE_MAGIC_SIZE;
  payload = data + CF_V2_PDF_STATE_HEADER_SIZE;
  payload_size = size - CF_V2_PDF_STATE_HEADER_SIZE;
  document = cf_v2_pdf_state_build_document(selectors, payload, payload_size,
                                            &expect, &document_size);
  if (!document ||
      cf_v2_pdf_state_build_options(options, sizeof(options), selectors,
                                    &expect) != 0) {
    free(document);
    return 0;
  }

  memset(&control, 0, sizeof(control));
  control.ppd_profile = selectors[14] % 4U;
  control.page_size = selectors[11];
  control.color_model = selectors[15];
  control.resolution = selectors[17];
  control.sides = selectors[8];
  control.orientation = selectors[3];
  control.scaling = selectors[4];
  control.position = selectors[19];
  control.output_order = selectors[9];
  control.mirror = selectors[13];
  control.route_mode = selectors[16];
  control.reserved = selectors[23];
  ppd = cf_v2_pdf_state_build_ppd(&control, &ppd_size);
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
  if (cf_v2_execute_direct_job(&job, 1, &result) && result.status == 0) {
    if (!result.captured || result.output_size < 5U ||
        result.output_size > CF_V2_CAPTURE_LIMIT ||
        memcmp(result.output, "%PDF-", 5U) != 0) {
      trap_after_cleanup = true;
      failure = "success-output-contract";
    } else {
      output_fd = mkstemp(output_path);
      if (output_fd >= 0) {
        int write_status =
            cf_v2_write_all(output_fd, result.output, result.output_size);
        int close_status = close(output_fd);

        output_fd = -1;
        if (write_status == 0 && close_status == 0) {
          trap_after_cleanup =
              !cf_v2_pdf_state_validate_output(output_path, &expect, &failure);
        }
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
    fprintf(stderr, "pdf-valid-state-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
