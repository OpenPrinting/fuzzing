// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_text_pdf_unused_direct_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <math.h>
#include <pdfio.h>
#include <stdbool.h>

#ifdef CF_V2_TEXT_SHARED_CONTRACT
#define CF_V2_TEXT_PDF_MAGIC "TXTJOB01"
#elif defined(CF_V2_TEXT_PDF_WRITER_CONTINUATION)
#define CF_V2_TEXT_PDF_MAGIC "TXTPDFC1"
#else
#define CF_V2_TEXT_PDF_MAGIC "TXTPDFO1"
#endif
#define CF_V2_TEXT_PDF_MAGIC_SIZE 8U
#define CF_V2_TEXT_PDF_SELECTORS 16U
#define CF_V2_TEXT_PDF_MAX_PAYLOAD 4096U
#define CF_V2_TEXT_PDF_MAX_OUTPUT (8U * 1024U * 1024U)
#define CF_V2_TEXT_PDF_MAX_PAGES 256U
#define CF_V2_TEXT_PDF_MAX_STREAMS 8U
#define CF_V2_TEXT_PDF_MAX_TOKENS (1024U * 1024U)

static const uint8_t cf_v2_text_pdf_begin[] = "CFTEXTPDF_BEGIN";
static const uint8_t cf_v2_text_pdf_end[] = "CFTEXTPDF_END";
static const uint8_t cf_v2_text_pdf_prefix[] = "CFTEXTPDF_BEGIN\n\f";
static const uint8_t cf_v2_text_pdf_suffix[] = "\fCFTEXTPDF_END\n";

typedef struct cf_v2_text_pdf_error_s {
  bool saw_error;
} cf_v2_text_pdf_error_t;

typedef struct cf_v2_text_pdf_sentinel_s {
  size_t begin_match;
  size_t end_match;
  bool saw_begin;
  bool saw_end;
} cf_v2_text_pdf_sentinel_t;

static bool cf_v2_text_pdf_fail(const char **failure, const char *reason) {
  if (failure && !*failure) {
    *failure = reason;
  }
  return false;
}

static bool cf_v2_text_pdf_error(pdfio_file_t *pdf, const char *message,
                                 void *data) {
  cf_v2_text_pdf_error_t *error = (cf_v2_text_pdf_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static bool cf_v2_text_pdf_name_is(pdfio_dict_t *dict, const char *key,
                                   const char *expected) {
  const char *value = dict ? pdfioDictGetName(dict, key) : NULL;

  return value && strcmp(value, expected) == 0;
}

static int cf_v2_text_pdf_hex(char value) {
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

static void cf_v2_text_pdf_match(size_t *matched, const uint8_t *needle,
                                 size_t needle_size, uint8_t value,
                                 bool *found) {
  if (*found) {
    return;
  }
  if (value == needle[*matched]) {
    (*matched)++;
  } else {
    *matched = value == needle[0] ? 1U : 0U;
  }
  if (*matched == needle_size) {
    *found = true;
    *matched = 0;
  }
}

static bool cf_v2_text_pdf_consume_hex(
    const char *token, cf_v2_text_pdf_sentinel_t *sentinels) {
  size_t length = strlen(token);

  if (length < 1U || token[0] != '<' ||
      (length > 1U && token[1] == '<')) {
    return true;
  }
  if (((length - 1U) & 1U) != 0U) {
    return false;
  }
  for (size_t index = 1U; index < length; index += 2U) {
    int high = cf_v2_text_pdf_hex(token[index]);
    int low = cf_v2_text_pdf_hex(token[index + 1U]);
    uint8_t value;

    if (high < 0 || low < 0) {
      return false;
    }
    value = (uint8_t)((high << 4) | low);
    cf_v2_text_pdf_match(&sentinels->begin_match, cf_v2_text_pdf_begin,
                         sizeof(cf_v2_text_pdf_begin) - 1U, value,
                         &sentinels->saw_begin);
    if (sentinels->saw_begin) {
      cf_v2_text_pdf_match(&sentinels->end_match, cf_v2_text_pdf_end,
                           sizeof(cf_v2_text_pdf_end) - 1U, value,
                           &sentinels->saw_end);
    }
  }
  return true;
}

static bool cf_v2_text_pdf_validate_streams(
    pdfio_obj_t *page, cf_v2_text_pdf_error_t *error,
    cf_v2_text_pdf_sentinel_t *sentinels, size_t *token_count,
    const char **failure) {
  size_t stream_count = pdfioPageGetNumStreams(page);

  if (stream_count < 1U || stream_count > CF_V2_TEXT_PDF_MAX_STREAMS) {
    return cf_v2_text_pdf_fail(failure, "page-stream-count");
  }
  for (size_t index = 0; index < stream_count; index++) {
    pdfio_stream_t *stream = pdfioPageOpenStream(page, index, true);
    char token[4096];
    int text_depth = 0;
    bool valid = true;

    if (!stream) {
      return cf_v2_text_pdf_fail(failure, "page-stream-open");
    }
    while (pdfioStreamGetToken(stream, token, sizeof(token))) {
      if (++(*token_count) > CF_V2_TEXT_PDF_MAX_TOKENS) {
        cf_v2_text_pdf_fail(failure, "content-token-budget");
        valid = false;
        break;
      }
      if (strcmp(token, "BT") == 0) {
        if (++text_depth > 1) {
          cf_v2_text_pdf_fail(failure, "nested-BT");
          valid = false;
          break;
        }
      } else if (strcmp(token, "ET") == 0) {
        if (text_depth != 1) {
          cf_v2_text_pdf_fail(failure, "unbalanced-ET");
          valid = false;
          break;
        }
        text_depth = 0;
      } else if (!cf_v2_text_pdf_consume_hex(token, sentinels)) {
        cf_v2_text_pdf_fail(failure, "malformed-hex-string");
        valid = false;
        break;
      }
    }
    if (text_depth != 0 || error->saw_error) {
      cf_v2_text_pdf_fail(failure,
                          error->saw_error ? "pdfio-stream-error"
                                           : "unterminated-BT");
      valid = false;
    }
    if (!pdfioStreamClose(stream)) {
      cf_v2_text_pdf_fail(failure, "page-stream-close");
      valid = false;
    }
    if (!valid) {
      return false;
    }
  }
  return true;
}

static bool cf_v2_text_pdf_validate_file(const char *path,
                                         const char **failure) {
  cf_v2_text_pdf_error_t error = {false};
  cf_v2_text_pdf_sentinel_t sentinels = {0, 0, false, false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_text_pdf_error, &error);
  size_t token_count = 0;
  bool valid = false;

  if (failure) {
    *failure = NULL;
  }
  if (!pdf || error.saw_error) {
    cf_v2_text_pdf_fail(failure, "pdf-open");
    goto done;
  }
  {
    pdfio_dict_t *catalog = pdfioFileGetCatalog(pdf);
    pdfio_obj_t *pages_object;
    pdfio_dict_t *pages;
    pdfio_array_t *kids;
    size_t page_count;

    if (!cf_v2_text_pdf_name_is(catalog, "Type", "Catalog") ||
        pdfioDictGetType(catalog, "Pages") != PDFIO_VALTYPE_INDIRECT ||
        !(pages_object = pdfioDictGetObj(catalog, "Pages")) ||
        !(pages = pdfioObjGetDict(pages_object)) ||
        !cf_v2_text_pdf_name_is(pages, "Type", "Pages") ||
        pdfioDictGetType(pages, "Count") != PDFIO_VALTYPE_NUMBER ||
        pdfioDictGetType(pages, "Kids") != PDFIO_VALTYPE_ARRAY ||
        !(kids = pdfioDictGetArray(pages, "Kids"))) {
      cf_v2_text_pdf_fail(failure, "page-tree-root");
      goto done;
    }
    page_count = pdfioFileGetNumPages(pdf);
    if (page_count < 2U) {
      cf_v2_text_pdf_fail(failure, "page-count-below-two");
      goto done;
    }
    if (page_count > CF_V2_TEXT_PDF_MAX_PAGES) {
      cf_v2_text_pdf_fail(failure, "page-count-budget");
      goto done;
    }
    if (!isfinite(pdfioDictGetNumber(pages, "Count"))) {
      cf_v2_text_pdf_fail(failure, "page-count-nonfinite");
      goto done;
    }
    if (pdfioDictGetNumber(pages, "Count") != (double)page_count) {
      cf_v2_text_pdf_fail(failure, "page-count-tree-mismatch");
      goto done;
    }
    if (pdfioArrayGetSize(kids) != page_count) {
      cf_v2_text_pdf_fail(failure, "page-kids-count-mismatch");
      goto done;
    }
    for (size_t index = 0; index < page_count; index++) {
      pdfio_obj_t *kid = pdfioArrayGetObj(kids, index);
      pdfio_obj_t *page = pdfioFileGetPage(pdf, index);
      pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
      pdfio_obj_t *parent =
          page_dict ? pdfioDictGetObj(page_dict, "Parent") : NULL;
      pdfio_rect_t media_box;

      if (!kid || !page ||
          pdfioObjGetNumber(kid) != pdfioObjGetNumber(page) ||
          pdfioObjGetGeneration(kid) != pdfioObjGetGeneration(page) ||
          !cf_v2_text_pdf_name_is(page_dict, "Type", "Page") || !parent ||
          pdfioObjGetNumber(parent) != pdfioObjGetNumber(pages_object) ||
          pdfioObjGetGeneration(parent) !=
              pdfioObjGetGeneration(pages_object) ||
          !pdfioPageGetRect(page, "MediaBox", &media_box) ||
          !isfinite(media_box.x1) || !isfinite(media_box.y1) ||
          !isfinite(media_box.x2) || !isfinite(media_box.y2) ||
          !cf_v2_text_pdf_validate_streams(page, &error, &sentinels,
                                           &token_count, failure)) {
        cf_v2_text_pdf_fail(failure, "page-object");
        goto done;
      }
    }
  }
  valid = sentinels.saw_begin && sentinels.saw_end && !error.saw_error;
  if (!valid) {
    cf_v2_text_pdf_fail(failure, "sentinel-preservation");
  }

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v2_text_pdf_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

static uint8_t cf_v2_text_pdf_material(uint8_t value, unsigned mode) {
  static const char punctuation[] = "{}[]()<>/*#;:'\"=+-_.,!?";

  switch (mode % 4U) {
    case 1U:
      return (uint8_t)('a' + value % 26U);
    case 2U:
      return (uint8_t)('0' + value % 10U);
    case 3U:
      return (uint8_t)punctuation[value % (sizeof(punctuation) - 1U)];
    default:
      return (uint8_t)(' ' + value % 95U);
  }
}

static uint8_t *cf_v2_text_pdf_build_document(const uint8_t *selectors,
                                              const uint8_t *payload,
                                              size_t payload_size,
                                              size_t *document_size) {
  size_t capacity = sizeof(cf_v2_text_pdf_prefix) - 1U + payload_size * 2U +
                    sizeof(cf_v2_text_pdf_suffix) - 1U;
  uint8_t *document = (uint8_t *)malloc(capacity);
  size_t used = 0;
  unsigned form_feeds = 0;

  if (!document) {
    return NULL;
  }
  memcpy(document + used, cf_v2_text_pdf_prefix,
         sizeof(cf_v2_text_pdf_prefix) - 1U);
  used += sizeof(cf_v2_text_pdf_prefix) - 1U;
  for (size_t index = 0; index < payload_size; index++) {
    unsigned selector = (payload[index] + selectors[12]) & 31U;

    if (selector == 0U) {
      document[used++] = '\n';
    } else if (selector == 1U) {
      document[used++] = '\t';
    } else if (selector == 2U) {
      document[used++] = '\b';
    } else if (selector == 3U && form_feeds < 16U) {
      document[used++] = '\f';
      form_feeds++;
    } else if (selector == 4U) {
      document[used++] = 0x1bU;
      document[used++] = (uint8_t)('7' + selectors[13] % 3U);
    } else {
      document[used++] =
          cf_v2_text_pdf_material(payload[index], selectors[9]);
    }
  }
  memcpy(document + used, cf_v2_text_pdf_suffix,
         sizeof(cf_v2_text_pdf_suffix) - 1U);
  used += sizeof(cf_v2_text_pdf_suffix) - 1U;
  *document_size = used;
  return document;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  const uint8_t *payload;
  size_t payload_size;
  size_t document_size = 0;
  uint8_t *document = NULL;
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  char output_path[] = "/tmp/cupsfilters-v2-text-pdf.XXXXXX";
  int output_fd = -1;
  int executed;
  bool trap_after_cleanup = false;
  const char *oracle_failure = NULL;

  memset(&result, 0, sizeof(result));
  if (!data || size < CF_V2_TEXT_PDF_MAGIC_SIZE +
                          CF_V2_TEXT_PDF_SELECTORS + 1U ||
      size > CF_V2_TEXT_PDF_MAGIC_SIZE + CF_V2_TEXT_PDF_SELECTORS +
                 CF_V2_TEXT_PDF_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_PDF_MAGIC,
             CF_V2_TEXT_PDF_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_TEXT_PDF_MAGIC_SIZE;
  payload = selectors + CF_V2_TEXT_PDF_SELECTORS;
  payload_size = size - CF_V2_TEXT_PDF_MAGIC_SIZE -
                 CF_V2_TEXT_PDF_SELECTORS;
  memcpy(&control, selectors, sizeof(control));
  cf_v2_apply_control_policy(&control);
  control.number_up = 0U;
  control.copies = 0U;
#ifdef CF_V2_TEXT_PDF_WRITER_CONTINUATION
  /* The faithful TXTPDFO1 lane retains the pretty-print rollover root. */
  control.route_mode &= (uint8_t)~1U;
#endif
  document = cf_v2_text_pdf_build_document(selectors, payload, payload_size,
                                           &document_size);
  if (!document) {
    return 0;
  }

  cf_v2_texttopdf_active = 1;
  executed = cf_v2_execute_direct(document, document_size, &control, 1,
                                  &result);
  cf_v2_release_texttopdf_lifecycle();
  if (executed && result.status == 0) {
    if (!result.captured || result.output_size == 0U ||
        result.output_size > CF_V2_TEXT_PDF_MAX_OUTPUT) {
      trap_after_cleanup = true;
      oracle_failure = "captured-output-bounds";
    } else if ((output_fd = mkstemp(output_path)) < 0 ||
               cf_v2_write_all(output_fd, result.output,
                               result.output_size) != 0 ||
               close(output_fd) != 0) {
      output_fd = -1;
    } else {
      output_fd = -1;
      trap_after_cleanup =
          !cf_v2_text_pdf_validate_file(output_path, &oracle_failure);
    }
  }

  if (output_fd >= 0) {
    close(output_fd);
  }
  unlink(output_path);
  cf_v2_free_run_result(&result);
  free(document);
  if (trap_after_cleanup) {
    fprintf(stderr, "text-pdf-output-oracle: %s\n",
            oracle_failure ? oracle_failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
