// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_text_job_unused_entry
#include "fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#ifdef CF_V2_TEXT_JOB_ROUTE_PDF
#include <pdfio.h>
#endif

#include <limits.h>

#define CF_V2_TEXT_JOB_MAGIC "TXTJOB02"
#define CF_V2_TEXT_JOB_MAGIC_SIZE 8U
#define CF_V2_TEXT_JOB_SELECTORS 24U
#define CF_V2_TEXT_JOB_MAX_PAYLOAD 256U
#define CF_V2_TEXT_JOB_DOCUMENT_CAPACITY (64U * 1024U)

typedef struct cf_v2_text_job_buffer_s {
  uint8_t data[CF_V2_TEXT_JOB_DOCUMENT_CAPACITY];
  size_t size;
} cf_v2_text_job_buffer_t;

static int cf_v2_text_job_add(cf_v2_text_job_buffer_t *buffer,
                              const void *data, size_t size) {
  if (size > sizeof(buffer->data) - buffer->size) {
    return 0;
  }
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int cf_v2_text_job_repeat(cf_v2_text_job_buffer_t *buffer,
                                 uint8_t value, size_t count) {
  if (count > sizeof(buffer->data) - buffer->size) {
    return 0;
  }
  memset(buffer->data + buffer->size, value, count);
  buffer->size += count;
  return 1;
}

static unsigned cf_v2_text_job_safe_width(const uint8_t *selector) {
  return 40U + (unsigned)selector[2] * 4U;
}

static unsigned cf_v2_text_job_safe_height(const uint8_t *selector) {
  return 20U + (unsigned)selector[4] * 2U;
}

static unsigned cf_v2_text_job_boundary_number(unsigned kind,
                                                unsigned parameter) {
  switch (kind % 8U) {
    case 0U:
      return 1U + parameter;
    case 1U:
      return 1U << (20U + parameter % 11U);
    case 2U:
      return (unsigned)INT_MAX - parameter;
    case 3U:
      return (unsigned)INT_MAX / (1U + parameter % 16U) + parameter;
    case 4U:
      return UINT_MAX / (1U + parameter % 16U) + parameter;
    case 5U:
      return 0x40000000U + parameter;
    case 6U:
      return 0x80000000U + parameter;
    default:
      return UINT_MAX - parameter;
  }
}

static unsigned cf_v2_text_job_column_count(const uint8_t *selector,
                                             unsigned violation) {
  if (violation != 2U) {
    return 1U + selector[5] % 4U;
  }
  if ((selector[5] & 1U) == 0U) {
    return cf_v2_text_job_boundary_number(selector[5], selector[7]);
  }
  return UINT_MAX / (1U + selector[6] % 16U) +
         (unsigned)((int)selector[7] - 32);
}

static int cf_v2_text_job_options(
    char *options, size_t capacity,
    const uint8_t selector[CF_V2_TEXT_JOB_SELECTORS], unsigned violation,
    unsigned *text_width, unsigned *text_height) {
  int length;

#ifdef CF_V2_TEXT_JOB_ROUTE_TEXT
  unsigned width = cf_v2_text_job_safe_width(selector);
  unsigned height = cf_v2_text_job_safe_height(selector);
  int tab_width = 1 + selector[10] % 16U;
  static const char *const overlong[] = {
    "truncate", "word-wrap", "wrap-at-width", "truncate",
  };
  const char *overlong_mode = overlong[selector[11] % 4U];

  if (violation == 1U) {
    /* Keep the wrapped allocation small while the logical row stays huge. */
    width = 0x40000000U + selector[2];
    height = 1U;
    (void)selector[1];
  } else if (violation == 3U) {
    tab_width = selector[10] == 0U ? 0 :
                (selector[10] == 1U ? -1 : INT_MAX);
  } else if (violation == 4U) {
    overlong_mode = "word-wrap";
  }
  *text_width = width;
  *text_height = height;
  length = snprintf(
      options, capacity,
      "PageWidth=%u PageHeight=%u PageLeft=0 PageRight=0 PageTop=0 "
      "PageBottom=0 OverLongLines=%s TabWidth=%d Pagination=%s "
      "PrinterEncoding=%s",
      width, height, overlong_mode, tab_width,
      selector[19] & 1U ? "true" : "false",
      selector[18] & 1U ? "UTF-8" : "ASCII");
#else
  unsigned columns = cf_v2_text_job_column_count(selector, violation);
  static const unsigned cpi_values[] = {6U, 8U, 10U, 12U, 15U, 16U, 18U, 20U};
  static const unsigned lpi_values[] = {1U, 4U, 6U, 8U, 10U, 12U, 16U, 24U};
  int pretty = selector[12] != 0U;
  int wrap = selector[11] != 0U;
  unsigned cpi = cpi_values[selector[8] % 8U];
  unsigned lpi = lpi_values[selector[9] % 8U];

  if (violation == 2U) {
    /* Exercise the multi-column arithmetic with a compact backing page. */
    cpi = 10U;
    lpi = 1U;
    wrap = 1;
  } else if (violation == 4U) {
    pretty = 1;
    wrap = 0;
  } else if (violation == 5U) {
    pretty = 1;
  } else if (violation == 6U) {
    /* Match texttopdf's pretty-print Letter geometry: 84 by 77 cells. */
    pretty = 1;
    wrap = 1;
    cpi = 12U;
    lpi = 8U;
  }
  *text_width = pretty ? 84U : 80U;
  *text_height = pretty ? 77U : 66U;
  if (violation == 2U) {
    *text_height = 10U;
  }
  length = snprintf(options, capacity,
                    "PageSize=Letter columns=%u cpi=%u lpi=%u "
                    "prettyprint=%s wrap=%s",
                    columns, cpi, lpi,
                    pretty ? "true" : "false", wrap ? "true" : "false");
#endif
  return length > 0 && (size_t)length < capacity;
}

static size_t cf_v2_text_job_title(
    uint8_t *title, size_t capacity,
    const uint8_t selector[CF_V2_TEXT_JOB_SELECTORS],
    const uint8_t *payload, size_t payload_size, unsigned violation) {
  size_t used = 0U;

  if (violation == 5U) {
    static const uint8_t leads[] = {
      0xc0U, 0xc2U, 0xdfU, 0xe0U, 0xefU, 0xf0U, 0xf4U, 0xffU,
    };
    title[used++] = leads[selector[13] % 8U];
    if ((selector[15] & 3U) == 1U && used < capacity) {
      title[used++] = (uint8_t)(0x80U + selector[16] % 64U);
    }
    return used;
  }
  while (used < 1U + selector[13] % 24U && used < capacity) {
    title[used] = (uint8_t)('A' + payload[used % payload_size] % 26U);
    used++;
  }
  return used;
}

static int cf_v2_text_job_safe_document(
    cf_v2_text_job_buffer_t *document,
    const uint8_t selector[CF_V2_TEXT_JOB_SELECTORS],
    const uint8_t *payload, size_t payload_size) {
  static const uint8_t prefix[] = "CF_TEXT_JOB_BEGIN\n";
  static const uint8_t suffix[] = "\nCF_TEXT_JOB_END\n";
  static const uint8_t endings[][2] = {{'\n', 0}, {'\r', 0}, {'\r', '\n'}, {'\n', 0}};
  size_t count = 16U + (size_t)selector[15] * 8U;

  if (!cf_v2_text_job_add(document, prefix, sizeof(prefix) - 1U)) {
    return 0;
  }
  for (size_t index = 0U; index < count; index++) {
    uint8_t value = payload[index % payload_size];
#ifdef CF_V2_TEXT_JOB_DEEP
    static const char deep_glyphs[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.,;:()[]{}";
    uint8_t glyph =
        (uint8_t)deep_glyphs[value % (sizeof(deep_glyphs) - 1U)];
#else
    uint8_t glyph = (uint8_t)('!' + value % 94U);
#endif

    if ((value % 31U) == 0U) {
      glyph = ' ';
    }
    if (!cf_v2_text_job_add(document, &glyph, 1U)) {
      return 0;
    }
    if ((index + 1U) % (8U + selector[14] * 2U) == 0U) {
      size_t ending_size = selector[17] % 4U == 2U ? 2U : 1U;
      if (!cf_v2_text_job_add(document, endings[selector[17] % 4U],
                              ending_size)) {
        return 0;
      }
    }
  }
  return cf_v2_text_job_add(document, suffix, sizeof(suffix) - 1U);
}

static int cf_v2_text_job_document(
    cf_v2_text_job_buffer_t *document,
    const uint8_t selector[CF_V2_TEXT_JOB_SELECTORS],
    const uint8_t *payload, size_t payload_size, unsigned violation,
    unsigned text_width, unsigned text_height) {
  if (violation == 0U || violation == 5U) {
    return cf_v2_text_job_safe_document(document, selector, payload,
                                        payload_size);
  }
  if (violation == 1U) {
    size_t wrapped_allocation = 16U + (size_t)selector[2] * 4U;
    return cf_v2_text_job_repeat(document, 'A',
                                 wrapped_allocation + 32U) &&
           cf_v2_text_job_add(document, "\n", 1U);
  }
  if (violation == 2U) {
    size_t page_cells = (size_t)text_width * text_height;
    size_t count = page_cells * 6U + (size_t)selector[15] * 16U;
    return cf_v2_text_job_repeat(document, 'A', count);
  }
  if (violation == 3U) {
    return cf_v2_text_job_add(document, "\t", 1U);
  }
  if (violation == 4U) {
#ifdef CF_V2_TEXT_JOB_ROUTE_TEXT
    size_t count = (size_t)text_width + 1U + selector[15];
    return cf_v2_text_job_repeat(document, 'A', count);
#else
    size_t count = (size_t)text_width * text_height + selector[15];
    return cf_v2_text_job_repeat(document, ' ', count) &&
           cf_v2_text_job_add(document, "while ", 6U);
#endif
  }
  if (violation == 6U) {
#ifdef CF_V2_TEXT_JOB_C_SOURCE
    size_t cells = (size_t)text_width * text_height;
    return cells > 1U && cf_v2_text_job_repeat(document, 'A', cells - 1U) &&
           cf_v2_text_job_add(document, "/*", 2U);
#else
    return cf_v2_text_job_repeat(document, 'P', text_width) &&
           cf_v2_text_job_add(document, "\fQ\n", 3U);
#endif
  }
  {
    static const uint8_t invalid[] = {
      0x80U, 0xc0U, 0xafU, 0xe0U, 0x80U, 0x80U, 0xffU, '\n',
    };
    return cf_v2_text_job_add(document, invalid, sizeof(invalid));
  }
}

#if defined(CF_V2_TEXT_JOB_ROUTE_PDF) && defined(CF_V2_TEXT_JOB_DEEP)
static bool cf_v2_text_job_pdf_error(pdfio_file_t *pdf, const char *message,
                                     void *data) {
  (void)pdf;
  (void)message;
  *(bool *)data = true;
  return false;
}

static int cf_v2_text_job_validate_pdf(const uint8_t *data, size_t size) {
  char path[] = "/tmp/cupsfilters-v2-text-job-pdf.XXXXXX";
  bool saw_error = false;
  pdfio_file_t *pdf = NULL;
  int fd = mkstemp(path);
  int valid = 0;

  if (fd < 0 || cf_v2_write_all(fd, data, size) != 0 || close(fd) != 0) {
    if (fd >= 0) {
      close(fd);
    }
    unlink(path);
    return 0;
  }
  pdf = pdfioFileOpen(path, NULL, NULL, cf_v2_text_job_pdf_error, &saw_error);
  if (pdf) {
    size_t pages = pdfioFileGetNumPages(pdf);
    valid = !saw_error && pages > 0U && pages <= 256U;
    if (!pdfioFileClose(pdf)) {
      valid = 0;
    }
  }
  unlink(path);
  return valid;
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t fixed_size = CF_V2_TEXT_JOB_MAGIC_SIZE +
                            CF_V2_TEXT_JOB_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  unsigned violation;
  unsigned text_width = 0U;
  unsigned text_height = 0U;
  char options[1024];
  uint8_t title[64];
  cf_v2_text_job_buffer_t *document;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_JOB_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_JOB_MAGIC, CF_V2_TEXT_JOB_MAGIC_SIZE) != 0) {
    return 0;
  }
  selector = data + CF_V2_TEXT_JOB_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
#ifdef CF_V2_TEXT_JOB_DEEP
  violation = 0U;
#else
  violation = selector[23] % 8U;
#endif
  if (!cf_v2_text_job_options(options, sizeof(options), selector, violation,
                              &text_width, &text_height)) {
    return 0;
  }
  document = (cf_v2_text_job_buffer_t *)calloc(1U, sizeof(*document));
  if (!document ||
      !cf_v2_text_job_document(document, selector, payload, payload_size,
                               violation, text_width, text_height)) {
    free(document);
    return 0;
  }

  memset(&job, 0, sizeof(job));
  job.control.ppd_profile = selector[0];
  job.control.page_size = selector[1];
  job.control.orientation = selector[22];
  job.control.sides = selector[21];
  job.control.copies = selector[20];
  job.control.number_up = 0U;
  cf_v2_apply_control_policy(&job.control);
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = title;
  job.title_size = cf_v2_text_job_title(
      title, sizeof(title), selector, payload, payload_size, violation);
  job.document = document->data;
  job.document_size = document->size;

  memset(&result, 0, sizeof(result));
#ifdef CF_V2_TEXT_JOB_ROUTE_PDF
  cf_v2_texttopdf_active = 1;
  executed = cf_v2_execute_direct_job(
      &job,
#ifdef CF_V2_TEXT_JOB_DEEP
      1,
#else
      0,
#endif
      &result);
  cf_v2_release_texttopdf_lifecycle();
#else
  executed = cf_v2_execute_direct_job(&job, 0, &result);
#endif

#if defined(CF_V2_TEXT_JOB_ROUTE_PDF) && defined(CF_V2_TEXT_JOB_DEEP)
  if (executed && result.status == 0 &&
      (!result.captured || result.output_size == 0U ||
       result.output_size > 8U * 1024U * 1024U ||
       !cf_v2_text_job_validate_pdf(result.output, result.output_size))) {
    cf_v2_free_run_result(&result);
    free(document);
    __builtin_trap();
  }
#else
  (void)executed;
#endif
  cf_v2_free_run_result(&result);
  free(document);
  return 0;
}
