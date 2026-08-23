// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "banner_graph_adapter.h"

#include <cups/cups.h>
#include <cups/ipp.h>
#include <cupsfilters/filter.h>
#include <cupsfilters/pdf.h>
#include <pdfio.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CF_V3_BANNER_CONTROL_BYTES 16U
#define CF_V3_BANNER_GRAPH_BYTES 10U
#define CF_V3_BANNER_JOB_BYTES 10U
#define CF_V3_BANNER_HEADER_BYTES                                           \
  (1U + CF_V3_BANNER_CONTROL_BYTES + CF_V3_BANNER_GRAPH_BYTES +            \
   CF_V3_BANNER_JOB_BYTES)
#define CF_V3_BANNER_MAX_INPUT (1024U * 1024U)
#define CF_V3_BANNER_MAX_CONTROL 32768U
#define CF_V3_BANNER_MAX_TRACKED 64U
#define CF_V3_BANNER_MAX_PDF_ALLOCS 16384U

enum cf_v3_banner_route_e {
  CF_V3_BANNER_STRUCTURED = 0,
  CF_V3_BANNER_RAW_CONTROL = 1,
  CF_V3_BANNER_RAW_PDF = 2,
};

typedef struct cf_v3_banner_buffer_s {
  uint8_t *bytes;
  size_t capacity;
  size_t length;
  bool failed;
} cf_v3_banner_buffer_t;

static int cf_v3_banner_tracking;
static int cf_v3_banner_output_fd = -1;
static FILE *cf_v3_banner_streams[CF_V3_BANNER_MAX_TRACKED];
static size_t cf_v3_banner_stream_count;
static void *cf_v3_banner_time_allocs[CF_V3_BANNER_MAX_TRACKED];
static size_t cf_v3_banner_time_count;
static void *cf_v3_banner_iterate_allocs[CF_V3_BANNER_MAX_TRACKED];
static size_t cf_v3_banner_iterate_count;
static void *cf_v3_banner_pdf_allocs[CF_V3_BANNER_MAX_PDF_ALLOCS];
static size_t cf_v3_banner_pdf_alloc_count;
static int cf_v3_banner_pdf_alloc_tracking;
static int cf_v3_banner_pdf_alloc_overflow;
static int cf_v3_banner_faithful;
static pdfio_file_t *cf_v3_banner_pdf_file;

extern FILE *__real_fdopen(int fd, const char *mode);
extern int __real_fclose(FILE *stream);
extern void *__real_malloc(size_t size);
extern void *__real_realloc(void *pointer, size_t size);
extern void __real_free(void *pointer);
extern pdfio_file_t *__real_pdfioFileOpen(
    const char *filename, pdfio_password_cb_t password_cb,
    void *password_data, pdfio_error_cb_t error_cb, void *error_data);
extern bool __real_pdfioFileClose(pdfio_file_t *pdf);
extern pdfio_dict_t *__real_pdfioDictCopy(pdfio_file_t *pdf,
                                         pdfio_dict_t *dict);

static void cf_v3_banner_forget_time(void *pointer);
static void cf_v3_banner_forget_iterate(void *pointer);

static bool cf_v3_banner_pdf_error(pdfio_file_t *pdf, const char *message,
                                   void *data) {
  (void)pdf;
  (void)data;
  return message && strncmp(message, "WARNING:", 8U) == 0;
}

static void cf_v3_banner_track_alloc(void *pointer, size_t size) {
  if (cf_v3_banner_tracking && pointer && size == 40U &&
      cf_v3_banner_time_count < CF_V3_BANNER_MAX_TRACKED) {
    cf_v3_banner_time_allocs[cf_v3_banner_time_count++] = pointer;
  } else if (cf_v3_banner_tracking && pointer &&
             size == sizeof(iterate_data_t) &&
             cf_v3_banner_iterate_count < CF_V3_BANNER_MAX_TRACKED) {
    cf_v3_banner_iterate_allocs[cf_v3_banner_iterate_count++] = pointer;
  }
  if (!cf_v3_banner_pdf_alloc_tracking || !pointer) {
    return;
  }
  if (cf_v3_banner_pdf_alloc_count >= CF_V3_BANNER_MAX_PDF_ALLOCS) {
    cf_v3_banner_pdf_alloc_overflow = 1;
    return;
  }
  cf_v3_banner_pdf_allocs[cf_v3_banner_pdf_alloc_count++] = pointer;
}

FILE *__wrap_fdopen(int fd, const char *mode) {
  FILE *stream = __real_fdopen(fd, mode);
  if (cf_v3_banner_tracking && stream && fd == cf_v3_banner_output_fd &&
      cf_v3_banner_stream_count < CF_V3_BANNER_MAX_TRACKED) {
    cf_v3_banner_streams[cf_v3_banner_stream_count++] = stream;
  }
  return stream;
}

static void cf_v3_banner_forget_stream(FILE *stream) {
  for (size_t index = 0; index < cf_v3_banner_stream_count; index++) {
    if (cf_v3_banner_streams[index] == stream) {
      cf_v3_banner_streams[index] =
          cf_v3_banner_streams[--cf_v3_banner_stream_count];
      cf_v3_banner_streams[cf_v3_banner_stream_count] = NULL;
      return;
    }
  }
}

int __wrap_fclose(FILE *stream) {
  cf_v3_banner_forget_stream(stream);
  return __real_fclose(stream);
}

void *__wrap_malloc(size_t size) {
  void *pointer = __real_malloc(size);
  cf_v3_banner_track_alloc(pointer, size);
  return pointer;
}

static void cf_v3_banner_forget_time(void *pointer) {
  for (size_t index = 0; index < cf_v3_banner_time_count; index++) {
    if (cf_v3_banner_time_allocs[index] == pointer) {
      cf_v3_banner_time_allocs[index] =
          cf_v3_banner_time_allocs[--cf_v3_banner_time_count];
      cf_v3_banner_time_allocs[cf_v3_banner_time_count] = NULL;
      return;
    }
  }
}

static void cf_v3_banner_forget_iterate(void *pointer) {
  for (size_t index = 0; index < cf_v3_banner_iterate_count; index++) {
    if (cf_v3_banner_iterate_allocs[index] == pointer) {
      cf_v3_banner_iterate_allocs[index] =
          cf_v3_banner_iterate_allocs[--cf_v3_banner_iterate_count];
      cf_v3_banner_iterate_allocs[cf_v3_banner_iterate_count] = NULL;
      return;
    }
  }
}

static void cf_v3_banner_forget_pdf_alloc(void *pointer) {
  for (size_t index = 0; index < cf_v3_banner_pdf_alloc_count; index++) {
    if (cf_v3_banner_pdf_allocs[index] == pointer) {
      cf_v3_banner_pdf_allocs[index] =
          cf_v3_banner_pdf_allocs[--cf_v3_banner_pdf_alloc_count];
      cf_v3_banner_pdf_allocs[cf_v3_banner_pdf_alloc_count] = NULL;
      return;
    }
  }
}

void __wrap_free(void *pointer) {
  cf_v3_banner_forget_time(pointer);
  cf_v3_banner_forget_iterate(pointer);
  cf_v3_banner_forget_pdf_alloc(pointer);
  __real_free(pointer);
}

void *__wrap_realloc(void *pointer, size_t size) {
  void *replacement = __real_realloc(pointer, size);

  if (replacement || size == 0U) {
    cf_v3_banner_forget_time(pointer);
    cf_v3_banner_forget_iterate(pointer);
    cf_v3_banner_forget_pdf_alloc(pointer);
  }
  if (replacement) {
    cf_v3_banner_track_alloc(replacement, size);
  }
  return replacement;
}

static void cf_v3_banner_pdf_allocs_clear(void) {
  memset(cf_v3_banner_pdf_allocs, 0, sizeof(cf_v3_banner_pdf_allocs));
  cf_v3_banner_pdf_alloc_count = 0U;
  cf_v3_banner_pdf_alloc_overflow = 0;
}

static void cf_v3_banner_pdf_allocs_release(void) {
  /* An overflow means some allocations were not recorded, not that the
   * recorded live pointers became unsafe to release. free/realloc wrappers
   * continuously remove dead entries, so every remaining entry is owned by
   * the abandoned PDFio graph. */
  while (cf_v3_banner_pdf_alloc_count) {
    void *pointer =
        cf_v3_banner_pdf_allocs[--cf_v3_banner_pdf_alloc_count];
    cf_v3_banner_pdf_allocs[cf_v3_banner_pdf_alloc_count] = NULL;
    cf_v3_banner_forget_time(pointer);
    cf_v3_banner_forget_iterate(pointer);
    __real_free(pointer);
  }
  cf_v3_banner_pdf_alloc_overflow = 0;
}

pdfio_file_t *__wrap_pdfioFileOpen(
    const char *filename, pdfio_password_cb_t password_cb,
    void *password_data, pdfio_error_cb_t error_cb, void *error_data) {
  pdfio_file_t *pdf;
  int continue_ownership =
      cf_v3_banner_tracking && !cf_v3_banner_faithful &&
      cf_v3_banner_pdf_file == NULL;

  if (!continue_ownership) {
    return __real_pdfioFileOpen(filename, password_cb, password_data,
                                error_cb, error_data);
  }
  cf_v3_banner_pdf_alloc_tracking = 1;
  pdf = __real_pdfioFileOpen(filename, password_cb, password_data,
                             error_cb ? error_cb : cf_v3_banner_pdf_error,
                             error_cb ? error_data : NULL);
  cf_v3_banner_pdf_alloc_tracking = 0;
  if (pdf) {
    cf_v3_banner_pdf_file = pdf;
  }
  return pdf;
}

pdfio_dict_t *__wrap_pdfioDictCopy(pdfio_file_t *pdf, pdfio_dict_t *dict) {
  pdfio_dict_t *copy;
  int previous_tracking = cf_v3_banner_pdf_alloc_tracking;

  if (cf_v3_banner_tracking && !cf_v3_banner_faithful) {
    cf_v3_banner_pdf_alloc_tracking = 1;
  }
  copy = __real_pdfioDictCopy(pdf, dict);
  cf_v3_banner_pdf_alloc_tracking = previous_tracking;
  return copy;
}

bool __wrap_pdfioFileClose(pdfio_file_t *pdf) {
  bool result = __real_pdfioFileClose(pdf);

  if (pdf && pdf == cf_v3_banner_pdf_file) {
    cf_v3_banner_pdf_file = NULL;
  }
  return result;
}

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

static void cf_v3_banner_tracking_begin(int output_fd, bool faithful) {
  memset(cf_v3_banner_streams, 0, sizeof(cf_v3_banner_streams));
  memset(cf_v3_banner_time_allocs, 0, sizeof(cf_v3_banner_time_allocs));
  memset(cf_v3_banner_iterate_allocs, 0,
         sizeof(cf_v3_banner_iterate_allocs));
  cf_v3_banner_stream_count = 0U;
  cf_v3_banner_time_count = 0U;
  cf_v3_banner_iterate_count = 0U;
  cf_v3_banner_pdf_allocs_clear();
  cf_v3_banner_pdf_alloc_tracking = 0;
  cf_v3_banner_pdf_file = NULL;
  cf_v3_banner_faithful = faithful;
  cf_v3_banner_output_fd = output_fd;
  cf_v3_banner_tracking = 1;
}

static void cf_v3_banner_tracking_end(bool faithful) {
  cf_v3_banner_tracking = 0;
  cf_v3_banner_pdf_alloc_tracking = 0;
  cf_v3_banner_pdf_file = NULL;
  if (faithful) {
    cf_v3_banner_pdf_allocs_clear();
  } else {
    cf_v3_banner_pdf_allocs_release();
  }
  cf_v3_banner_faithful = 0;
  cf_v3_banner_output_fd = -1;
  if (faithful) {
    memset(cf_v3_banner_streams, 0, sizeof(cf_v3_banner_streams));
    memset(cf_v3_banner_time_allocs, 0, sizeof(cf_v3_banner_time_allocs));
    memset(cf_v3_banner_iterate_allocs, 0,
           sizeof(cf_v3_banner_iterate_allocs));
    cf_v3_banner_stream_count = 0U;
    cf_v3_banner_time_count = 0U;
    cf_v3_banner_iterate_count = 0U;
    return;
  }
  while (cf_v3_banner_stream_count) {
    FILE *stream = cf_v3_banner_streams[--cf_v3_banner_stream_count];
    cf_v3_banner_streams[cf_v3_banner_stream_count] = NULL;
    if (stream) {
      (void)__real_fclose(stream);
    }
  }
  for (size_t index = 0; index < cf_v3_banner_time_count; index++) {
    char *value = (char *)cf_v3_banner_time_allocs[index];
    if (value && memcmp(value, "unknown", sizeof("unknown")) == 0) {
      __real_free(value);
    }
    cf_v3_banner_time_allocs[index] = NULL;
  }
  cf_v3_banner_time_count = 0U;
  while (cf_v3_banner_iterate_count) {
    void *pointer =
        cf_v3_banner_iterate_allocs[--cf_v3_banner_iterate_count];
    cf_v3_banner_iterate_allocs[cf_v3_banner_iterate_count] = NULL;
    __real_free(pointer);
  }
}

static uint8_t cf_v3_banner_byte(const uint8_t *data, size_t size,
                                 size_t index, uint8_t fallback) {
  return data && index < size ? data[index] : fallback;
}

static bool cf_v3_banner_append(cf_v3_banner_buffer_t *buffer,
                                const void *bytes, size_t count) {
  if (!buffer || buffer->failed || count > buffer->capacity - buffer->length) {
    if (buffer) {
      buffer->failed = true;
    }
    return false;
  }
  memcpy(buffer->bytes + buffer->length, bytes, count);
  buffer->length += count;
  return true;
}

static bool cf_v3_banner_appendf(cf_v3_banner_buffer_t *buffer,
                                 const char *format, ...) {
  char line[2048];
  va_list arguments;
  int count;

  va_start(arguments, format);
  count = vsnprintf(line, sizeof(line), format, arguments);
  va_end(arguments);
  return count >= 0 && (size_t)count < sizeof(line) &&
         cf_v3_banner_append(buffer, line, (size_t)count);
}

static void cf_v3_banner_value(const uint8_t *material, size_t material_size,
                               unsigned recipe, size_t target,
                               const char *prefix, char output[320]) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;-_";
  size_t used = (size_t)snprintf(output, 320U, "%s", prefix);

  if (target > 255U) {
    target = 255U;
  }
  while (used < target && used + 1U < 320U) {
    unsigned value = material_size
                         ? material[(used * 5U + recipe * 13U) % material_size]
                         : (unsigned)(used * 37U + recipe * 29U);
    output[used] = alphabet[(value + recipe + used) %
                            (sizeof(alphabet) - 1U)];
    used++;
  }
  output[used] = '\0';
}

static bool cf_v3_banner_emit_directive(cf_v3_banner_buffer_t *document,
                                         bool embedded, const char *ending,
                                         const char *key,
                                         const char *value) {
  return cf_v3_banner_appendf(document, "%s%s%s%s", embedded ? "%" : "",
                              key, value ? " " : "", value ? value : "") &&
         cf_v3_banner_append(document, ending, strlen(ending));
}

static bool cf_v3_banner_structured_control(
    const uint8_t control[CF_V3_BANNER_CONTROL_BYTES],
    const uint8_t *material, size_t material_size, const char *template_path,
    cf_v3_banner_buffer_t *document) {
  static const char *const show_values[] = {
      "job-id",
      "job-name printer-name options",
      "imageable-area job-billing job-id job-name "
      "job-originating-host-name job-originating-user-name job-uuid options "
      "paper-name paper-size printer-driver-name printer-driver-version "
      "printer-info printer-location printer-make-and-model printer-name "
      "time-at-creation time-at-processing",
      "unknown-token",
      "job-name unknown-token paper-size",
      "job-id job-name printer-name job-originating-user-name",
      "job-originating-host-name job-billing job-uuid",
      "JOB-UUID PRINTER-INFO",
  };
  static const size_t lengths[] = {1U, 7U, 31U, 63U, 127U, 255U};
  const bool embedded = control[9] % 3U == 2U;
  const char *ending = (control[6] & 1U) ? "\r\n" : "\n";
  const unsigned marker = control[0] % 7U;
  const unsigned template_mode = control[1] % 6U;
  const unsigned show_mode = control[2] % 8U;
  const unsigned order = control[7] % 4U;
  char header[320], footer[320];
  const char *keys[12];
  const char *values[12];
  size_t count = 0U;

  if (embedded) {
    cf_v3_banner_appendf(document, "%%PDF-1.%u%s", 4U + control[10] % 4U,
                         ending);
  }
  switch (marker) {
    case 0U:
      cf_v3_banner_appendf(document, "%s#PDF-BANNER%s",
                           embedded ? "%" : "", ending);
      break;
    case 1U:
      cf_v3_banner_appendf(document, "%sPDF-BANNER%s",
                           embedded ? "%" : "", ending);
      break;
    case 2U:
      cf_v3_banner_appendf(document, "%s  #pDf-BaNnEr extra%s",
                           embedded ? "%" : "", ending);
      break;
    case 3U:
      cf_v3_banner_appendf(document, "preamble%s%s#PDF-BANNER%s", ending,
                           embedded ? "%" : "", ending);
      break;
    case 4U:
      cf_v3_banner_appendf(document, "%s\tPDF-BANNER%s",
                           embedded ? "%" : "", ending);
      break;
    case 5U:
      cf_v3_banner_appendf(document, "not-a-banner-marker%s", ending);
      break;
    default:
      cf_v3_banner_appendf(document, "%snot-a-banner-marker%s",
                           embedded ? "%" : "", ending);
      break;
  }

  cf_v3_banner_value(material, material_size, control[13],
                     lengths[control[11] % 6U], "header-", header);
  cf_v3_banner_value(material, material_size, control[14],
                     lengths[control[12] % 6U], "footer-", footer);

#define CF_V3_ADD_DIRECTIVE(k, v) \
  do {                              \
    keys[count] = (k);              \
    values[count++] = (v);          \
  } while (0)
  if (template_mode == 1U || template_mode == 3U) {
    CF_V3_ADD_DIRECTIVE("Template", "default.pdf");
  } else if (template_mode == 2U || template_mode == 4U) {
    CF_V3_ADD_DIRECTIVE("Template", template_path);
  } else if (template_mode == 5U) {
    CF_V3_ADD_DIRECTIVE("Template", "/definitely/missing/banner.pdf");
  }
  if (control[3] % 3U) {
    CF_V3_ADD_DIRECTIVE("Header", header);
  }
  if (control[3] % 3U == 2U) {
    CF_V3_ADD_DIRECTIVE("Header", "second-header");
  }
  if (control[4] % 3U) {
    CF_V3_ADD_DIRECTIVE("Footer", footer);
  }
  if (control[4] % 3U == 2U) {
    CF_V3_ADD_DIRECTIVE("Footer", "second-footer");
  }
  CF_V3_ADD_DIRECTIVE("Show", show_values[show_mode]);
  if (control[12] & 1U) {
    CF_V3_ADD_DIRECTIVE("Show", show_values[(show_mode + 3U) % 8U]);
  }
  if (control[5] % 4U == 1U) {
    CF_V3_ADD_DIRECTIVE("Image", "ignored.png");
  } else if (control[5] % 4U == 2U) {
    CF_V3_ADD_DIRECTIVE("Notice", "ignored");
  } else if (control[5] % 4U == 3U) {
    CF_V3_ADD_DIRECTIVE("Unknown-Key", "ignored");
  }
  if (template_mode == 3U) {
    CF_V3_ADD_DIRECTIVE("Template", template_path);
  } else if (template_mode == 4U) {
    CF_V3_ADD_DIRECTIVE("Template", "/definitely/missing/second.pdf");
  }
#undef CF_V3_ADD_DIRECTIVE

  for (size_t emitted = 0U; emitted < count; emitted++) {
    size_t index;
    if (order == 1U) {
      index = count - emitted - 1U;
    } else if (order == 2U) {
      index = (emitted * 5U) % count;
    } else if (order == 3U) {
      index = (emitted + control[15]) % count;
    } else {
      index = emitted;
    }
    if (!cf_v3_banner_emit_directive(document, embedded, ending, keys[index],
                                      values[index])) {
      return false;
    }
    if ((control[15] & 3U) == 3U && emitted == count / 2U &&
        !cf_v3_banner_append(document, ending, strlen(ending))) {
      return false;
    }
  }
  if (control[8] % 5U == 1U) {
    cf_v3_banner_emit_directive(document, embedded, ending, "No-Value", NULL);
  } else if (control[8] % 5U == 2U) {
    cf_v3_banner_emit_directive(document, embedded, ending, "0", "obj");
  } else if (control[8] % 5U == 3U) {
    cf_v3_banner_emit_directive(document, embedded, ending, "Unknown-Tail",
                                "value");
  } else if (control[8] % 5U == 4U) {
    cf_v3_banner_appendf(document, "%s%%EOF%s", embedded ? "%" : "",
                         ending);
  }
  return !document->failed;
}

static bool cf_v3_banner_font_directive(const uint8_t *line, size_t size) {
  size_t offset = 0U;
  static const char *const blocked[] = {"font", "font-size"};

  while (offset < size && isspace((unsigned char)line[offset])) {
    offset++;
  }
  while (offset < size && line[offset] == '%') {
    offset++;
  }
  for (size_t index = 0U; index < sizeof(blocked) / sizeof(blocked[0]);
       index++) {
    const size_t length = strlen(blocked[index]);
    if (length <= size - offset &&
        strncasecmp((const char *)line + offset, blocked[index], length) == 0 &&
        (offset + length == size ||
         isspace((unsigned char)line[offset + length]))) {
      return true;
    }
  }
  return false;
}

static void cf_v3_banner_gate_font_directives(uint8_t *bytes, size_t size) {
  size_t start = 0U;
  while (start < size) {
    size_t end = start;
    while (end < size && bytes[end] != '\n' && bytes[end] != '\r') {
      end++;
    }
    if (cf_v3_banner_font_directive(bytes + start, end - start)) {
      size_t offset = start;
      while (offset < end &&
             (isspace((unsigned char)bytes[offset]) || bytes[offset] == '%')) {
        offset++;
      }
      if (offset < end) {
        bytes[offset] = 'X';
      }
    }
    start = end < size ? end + 1U : size;
  }
}

static bool cf_v3_banner_write_all(int fd, const void *data, size_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  while (size) {
    ssize_t count = write(fd, bytes, size);
    if (count <= 0) {
      return false;
    }
    bytes += (size_t)count;
    size -= (size_t)count;
  }
  return true;
}

static bool cf_v3_banner_copy_file(const char *source, const char *target) {
  uint8_t buffer[8192];
  int input = open(source, O_RDONLY);
  int output = -1;
  bool valid = false;
  if (input < 0 || (output = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
    goto done;
  }
  for (;;) {
    ssize_t count = read(input, buffer, sizeof(buffer));
    if (count < 0) {
      goto done;
    }
    if (!count) {
      break;
    }
    if (!cf_v3_banner_write_all(output, buffer, (size_t)count)) {
      goto done;
    }
  }
  valid = true;
done:
  if (input >= 0) {
    close(input);
  }
  if (output >= 0) {
    close(output);
  }
  return valid;
}

static bool cf_v3_banner_generic_pdf(const char *path,
                                     unsigned expected_pages) {
  pdfio_file_t *pdf = pdfioFileOpen(path, NULL, NULL,
                                    cf_v3_banner_pdf_error, NULL);
  bool valid = false;
  if (!pdf || pdfioFileGetNumObjs(pdf) > 1024U ||
      pdfioFileGetNumPages(pdf) != expected_pages) {
    goto done;
  }
  for (unsigned index = 0U; index < expected_pages; index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, index);
    size_t streams = page ? pdfioPageGetNumStreams(page) : 0U;
    if (!page || !streams || streams > 32U) {
      goto done;
    }
  }
  valid = true;
done:
  if (pdf && !pdfioFileClose(pdf)) {
    valid = false;
  }
  return valid;
}

static void cf_v3_banner_add_option(cf_filter_data_t *filter_data,
                                    const char *name, const char *value) {
  filter_data->num_options = cupsAddOption(
      name, value, filter_data->num_options, &filter_data->options);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const char *const number_up_text[] = {"1", "2", "3", "4", "8"};
  static const unsigned number_up_values[] = {1U, 2U, 3U, 4U, 8U};
  static const size_t value_lengths[] = {1U, 7U, 31U, 63U, 127U, 255U};
  uint8_t control[CF_V3_BANNER_CONTROL_BYTES] = {0};
  uint8_t graph_input[CF_V3_BANNER_GRAPH_BYTES + 64U] = {0};
  uint8_t job[CF_V3_BANNER_JOB_BYTES] = {0};
  const uint8_t *material = NULL;
  size_t material_size = 0U;
  uint8_t *document_bytes = NULL;
  size_t document_size = 0U;
  uint8_t *expected = NULL;
  size_t expected_length = 0U;
  char template_path[1024] = "";
  char data_directory[] = "/tmp/cf-v3-banner-data-XXXXXX";
  char default_path[1200] = "";
  char input_path[] = "/tmp/cf-v3-banner-input-XXXXXX";
  char output_path[] = "/tmp/cf-v3-banner-output-XXXXXX";
  char printer[320], title[320], user[320], host[320], billing[320], uuid[320];
  cf_filter_data_t filter_data = {0};
  int input_fd = -1, output_fd = -1, filter_input_fd = -1;
  int filter_output_fd = -1;
  int status = 1;
  unsigned number_up_index, expected_pages;
  bool graph_valid_media = false;
  bool faithful;
  unsigned route;

  if (!data || !size || size > CF_V3_BANNER_MAX_INPUT) {
    return 0;
  }
  faithful = (data[0] & 0x80U) != 0U;
  route = data[0] & 0x03U;
  if (route > CF_V3_BANNER_RAW_PDF) {
    route = CF_V3_BANNER_STRUCTURED;
  }
  for (size_t index = 0U; index < sizeof(control); index++) {
    control[index] = cf_v3_banner_byte(data, size, 1U + index, 0U);
  }
  for (size_t index = 0U; index < CF_V3_BANNER_GRAPH_BYTES; index++) {
    graph_input[index] = cf_v3_banner_byte(
        data, size, 1U + CF_V3_BANNER_CONTROL_BYTES + index, 0U);
  }
  for (size_t index = 0U; index < sizeof(job); index++) {
    job[index] = cf_v3_banner_byte(
        data, size,
        1U + CF_V3_BANNER_CONTROL_BYTES + CF_V3_BANNER_GRAPH_BYTES + index,
        0U);
  }
  if (size > CF_V3_BANNER_HEADER_BYTES) {
    material = data + CF_V3_BANNER_HEADER_BYTES;
    material_size = size - CF_V3_BANNER_HEADER_BYTES;
  }
  if (material_size > 64U) {
    material_size = 64U;
  }
  if (material_size) {
    memcpy(graph_input + CF_V3_BANNER_GRAPH_BYTES, material, material_size);
  }

  expected = (uint8_t *)malloc(CF_V3_BANNER_GRAPH_MAX_CONTENT);
  if (!expected || !mkdtemp(data_directory) ||
      !cf_v3_banner_graph_build(
          graph_input, CF_V3_BANNER_GRAPH_BYTES + material_size, template_path,
          expected, CF_V3_BANNER_GRAPH_MAX_CONTENT, &expected_length,
          &graph_valid_media)) {
    goto done;
  }
  if (snprintf(default_path, sizeof(default_path), "%s/default.pdf",
               data_directory) < 0 ||
      !cf_v3_banner_copy_file(template_path, default_path)) {
    goto done;
  }

  if (route == CF_V3_BANNER_STRUCTURED) {
    cf_v3_banner_buffer_t document;
    document_bytes = (uint8_t *)malloc(CF_V3_BANNER_MAX_CONTROL);
    if (!document_bytes) {
      goto done;
    }
    document.bytes = document_bytes;
    document.capacity = CF_V3_BANNER_MAX_CONTROL;
    document.length = 0U;
    document.failed = false;
    if (!cf_v3_banner_structured_control(control, material, material_size,
                                         template_path, &document)) {
      goto done;
    }
    document_size = document.length;
  } else {
    const size_t offset = size > 1U ? 1U : size;
    document_size = size - offset;
    document_bytes = (uint8_t *)malloc(document_size ? document_size : 1U);
    if (!document_bytes) {
      goto done;
    }
    if (document_size) {
      memcpy(document_bytes, data + offset, document_size);
      cf_v3_banner_gate_font_directives(document_bytes, document_size);
    }
  }

  input_fd = mkstemp(input_path);
  output_fd = mkstemp(output_path);
  if (input_fd < 0 || output_fd < 0 ||
      !cf_v3_banner_write_all(input_fd, document_bytes, document_size) ||
      lseek(input_fd, 0, SEEK_SET) < 0 ||
      (filter_input_fd = dup(input_fd)) < 0 ||
      (filter_output_fd = dup(output_fd)) < 0) {
    goto done;
  }

  memset(&filter_data, 0, sizeof(filter_data));
  cf_v3_banner_value(material, material_size, job[0],
                     value_lengths[job[7] % 6U], "P", printer);
  cf_v3_banner_value(material, material_size, job[2],
                     value_lengths[(job[7] + 1U) % 6U], "T", title);
  cf_v3_banner_value(material, material_size, job[4],
                     value_lengths[(job[7] + 2U) % 6U], "U", user);
  cf_v3_banner_value(material, material_size, job[6],
                     value_lengths[job[6] % 6U], "H", host);
  cf_v3_banner_value(material, material_size, job[8],
                     value_lengths[(job[6] + 1U) % 6U], "B", billing);
  cf_v3_banner_value(material, material_size, job[9],
                     value_lengths[(job[6] + 2U) % 6U], "J", uuid);
  filter_data.job_id = 37 + job[0] % 97U;
  filter_data.job_user = user;
  filter_data.job_title = title;
  filter_data.printer = printer;
  filter_data.printer_attrs = ippNew();
  filter_data.job_attrs = ippNew();
  if (!filter_data.printer_attrs || !filter_data.job_attrs) {
    goto done;
  }
  number_up_index = job[4] % 5U;
  cf_v3_banner_add_option(&filter_data, "number-up",
                          number_up_text[number_up_index]);
  cf_v3_banner_add_option(&filter_data, "job-originating-host-name", host);
  cf_v3_banner_add_option(&filter_data, "job-billing", billing);
  cf_v3_banner_add_option(&filter_data, "job-uuid", uuid);
  cf_v3_banner_add_option(&filter_data, "printer-info", "BNRV3");
  if (job[5] % 3U == 1U) {
    cf_v3_banner_add_option(&filter_data, "sides", "two-sided-long-edge");
  } else if (job[5] % 3U == 2U) {
    cf_v3_banner_add_option(&filter_data, "sides", "two-sided-short-edge");
  }
  expected_pages = number_up_values[number_up_index];
  if (job[5] % 3U) {
    expected_pages *= 2U;
  }

  cf_v3_banner_tracking_begin(filter_output_fd, faithful);
  status = cfFilterBannerToPDF(filter_input_fd, filter_output_fd, 1,
                               &filter_data, data_directory);
  cf_v3_banner_tracking_end(faithful);
  filter_input_fd = -1;
  filter_output_fd = -1;

  if (!faithful && status == 0) {
    bool output_valid = route == CF_V3_BANNER_STRUCTURED && graph_valid_media
                            ? cf_v3_banner_graph_validate(
                                  output_path, graph_input,
                                  CF_V3_BANNER_GRAPH_BYTES + material_size,
                                  expected, expected_length, expected_pages)
                            : cf_v3_banner_generic_pdf(output_path,
                                                       expected_pages);
    if (!output_valid) {
      __builtin_trap();
    }
  }

done:
  if (cf_v3_banner_tracking) {
    cf_v3_banner_tracking_end(faithful);
  }
  if (filter_input_fd >= 0) {
    close(filter_input_fd);
  }
  if (filter_output_fd >= 0) {
    close(filter_output_fd);
  }
  if (input_fd >= 0) {
    close(input_fd);
  }
  if (output_fd >= 0) {
    close(output_fd);
  }
  if (filter_data.options) {
    cupsFreeOptions(filter_data.num_options, filter_data.options);
  }
  if (filter_data.printer_attrs) {
    ippDelete(filter_data.printer_attrs);
  }
  if (filter_data.job_attrs) {
    ippDelete(filter_data.job_attrs);
  }
  if (template_path[0]) {
    unlink(template_path);
  }
  if (default_path[0]) {
    unlink(default_path);
  }
  rmdir(data_directory);
  unlink(input_path);
  unlink(output_path);
  free(expected);
  free(document_bytes);
  return 0;
}
