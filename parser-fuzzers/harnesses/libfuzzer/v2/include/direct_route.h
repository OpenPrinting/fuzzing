// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_DIRECT_ROUTE_H
#define CUPSFILTERS_FUZZ_V2_DIRECT_ROUTE_H

#include "control.h"
#include "job.h"
#include "profiles.h"
#include "runtime.h"
#include "validity.h"

#include <cups/cups.h>
#include <cups/ipp.h>
#include <cupsfilters/filter.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <ppd/ppd-filter.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CF_V2_STDIO_STREAM_CONTINUATION
static void cf_v2_release_fdopen_streams(void);
#endif

#ifndef CF_V2_FILTER_FUNCTION
#error "CF_V2_FILTER_FUNCTION must name one cfFilter or ppdFilter entry"
#endif
#ifndef CF_V2_TARGET_NAME
#error "CF_V2_TARGET_NAME must be a string literal"
#endif
#ifndef CF_V2_INPUT_MIME
#error "CF_V2_INPUT_MIME must be a string literal"
#endif
#ifndef CF_V2_OUTPUT_MIME
#error "CF_V2_OUTPUT_MIME must be a string literal"
#endif

#define CF_V2_CAPTURE_LIMIT (8U * 1024U * 1024U)

typedef struct cf_v2_run_result_s {
  uint8_t *output;
  size_t output_size;
  int status;
  int captured;
#ifdef CF_V2_CAPTURE_PAGE_LOGS
  unsigned page_log_count;
  unsigned page_log_overflow;
  unsigned page_log_page[16];
  unsigned page_log_copies[16];
#endif
#ifdef CF_V2_CAPTURE_TEXT_TAIL_LOGS
  unsigned text_incomplete_log_count;
  unsigned text_iconv_log_count;
  unsigned text_illegal_log_count;
#endif
} cf_v2_run_result_t;

static void cf_v2_log(void *data, cf_loglevel_t level,
                      const char *message, ...) {
  if (!message) {
    return;
  }
  if (getenv("CF_V2_TRACE_LOG")) {
    va_list trace_arguments;

    va_start(trace_arguments, message);
    fprintf(stderr, "CF_V2_LOG level=%d ", (int)level);
    vfprintf(stderr, message, trace_arguments);
    fputc('\n', stderr);
    va_end(trace_arguments);
  }
#if defined(CF_V2_CAPTURE_PAGE_LOGS) || \
    defined(CF_V2_CAPTURE_TEXT_TAIL_LOGS)
  cf_v2_run_result_t *result = (cf_v2_run_result_t *)data;
  char formatted[128];
#ifdef CF_V2_CAPTURE_PAGE_LOGS
  unsigned page;
  unsigned copies;
#endif
  va_list arguments;

  if (!result) {
    return;
  }
  va_start(arguments, message);
  vsnprintf(formatted, sizeof(formatted), message, arguments);
  va_end(arguments);
#ifdef CF_V2_CAPTURE_PAGE_LOGS
  if (level == CF_LOGLEVEL_CONTROL &&
      sscanf(formatted, "PAGE: %u %u", &page, &copies) == 2) {
    if (result->page_log_count < 16U) {
      const unsigned index = result->page_log_count++;
      result->page_log_page[index] = page;
      result->page_log_copies[index] = copies;
    } else {
      result->page_log_overflow = 1U;
    }
  }
#endif
#ifdef CF_V2_CAPTURE_TEXT_TAIL_LOGS
  if (strstr(formatted, "ends with incomplete UTF-8 character sequence")) {
    result->text_incomplete_log_count++;
  }
  if (strstr(formatted, "iconv() message:")) {
    result->text_iconv_log_count++;
  }
  if (strstr(formatted, "Illegal UTF-8 sequence found")) {
    result->text_illegal_log_count++;
  }
#endif
#else
  (void)data;
  (void)level;
  (void)message;
#endif
}

static int cf_v2_not_canceled(void *data) {
  (void)data;
  return 0;
}

#ifdef CF_V2_DIRECT_FAULT_INJECTION
enum {
  CF_V2_DIRECT_FAULT_NONE = 0,
  CF_V2_DIRECT_FAULT_EMPTY_INPUT = 1,
  CF_V2_DIRECT_FAULT_INVALID_INPUT = 2,
  CF_V2_DIRECT_FAULT_INVALID_OUTPUT = 3,
  CF_V2_DIRECT_FAULT_OUTPUT_FULL = 4,
  CF_V2_DIRECT_FAULT_CANCELED = 5,
  CF_V2_DIRECT_FAULT_COUNT = 6
};

static int cf_v2_canceled(void *data) {
  (void)data;
  return 1;
}
#endif

static int cf_v2_capture_file(FILE *file, cf_v2_run_result_t *result) {
  long length;

  if (fflush(file) != 0 || fseek(file, 0, SEEK_END) != 0) {
    return -1;
  }
  length = ftell(file);
  if (length < 0 || (unsigned long)length > CF_V2_CAPTURE_LIMIT ||
      fseek(file, 0, SEEK_SET) != 0) {
    return -1;
  }
  if (length > 0) {
    result->output = (uint8_t *)malloc((size_t)length);
    if (!result->output ||
        fread(result->output, 1U, (size_t)length, file) != (size_t)length) {
      free(result->output);
      result->output = NULL;
      return -1;
    }
  }
  result->output_size = (size_t)length;
  result->captured = 1;
  return 0;
}

static void cf_v2_free_run_result(cf_v2_run_result_t *result) {
  if (!result) {
    return;
  }
  free(result->output);
  memset(result, 0, sizeof(*result));
}

static int cf_v2_execute_direct_internal(const uint8_t *document,
                                         size_t document_size,
                                         const cf_v2_control_t *control,
                                         const cf_v2_job_input_t *job,
                                         int capture_output,
                                         cf_v2_run_result_t *result) {
  char input_path[] = "/tmp/cupsfilters-v2-input.XXXXXX";
  char ppd_path[] = "/tmp/cupsfilters-v2-ppd.XXXXXX";
  char options_text[1024];
  cf_filter_data_t filter_data;
  char *job_options = NULL;
  char *job_title = NULL;
  cups_option_t *options = NULL;
  ipp_t *printer_attrs = NULL;
  FILE *capture = NULL;
  int input_fd = -1;
  int output_fd = -1;
  int filter_input_fd = -1;
  int filter_output_fd = -1;
  int ppd_fd = -1;
  int ppd_loaded = 0;
  int status = 0;
  void *parameters = NULL;
#ifdef CF_V2_DIRECT_FAULT_INJECTION
  unsigned fault_mode = control->reserved % CF_V2_DIRECT_FAULT_COUNT;
#endif
#ifdef CF_V2_OUTPUT_FORMAT
  cf_filter_out_format_t output_format = CF_V2_OUTPUT_FORMAT;
#endif
#ifdef CF_V2_TEXTTOPDF_PARAMETERS
  cf_filter_texttopdf_parameter_t text_parameters;
#endif
#ifdef CF_V2_BANNER_PARAMETERS
  char banner_directory[PATH_MAX];
#endif

  memset(result, 0, sizeof(*result));
  memset(&filter_data, 0, sizeof(filter_data));
  cf_v2_init_runtime();

#ifdef CF_V2_VALIDATE_PNG
  if (!cf_v2_validate_png(document, document_size)) {
    return 0;
  }
#endif
#ifdef CF_V2_VALIDATE_SIMPLE_RASTER
  if (!cf_v2_validate_simple_raster(document, document_size)) {
    return 0;
  }
#endif
#ifdef CF_V2_IMAGE_ASCII85_CONTINUATION
  if (!cf_v2_png_width_aligned(document, document_size, 4U)) {
    return 0;
  }
#endif
#ifdef CF_V2_VALIDATE_PDF_DEPTH
  if (!cf_v2_validate_pdf_policy(document, document_size,
                                 CF_V2_PDF_REJECT_INTERACTIVE)) {
    return 0;
  }
#endif
#ifdef CF_V2_VALIDATE_PDF_INTERACTIVE
  if (!cf_v2_validate_pdf_policy(document, document_size,
                                 CF_V2_PDF_REQUIRE_INTERACTIVE)) {
    return 0;
  }
#endif
  if (job) {
    job_options = (char *)malloc(job->options_size + 1U);
    job_title = (char *)malloc(job->title_size + 1U);
    if (!job_options || !job_title) {
      goto cleanup;
    }
    memcpy(job_options, job->options, job->options_size);
    job_options[job->options_size] = '\0';
    memcpy(job_title, job->title, job->title_size);
    job_title[job->title_size] = '\0';
  } else if (cf_v2_build_options(options_text, sizeof(options_text), control) !=
             0) {
    return 0;
  }

  input_fd = mkstemp(input_path);
  if (input_fd < 0) {
    return 0;
  }
  unlink(input_path);
  if (
#ifdef CF_V2_DIRECT_FAULT_INJECTION
      (fault_mode != CF_V2_DIRECT_FAULT_EMPTY_INPUT &&
       cf_v2_write_all(input_fd, document, document_size) != 0) ||
#else
      cf_v2_write_all(input_fd, document, document_size) != 0 ||
#endif
      lseek(input_fd, 0, SEEK_SET) < 0) {
    goto cleanup;
  }
#ifdef CF_V2_VALIDATE_RASTER
  {
    unsigned raster_flags = 0;
#ifdef CF_V2_RASTER_PDF_COLORSPACE
    raster_flags |= CF_V2_RASTER_REQUIRE_PDF_COLORSPACE;
#endif
#ifdef CF_V2_RASTER_ESCPX_SAFE_WEAVE
    raster_flags |= CF_V2_RASTER_REQUIRE_ESCPX_WEAVE;
#endif
#ifdef CF_V2_RASTER_POLICY_COMPRESSION_1
    raster_flags |= CF_V2_RASTER_REQUIRE_COMPRESSION_1;
#endif
#ifdef CF_V2_RASTER_POLICY_COMPRESSION_2
    raster_flags |= CF_V2_RASTER_REQUIRE_COMPRESSION_2;
#endif
#ifdef CF_V2_RASTER_POLICY_COMPRESSION_3
    raster_flags |= CF_V2_RASTER_REQUIRE_COMPRESSION_3;
#endif
#ifdef CF_V2_RASTER_POLICY_COMPRESSION_10
    raster_flags |= CF_V2_RASTER_REQUIRE_COMPRESSION_10;
#endif
#ifdef CF_V2_RASTER_POLICY_REJECT_COMPRESSION_3
    raster_flags |= CF_V2_RASTER_REJECT_COMPRESSION_3;
#endif
#ifdef CF_V2_RASTER_POLICY_MULTIROW
    raster_flags |= CF_V2_RASTER_REQUIRE_MULTIROW;
#endif
#ifdef CF_V2_RASTER_POLICY_MODE10_RGB
    raster_flags |= CF_V2_RASTER_REQUIRE_MODE10_RGB;
#endif
    if (!cf_v2_validate_raster_fd(input_fd, raster_flags)) {
      goto cleanup;
    }
  }
#endif

  if (capture_output) {
    capture = tmpfile();
    if (!capture || (output_fd = dup(fileno(capture))) < 0) {
      goto cleanup;
    }
  } else {
    output_fd = open(
#ifdef CF_V2_DIRECT_FAULT_INJECTION
        fault_mode == CF_V2_DIRECT_FAULT_OUTPUT_FULL ? "/dev/full" :
#endif
        "/dev/null", O_WRONLY);
    if (output_fd < 0) {
      goto cleanup;
    }
  }

  if (!job || job->ppd_size) {
    ppd_fd = mkstemp(ppd_path);
    if (ppd_fd < 0) {
      goto cleanup;
    }
    if (job) {
      if (cf_v2_write_all(ppd_fd, job->ppd, job->ppd_size) != 0 ||
          close(ppd_fd) != 0) {
        goto cleanup;
      }
      ppd_fd = -1;
    } else {
      FILE *ppd_file = fdopen(ppd_fd, "w");
      if (!ppd_file) {
        goto cleanup;
      }
      ppd_fd = -1;
      if (cf_v2_write_ppd(ppd_file, control, CF_V2_TARGET_NAME) != 0) {
        (void)fclose(ppd_file);
        goto cleanup;
      }
      if (fclose(ppd_file) != 0) {
        goto cleanup;
      }
    }
  }

  filter_data.printer = (char *)"oss-fuzz-v2";
  filter_data.job_id = 1;
  filter_data.job_user = (char *)"fuzzer";
  filter_data.job_title =
      job && job->title_size ? job_title : (char *)CF_V2_TARGET_NAME;
  filter_data.copies = 1 + control->copies % 4U;
  filter_data.content_type = (char *)CF_V2_INPUT_MIME;
  filter_data.final_content_type = (char *)CF_V2_OUTPUT_MIME;
  filter_data.back_pipe[0] = filter_data.back_pipe[1] = -1;
  filter_data.side_pipe[0] = filter_data.side_pipe[1] = -1;
  filter_data.logfunc = cf_v2_log;
#if defined(CF_V2_CAPTURE_PAGE_LOGS) || \
    defined(CF_V2_CAPTURE_TEXT_TAIL_LOGS)
  filter_data.logdata = result;
#endif
#ifdef CF_V2_DIRECT_FAULT_INJECTION
  filter_data.iscanceledfunc =
      fault_mode == CF_V2_DIRECT_FAULT_CANCELED ? cf_v2_canceled
                                                : cf_v2_not_canceled;
#else
  filter_data.iscanceledfunc = cf_v2_not_canceled;
#endif
  filter_data.num_options = cupsParseOptions(job ? job_options : options_text,
                                             0, &options);
  filter_data.options = options;
  filter_input_fd = input_fd;
  filter_output_fd = output_fd;
#ifdef CF_V2_DIRECT_FAULT_INJECTION
  if (fault_mode == CF_V2_DIRECT_FAULT_INVALID_INPUT) {
    filter_input_fd = -1;
  } else if (fault_mode == CF_V2_DIRECT_FAULT_INVALID_OUTPUT) {
    filter_output_fd = -1;
  }
#endif

#ifdef CF_V2_NEEDS_PCLM_ATTRS
  printer_attrs = ippNew();
  if (printer_attrs && !job) {
    ippAddInteger(printer_attrs, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                  "pclm-strip-height-preferred", 16);
    ippAddResolution(printer_attrs, IPP_TAG_PRINTER,
                     "pclm-source-resolution-supported", IPP_RES_PER_INCH,
                     300, 300);
    ippAddResolution(printer_attrs, IPP_TAG_PRINTER,
                     "pclm-source-resolution-default", IPP_RES_PER_INCH,
                     300, 300);
    ippAddString(printer_attrs, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
                 "pclm-compression-method-preferred", NULL, "flate");
  }
  filter_data.printer_attrs = printer_attrs;
#endif

#ifdef CF_V2_OUTPUT_FORMAT
  parameters = &output_format;
#elif defined(CF_V2_TEXTTOPDF_PARAMETERS)
  memset(&text_parameters, 0, sizeof(text_parameters));
  text_parameters.data_dir = (char *)cf_v2_data_dir();
#ifdef CF_V2_CHARSET
  text_parameters.char_set = (char *)CF_V2_CHARSET;
#else
  text_parameters.char_set = (char *)"utf-8";
#endif
  text_parameters.content_type = (char *)CF_V2_INPUT_MIME;
  parameters = &text_parameters;
#elif defined(CF_V2_BANNER_PARAMETERS)
  snprintf(banner_directory, sizeof(banner_directory), "%s/data",
           cf_v2_data_dir());
  parameters = banner_directory;
#endif

  if (job && !job->ppd_size) {
    result->status = CF_V2_FILTER_FUNCTION(filter_input_fd, filter_output_fd, 1,
                                           &filter_data, parameters);
    status = 1;
  } else if (ppdFilterLoadPPDFile(&filter_data, ppd_path) == 0) {
    ppd_loaded = 1;
#ifdef CF_V2_POST_PPD_LOAD_HOOK
    if (CF_V2_POST_PPD_LOAD_HOOK(&filter_data) != 0) {
      goto cleanup;
    }
#endif
    result->status = CF_V2_FILTER_FUNCTION(filter_input_fd, filter_output_fd, 1,
                                            &filter_data, parameters);
    status = 1;
  }

cleanup:
#ifdef CF_V2_STDIO_STREAM_CONTINUATION
  /* Release filter-owned stdio objects before their descriptors can be reused. */
  cf_v2_release_fdopen_streams();
#endif
  if (filter_data.options) {
    cupsFreeOptions(filter_data.num_options, filter_data.options);
    filter_data.options = NULL;
  }
  if (ppd_loaded) {
    ppdFilterFreePPDFile(&filter_data);
  }
  if (printer_attrs) {
    ippDelete(printer_attrs);
  }
  unlink(ppd_path);
  if (output_fd >= 0) {
    (void)close(output_fd);
  }
  if (input_fd >= 0) {
    (void)close(input_fd);
  }
  if (ppd_fd >= 0) {
    (void)close(ppd_fd);
  }
  if (capture) {
    if (status && cf_v2_capture_file(capture, result) != 0) {
      status = 0;
    }
    fclose(capture);
  }
  free(job_options);
  free(job_title);
  return status;
}

static int cf_v2_execute_direct(const uint8_t *document,
                                size_t document_size,
                                const cf_v2_control_t *control,
                                int capture_output,
                                cf_v2_run_result_t *result) {
  return cf_v2_execute_direct_internal(document, document_size, control, NULL,
                                       capture_output, result);
}

static int cf_v2_execute_direct_job(const cf_v2_job_input_t *job,
                                    int capture_output,
                                    cf_v2_run_result_t *result) {
  if (!job) {
    return 0;
  }
  return cf_v2_execute_direct_internal(
      job->document, job->document_size, &job->control, job, capture_output,
      result);
}

#endif
