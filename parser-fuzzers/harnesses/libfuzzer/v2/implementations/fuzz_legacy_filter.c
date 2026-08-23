// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#ifdef CF_V2_COUPLED_PPD
#include "../include/coupled.h"
#endif
#ifdef CF_V2_JOB_INPUT
#include "../include/job.h"
#endif
#include "../include/control.h"
#include "../include/profiles.h"
#include "../include/runtime.h"
#include "../include/validity.h"

#include <fcntl.h>
#include <cupsfilters/filter.h>
#include <ppd/ppd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CF_V2_LEGACY_SOURCE
#error "CF_V2_LEGACY_SOURCE must be a quoted source path"
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
#ifndef CF_V2_MAX_DOCUMENT
#define CF_V2_MAX_DOCUMENT (2U * 1024U * 1024U)
#endif
#ifndef CF_V2_MAX_PPD
#define CF_V2_MAX_PPD (256U * 1024U)
#endif

static ppd_file_t *cf_v2_open_ppd;

/*
 * glibc retains strings allocated by setenv(), even after unsetenv().  A
 * persistent fuzzer calling a legacy main millions of times would therefore
 * grow in proportion to executions.  These mutable process-lifetime slots
 * preserve the real environment interface without allocating per input.
 */
static char cf_v2_ppd_env[sizeof("PPD=") + PATH_MAX];
static char cf_v2_content_type_env[] = "CONTENT_TYPE=" CF_V2_INPUT_MIME;
static char cf_v2_final_content_type_env[] =
    "FINAL_CONTENT_TYPE=" CF_V2_OUTPUT_MIME;
static char cf_v2_printer_env[] = "PRINTER=oss-fuzz-v2";
static char cf_v2_device_uri_env[] = "DEVICE_URI=file:/dev/null";
static int cf_v2_environment_installed;

static int cf_v2_install_environment(const char *ppd_path) {
  int length = snprintf(cf_v2_ppd_env, sizeof(cf_v2_ppd_env), "PPD=%s",
                        ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_ppd_env)) {
    return -1;
  }
  if (cf_v2_environment_installed) {
    return 0;
  }
  if (putenv(cf_v2_ppd_env) != 0 || putenv(cf_v2_content_type_env) != 0 ||
      putenv(cf_v2_final_content_type_env) != 0 ||
      putenv(cf_v2_printer_env) != 0 || putenv(cf_v2_device_uri_env) != 0) {
    return -1;
  }
  cf_v2_environment_installed = 1;
  return 0;
}

static ppd_file_t *cf_v2_ppd_open_file(const char *path) {
  cf_v2_open_ppd = ppdOpenFile(path);
  return cf_v2_open_ppd;
}

static void cf_v2_ppd_close(ppd_file_t *ppd) {
  if (ppd == cf_v2_open_ppd) {
    cf_v2_open_ppd = NULL;
  }
  ppdClose(ppd);
}

static int cf_v2_filter_fprintf(FILE *stream, const char *format, ...) {
  va_list args;
  int result;

  if (stream == stderr) {
    return 0;
  }
  va_start(args, format);
  result = vfprintf(stream, format, args);
  va_end(args);
  return result;
}

static int cf_v2_filter_fputs(const char *text, FILE *stream) {
  return stream == stderr ? 0 : fputs(text, stream);
}

static void cf_v2_cancel_job(int signal_number) {
  (void)signal_number;
}

static void cf_v2_cups_log(void *data, cf_loglevel_t level,
                           const char *message, ...) {
  (void)data;
  (void)level;
  (void)message;
}

#define ppdOpenFile cf_v2_ppd_open_file
#undef ppdClose
#define ppdClose cf_v2_ppd_close
#define fprintf cf_v2_filter_fprintf
#define fputs cf_v2_filter_fputs
#define cfCUPSLogFunc cf_v2_cups_log
#define main cf_v2_legacy_main
#include CF_V2_LEGACY_SOURCE
#undef main
#undef fputs
#undef fprintf
#undef cfCUPSLogFunc
#undef ppdClose
#undef ppdOpenFile

static int cf_v2_execute_legacy(const uint8_t *document,
                                size_t document_size,
                                const cf_v2_control_t *control
#if defined(CF_V2_COUPLED_PPD) || defined(CF_V2_JOB_INPUT)
                                , const uint8_t *ppd_data, size_t ppd_size
#endif
#ifdef CF_V2_JOB_INPUT
                                , const uint8_t *options_data,
                                size_t options_size, const uint8_t *title_data,
                                size_t title_size
#endif
                                ) {
  char input_path[] = "/tmp/cupsfilters-v2-input.XXXXXX";
  char ppd_path[] = "/tmp/cupsfilters-v2-ppd.XXXXXX";
  char options_text[1024];
  char *argv[8];
  char *job_options = NULL;
  char *job_title = NULL;
  int input_fd = -1;
  int ppd_fd = -1;
  int saved_stdout = -1;
  int sink = -1;
  void (*saved_sigterm)(int) = SIG_ERR;

#ifdef CF_V2_JOB_INPUT
  job_options = (char *)malloc(options_size + 1U);
  job_title = (char *)malloc(title_size + 1U);
  if (!job_options || !job_title) {
    goto cleanup;
  }
  memcpy(job_options, options_data, options_size);
  job_options[options_size] = '\0';
  memcpy(job_title, title_data, title_size);
  job_title[title_size] = '\0';
#else
  if (cf_v2_build_options(options_text, sizeof(options_text), control) != 0) {
    return 0;
  }
#endif
  input_fd = mkstemp(input_path);
  if (input_fd < 0 ||
      cf_v2_write_all(input_fd, document, document_size) != 0 ||
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
  close(input_fd);
  input_fd = -1;

  ppd_fd = mkstemp(ppd_path);
  if (ppd_fd < 0) {
    goto cleanup;
  }
#if defined(CF_V2_COUPLED_PPD) || defined(CF_V2_JOB_INPUT)
  if (ppd_size) {
    if (cf_v2_write_all(ppd_fd, ppd_data, ppd_size) != 0 ||
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
    int write_status = cf_v2_write_ppd(ppd_file, control, CF_V2_TARGET_NAME);
    int close_status = fclose(ppd_file);
    if (write_status != 0 || close_status != 0) {
      goto cleanup;
    }
  }
#else
  {
    FILE *ppd_file = fdopen(ppd_fd, "w");
    if (!ppd_file) {
      goto cleanup;
    }
    ppd_fd = -1;
    int write_status = cf_v2_write_ppd(ppd_file, control, CF_V2_TARGET_NAME);
    int close_status = fclose(ppd_file);
    if (write_status != 0 || close_status != 0) {
      goto cleanup;
    }
  }
#endif

  if (cf_v2_install_environment(ppd_path) != 0) {
    goto cleanup;
  }
  saved_sigterm = signal(SIGTERM, cf_v2_cancel_job);

  saved_stdout = dup(STDOUT_FILENO);
  sink = open("/dev/null", O_WRONLY);
  if (saved_stdout >= 0 && sink >= 0) {
    (void)dup2(sink, STDOUT_FILENO);
  }
  if (sink >= 0) {
    close(sink);
  }

  argv[0] = (char *)CF_V2_TARGET_NAME;
  argv[1] = (char *)"1";
  argv[2] = (char *)"fuzzer";
  argv[3] =
#ifdef CF_V2_JOB_INPUT
      title_size ? job_title : (char *)"v2";
#else
      (char *)"v2";
#endif
  argv[4] = (char *)"1";
  argv[5] =
#ifdef CF_V2_JOB_INPUT
      job_options;
#else
      options_text;
#endif
  argv[6] = input_path;
  argv[7] = NULL;
  cf_v2_open_ppd = NULL;
  (void)cf_v2_legacy_main(7, argv);
  fflush(stdout);

  if (cf_v2_open_ppd) {
    cf_v2_ppd_close(cf_v2_open_ppd);
  }
#ifdef CF_V2_RESET_PCLX_GLOBALS
  memset(DitherLuts, 0, sizeof(DitherLuts));
  memset(DitherStates, 0, sizeof(DitherStates));
#endif

cleanup:
  if (saved_stdout >= 0) {
    (void)dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
  }
  if (saved_sigterm != SIG_ERR) {
    (void)signal(SIGTERM, saved_sigterm);
  }
  if (input_fd >= 0) {
    close(input_fd);
  }
  if (ppd_fd >= 0) {
    close(ppd_fd);
  }
  unlink(input_path);
  unlink(ppd_path);
  free(job_options);
  free(job_title);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_control_t control;
  const uint8_t *document;
  size_t document_size;
#ifdef CF_V2_COUPLED_PPD
  cf_v2_coupled_input_t coupled;

  if (!cf_v2_parse_coupled_input(data, size, CF_V2_MAX_PPD,
                                 CF_V2_MAX_DOCUMENT, &coupled)) {
    return 0;
  }
  control = coupled.control;
  document = coupled.document;
  document_size = coupled.document_size;
#elif defined(CF_V2_JOB_INPUT)
  cf_v2_job_input_t job;

  if (!cf_v2_parse_job_input(data, size, CF_V2_MAX_PPD, 16U * 1024U,
                             4U * 1024U, CF_V2_MAX_DOCUMENT, &job)) {
    return 0;
  }
  control = job.control;
  document = job.document;
  document_size = job.document_size;
#else

  if (!cf_v2_split_input(data, size, CF_V2_MAX_DOCUMENT, &document,
                         &document_size, &control)) {
    return 0;
  }
#endif
#ifdef CF_V2_VALIDATE_COMMAND_SAFE
  if (!cf_v2_validate_command_safe(document, document_size)) {
    return 0;
  }
#endif
#ifdef CF_V2_VALIDATE_COMMAND_NUL_BOUNDARY
  if (!cf_v2_command_has_leading_nul_line(document, document_size)) {
    return 0;
  }
#endif
  cf_v2_init_runtime();
  return cf_v2_execute_legacy(document, document_size, &control
#ifdef CF_V2_COUPLED_PPD
                              , coupled.ppd, coupled.ppd_size
#elif defined(CF_V2_JOB_INPUT)
                              , job.ppd, job.ppd_size, job.options,
                              job.options_size, job.title, job.title_size
#endif
                              );
}
