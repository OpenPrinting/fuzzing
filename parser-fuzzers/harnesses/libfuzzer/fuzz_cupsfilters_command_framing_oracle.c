// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "fuzz_cupsfilters_profiles.h"

#include <ctype.h>
#include <fcntl.h>
#include <ppd/ppd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
#define CUPSFILTERS_COMMAND_HAS_ASAN_REPORT_FD 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) && \
    !defined(CUPSFILTERS_COMMAND_HAS_ASAN_REPORT_FD)
#include <sanitizer/common_interface_defs.h>
#define CUPSFILTERS_COMMAND_HAS_ASAN_REPORT_FD 1
#endif

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX) == \
    defined(CUPSFILTERS_COMMAND_FRAMING_PCLX)
#error "define exactly one command framing target"
#endif

#define CUPSFILTERS_COMMAND_MAX_INPUT 8192U
#define CUPSFILTERS_COMMAND_MAX_LINE 4096U

typedef struct {
  uint8_t *data;
  size_t size;
  size_t capacity;
} cupsfilters_command_output_t;

static ppd_file_t *cupsfilters_opened_ppd;
static char cupsfilters_command_ppd_env[4100] = "PPD=";
static int cupsfilters_command_ppd_env_installed;

static ppd_file_t *cupsfilters_command_ppd_open(const char *filename) {
  ppd_file_t *ppd = ppdOpenFile(filename);

  cupsfilters_opened_ppd = ppd;
  return ppd;
}

static void cupsfilters_command_ppd_close(ppd_file_t *ppd) {
  if (ppd == cupsfilters_opened_ppd) {
    cupsfilters_opened_ppd = NULL;
  }
  ppdClose(ppd);
}

#define ppdOpenFile cupsfilters_command_ppd_open
#undef ppdClose
#define ppdClose cupsfilters_command_ppd_close
#define main cupsfilters_command_legacy_main
#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
#include "commandtoescpx.c"
#else
#include "commandtopclx.c"
#endif
#undef main
#undef ppdClose
#undef ppdOpenFile

static int cupsfilters_command_append(cupsfilters_command_output_t *output,
                                      const void *data, size_t size) {
  if (size > output->capacity - output->size) {
    return 0;
  }
  memcpy(output->data + output->size, data, size);
  output->size += size;
  return 1;
}

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
static int cupsfilters_command_append_byte(
    cupsfilters_command_output_t *output, int value) {
  uint8_t byte = (uint8_t)value;

  return cupsfilters_command_append(output, &byte, 1);
}
#endif

static int cupsfilters_command_validate(const uint8_t *data, size_t size) {
  static const uint8_t header[] = "#CUPS-COMMAND";
  size_t line_size = 0;

  if (!data || size <= 1 || size > CUPSFILTERS_COMMAND_MAX_INPUT ||
      data[0] > 1 ||
      size - 1 < sizeof(header) - 1 ||
      memcmp(data + 1, header, sizeof(header) - 1) != 0) {
    return 0;
  }

  for (size_t i = 1; i < size; i++) {
    uint8_t byte = data[i];

    if (byte == '\n') {
      line_size = 0;
      continue;
    }
    if (byte != '\t' && byte != '\r' &&
        (byte < 0x20 || byte > 0x7e)) {
      return 0;
    }
    if (++line_size > CUPSFILTERS_COMMAND_MAX_LINE) {
      return 0;
    }
  }

  return 1;
}

static int cupsfilters_command_reference_line(
    char *line, uint8_t selector, cupsfilters_command_output_t *output,
    int *feedpage) {
  char *lineptr = line;

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
  (void)selector;
#else
  (void)feedpage;
#endif

  while (*lineptr && isspace((unsigned char)*lineptr)) {
    lineptr++;
  }
  if (*lineptr == '#' || !*lineptr) {
    return 1;
  }

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
  if (strncasecmp(lineptr, "Clean", 5) == 0) {
    return cupsfilters_command_append(output, "CH\002\000\000\000", 6);
  }
  if (strncasecmp(lineptr, "PrintAlignmentPage", 18) == 0) {
    int phase = atoi(lineptr + 18);

    *feedpage = 1;
    return cupsfilters_command_append(output, "DT\003\000\000", 5) &&
           cupsfilters_command_append_byte(output, phase & 255) &&
           cupsfilters_command_append_byte(output, phase >> 8);
  }
  if (strncasecmp(lineptr, "PrintSelfTestPage", 17) == 0) {
    *feedpage = 1;
    return cupsfilters_command_append(output, "VI\002\000\000\000", 6) &&
           cupsfilters_command_append(output, "NC\002\000\000\000", 6);
  }
  if (strncasecmp(lineptr, "ReportLevels", 12) == 0) {
    return cupsfilters_command_append(output, "IQ\001\000\001", 5);
  }
  if (strncasecmp(lineptr, "SetAlignment", 12) == 0) {
    int phase;
    int x;

    if (sscanf(lineptr + 12, "%d%d", &phase, &x) != 2) {
      return 1;
    }
    return cupsfilters_command_append(output, "DA\004\000", 4) &&
           cupsfilters_command_append_byte(output, 0) &&
           cupsfilters_command_append_byte(output, phase) &&
           cupsfilters_command_append_byte(output, 0) &&
           cupsfilters_command_append_byte(output, x) &&
           cupsfilters_command_append(output, "SV\000\000", 4);
  }
#else
  if (strncasecmp(lineptr, "Clean", 5) == 0 && selector == 1) {
    return cupsfilters_command_append(
        output,
        "\033&b16WPML \004\000\006\001\004\001\005\001\001\004\001\144",
        22);
  }
#endif

  return 1;
}

static int cupsfilters_command_make_expected(
    const uint8_t *document, size_t document_size, uint8_t selector,
    cupsfilters_command_output_t *output) {
  size_t offset = 0;
  int feedpage = 0;
  char line[CUPSFILTERS_COMMAND_MAX_LINE + 1];

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
  if (selector == 1 &&
      !cupsfilters_command_append(
          output, "\000\000\000\033\001@EJL 1284.4\n@EJL     \n\033@", 29)) {
    return 0;
  }
  if (!cupsfilters_command_append(output, "\033@", 2) ||
      !cupsfilters_command_append(output, "\033(R\010\000\000REMOTE1", 13)) {
    return 0;
  }
#else
  if (!cupsfilters_command_append(output, "\033E", 2)) {
    return 0;
  }
#endif

  while (offset < document_size) {
    const uint8_t *newline =
        memchr(document + offset, '\n', document_size - offset);
    size_t line_size =
        newline ? (size_t)(newline - document - offset)
                : document_size - offset;

    memcpy(line, document + offset, line_size);
    line[line_size] = '\0';
    if (!cupsfilters_command_reference_line(line, selector, output,
                                            &feedpage)) {
      return 0;
    }
    offset += line_size + (newline != NULL);
  }

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
  if (!cupsfilters_command_append(output, "\033\000\000\000", 4)) {
    return 0;
  }
  if (feedpage &&
      !cupsfilters_command_append(output, "\r\n\f", 3)) {
    return 0;
  }
  return cupsfilters_command_append(output, "\033@", 2);
#else
  (void)feedpage;
  return cupsfilters_command_append(output, "\033E", 2);
#endif
}

static int cupsfilters_command_write_all(int fd, const uint8_t *data,
                                         size_t size) {
  size_t offset = 0;

  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);

    if (written < 0) {
      return 0;
    }
    if (written == 0) {
      return 0;
    }
    offset += (size_t)written;
  }
  return 1;
}

static int cupsfilters_command_temp_path(char *path, size_t path_size,
                                         const char *suffix) {
  const char *tmpdir = getenv("TMPDIR");
  int length;

  if (!tmpdir || !*tmpdir) {
    tmpdir = "/tmp";
  }
  length = snprintf(path, path_size, "%s/cupsfilters-command-%s.XXXXXX",
                    tmpdir, suffix);
  return length > 0 && (size_t)length < path_size;
}

static int cupsfilters_command_create_input(char *path, size_t path_size,
                                            const uint8_t *data,
                                            size_t size) {
  int fd;
  int ok;

  if (!cupsfilters_command_temp_path(path, path_size, "input")) {
    return 0;
  }
  fd = mkstemp(path);
  if (fd < 0) {
    path[0] = '\0';
    return 0;
  }
  ok = cupsfilters_command_write_all(fd, data, size);
  if (close(fd) != 0) {
    ok = 0;
  }
  if (!ok) {
    unlink(path);
    path[0] = '\0';
  }
  return ok;
}

static int cupsfilters_command_create_ppd(char *path, size_t path_size,
                                          uint8_t selector) {
  FILE *file = NULL;
  int fd;
  int ok;
#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
  size_t profile = selector ? 3 : 0;
  const char *filter_name = "commandtoescpx";
#else
  size_t profile = selector ? 1 : 0;
  const char *filter_name = "commandtopclx";
#endif

  if (!cupsfilters_command_temp_path(path, path_size, "profile")) {
    return 0;
  }
  fd = mkstemp(path);
  if (fd < 0) {
    path[0] = '\0';
    return 0;
  }
  file = fdopen(fd, "w");
  if (!file) {
    close(fd);
    unlink(path);
    path[0] = '\0';
    return 0;
  }

  ok = cupsfilters_fuzz_write_ppd(file, profile, filter_name) == 0;
  if (fflush(file) != 0 || fclose(file) != 0) {
    ok = 0;
  }
  if (!ok) {
    unlink(path);
    path[0] = '\0';
  }
  return ok;
}

static int cupsfilters_command_set_ppd_env(const char *path) {
  size_t path_size = strlen(path);

  if (path_size + 5U > sizeof(cupsfilters_command_ppd_env)) {
    return 0;
  }
  memcpy(cupsfilters_command_ppd_env + 4, path, path_size + 1U);
  if (!cupsfilters_command_ppd_env_installed) {
    if (putenv(cupsfilters_command_ppd_env) != 0) {
      cupsfilters_command_ppd_env[4] = '\0';
      return 0;
    }
    cupsfilters_command_ppd_env_installed = 1;
  }
  return 1;
}

static int cupsfilters_command_compare_capture(
    FILE *capture, const cupsfilters_command_output_t *expected) {
  uint8_t buffer[1024];
  size_t offset = 0;
  long capture_size;

  if (fseek(capture, 0, SEEK_END) != 0 ||
      (capture_size = ftell(capture)) < 0 ||
      fseek(capture, 0, SEEK_SET) != 0) {
    return -1;
  }
  if ((size_t)capture_size != expected->size) {
    return 0;
  }

  while (offset < expected->size) {
    size_t chunk = expected->size - offset;

    if (chunk > sizeof(buffer)) {
      chunk = sizeof(buffer);
    }
    if (fread(buffer, 1, chunk, capture) != chunk) {
      return -1;
    }
    if (memcmp(buffer, expected->data + offset, chunk) != 0) {
      return 0;
    }
    offset += chunk;
  }
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *document;
  size_t document_size;
  cupsfilters_command_output_t expected = {0};
  char input_path[4096] = "";
  char ppd_path[4096] = "";
  FILE *capture_stdout = NULL;
  FILE *capture_stderr = NULL;
  int saved_stdout = -1;
  int saved_stderr = -1;
  int stdio_redirected = 0;
  int oracle_failed = 0;
  char *argv[8];

  if (!cupsfilters_command_validate(data, size)) {
    return 0;
  }

  document = data + 1;
  document_size = size - 1;
  expected.capacity = document_size * 4 + 128;
  expected.data = malloc(expected.capacity);
  if (!expected.data ||
      !cupsfilters_command_make_expected(document, document_size, data[0],
                                         &expected) ||
      !cupsfilters_command_create_input(input_path, sizeof(input_path),
                                        document, document_size) ||
      !cupsfilters_command_create_ppd(ppd_path, sizeof(ppd_path), data[0]) ||
      !cupsfilters_command_set_ppd_env(ppd_path)) {
    goto cleanup;
  }

  capture_stdout = tmpfile();
  capture_stderr = tmpfile();
  if (!capture_stdout || !capture_stderr) {
    goto cleanup;
  }

  fflush(stdout);
  fflush(stderr);
  saved_stdout = dup(STDOUT_FILENO);
  saved_stderr = dup(STDERR_FILENO);
  if (saved_stdout < 0 || saved_stderr < 0) {
    goto cleanup;
  }
#ifdef CUPSFILTERS_COMMAND_HAS_ASAN_REPORT_FD
  __sanitizer_set_report_fd((void *)(intptr_t)saved_stderr);
#endif
  if (dup2(fileno(capture_stdout), STDOUT_FILENO) < 0 ||
      dup2(fileno(capture_stderr), STDERR_FILENO) < 0) {
    goto cleanup;
  }
  stdio_redirected = 1;
  clearerr(stdout);
  clearerr(stderr);

#if defined(CUPSFILTERS_COMMAND_FRAMING_ESCPX)
  argv[0] = (char *)"commandtoescpx";
#else
  argv[0] = (char *)"commandtopclx";
#endif
  argv[1] = (char *)"1";
  argv[2] = (char *)"libfuzzer";
  argv[3] = (char *)"command framing oracle";
  argv[4] = (char *)"1";
  argv[5] = (char *)"";
  argv[6] = input_path;
  argv[7] = NULL;

  cupsfilters_opened_ppd = NULL;
  if (cupsfilters_command_legacy_main(7, argv) == 0) {
    int compare_result;

    fflush(stdout);
    fflush(stderr);
    compare_result =
        cupsfilters_command_compare_capture(capture_stdout, &expected);
    oracle_failed = compare_result == 0;
  }

cleanup:
  if (cupsfilters_opened_ppd) {
    cupsfilters_command_ppd_close(cupsfilters_opened_ppd);
  }
  cupsfilters_opened_ppd = NULL;

  if (stdio_redirected) {
    fflush(stdout);
    fflush(stderr);
  }
  if (saved_stdout >= 0) {
    (void)dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
  }
  if (saved_stderr >= 0) {
    (void)dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
  }
#ifdef CUPSFILTERS_COMMAND_HAS_ASAN_REPORT_FD
  if (saved_stderr >= 0) {
    __sanitizer_set_report_fd((void *)(intptr_t)STDERR_FILENO);
  }
#endif
  clearerr(stdout);
  clearerr(stderr);

  if (capture_stdout) {
    fclose(capture_stdout);
  }
  if (capture_stderr) {
    fclose(capture_stderr);
  }
  if (input_path[0]) {
    unlink(input_path);
  }
  if (ppd_path[0]) {
    unlink(ppd_path);
  }
  free(expected.data);

  if (oracle_failed) {
    __builtin_trap();
  }
  return 0;
}
