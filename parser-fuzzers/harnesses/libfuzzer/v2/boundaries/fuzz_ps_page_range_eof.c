// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerTestOneInput cf_v2_ps_page_range_unused_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V2_PS_PAGE_RANGE_MAGIC "PSPGEOF1"
#define CF_V2_PS_PAGE_RANGE_MAGIC_SIZE 8U
#define CF_V2_PS_PAGE_RANGE_SELECTORS 8U
#define CF_V2_PS_PAGE_RANGE_MAX_PAYLOAD 128U
#define CF_V2_PS_PAGE_RANGE_WATCHDOG_SECONDS 1U

static volatile sig_atomic_t cf_v2_ps_page_range_child = -1;
static volatile sig_atomic_t cf_v2_ps_page_range_is_child = 0;
static volatile sig_atomic_t cf_v2_ps_page_range_timed_out = 0;

pid_t __real_fork(void);
void __real_exit(int status) __attribute__((noreturn));

pid_t __wrap_fork(void) {
  pid_t child = __real_fork();

  if (child > 0) {
    cf_v2_ps_page_range_child = (sig_atomic_t)child;
  } else if (child == 0) {
    cf_v2_ps_page_range_is_child = 1;
  }
  return child;
}

void __wrap_exit(int status) {
  if (cf_v2_ps_page_range_is_child) {
    _exit(status);
  }
  __real_exit(status);
}

static void cf_v2_ps_page_range_timeout(int signal_number) {
  (void)signal_number;
  cf_v2_ps_page_range_timed_out = 1;
  if (cf_v2_ps_page_range_child > 0) {
    (void)kill((pid_t)cf_v2_ps_page_range_child, SIGKILL);
  }
}

static char *cf_v2_ps_page_range_ppd(const cf_v2_control_t *control,
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

static int cf_v2_ps_page_range_append(char *document, size_t capacity,
                                      size_t *used, const char *format, ...) {
  va_list arguments;
  int length;

  if (*used >= capacity) {
    return 0;
  }
  va_start(arguments, format);
  length = vsnprintf(document + *used, capacity - *used, format, arguments);
  va_end(arguments);
  if (length < 0 || (size_t)length >= capacity - *used) {
    return 0;
  }
  *used += (size_t)length;
  return 1;
}

static char cf_v2_ps_page_range_material(uint8_t value) {
  return (char)('A' + value % 26U);
}

static uint8_t *cf_v2_ps_page_range_document(
    const uint8_t selectors[CF_V2_PS_PAGE_RANGE_SELECTORS],
    const uint8_t *payload, size_t payload_size, unsigned selected_page,
    size_t *document_size) {
  const unsigned termination = selectors[2] % 8U;
  const unsigned payload_lines = selectors[3] % 4U;
  const size_t capacity = 4096U + payload_size * 8U;
  uint8_t *bytes = (uint8_t *)malloc(capacity);
  char *document = (char *)bytes;
  size_t used = 0;
  unsigned page;

  if (!bytes ||
      !cf_v2_ps_page_range_append(
          document, capacity, &used,
          "%%!PS-Adobe-3.0\n"
          "%%%%Pages: %u\n"
          "%%%%BoundingBox: 0 0 612 792\n"
          "%%%%Creator: cups-filters-v2-page-range-eof\n"
          "%%%%EndComments\n",
          selected_page)) {
    free(bytes);
    return NULL;
  }

  for (page = 1U; page <= selected_page; page++) {
    if (!cf_v2_ps_page_range_append(document, capacity, &used,
                                    "%%%%Page: (%u-%c) %u\n", page,
                                    cf_v2_ps_page_range_material(
                                        payload[(page - 1U) % payload_size]),
                                    page)) {
      free(bytes);
      return NULL;
    }
    if (page < selected_page) {
      if (!cf_v2_ps_page_range_append(document, capacity, &used,
                                      "0 0 moveto (%c) show showpage\n",
                                      cf_v2_ps_page_range_material(
                                          payload[page % payload_size]))) {
        free(bytes);
        return NULL;
      }
    }
  }

  if (termination == 7U) {
    *document_size = used;
    return bytes;
  }

  for (page = 0; page < payload_lines; page++) {
    if (!cf_v2_ps_page_range_append(
            document, capacity, &used, "0 %u moveto (%c%c) show\n", page,
            cf_v2_ps_page_range_material(payload[page % payload_size]),
            cf_v2_ps_page_range_material(
                payload[(page + selectors[4]) % payload_size]))) {
      free(bytes);
      return NULL;
    }
  }
  if ((termination & 1U) &&
      !cf_v2_ps_page_range_append(document, capacity, &used, "showpage\n")) {
    free(bytes);
    return NULL;
  }
  if (termination == 2U || termination == 5U) {
    if (!cf_v2_ps_page_range_append(document, capacity, &used,
                                    "%%%%Page: continuation %u\n",
                                    selected_page + 1U)) {
      free(bytes);
      return NULL;
    }
  }
  if (!cf_v2_ps_page_range_append(document, capacity, &used,
                                  "%%%%Trailer\n%%%%Pages: %u\n",
                                  selected_page)) {
    free(bytes);
    return NULL;
  }
  if (termination != 4U &&
      !cf_v2_ps_page_range_append(document, capacity, &used, "%%%%EOF\n")) {
    free(bytes);
    return NULL;
  }
  *document_size = used;
  return bytes;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t fixed_size = CF_V2_PS_PAGE_RANGE_MAGIC_SIZE +
                            CF_V2_PS_PAGE_RANGE_SELECTORS;
  const uint8_t *selectors;
  const uint8_t *payload;
  size_t payload_size;
  unsigned selected_page;
  char input_range[32];
  char options[160];
  char title[32];
  char *ppd = NULL;
  size_t ppd_size = 0;
  uint8_t *document = NULL;
  size_t document_size = 0;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  struct sigaction action;
  struct sigaction previous_action;
  int options_length;
  int title_length;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_PS_PAGE_RANGE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_PS_PAGE_RANGE_MAGIC,
             CF_V2_PS_PAGE_RANGE_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V2_PS_PAGE_RANGE_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  selected_page = 1U + selectors[0] % 4U;

  switch (selectors[1] % 4U) {
    case 0U:
      (void)snprintf(input_range, sizeof(input_range), "%u", selected_page);
      break;
    case 1U:
      (void)snprintf(input_range, sizeof(input_range), "1-%u", selected_page);
      break;
    case 2U:
      (void)snprintf(input_range, sizeof(input_range), "%u-%u",
                     selected_page, selected_page);
      break;
    default:
      (void)snprintf(input_range, sizeof(input_range), "1,%u",
                     selected_page);
      break;
  }

  memset(&job, 0, sizeof(job));
  job.control.page_size = selectors[5];
  job.control.sides = selectors[6];
  job.control.resolution = selectors[7];
  ppd = cf_v2_ps_page_range_ppd(&job.control, &ppd_size);
  document = cf_v2_ps_page_range_document(
      selectors, payload, payload_size, selected_page, &document_size);
  options_length = snprintf(
      options, sizeof(options),
      "input-page-ranges=%s page-ranges=1-%u page-set=all number-up=1 "
      "output-order=normal copies=1 emit-jcl=false",
      input_range, selected_page);
  title_length = snprintf(title, sizeof(title), "page-range-%u", selected_page);
  if (!ppd || !document || options_length < 0 ||
      (size_t)options_length >= sizeof(options) || title_length < 0 ||
      (size_t)title_length >= sizeof(title)) {
    free(document);
    free(ppd);
    return 0;
  }

  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_length;
  job.title = (const uint8_t *)title;
  job.title_size = (size_t)title_length;
  job.document = document;
  job.document_size = document_size;

  memset(&action, 0, sizeof(action));
  action.sa_handler = cf_v2_ps_page_range_timeout;
  sigemptyset(&action.sa_mask);
  cf_v2_ps_page_range_child = -1;
  cf_v2_ps_page_range_timed_out = 0;
  if (sigaction(SIGALRM, &action, &previous_action) != 0) {
    free(document);
    free(ppd);
    return 0;
  }
  alarm(CF_V2_PS_PAGE_RANGE_WATCHDOG_SECONDS);
  (void)cf_v2_execute_direct_job(&job, 0, &result);
  alarm(0);
  (void)sigaction(SIGALRM, &previous_action, NULL);
  cf_v2_free_run_result(&result);
  free(document);
  free(ppd);

  if (cf_v2_ps_page_range_timed_out) {
    __builtin_trap();
  }
  return 0;
}
