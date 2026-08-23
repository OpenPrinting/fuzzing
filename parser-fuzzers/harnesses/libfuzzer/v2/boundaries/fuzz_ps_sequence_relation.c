// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerTestOneInput cf_v2_ps_sequence_unused_entrypoint
#include "../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include "../include/sequence_relation.h"

#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V2_PS_SEQUENCE_MAX_PAYLOAD 512U
#define CF_V2_PS_SEQUENCE_MAX_MARKER 32U
#define CF_V2_PS_SEQUENCE_MAX_PREFIX 512U
#define CF_V2_PS_SEQUENCE_MAX_DOCUMENT 65536U
#define CF_V2_PS_SEQUENCE_MAX_PAGES 16U
#define CF_V2_PS_SEQUENCE_WATCHDOG_SECONDS 1U

typedef struct cf_v2_ps_sequence_buffer_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v2_ps_sequence_buffer_t;

typedef struct cf_v2_ps_sequence_offsets_s {
  size_t header_end;
  size_t last_marker_end;
  size_t last_body_end;
  size_t trailer_end;
  size_t full_end;
  unsigned pages;
} cf_v2_ps_sequence_offsets_t;

static cf_v2_relation_stats_t cf_v2_ps_sequence_stats;
static volatile sig_atomic_t cf_v2_ps_sequence_child = -1;
static volatile sig_atomic_t cf_v2_ps_sequence_is_child = 0;
static volatile sig_atomic_t cf_v2_ps_sequence_timed_out = 0;

pid_t __real_fork(void);
void __real_exit(int status) __attribute__((noreturn));

pid_t
__wrap_fork(void)
{
  pid_t child = __real_fork();

  if (child > 0)
    cf_v2_ps_sequence_child = (sig_atomic_t)child;
  else if (child == 0)
    cf_v2_ps_sequence_is_child = 1;
  return child;
}

void
__wrap_exit(int status)
{
  if (cf_v2_ps_sequence_is_child)
    _exit(status);
  __real_exit(status);
}

static void
cf_v2_ps_sequence_timeout(int signal_number)
{
  (void)signal_number;
  cf_v2_ps_sequence_timed_out = 1;
  if (cf_v2_ps_sequence_child > 0)
    (void)kill((pid_t)cf_v2_ps_sequence_child, SIGKILL);
}

static int
cf_v2_ps_sequence_append(cf_v2_ps_sequence_buffer_t *buffer,
                         const void *data, size_t size)
{
  if (!buffer || !data || size > buffer->capacity - buffer->size)
    return 0;
  memcpy(buffer->data + buffer->size, data, size);
  buffer->size += size;
  return 1;
}

static int
cf_v2_ps_sequence_printf(cf_v2_ps_sequence_buffer_t *buffer,
                         const char *format, ...)
{
  va_list arguments;
  int length;

  if (!buffer || buffer->size >= buffer->capacity)
    return 0;
  va_start(arguments, format);
  length = vsnprintf((char *)buffer->data + buffer->size,
                     buffer->capacity - buffer->size, format, arguments);
  va_end(arguments);
  if (length < 0 || (size_t)length >= buffer->capacity - buffer->size)
    return 0;
  buffer->size += (size_t)length;
  return 1;
}

static char
cf_v2_ps_sequence_printable(const cf_v2_opaque_bytes_t *opaque,
                            size_t index)
{
  return (char)('A' + opaque->data[index % opaque->size] % 26U);
}

static void
cf_v2_ps_sequence_marker(char marker[CF_V2_PS_SEQUENCE_MAX_MARKER + 1U],
                         const cf_v2_sequence_relation_t *sequence)
{
  static const char canonical[] = "%%Page:";
  size_t length = cf_v2_length_relation_value(&sequence->marker_length);
  size_t index;

  if (length > CF_V2_PS_SEQUENCE_MAX_MARKER)
    length = CF_V2_PS_SEQUENCE_MAX_MARKER;
  for (index = 0U; index < length; index ++)
    marker[index] = index < sizeof(canonical) - 1U ? canonical[index] :
        cf_v2_ps_sequence_printable(&sequence->opaque, index);
  marker[length] = '\0';
}

static int
cf_v2_ps_sequence_framing(cf_v2_ps_sequence_buffer_t *buffer,
                          const cf_v2_sequence_relation_t *sequence)
{
  unsigned framing =
      (unsigned)cf_v2_scalar_relation_value(&sequence->framing) % 3U;

#ifdef CF_V2_PS_SEQUENCE_DEEP
  if (!framing)
    framing = 1U;
#endif
  switch (framing) {
    case 0U:
      return 1;
    case 2U:
      return cf_v2_ps_sequence_append(buffer, "\r\n", 2U);
    default:
      return cf_v2_ps_sequence_append(buffer, "\n", 1U);
  }
}

static int
cf_v2_ps_sequence_line(cf_v2_ps_sequence_buffer_t *buffer,
                       const cf_v2_sequence_relation_t *sequence,
                       const char *line)
{
  return cf_v2_ps_sequence_append(buffer, line, strlen(line)) &&
         cf_v2_ps_sequence_framing(buffer, sequence);
}

static int
cf_v2_ps_sequence_prefix(cf_v2_ps_sequence_buffer_t *buffer,
                         const cf_v2_sequence_relation_t *sequence)
{
  size_t length = cf_v2_length_relation_value(&sequence->prefix_length);
  size_t index;

  if (length > CF_V2_PS_SEQUENCE_MAX_PREFIX)
    length = CF_V2_PS_SEQUENCE_MAX_PREFIX;
  if (!length)
    return 1;
  if (!cf_v2_ps_sequence_append(buffer, "%", 1U))
    return 0;
  for (index = 0U; index < length; index ++) {
    char byte = cf_v2_ps_sequence_printable(&sequence->opaque, index + 23U);

    if (!cf_v2_ps_sequence_append(buffer, &byte, 1U))
      return 0;
  }
  return cf_v2_ps_sequence_framing(buffer, sequence);
}

static int
cf_v2_ps_sequence_data(cf_v2_ps_sequence_buffer_t *buffer,
                       const cf_v2_sequence_relation_t *sequence,
                       unsigned argument)
{
  size_t length = 1U + argument % sequence->opaque.size;
  size_t index;

  if (!cf_v2_ps_sequence_printf(buffer, "%%%%BeginData: %zu Binary Bytes\n",
                                length))
    return 0;
  for (index = 0U; index < length; index ++) {
    uint8_t byte = sequence->opaque.data[
        (index + argument) % sequence->opaque.size];

    if (!cf_v2_ps_sequence_append(buffer, &byte, 1U))
      return 0;
  }
  return cf_v2_ps_sequence_line(buffer, sequence, "%%EndData");
}

static uint8_t *
cf_v2_ps_sequence_document(cf_v2_sequence_relation_t *sequence,
                           cf_v2_ps_sequence_offsets_t *offsets,
                           size_t *document_size)
{
  cf_v2_ps_sequence_buffer_t buffer;
  char marker[CF_V2_PS_SEQUENCE_MAX_MARKER + 1U];
  size_t page_budget = cf_v2_cardinality_value(&sequence->item_count);
  size_t action_count = cf_v2_cardinality_value(&sequence->action_count);
  size_t action_index;
  unsigned current_page = 0U;
  size_t cutoff;

  memset(offsets, 0, sizeof(*offsets));
  if (page_budget > CF_V2_PS_SEQUENCE_MAX_PAGES)
    page_budget = CF_V2_PS_SEQUENCE_MAX_PAGES;
  buffer.data = (uint8_t *)malloc(CF_V2_PS_SEQUENCE_MAX_DOCUMENT);
  buffer.size = 0U;
  buffer.capacity = CF_V2_PS_SEQUENCE_MAX_DOCUMENT;
  if (!buffer.data)
    return NULL;
  cf_v2_ps_sequence_marker(marker, sequence);

  if (!cf_v2_ps_sequence_line(&buffer, sequence, "%!PS-Adobe-3.0") ||
      !cf_v2_ps_sequence_line(&buffer, sequence, "%%Pages: (atend)") ||
      !cf_v2_ps_sequence_line(&buffer, sequence, "%%EndComments") ||
      !cf_v2_ps_sequence_prefix(&buffer, sequence))
    goto fail;
  offsets->header_end = buffer.size;

  for (action_index = 0U; action_index < action_count; action_index ++) {
    cf_v2_action_t action;
    unsigned repetition;

    if (!cf_v2_sequence_relation_next_action(sequence, action_index,
                                             &action))
      break;
    cf_v2_relation_stats_action(&cf_v2_ps_sequence_stats, action.kind);
    for (repetition = 0U; repetition < action.repetitions; repetition ++) {
      switch (action.kind) {
        case CF_V2_ACTION_PARSE:
          if (!cf_v2_ps_sequence_printf(
                  &buffer, "%%%%BeginSetup\n/v%u %u def\n%%%%EndSetup\n",
                  action.argument, repetition))
            goto fail;
          break;
        case CF_V2_ACTION_SELECT:
          if (page_budget) {
            current_page ++;
            if (!cf_v2_ps_sequence_printf(
                    &buffer, "%s (%u-%c) %u", marker, current_page,
                    cf_v2_ps_sequence_printable(&sequence->opaque,
                                                current_page),
                    current_page) ||
                !cf_v2_ps_sequence_framing(&buffer, sequence))
              goto fail;
            page_budget --;
            offsets->pages = current_page;
            offsets->last_marker_end = buffer.size;
          }
          break;
        case CF_V2_ACTION_EMIT:
          if (current_page &&
              (!cf_v2_ps_sequence_printf(
                   &buffer, "0 0 moveto (%c%u) show showpage",
                   cf_v2_ps_sequence_printable(&sequence->opaque,
                                               action.argument),
                   repetition) ||
               !cf_v2_ps_sequence_framing(&buffer, sequence)))
            goto fail;
          if (current_page)
            offsets->last_body_end = buffer.size;
          break;
        case CF_V2_ACTION_READ:
          if (current_page &&
              !cf_v2_ps_sequence_data(&buffer, sequence,
                                      action.argument + repetition))
            goto fail;
          if (current_page)
            offsets->last_body_end = buffer.size;
          break;
        case CF_V2_ACTION_FINISH:
          if (!cf_v2_ps_sequence_line(&buffer, sequence, "%%PageTrailer"))
            goto fail;
          if (current_page)
            offsets->last_body_end = buffer.size;
          break;
        default:
          break;
      }
    }
  }

  if (!cf_v2_ps_sequence_printf(&buffer, "%%%%Trailer\n%%%%Pages: %u\n",
                                offsets->pages))
    goto fail;
  offsets->trailer_end = buffer.size;
  if (!cf_v2_ps_sequence_line(&buffer, sequence, "%%EOF"))
    goto fail;
  offsets->full_end = buffer.size;

  switch ((unsigned)cf_v2_scalar_relation_value(&sequence->termination) %
          5U) {
    case 0U:
      cutoff = offsets->header_end;
      break;
    case 1U:
      cutoff = offsets->last_marker_end ? offsets->last_marker_end :
                                          offsets->header_end;
      break;
    case 2U:
      cutoff = offsets->last_body_end > offsets->last_marker_end ?
                   offsets->last_body_end : offsets->last_marker_end;
      if (!cutoff)
        cutoff = offsets->header_end;
      break;
    case 3U:
      cutoff = offsets->trailer_end;
      break;
    default:
      cutoff = offsets->full_end;
      break;
  }
#ifdef CF_V2_PS_SEQUENCE_DEEP
  if (offsets->pages && cutoff < offsets->trailer_end)
    cutoff = offsets->full_end;
#endif
  *document_size = cutoff;
  return buffer.data;

fail:
  free(buffer.data);
  return NULL;
}

static char *
cf_v2_ps_sequence_ppd(const cf_v2_control_t *control, size_t *ppd_size)
{
  char *ppd = NULL;
  FILE *stream = open_memstream(&ppd, ppd_size);
  int write_status;
  int close_status;

  if (!stream)
    return NULL;
  write_status = cf_v2_write_ppd(stream, control, CF_V2_TARGET_NAME);
  close_status = fclose(stream);
  if (write_status != 0 || close_status != 0) {
    free(ppd);
    return NULL;
  }
  return ppd;
}

static void
cf_v2_ps_sequence_range(char *range, size_t capacity, unsigned pages,
                        size_t requested)
{
  if (!pages || !requested)
    (void)snprintf(range, capacity, "0");
  else if (requested == 1U)
    (void)snprintf(range, capacity, "%u", pages);
  else if (requested >= pages)
    (void)snprintf(range, capacity, "1-%u", pages);
  else
    (void)snprintf(range, capacity, "%u-%u",
                   pages - (unsigned)requested + 1U, pages);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t max_size = CF_V2_SEQUENCE_RELATION_MAGIC_SIZE +
                          CF_V2_SEQUENCE_RELATION_HEADER_SIZE +
                          CF_V2_PS_SEQUENCE_MAX_PAYLOAD;
  cf_v2_sequence_relation_t sequence;
  cf_v2_ps_sequence_offsets_t offsets;
  cf_v2_control_t control;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  struct sigaction action;
  struct sigaction previous_action;
  uint8_t *document;
  size_t document_size = 0U;
  char *ppd;
  size_t ppd_size = 0U;
  char input_range[32];
  char options[192];
  int options_length;

  if (size > max_size ||
      !cf_v2_sequence_relation_decode(data, size, 7U, 0U, 8U,
                                      CF_V2_PS_SEQUENCE_MAX_PAGES,
                                      &sequence))
    return 0;
  cf_v2_relation_stats_register(&cf_v2_ps_sequence_stats,
                                CF_V2_TARGET_NAME);
  cf_v2_sequence_relation_record(&cf_v2_ps_sequence_stats, &sequence);

  document = cf_v2_ps_sequence_document(&sequence, &offsets,
                                        &document_size);
  if (!document)
    return 0;
  memset(&control, 0, sizeof(control));
  control.page_size = sequence.opaque.data[0];
  control.resolution = sequence.opaque.data[
      sequence.opaque.size > 1U ? 1U : 0U];
  control.sides = sequence.opaque.data[
      sequence.opaque.size > 2U ? 2U : 0U];
  ppd = cf_v2_ps_sequence_ppd(&control, &ppd_size);
  cf_v2_ps_sequence_range(
      input_range, sizeof(input_range), offsets.pages,
      cf_v2_cardinality_value(&sequence.selection_count));
  options_length = snprintf(
      options, sizeof(options),
      "input-page-ranges=%s page-ranges=1-%u page-set=all number-up=1 "
      "output-order=normal copies=1 emit-jcl=false",
      input_range, offsets.pages ? offsets.pages : 1U);
  if (!ppd || options_length < 0 ||
      (size_t)options_length >= sizeof(options)) {
    free(ppd);
    free(document);
    return 0;
  }

  memset(&job, 0, sizeof(job));
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_length;
  job.title = (const uint8_t *)"sequence-relation";
  job.title_size = sizeof("sequence-relation") - 1U;
  job.document = document;
  job.document_size = document_size;

  memset(&action, 0, sizeof(action));
  action.sa_handler = cf_v2_ps_sequence_timeout;
  sigemptyset(&action.sa_mask);
  cf_v2_ps_sequence_child = -1;
  cf_v2_ps_sequence_timed_out = 0;
  if (sigaction(SIGALRM, &action, &previous_action) != 0) {
    free(ppd);
    free(document);
    return 0;
  }
  memset(&result, 0, sizeof(result));
  alarm(CF_V2_PS_SEQUENCE_WATCHDOG_SECONDS);
  (void)cf_v2_execute_direct_job(&job, 0, &result);
  alarm(0);
  (void)sigaction(SIGALRM, &previous_action, NULL);
  cf_v2_free_run_result(&result);
  free(ppd);
  free(document);

  if (cf_v2_ps_sequence_timed_out)
    __builtin_trap();
  return 0;
}
