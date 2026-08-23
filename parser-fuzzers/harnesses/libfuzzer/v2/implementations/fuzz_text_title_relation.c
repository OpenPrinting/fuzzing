// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerTestOneInput cf_v2_text_title_relation_unused_entrypoint
#include "fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include "../include/relation_program.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_TITLE_RELATION_MAGIC "TXTREL01"
#define CF_V2_TEXT_TITLE_RELATION_MAGIC_SIZE 8U
#define CF_V2_TEXT_TITLE_RELATION_HEADER_SIZE 7U
#define CF_V2_TEXT_TITLE_RELATION_MAX_PAYLOAD 256U
#define CF_V2_TEXT_TITLE_RELATION_MAX_TITLE 256U
#define CF_V2_TEXT_TITLE_RELATION_MAX_DOCUMENT 4096U

static cf_v2_relation_stats_t cf_v2_text_title_relation_stats;

static int16_t
cf_v2_text_title_relation_delta(const uint8_t *header)
{
  uint16_t encoded = (uint16_t)header[1] |
                     ((uint16_t)header[2] << 8U);

  return (int16_t)encoded;
}

static size_t
cf_v2_text_title_relation_build_title(
    uint8_t *title, size_t capacity, const cf_v2_length_relation_t *length,
    cf_v2_opaque_bytes_t opaque)
{
  size_t wanted = cf_v2_length_relation_value(length);
  size_t index;

  if (wanted > capacity)
    wanted = capacity;
  for (index = 0U; index < wanted; index ++)
    title[index] = opaque.data[index % opaque.size];
  return wanted;
}

static void
cf_v2_text_title_relation_project_ascii(uint8_t *text, size_t size)
{
  size_t index;

  for (index = 0U; index < size; index ++)
    text[index] &= 0x7fU;
}

static size_t
cf_v2_text_title_relation_build_document(
    uint8_t *document, size_t capacity, size_t declarations)
{
  static const char prefix[] = "int main(void) {\n";
  static const char suffix[] = "  return 0;\n}\n";
  size_t used = 0U;
  size_t index;

  if (sizeof(prefix) - 1U + sizeof(suffix) - 1U > capacity)
    return 0U;
  memcpy(document + used, prefix, sizeof(prefix) - 1U);
  used += sizeof(prefix) - 1U;
  for (index = 0U; index < declarations; index ++) {
    int length = snprintf((char *)document + used, capacity - used,
                          "  int value_%zu = %zu;\n", index, index);

    if (length < 0 || (size_t)length >= capacity - used)
      break;
    used += (size_t)length;
  }
  memcpy(document + used, suffix, sizeof(suffix) - 1U);
  return used + sizeof(suffix) - 1U;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size = CF_V2_TEXT_TITLE_RELATION_MAGIC_SIZE +
                            CF_V2_TEXT_TITLE_RELATION_HEADER_SIZE;
  const uint8_t *header;
  cf_v2_scalar_relation_t prettyprint;
  cf_v2_length_relation_t title_length;
  cf_v2_cardinality_relation_t declaration_count;
  cf_v2_opaque_bytes_t opaque;
  uint8_t title[CF_V2_TEXT_TITLE_RELATION_MAX_TITLE];
  uint8_t document[CF_V2_TEXT_TITLE_RELATION_MAX_DOCUMENT];
  char options[64];
  size_t document_size;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_TITLE_RELATION_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_TITLE_RELATION_MAGIC,
             CF_V2_TEXT_TITLE_RELATION_MAGIC_SIZE))
    return 0;
  header = data + CF_V2_TEXT_TITLE_RELATION_MAGIC_SIZE;
  opaque = cf_v2_opaque_bytes(data + fixed_size, size - fixed_size);
  if (!opaque.size)
    return 0;

  title_length.mode = cf_v2_relation_mode(header[0]);
  title_length.base = opaque.size;
  title_length.signed_delta = cf_v2_text_title_relation_delta(header);
  prettyprint.mode = cf_v2_relation_mode(header[3]);
  prettyprint.derived_value = 1;
  prettyprint.explicit_value = header[4] & 1U;
  declaration_count.class_id = (cf_v2_cardinality_class_t)(
      header[5] % CF_V2_CARDINALITY_CLASS_COUNT);
  declaration_count.parameter = header[6];
  declaration_count.boundary = 16U;
  declaration_count.limit = 64U;

  cf_v2_relation_stats_register(&cf_v2_text_title_relation_stats,
                                CF_V2_TARGET_NAME);
  cf_v2_relation_stats_scalar(&cf_v2_text_title_relation_stats,
                              prettyprint.mode);
  cf_v2_relation_stats_length(&cf_v2_text_title_relation_stats,
                              title_length.mode);
  cf_v2_relation_stats_cardinality(&cf_v2_text_title_relation_stats,
                                   declaration_count.class_id);
  cf_v2_relation_stats_opaque(&cf_v2_text_title_relation_stats,
                              opaque.size);

  document_size = cf_v2_text_title_relation_build_document(
      document, sizeof(document), cf_v2_cardinality_value(&declaration_count));
  if (!document_size)
    return 0;
  (void)snprintf(options, sizeof(options),
                 "PageSize=A4 prettyprint=%s wrap=true",
                 cf_v2_scalar_relation_value(&prettyprint) ? "true" :
                                                             "false");

  memset(&job, 0, sizeof(job));
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = title;
  job.title_size = cf_v2_text_title_relation_build_title(
      title, sizeof(title), &title_length, opaque);
#ifdef CF_V2_TEXT_TITLE_RELATION_DEEP
  cf_v2_text_title_relation_project_ascii(title, job.title_size);
#endif
  job.document = document;
  job.document_size = document_size;

  memset(&result, 0, sizeof(result));
#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
  cf_v2_texttopdf_active = 1;
#endif
  (void)cf_v2_execute_direct_job(&job, 0, &result);
#ifdef CF_V2_TEXTTOPDF_LEAK_GUARD
  cf_v2_release_texttopdf_lifecycle();
#endif
  cf_v2_free_run_result(&result);
  return 0;
}
