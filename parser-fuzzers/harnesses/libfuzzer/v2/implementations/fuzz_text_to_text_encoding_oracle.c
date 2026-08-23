// SPDX-License-Identifier: Apache-2.0
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_TEXT_ENCODING_MAGIC "TXTENC01"
#define CF_V2_TEXT_ENCODING_MAGIC_SIZE 8U
#define CF_V2_TEXT_ENCODING_SELECTORS 4U
#define CF_V2_TEXT_ENCODING_MAX_PAYLOAD 256U
#define CF_V2_TEXT_ENCODING_LINE_BYTES 80U

typedef struct cf_v2_text_encoding_glyph_s
{
  const uint8_t *utf8;
  size_t utf8_size;
  const uint8_t *encoded;
  size_t encoded_size;
} cf_v2_text_encoding_glyph_t;

typedef struct cf_v2_text_encoding_profile_s
{
  const char *name;
  const cf_v2_text_encoding_glyph_t *glyphs;
  size_t glyph_count;
  size_t critical_glyph;
} cf_v2_text_encoding_profile_t;

typedef struct cf_v2_text_encoding_buffer_s
{
  uint8_t *data;
  size_t size;
  size_t capacity;
} cf_v2_text_encoding_buffer_t;

static const uint8_t cf_v2_ascii_a[] = {'A'};
static const uint8_t cf_v2_ascii_b[] = {'B'};
static const uint8_t cf_v2_ascii_tilde[] = {'~'};
static const uint8_t cf_v2_utf8_eacute[] = {0xc3U, 0xa9U};
static const uint8_t cf_v2_utf8_pound[] = {0xc2U, 0xa3U};
static const uint8_t cf_v2_utf8_ccedilla[] = {0xc3U, 0x87U};
static const uint8_t cf_v2_utf8_ntilde[] = {0xc3U, 0xb1U};
static const uint8_t cf_v2_utf8_euro[] = {0xe2U, 0x82U, 0xacU};
static const uint8_t cf_v2_utf8_left_quote[] = {0xe2U, 0x80U, 0x9cU};
static const uint8_t cf_v2_utf8_em_dash[] = {0xe2U, 0x80U, 0x94U};
static const uint8_t cf_v2_utf8_smile[] = {0xf0U, 0x9fU, 0x98U, 0x80U};
static const uint8_t cf_v2_latin1_eacute[] = {0xe9U};
static const uint8_t cf_v2_latin1_pound[] = {0xa3U};
static const uint8_t cf_v2_latin1_ccedilla[] = {0xc7U};
static const uint8_t cf_v2_latin1_ntilde[] = {0xf1U};
static const uint8_t cf_v2_cp1252_euro[] = {0x80U};
static const uint8_t cf_v2_cp1252_left_quote[] = {0x93U};
static const uint8_t cf_v2_cp1252_em_dash[] = {0x97U};

static const cf_v2_text_encoding_glyph_t cf_v2_ascii_glyphs[] = {
  {cf_v2_ascii_a, sizeof(cf_v2_ascii_a), cf_v2_ascii_a,
   sizeof(cf_v2_ascii_a)},
  {cf_v2_ascii_b, sizeof(cf_v2_ascii_b), cf_v2_ascii_b,
   sizeof(cf_v2_ascii_b)},
  {cf_v2_ascii_tilde, sizeof(cf_v2_ascii_tilde), cf_v2_ascii_tilde,
   sizeof(cf_v2_ascii_tilde)},
};

static const cf_v2_text_encoding_glyph_t cf_v2_latin1_glyphs[] = {
  {cf_v2_ascii_a, sizeof(cf_v2_ascii_a), cf_v2_ascii_a,
   sizeof(cf_v2_ascii_a)},
  {cf_v2_utf8_eacute, sizeof(cf_v2_utf8_eacute), cf_v2_latin1_eacute,
   sizeof(cf_v2_latin1_eacute)},
  {cf_v2_utf8_pound, sizeof(cf_v2_utf8_pound), cf_v2_latin1_pound,
   sizeof(cf_v2_latin1_pound)},
  {cf_v2_utf8_ccedilla, sizeof(cf_v2_utf8_ccedilla), cf_v2_latin1_ccedilla,
   sizeof(cf_v2_latin1_ccedilla)},
  {cf_v2_utf8_ntilde, sizeof(cf_v2_utf8_ntilde), cf_v2_latin1_ntilde,
   sizeof(cf_v2_latin1_ntilde)},
};

static const cf_v2_text_encoding_glyph_t cf_v2_cp1252_glyphs[] = {
  {cf_v2_ascii_a, sizeof(cf_v2_ascii_a), cf_v2_ascii_a,
   sizeof(cf_v2_ascii_a)},
  {cf_v2_utf8_euro, sizeof(cf_v2_utf8_euro), cf_v2_cp1252_euro,
   sizeof(cf_v2_cp1252_euro)},
  {cf_v2_utf8_left_quote, sizeof(cf_v2_utf8_left_quote),
   cf_v2_cp1252_left_quote, sizeof(cf_v2_cp1252_left_quote)},
  {cf_v2_utf8_em_dash, sizeof(cf_v2_utf8_em_dash), cf_v2_cp1252_em_dash,
   sizeof(cf_v2_cp1252_em_dash)},
  {cf_v2_utf8_eacute, sizeof(cf_v2_utf8_eacute), cf_v2_latin1_eacute,
   sizeof(cf_v2_latin1_eacute)},
};

static const cf_v2_text_encoding_glyph_t cf_v2_utf8_glyphs[] = {
  {cf_v2_ascii_a, sizeof(cf_v2_ascii_a), cf_v2_ascii_a,
   sizeof(cf_v2_ascii_a)},
  {cf_v2_utf8_euro, sizeof(cf_v2_utf8_euro), cf_v2_utf8_euro,
   sizeof(cf_v2_utf8_euro)},
  {cf_v2_utf8_smile, sizeof(cf_v2_utf8_smile), cf_v2_utf8_smile,
   sizeof(cf_v2_utf8_smile)},
  {cf_v2_utf8_eacute, sizeof(cf_v2_utf8_eacute), cf_v2_utf8_eacute,
   sizeof(cf_v2_utf8_eacute)},
};

static const cf_v2_text_encoding_profile_t cf_v2_encoding_profiles[] = {
  {"ASCII", cf_v2_ascii_glyphs,
   sizeof(cf_v2_ascii_glyphs) / sizeof(cf_v2_ascii_glyphs[0]), 2U},
  {"ISO-8859-1", cf_v2_latin1_glyphs,
   sizeof(cf_v2_latin1_glyphs) / sizeof(cf_v2_latin1_glyphs[0]), 1U},
  {"CP1252", cf_v2_cp1252_glyphs,
   sizeof(cf_v2_cp1252_glyphs) / sizeof(cf_v2_cp1252_glyphs[0]), 1U},
  {"UTF-8", cf_v2_utf8_glyphs,
   sizeof(cf_v2_utf8_glyphs) / sizeof(cf_v2_utf8_glyphs[0]), 2U},
};

static int
cf_v2_text_encoding_append(cf_v2_text_encoding_buffer_t *buffer,
                           const uint8_t *material, size_t material_size)
{
  if (!buffer || !material || material_size > buffer->capacity - buffer->size)
    return 0;
  memcpy(buffer->data + buffer->size, material, material_size);
  buffer->size += material_size;
  return 1;
}

static int
cf_v2_text_encoding_append_byte(cf_v2_text_encoding_buffer_t *buffer,
                                uint8_t value)
{
  return cf_v2_text_encoding_append(buffer, &value, 1U);
}

static int
cf_v2_text_encoding_newline(cf_v2_text_encoding_buffer_t *document,
                            cf_v2_text_encoding_buffer_t *expected,
                            size_t *column)
{
  if (!cf_v2_text_encoding_append_byte(document, '\n') ||
      !cf_v2_text_encoding_append_byte(expected, '\n'))
    return 0;
  *column = 0;
  return 1;
}

static int
cf_v2_text_encoding_append_glyph(
    cf_v2_text_encoding_buffer_t *document,
    cf_v2_text_encoding_buffer_t *expected,
    const cf_v2_text_encoding_glyph_t *glyph, size_t *column)
{
  if (*column && *column + glyph->encoded_size > CF_V2_TEXT_ENCODING_LINE_BYTES)
    if (!cf_v2_text_encoding_newline(document, expected, column))
      return 0;
  if (!cf_v2_text_encoding_append(document, glyph->utf8, glyph->utf8_size) ||
      !cf_v2_text_encoding_append(expected, glyph->encoded,
                                  glyph->encoded_size))
    return 0;
  *column += glyph->encoded_size;
  return 1;
}

static int
cf_v2_text_encoding_pad_to(cf_v2_text_encoding_buffer_t *document,
                           cf_v2_text_encoding_buffer_t *expected,
                           size_t target, size_t *column)
{
  while (document->size < target)
  {
    const uint8_t value = *column == CF_V2_TEXT_ENCODING_LINE_BYTES ? '\n' : 'x';

    if (!cf_v2_text_encoding_append_byte(document, value) ||
        !cf_v2_text_encoding_append_byte(expected, value))
      return 0;
    if (value == '\n')
      *column = 0;
    else
      (*column) ++;
  }
  return document->size == target;
}

static int
cf_v2_text_encoding_build(const uint8_t *selector, const uint8_t *payload,
                          size_t payload_size, uint8_t **document_data,
                          size_t *document_size, uint8_t **expected_data,
                          size_t *expected_size,
                          const cf_v2_text_encoding_profile_t **profile_out)
{
  static const int boundary_delta[] = {-3, -2, -1, 0, 1, 2};
  const cf_v2_text_encoding_profile_t *profile =
      &cf_v2_encoding_profiles[selector[0] %
                               (sizeof(cf_v2_encoding_profiles) /
                                sizeof(cf_v2_encoding_profiles[0]))];
  const size_t boundary = selector[1] & 1U ? 4096U : 2048U;
  const int delta = boundary_delta[selector[2] %
                                   (sizeof(boundary_delta) /
                                    sizeof(boundary_delta[0]))];
  const size_t critical_offset = (size_t)((int)boundary + delta);
  const size_t capacity = 8192U + payload_size * 4U;
  cf_v2_text_encoding_buffer_t document = {NULL, 0, capacity};
  cf_v2_text_encoding_buffer_t expected = {NULL, 0, capacity};
  size_t column = 0;
  size_t index;

  document.data = (uint8_t *)malloc(capacity);
  expected.data = (uint8_t *)malloc(capacity);
  if (!document.data || !expected.data)
    goto fail;
  if (!cf_v2_text_encoding_pad_to(&document, &expected, critical_offset,
                                  &column) ||
      !cf_v2_text_encoding_append_glyph(
          &document, &expected, &profile->glyphs[profile->critical_glyph],
          &column))
    goto fail;

  for (index = 0; index < payload_size; index ++)
  {
    const size_t glyph_index =
        (payload[index] + selector[3] + index * 3U) % profile->glyph_count;

    if (!cf_v2_text_encoding_append_glyph(
            &document, &expected, &profile->glyphs[glyph_index], &column))
      goto fail;
  }
  if (column && !cf_v2_text_encoding_newline(&document, &expected, &column))
    goto fail;

  *document_data = document.data;
  *document_size = document.size;
  *expected_data = expected.data;
  *expected_size = expected.size;
  *profile_out = profile;
  return 1;

fail:
  free(document.data);
  free(expected.data);
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_V2_TEXT_ENCODING_MAGIC_SIZE + CF_V2_TEXT_ENCODING_SELECTORS;
  const uint8_t *selector;
  const uint8_t *payload;
  uint8_t *document = NULL;
  uint8_t *expected = NULL;
  const cf_v2_text_encoding_profile_t *profile = NULL;
  size_t payload_size;
  size_t document_size = 0;
  size_t expected_size = 0;
  char options[512];
  static const uint8_t title[] = "text-to-text encoding oracle";
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  int options_size;
  int executed;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_TEXT_ENCODING_MAX_PAYLOAD ||
      memcmp(data, CF_V2_TEXT_ENCODING_MAGIC,
             CF_V2_TEXT_ENCODING_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_TEXT_ENCODING_MAGIC_SIZE;
  payload = data + fixed_size;
  payload_size = size - fixed_size;
  if (!cf_v2_text_encoding_build(selector, payload, payload_size, &document,
                                 &document_size, &expected, &expected_size,
                                 &profile))
    return 0;

  options_size = snprintf(
      options, sizeof(options),
      "PageWidth=132 PageHeight=66 PageLeft=0 PageRight=0 PageTop=0 "
      "PageBottom=0 PrinterEncoding=%s OverLongLines=wrap-at-width "
      "TabWidth=8 Pagination=false SendFF=false NewlineCharacters=lf "
      "page-ranges=1-99 page-set=all OutputOrder=normal Collate=true",
      profile->name);
  if (options_size < 0 || (size_t)options_size >= sizeof(options))
    goto cleanup;

  memset(&job, 0, sizeof(job));
  job.options = (const uint8_t *)options;
  job.options_size = (size_t)options_size;
  job.title = title;
  job.title_size = sizeof(title) - 1U;
  job.document = document;
  job.document_size = document_size;
  memset(&result, 0, sizeof(result));
  executed = cf_v2_execute_direct_job(&job, 1, &result);
  if (executed && result.captured &&
      (result.status != 0 || result.output_size != expected_size ||
       (expected_size && memcmp(result.output, expected, expected_size) != 0)))
    __builtin_trap();
  cf_v2_free_run_result(&result);

cleanup:
  free(document);
  free(expected);
  return 0;
}
