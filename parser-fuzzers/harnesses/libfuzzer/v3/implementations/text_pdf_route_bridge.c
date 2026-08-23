// SPDX-License-Identifier: Apache-2.0
#include "text_pdf_route.h"
#include "text_pdf_route_bridge.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_text_pdf_runner_t)(const uint8_t *, size_t);

extern int cf_v3_text_pdf_job_plain_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_job_plain_ascii_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_job_c_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_direct_plain_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_direct_plain_ascii_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_direct_c_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_direct_shell_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_direct_perl_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_layout_utf8_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_layout_ascii_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_output_oracle_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_output_continuation_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_direction_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_duplex_boundary_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_duplex_continuation_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_title_utf8_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_title_relation_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_title_deep_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_shared_output_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_boundary_plain_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_boundary_c_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_deep_plain_legacy(const uint8_t *, size_t);
extern int cf_v3_text_pdf_deep_c_legacy(const uint8_t *, size_t);

static int
cf_v3_text_pdf_call(unsigned route, int faithful,
                    cf_v3_text_pdf_runner_t runner,
                    const uint8_t *data, size_t size)
{
  int result = runner(data, size);

  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "text_to_pdf route=%u faithful=%d input=%zu\n",
            route, faithful, size);
  return result;
}

static uint8_t
cf_v3_text_pdf_printable(uint8_t value)
{
  return (uint8_t)(' ' + value % 95U);
}

static uint8_t
cf_v3_text_pdf_plain_byte(uint8_t value)
{
  if (value == '\n' || value == '\r' || value == '\t' || value == '\f')
    return value;
  return cf_v3_text_pdf_printable(value);
}

static size_t
cf_v3_text_pdf_document(uint8_t *output, size_t capacity,
                        const uint8_t *material, size_t material_size,
                        int c_source)
{
  static const char c_prefix[] = "int main(void) {\n  /* fuzz material */\n  ";
  static const char c_suffix[] = "\n  return 0;\n}\n";
  static const char c_alphabet[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      " _+-=;,.()[]{}<>/*\"'";
  size_t limit = material_size < 2048U ? material_size : 2048U;
  size_t used = 0U;

  if (c_source)
  {
    const size_t suffix_size = sizeof(c_suffix) - 1U;

    if (sizeof(c_prefix) - 1U + sizeof(c_suffix) - 1U > capacity)
      return 0U;
    memcpy(output, c_prefix, sizeof(c_prefix) - 1U);
    used = sizeof(c_prefix) - 1U;
    for (size_t index = 0U;
         index < limit && used + suffix_size + 3U <= capacity; index++)
    {
      uint8_t current = (uint8_t)c_alphabet[
          material[index] % (sizeof(c_alphabet) - 1U)];

      if (current == '/' && index + 1U < limit)
      {
        uint8_t next = (uint8_t)c_alphabet[
            material[index + 1U] % (sizeof(c_alphabet) - 1U)];

        /* Keep comment lexer coverage without allowing the two-byte opener to
         * straddle a column rollover and reach Page[line][column - 1]. */
        if ((next == '/' || next == '*') && used && output[used - 1U] != '\n')
          output[used++] = '\n';
      }
      output[used++] = current;
      if ((index + 1U) % 64U == 0U)
        output[used++] = '\n';
    }
    memcpy(output + used, c_suffix, suffix_size);
    return used + suffix_size;
  }

  for (size_t index = 0U; index < limit && used + 2U < capacity; index++)
  {
    uint8_t current = cf_v3_text_pdf_plain_byte(material[index]);

    if (current == '/' && index + 1U < limit)
    {
      uint8_t next = cf_v3_text_pdf_plain_byte(material[index + 1U]);

      if ((next == '/' || next == '*') && used && output[used - 1U] != '\n')
        output[used++] = '\n';
    }
    output[used++] = current;
  }
  if (!used || output[used - 1U] != '\n')
  {
    if (used >= capacity)
      return 0U;
    output[used++] = '\n';
  }
  return used;
}

static int
cf_v3_text_pdf_pack_job(unsigned route, int faithful,
                        cf_v3_text_pdf_runner_t runner,
                        const uint8_t *header, const uint8_t *material,
                        size_t material_size, int c_source)
{
  uint8_t input[CF_V2_JOB_FIXED_SIZE + 512U + 64U + 4096U];
  uint8_t document[4096U];
  char options[512];
  uint8_t title[64U];
  static const unsigned cpi[] = {6U, 8U, 10U, 12U, 15U};
  static const unsigned lpi[] = {4U, 6U, 8U, 10U};
  unsigned columns = 1U + header[0] % 4U;
  int pretty = (header[3] & 1U) != 0U;
  int option_length;
  size_t options_size;
  size_t title_size;
  size_t document_size;
  size_t input_size;
  size_t offset;

  if (faithful)
    return cf_v3_text_pdf_call(route, faithful, runner,
                               material, material_size);
  document_size = cf_v3_text_pdf_document(
      document, sizeof(document), material, material_size, c_source);
  if (!document_size)
    return 0;
  option_length = snprintf(
      options, sizeof(options),
      "PageSize=%s columns=%u cpi=%u lpi=%u prettyprint=%s wrap=true",
      header[1] & 1U ? "Letter" : "A4", columns,
      cpi[header[2] % (sizeof(cpi) / sizeof(cpi[0]))],
      lpi[header[4] % (sizeof(lpi) / sizeof(lpi[0]))],
      pretty ? "true" : "false");
  if (option_length <= 0 || (size_t)option_length >= sizeof(options))
    return 0;
  options_size = (size_t)option_length;
  title_size = 1U + header[5] % 32U;
  for (size_t index = 0U; index < title_size; index++)
    title[index] = (uint8_t)('A' + material[index % material_size] % 26U);

  input_size = CF_V2_JOB_FIXED_SIZE + options_size + title_size + document_size;
  if (input_size > sizeof(input))
    return 0;
  cf_v2_job_store_u32le(input, 0U);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)options_size);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_size);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)document_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, header, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, options, options_size);
  offset += options_size;
  memcpy(input + offset, title, title_size);
  offset += title_size;
  memcpy(input + offset, document, document_size);
  return cf_v3_text_pdf_call(route, faithful, runner, input, input_size);
}

static int
cf_v3_text_pdf_pack_direct(unsigned route, int faithful,
                           cf_v3_text_pdf_runner_t runner,
                           const uint8_t *header, const uint8_t *material,
                           size_t material_size)
{
  uint8_t input[2048U + CF_V2_CONTROL_SIZE];
  uint8_t control[CF_V2_CONTROL_SIZE];
  size_t document_size = material_size < 2048U ? material_size : 2048U;

  if (!document_size)
    return 0;
  memcpy(input, material, document_size);
  memcpy(control, header, sizeof(control));
  if (!faithful)
  {
    control[6] |= 1U;
    control[8] = 0U;
    control[14] = 0U;
  }
  memcpy(input + document_size, control, sizeof(control));
  return cf_v3_text_pdf_call(route, faithful, runner, input,
                             document_size + sizeof(control));
}

static int
cf_v3_text_pdf_pack_state(unsigned route, int faithful,
                          const char magic[8], size_t selector_size,
                          size_t max_payload, cf_v3_text_pdf_runner_t runner,
                          const uint8_t *header, const uint8_t *material,
                          size_t material_size)
{
  uint8_t input[8U + CF_V3_TEXT_PDF_HEADER_SIZE +
                CF_V3_TEXT_PDF_MAX_MATERIAL];
  size_t payload_size = material_size < max_payload ?
      material_size : max_payload;
  size_t input_size;

  if (!payload_size || selector_size > CF_V3_TEXT_PDF_HEADER_SIZE)
    return 0;
  input_size = 8U + selector_size + payload_size;
  memcpy(input, magic, 8U);
  memcpy(input + 8U, header, selector_size);
  memcpy(input + 8U + selector_size, material, payload_size);
  return cf_v3_text_pdf_call(route, faithful, runner, input, input_size);
}

static int
cf_v3_text_pdf_pack_job_state(unsigned route, int faithful,
                              cf_v3_text_pdf_runner_t runner,
                              const uint8_t *header,
                              const uint8_t *material,
                              size_t material_size)
{
  uint8_t safe_header[CF_V3_TEXT_PDF_HEADER_SIZE];

  memcpy(safe_header, header, sizeof(safe_header));
  if (!faithful)
    safe_header[11] = 1U;
  return cf_v3_text_pdf_pack_state(
      route, faithful, "TXTJOB02", 24U, 256U, runner,
      safe_header, material, material_size);
}

static int
cf_v3_text_pdf_pack_layout(unsigned route, int faithful,
                           cf_v3_text_pdf_runner_t runner,
                           const uint8_t *header, const uint8_t *material,
                           size_t material_size)
{
  uint8_t safe_header[CF_V3_TEXT_PDF_HEADER_SIZE];

  memcpy(safe_header, header, sizeof(safe_header));
  if (!faithful)
  {
    safe_header[6] |= 1U;
    safe_header[14] &= (uint8_t)~1U;
  }
  return cf_v3_text_pdf_pack_state(
      route, faithful, "TXTSTAT1", 16U, 4096U, runner,
      safe_header, material, material_size);
}

static int
cf_v3_text_pdf_pack_fixed(unsigned route, int faithful,
                          const char magic[8], size_t selector_size,
                          cf_v3_text_pdf_runner_t runner,
                          const uint8_t *header)
{
  uint8_t input[8U + CF_V3_TEXT_PDF_HEADER_SIZE];

  if (selector_size > CF_V3_TEXT_PDF_HEADER_SIZE)
    return 0;
  memcpy(input, magic, 8U);
  memcpy(input + 8U, header, selector_size);
  return cf_v3_text_pdf_call(route, faithful, runner, input,
                             8U + selector_size);
}

int
cf_v3_text_pdf_run(const uint8_t *header, const uint8_t *material,
                   size_t material_size)
{
  const unsigned route = cf_v3_text_pdf_route(header);
  const int faithful = cf_v3_text_pdf_faithful(header);

  switch (route)
  {
    case CF_V3_TEXT_PDF_ROUTE_JOB_PLAIN:
      return cf_v3_text_pdf_pack_job(
          route, faithful,
          faithful && !cf_v3_text_pdf_faithful_ascii_job(header) ?
              cf_v3_text_pdf_job_plain_legacy :
              cf_v3_text_pdf_job_plain_ascii_legacy,
          header, material, material_size, 0);
    case CF_V3_TEXT_PDF_ROUTE_JOB_C:
      return cf_v3_text_pdf_pack_job(
          route, faithful, cf_v3_text_pdf_job_c_legacy,
          header, material, material_size, 1);
    case CF_V3_TEXT_PDF_ROUTE_DIRECT_PLAIN:
      return cf_v3_text_pdf_pack_direct(
          route, faithful,
          faithful ? cf_v3_text_pdf_direct_plain_legacy :
                     cf_v3_text_pdf_direct_plain_ascii_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_DIRECT_C:
      return cf_v3_text_pdf_pack_direct(
          route, faithful, cf_v3_text_pdf_direct_c_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_DIRECT_SHELL:
      return cf_v3_text_pdf_pack_direct(
          route, faithful, cf_v3_text_pdf_direct_shell_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_DIRECT_PERL:
      return cf_v3_text_pdf_pack_direct(
          route, faithful, cf_v3_text_pdf_direct_perl_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_LAYOUT_UTF8:
      return cf_v3_text_pdf_pack_layout(
          route, faithful,
          faithful ? cf_v3_text_pdf_layout_utf8_legacy :
                     cf_v3_text_pdf_layout_ascii_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_LAYOUT_ASCII:
      return cf_v3_text_pdf_pack_layout(
          route, faithful, cf_v3_text_pdf_layout_ascii_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_OUTPUT_ORACLE:
      return cf_v3_text_pdf_pack_state(
          route, faithful, faithful ? "TXTPDFO1" : "TXTPDFC1",
          16U, 4096U,
          faithful ? cf_v3_text_pdf_output_oracle_legacy :
                     cf_v3_text_pdf_output_continuation_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_OUTPUT_CONTINUATION:
      return cf_v3_text_pdf_pack_state(
          route, faithful, "TXTPDFC1", 16U, 4096U,
          cf_v3_text_pdf_output_continuation_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_DIRECTION:
      return cf_v3_text_pdf_pack_fixed(
          route, faithful, "TXTDIR01", 10U,
          cf_v3_text_pdf_direction_legacy, header);
    case CF_V3_TEXT_PDF_ROUTE_DUPLEX_BOUNDARY:
      return cf_v3_text_pdf_pack_fixed(
          route, faithful, "TXTDUP01", 10U,
          faithful ? cf_v3_text_pdf_duplex_boundary_legacy :
                     cf_v3_text_pdf_duplex_continuation_legacy,
          header);
    case CF_V3_TEXT_PDF_ROUTE_DUPLEX_CONTINUATION:
      return cf_v3_text_pdf_pack_fixed(
          route, faithful, "TXTDUP01", 10U,
          cf_v3_text_pdf_duplex_continuation_legacy, header);
    case CF_V3_TEXT_PDF_ROUTE_TITLE_UTF8:
      if (faithful)
        return cf_v3_text_pdf_pack_state(
            route, faithful, "TXTTIT01", 8U, 64U,
            cf_v3_text_pdf_title_utf8_legacy,
            header, material, material_size);
      return cf_v3_text_pdf_pack_state(
          route, faithful, "TXTREL01", 7U, 256U,
          cf_v3_text_pdf_title_deep_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_TITLE_RELATION:
      return cf_v3_text_pdf_pack_state(
          route, faithful, "TXTREL01", 7U, 256U,
          faithful ? cf_v3_text_pdf_title_relation_legacy :
                     cf_v3_text_pdf_title_deep_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_TITLE_DEEP:
      return cf_v3_text_pdf_pack_state(
          route, faithful, "TXTREL01", 7U, 256U,
          cf_v3_text_pdf_title_deep_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_SHARED_OUTPUT:
      return cf_v3_text_pdf_pack_state(
          route, faithful, "TXTJOB01", 16U, 4096U,
          cf_v3_text_pdf_shared_output_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_BOUNDARY_PLAIN:
      return cf_v3_text_pdf_pack_job_state(
          route, faithful,
          faithful ? cf_v3_text_pdf_boundary_plain_legacy :
                     cf_v3_text_pdf_deep_plain_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_BOUNDARY_C:
      return cf_v3_text_pdf_pack_job_state(
          route, faithful,
          faithful ? cf_v3_text_pdf_boundary_c_legacy :
                     cf_v3_text_pdf_deep_c_legacy,
          header, material, material_size);
    case CF_V3_TEXT_PDF_ROUTE_DEEP_CONTRACT:
      return cf_v3_text_pdf_pack_job_state(
          route, faithful,
          cf_v3_text_pdf_deep_plain_legacy,
          header, material, material_size);
    default:
      return 0;
  }
}
