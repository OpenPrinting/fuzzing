// SPDX-License-Identifier: Apache-2.0
#include "text_route.h"
#include "text_route_bridge.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_text_runner_t)(const uint8_t *, size_t);

extern int cf_v3_text_job_legacy(const uint8_t *, size_t);
extern int cf_v3_text_raw_legacy(const uint8_t *, size_t);
extern int cf_v3_text_layout_legacy(const uint8_t *, size_t);
extern int cf_v3_text_determinism_legacy(const uint8_t *, size_t);
extern int cf_v3_text_selection_legacy(const uint8_t *, size_t);
extern int cf_v3_text_encoding_legacy(const uint8_t *, size_t);
extern int cf_v3_text_tail_legacy(const uint8_t *, size_t);
extern int cf_v3_text_illegal_legacy(const uint8_t *, size_t);
extern int cf_v3_text_line_legacy(const uint8_t *, size_t);
extern int cf_v3_text_line_continuation_legacy(const uint8_t *, size_t);
extern int cf_v3_text_page_content_legacy(const uint8_t *, size_t);
extern int cf_v3_text_page_array_legacy(const uint8_t *, size_t);
extern int cf_v3_text_shared_contract_legacy(const uint8_t *, size_t);
extern int cf_v3_text_boundary_contract_legacy(const uint8_t *, size_t);
extern int cf_v3_text_deep_contract_legacy(const uint8_t *, size_t);

static int
cf_v3_text_call(unsigned route, int faithful, cf_v3_text_runner_t runner,
                const uint8_t *data, size_t size)
{
  int result = runner(data, size);

  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "text_to_text route=%u faithful=%d input=%zu\n",
            route, faithful, size);
  return result;
}

static int
cf_v3_text_pack_direct(unsigned route, int faithful,
                       cf_v3_text_runner_t runner, const uint8_t *header,
                       const uint8_t *material, size_t material_size)
{
  uint8_t input[CF_V3_TEXT_MAX_MATERIAL + CF_V2_CONTROL_SIZE];
  uint8_t control[CF_V2_CONTROL_SIZE];

  if (!material_size || material_size > CF_V3_TEXT_MAX_MATERIAL)
    return 0;
  memcpy(input, material, material_size);
  memcpy(control, header, sizeof(control));
  if (!faithful)
  {
    control[7] = 0U;
    control[11] = 0U;
  }
  memcpy(input + material_size, control, sizeof(control));
  return cf_v3_text_call(route, faithful, runner, input,
                         material_size + CF_V2_CONTROL_SIZE);
}

static int
cf_v3_text_pack_state(unsigned route, int faithful, const char magic[8],
                      size_t selector_size, size_t max_payload,
                      cf_v3_text_runner_t runner, const uint8_t *header,
                      const uint8_t *material, size_t material_size)
{
  uint8_t input[8U + CF_V3_TEXT_HEADER_SIZE + CF_V3_TEXT_MAX_MATERIAL];
  size_t payload_size = material_size < max_payload ? material_size : max_payload;
  size_t input_size;

  if (!payload_size || selector_size > CF_V3_TEXT_HEADER_SIZE)
    return 0;
  input_size = 8U + selector_size + payload_size;
  memcpy(input, magic, 8U);
  memcpy(input + 8U, header, selector_size);
  memcpy(input + 8U + selector_size, material, payload_size);
  return cf_v3_text_call(route, faithful, runner, input, input_size);
}

static size_t
cf_v3_text_options(char *options, size_t capacity, const uint8_t *header,
                   int faithful)
{
  static const char *const encodings[] = {
    "ASCII", "UTF-8", "ISO-8859-1", "CP1252"
  };
  static const char *const overlong[] = {
    "truncate", "word-wrap", "wrap-at-width"
  };
  static const char *const newlines[] = {"lf", "cr", "crlf"};
  unsigned width = 32U + (unsigned)(header[1] % 57U);
  unsigned height = 2U + (unsigned)(header[2] % 65U);
  unsigned left = header[3] % 17U;
  unsigned right = header[4] % 5U;
  unsigned top = header[5] % 8U;
  unsigned bottom = header[6] % 4U;
  unsigned tab = 1U + header[7] % 16U;
  unsigned copies = faithful ? 1U + header[8] % 4U : 1U;
  const char *overlong_mode = overlong[header[9] % 3U];
  int length;

  if (!faithful && !strcmp(overlong_mode, "word-wrap"))
    overlong_mode = "wrap-at-width";
  if (!faithful)
  {
    left = 0U;
    top = 0U;
  }

  length = snprintf(
      options, capacity,
      "PageWidth=%u PageHeight=%u PageLeft=%u PageRight=%u PageTop=%u "
      "PageBottom=%u OverLongLines=%s TabWidth=%u PrinterEncoding=%s "
      "Pagination=%s SendFF=%s NewlineCharacters=%s page-ranges=%s "
      "page-set=%s OutputOrder=%s Collate=%s copies=%u",
      width, height, left, right, top, bottom,
      overlong_mode, tab, encodings[header[10] % 4U],
      header[11] & 1U ? "true" : "false",
      header[12] & 1U ? "true" : "false",
      newlines[header[13] % 3U],
      header[14] % 3U == 0U ? "1-99" :
          (header[14] % 3U == 1U ? "1,3-5" : "2-4"),
      header[15] % 3U == 0U ? "all" :
          (header[15] % 3U == 1U ? "odd" : "even"),
      faithful && (header[16] & 1U) ? "reverse" : "normal",
      faithful && (header[17] & 1U) ? "true" : "false", copies);
  return length > 0 && (size_t)length < capacity ? (size_t)length : 0U;
}

static int
cf_v3_text_pack_job(unsigned route, int faithful, const uint8_t *header,
                    const uint8_t *material, size_t material_size)
{
  static const char *const titles[] = {
    "text-v3", "utf8-layout", "page-selection", "encoding-boundary"
  };
  uint8_t input[CF_V2_JOB_FIXED_SIZE + 1024U + 64U +
                CF_V3_TEXT_MAX_MATERIAL];
  char options[1024];
  const char *title = titles[header[18] %
      (sizeof(titles) / sizeof(titles[0]))];
  size_t options_size;
  size_t title_size = strlen(title);
  size_t offset;
  size_t input_size;

  if (!material_size || material_size > CF_V3_TEXT_MAX_MATERIAL ||
      !(options_size = cf_v3_text_options(options, sizeof(options), header,
                                          faithful)))
    return 0;
  input_size = CF_V2_JOB_FIXED_SIZE + options_size + title_size + material_size;
  if (input_size > sizeof(input))
    return 0;
  cf_v2_job_store_u32le(input, 0U);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)options_size);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_size);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)material_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, header, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, options, options_size);
  offset += options_size;
  memcpy(input + offset, title, title_size);
  offset += title_size;
  memcpy(input + offset, material, material_size);
  return cf_v3_text_call(route, faithful, cf_v3_text_job_legacy,
                         input, input_size);
}

int
cf_v3_text_run(const uint8_t *header, const uint8_t *material,
               size_t material_size)
{
  const unsigned route = cf_v3_text_route(header);
  const int faithful = cf_v3_text_faithful(header);

  switch (route)
  {
    case CF_V3_TEXT_ROUTE_JOB:
      return cf_v3_text_pack_job(route, faithful, header,
                                 material, material_size);
    case CF_V3_TEXT_ROUTE_RAW:
      return cf_v3_text_pack_direct(route, faithful, cf_v3_text_raw_legacy,
                                    header, material, material_size);
    case CF_V3_TEXT_ROUTE_LAYOUT:
      return cf_v3_text_pack_state(route, faithful, "TXT2TXT1", 16U, 4096U,
                                   cf_v3_text_layout_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_DETERMINISM:
      return cf_v3_text_pack_direct(route, faithful,
                                    cf_v3_text_determinism_legacy,
                                    header, material, material_size);
    case CF_V3_TEXT_ROUTE_PAGE_SELECTION:
      return cf_v3_text_pack_state(route, faithful, "TXTSEL01", 16U, 256U,
                                   cf_v3_text_selection_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_ENCODING:
      return cf_v3_text_pack_state(route, faithful, "TXTENC01", 4U, 256U,
                                   cf_v3_text_encoding_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_ENCODING_TAIL:
      return cf_v3_text_pack_state(route, faithful, "TXTTAIL1", 5U, 256U,
                                   cf_v3_text_tail_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_ILLEGAL_UTF8:
      return cf_v3_text_pack_state(route, faithful, "TXTILL01", 5U, 256U,
                                   cf_v3_text_illegal_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_LINE_LAYOUT:
      return cf_v3_text_pack_state(
          route, faithful, "TXTLAY01", 8U, 256U,
          faithful ? cf_v3_text_line_legacy :
                     cf_v3_text_line_continuation_legacy,
          header, material, material_size);
    case CF_V3_TEXT_ROUTE_LINE_CONTINUATION:
      return cf_v3_text_pack_state(route, faithful, "TXTLAY01", 8U, 256U,
                                   cf_v3_text_line_continuation_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_PAGE_CONTENT:
      return cf_v3_text_pack_state(route, faithful, "TXTORD01", 8U, 128U,
                                   cf_v3_text_page_content_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_PAGE_ARRAY:
      return cf_v3_text_pack_state(
          route, faithful, faithful ? "TXTPAGE1" : "TXTSEL01",
          16U, 256U,
          faithful ? cf_v3_text_page_array_legacy :
                     cf_v3_text_selection_legacy,
          header, material, material_size);
    case CF_V3_TEXT_ROUTE_SHARED_CONTRACT:
      return cf_v3_text_pack_state(route, faithful, "TXTJOB01", 16U, 4096U,
                                   cf_v3_text_shared_contract_legacy,
                                   header, material, material_size);
    case CF_V3_TEXT_ROUTE_BOUNDARY_CONTRACT:
      if (faithful)
        return cf_v3_text_pack_state(
            route, faithful, "TXTJOB02", 24U, 256U,
            cf_v3_text_boundary_contract_legacy,
            header, material, material_size);
      else
      {
        uint8_t safe_header[CF_V3_TEXT_HEADER_SIZE];

        memcpy(safe_header, header, sizeof(safe_header));
        /* Deep-contract documents can still exceed the selected line width.
         * Keep the known first-word under-read behind the faithful policy. */
        safe_header[11] = 0U;
        return cf_v3_text_pack_state(
            route, faithful, "TXTJOB02", 24U, 256U,
            cf_v3_text_deep_contract_legacy,
            safe_header, material, material_size);
      }
    default:
      return 0;
  }
}
