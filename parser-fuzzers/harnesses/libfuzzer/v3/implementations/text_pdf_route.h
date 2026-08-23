// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_TEXT_PDF_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_TEXT_PDF_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_TEXT_PDF_MAGIC "TXPV3R01"
#define CF_V3_TEXT_PDF_MAGIC_SIZE 8U
#define CF_V3_TEXT_PDF_HEADER_SIZE 40U
#define CF_V3_TEXT_PDF_FIXED_SIZE \
  (CF_V3_TEXT_PDF_MAGIC_SIZE + CF_V3_TEXT_PDF_HEADER_SIZE)
#define CF_V3_TEXT_PDF_MAX_MATERIAL 8192U
#define CF_V3_TEXT_PDF_MAX_INPUT \
  (CF_V3_TEXT_PDF_FIXED_SIZE + CF_V3_TEXT_PDF_MAX_MATERIAL)
#define CF_V3_TEXT_PDF_ROUTE_OFFSET 39U
#define CF_V3_TEXT_PDF_ROUTE_MASK 0x1fU
#define CF_V3_TEXT_PDF_FLAG_FAITHFUL 0x80U
#define CF_V3_TEXT_PDF_FAITHFUL_BACKEND_OFFSET 38U
#define CF_V3_TEXT_PDF_FLAG_FAITHFUL_ASCII_JOB 0x80U

enum cf_v3_text_pdf_route_e
{
  CF_V3_TEXT_PDF_ROUTE_JOB_PLAIN = 0,
  CF_V3_TEXT_PDF_ROUTE_JOB_C,
  CF_V3_TEXT_PDF_ROUTE_DIRECT_PLAIN,
  CF_V3_TEXT_PDF_ROUTE_DIRECT_C,
  CF_V3_TEXT_PDF_ROUTE_DIRECT_SHELL,
  CF_V3_TEXT_PDF_ROUTE_DIRECT_PERL,
  CF_V3_TEXT_PDF_ROUTE_LAYOUT_UTF8,
  CF_V3_TEXT_PDF_ROUTE_LAYOUT_ASCII,
  CF_V3_TEXT_PDF_ROUTE_OUTPUT_ORACLE,
  CF_V3_TEXT_PDF_ROUTE_OUTPUT_CONTINUATION,
  CF_V3_TEXT_PDF_ROUTE_DIRECTION,
  CF_V3_TEXT_PDF_ROUTE_DUPLEX_BOUNDARY,
  CF_V3_TEXT_PDF_ROUTE_DUPLEX_CONTINUATION,
  CF_V3_TEXT_PDF_ROUTE_TITLE_UTF8,
  CF_V3_TEXT_PDF_ROUTE_TITLE_RELATION,
  CF_V3_TEXT_PDF_ROUTE_TITLE_DEEP,
  CF_V3_TEXT_PDF_ROUTE_SHARED_OUTPUT,
  CF_V3_TEXT_PDF_ROUTE_BOUNDARY_PLAIN,
  CF_V3_TEXT_PDF_ROUTE_BOUNDARY_C,
  CF_V3_TEXT_PDF_ROUTE_DEEP_CONTRACT,
  CF_V3_TEXT_PDF_ROUTE_COUNT
};

static inline int
cf_v3_text_pdf_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_TEXT_PDF_FIXED_SIZE + 1U &&
         size <= CF_V3_TEXT_PDF_MAX_INPUT &&
         !memcmp(data, CF_V3_TEXT_PDF_MAGIC, CF_V3_TEXT_PDF_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_text_pdf_header(uint8_t *data)
{
  return data + CF_V3_TEXT_PDF_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_text_pdf_const_header(const uint8_t *data)
{
  return data + CF_V3_TEXT_PDF_MAGIC_SIZE;
}

static inline unsigned
cf_v3_text_pdf_route(const uint8_t *header)
{
  return (header[CF_V3_TEXT_PDF_ROUTE_OFFSET] &
          CF_V3_TEXT_PDF_ROUTE_MASK) % CF_V3_TEXT_PDF_ROUTE_COUNT;
}

static inline int
cf_v3_text_pdf_faithful(const uint8_t *header)
{
  return (header[CF_V3_TEXT_PDF_ROUTE_OFFSET] &
          CF_V3_TEXT_PDF_FLAG_FAITHFUL) != 0U;
}

static inline int
cf_v3_text_pdf_faithful_ascii_job(const uint8_t *header)
{
  return (header[CF_V3_TEXT_PDF_FAITHFUL_BACKEND_OFFSET] &
          CF_V3_TEXT_PDF_FLAG_FAITHFUL_ASCII_JOB) != 0U;
}

static inline void
cf_v3_text_pdf_set_route(uint8_t *header, unsigned route)
{
  header[CF_V3_TEXT_PDF_ROUTE_OFFSET] =
      (uint8_t)((header[CF_V3_TEXT_PDF_ROUTE_OFFSET] &
                 CF_V3_TEXT_PDF_FLAG_FAITHFUL) |
                (route % CF_V3_TEXT_PDF_ROUTE_COUNT));
}

#endif
