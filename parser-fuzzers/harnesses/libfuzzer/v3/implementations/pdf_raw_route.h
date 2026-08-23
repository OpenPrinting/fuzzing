// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PDF_RAW_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_PDF_RAW_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PDF_RAW_MAGIC "P2PRV301"
#define CF_V3_PDF_RAW_MAGIC_SIZE 8U
#define CF_V3_PDF_RAW_HEADER_SIZE 32U
#define CF_V3_PDF_RAW_FIXED_SIZE \
  (CF_V3_PDF_RAW_MAGIC_SIZE + CF_V3_PDF_RAW_HEADER_SIZE)
#define CF_V3_PDF_RAW_MAX_MATERIAL (4U * 1024U * 1024U)
#define CF_V3_PDF_RAW_MAX_INPUT \
  (CF_V3_PDF_RAW_FIXED_SIZE + CF_V3_PDF_RAW_MAX_MATERIAL)
#define CF_V3_PDF_RAW_ROUTE_OFFSET 31U
#define CF_V3_PDF_RAW_ROUTE_MASK 0x01U
#define CF_V3_PDF_RAW_FLAG_FAITHFUL 0x80U

enum cf_v3_pdf_raw_route_e
{
  CF_V3_PDF_RAW_ROUTE_DIRECT = 0,
  CF_V3_PDF_RAW_ROUTE_JOB,
  CF_V3_PDF_RAW_ROUTE_COUNT
};

static inline int
cf_v3_pdf_raw_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_PDF_RAW_FIXED_SIZE + 1U &&
         size <= CF_V3_PDF_RAW_MAX_INPUT &&
         !memcmp(data, CF_V3_PDF_RAW_MAGIC, CF_V3_PDF_RAW_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_pdf_raw_header(uint8_t *data)
{
  return data + CF_V3_PDF_RAW_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_pdf_raw_const_header(const uint8_t *data)
{
  return data + CF_V3_PDF_RAW_MAGIC_SIZE;
}

static inline unsigned
cf_v3_pdf_raw_route(const uint8_t *header)
{
  return header[CF_V3_PDF_RAW_ROUTE_OFFSET] & CF_V3_PDF_RAW_ROUTE_MASK;
}

static inline int
cf_v3_pdf_raw_faithful(const uint8_t *header)
{
  return (header[CF_V3_PDF_RAW_ROUTE_OFFSET] &
          CF_V3_PDF_RAW_FLAG_FAITHFUL) != 0U;
}

#endif
