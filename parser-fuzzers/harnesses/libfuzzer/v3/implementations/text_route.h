// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_TEXT_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_TEXT_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_TEXT_MAGIC "TXTV3R01"
#define CF_V3_TEXT_MAGIC_SIZE 8U
#define CF_V3_TEXT_HEADER_SIZE 32U
#define CF_V3_TEXT_FIXED_SIZE \
  (CF_V3_TEXT_MAGIC_SIZE + CF_V3_TEXT_HEADER_SIZE)
#define CF_V3_TEXT_MAX_MATERIAL 4096U
#define CF_V3_TEXT_MAX_INPUT \
  (CF_V3_TEXT_FIXED_SIZE + CF_V3_TEXT_MAX_MATERIAL)
#define CF_V3_TEXT_ROUTE_OFFSET 31U
#define CF_V3_TEXT_ROUTE_MASK 0x0fU
#define CF_V3_TEXT_FLAG_FAITHFUL 0x80U

enum cf_v3_text_route_e
{
  CF_V3_TEXT_ROUTE_JOB = 0,
  CF_V3_TEXT_ROUTE_RAW,
  CF_V3_TEXT_ROUTE_LAYOUT,
  CF_V3_TEXT_ROUTE_DETERMINISM,
  CF_V3_TEXT_ROUTE_PAGE_SELECTION,
  CF_V3_TEXT_ROUTE_ENCODING,
  CF_V3_TEXT_ROUTE_ENCODING_TAIL,
  CF_V3_TEXT_ROUTE_ILLEGAL_UTF8,
  CF_V3_TEXT_ROUTE_LINE_LAYOUT,
  CF_V3_TEXT_ROUTE_LINE_CONTINUATION,
  CF_V3_TEXT_ROUTE_PAGE_CONTENT,
  CF_V3_TEXT_ROUTE_PAGE_ARRAY,
  CF_V3_TEXT_ROUTE_SHARED_CONTRACT,
  CF_V3_TEXT_ROUTE_BOUNDARY_CONTRACT,
  CF_V3_TEXT_ROUTE_COUNT
};

static inline int
cf_v3_text_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_TEXT_FIXED_SIZE + 1U &&
         size <= CF_V3_TEXT_MAX_INPUT &&
         !memcmp(data, CF_V3_TEXT_MAGIC, CF_V3_TEXT_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_text_header(uint8_t *data)
{
  return data + CF_V3_TEXT_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_text_const_header(const uint8_t *data)
{
  return data + CF_V3_TEXT_MAGIC_SIZE;
}

static inline unsigned
cf_v3_text_route(const uint8_t *header)
{
  return (header[CF_V3_TEXT_ROUTE_OFFSET] & CF_V3_TEXT_ROUTE_MASK) %
         CF_V3_TEXT_ROUTE_COUNT;
}

static inline int
cf_v3_text_faithful(const uint8_t *header)
{
  return (header[CF_V3_TEXT_ROUTE_OFFSET] &
          CF_V3_TEXT_FLAG_FAITHFUL) != 0U;
}

static inline void
cf_v3_text_set_route(uint8_t *header, unsigned route)
{
  header[CF_V3_TEXT_ROUTE_OFFSET] =
      (uint8_t)((header[CF_V3_TEXT_ROUTE_OFFSET] &
                 CF_V3_TEXT_FLAG_FAITHFUL) |
                (route % CF_V3_TEXT_ROUTE_COUNT));
}

#endif
