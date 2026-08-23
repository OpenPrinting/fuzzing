// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PS_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_PS_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PS_MAGIC "PSV3R001"
#define CF_V3_PS_MAGIC_SIZE 8U
#define CF_V3_PS_HEADER_SIZE 40U
#define CF_V3_PS_FIXED_SIZE (CF_V3_PS_MAGIC_SIZE + CF_V3_PS_HEADER_SIZE)
#define CF_V3_PS_MAX_MATERIAL (4U * 1024U * 1024U)
#define CF_V3_PS_MAX_INPUT (CF_V3_PS_FIXED_SIZE + CF_V3_PS_MAX_MATERIAL)
#define CF_V3_PS_ROUTE_OFFSET 39U
#define CF_V3_PS_ROUTE_MASK 0x07U
#define CF_V3_PS_FLAG_FAITHFUL 0x80U

enum cf_v3_ps_route_e
{
  CF_V3_PS_ROUTE_JOB = 0,
  CF_V3_PS_ROUTE_RAW,
  CF_V3_PS_ROUTE_DSC,
  CF_V3_PS_ROUTE_PAGE_RANGE_EOF,
  CF_V3_PS_ROUTE_SEQUENCE,
  CF_V3_PS_ROUTE_SEQUENCE_DEEP,
  CF_V3_PS_ROUTE_COUNT
};

static inline int
cf_v3_ps_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_PS_FIXED_SIZE + 1U &&
         size <= CF_V3_PS_MAX_INPUT &&
         !memcmp(data, CF_V3_PS_MAGIC, CF_V3_PS_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_ps_header(uint8_t *data)
{
  return data + CF_V3_PS_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_ps_const_header(const uint8_t *data)
{
  return data + CF_V3_PS_MAGIC_SIZE;
}

static inline unsigned
cf_v3_ps_route(const uint8_t *header)
{
  return (header[CF_V3_PS_ROUTE_OFFSET] & CF_V3_PS_ROUTE_MASK) %
         CF_V3_PS_ROUTE_COUNT;
}

static inline int
cf_v3_ps_faithful(const uint8_t *header)
{
  return (header[CF_V3_PS_ROUTE_OFFSET] & CF_V3_PS_FLAG_FAITHFUL) != 0U;
}

static inline void
cf_v3_ps_set_route(uint8_t *header, unsigned route)
{
  header[CF_V3_PS_ROUTE_OFFSET] =
      (uint8_t)((header[CF_V3_PS_ROUTE_OFFSET] & CF_V3_PS_FLAG_FAITHFUL) |
                (route % CF_V3_PS_ROUTE_COUNT));
}

#endif
