// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_PWG_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_PWG_ROUTE_H

#include "../../v2/include/arithmetic_layout.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_RASTER_PWG_FLAG_FAITHFUL 0x80U
#define CF_V3_RASTER_PWG_ROUTE_MASK 0x1fU
#define CF_V3_RASTER_PWG_ROUTE_OFFSET \
  (CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE + 79U)
#define CF_V3_RASTER_PWG_FIXED_SIZE \
  (CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE + \
   CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE)
#define CF_V3_RASTER_PWG_MAX_INPUT \
  (CF_V3_RASTER_PWG_FIXED_SIZE + 4096U)

enum cf_v3_raster_pwg_route_e
{
  CF_V3_RASTER_PWG_ROUTE_DIRECT_PWG = 0,
  CF_V3_RASTER_PWG_ROUTE_DIRECT_APPLE,
  CF_V3_RASTER_PWG_ROUTE_DIRECT_PCLM,
  CF_V3_RASTER_PWG_ROUTE_STATE_PWG,
  CF_V3_RASTER_PWG_ROUTE_STATE_APPLE,
  CF_V3_RASTER_PWG_ROUTE_STATE_PCLM,
  CF_V3_RASTER_PWG_ROUTE_ORACLE_PWG,
  CF_V3_RASTER_PWG_ROUTE_ORACLE_APPLE,
  CF_V3_RASTER_PWG_ROUTE_BACKSIDE_PWG,
  CF_V3_RASTER_PWG_ROUTE_BACKSIDE_APPLE,
  CF_V3_RASTER_PWG_ROUTE_BACKSIDE_NATIVE_BOUNDARY,
  CF_V3_RASTER_PWG_ROUTE_BACKSIDE_MANUAL_BOUNDARY,
  CF_V3_RASTER_PWG_ROUTE_METADATA,
  CF_V3_RASTER_PWG_ROUTE_PAGE_NAME,
  CF_V3_RASTER_PWG_ROUTE_PACKED_PIXEL,
  CF_V3_RASTER_PWG_ROUTE_COUNT
};

static inline int
cf_v3_raster_pwg_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_RASTER_PWG_FIXED_SIZE + 1U &&
         size <= CF_V3_RASTER_PWG_MAX_INPUT &&
         !memcmp(data, CF_V2_ARITHMETIC_LAYOUT_MAGIC,
                 CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_raster_pwg_header(uint8_t *data)
{
  return data + CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_raster_pwg_const_header(const uint8_t *data)
{
  return data + CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE;
}

static inline unsigned
cf_v3_raster_pwg_route(const uint8_t *header)
{
  return (header[79] & CF_V3_RASTER_PWG_ROUTE_MASK) %
         CF_V3_RASTER_PWG_ROUTE_COUNT;
}

static inline int
cf_v3_raster_pwg_faithful(const uint8_t *header)
{
  return (header[79] & CF_V3_RASTER_PWG_FLAG_FAITHFUL) != 0U;
}

static inline void
cf_v3_raster_pwg_set_route(uint8_t *header, unsigned route)
{
  header[79] = (uint8_t)((header[79] & CF_V3_RASTER_PWG_FLAG_FAITHFUL) |
                         (route % CF_V3_RASTER_PWG_ROUTE_COUNT));
}

static inline void
cf_v3_raster_pwg_normalize_mutation(uint8_t *data, size_t size)
{
  uint8_t *header;

  if (!cf_v3_raster_pwg_input(data, size))
    return;
  header = cf_v3_raster_pwg_header(data);
  header[79] = (uint8_t)cf_v3_raster_pwg_route(header);
}

#endif
