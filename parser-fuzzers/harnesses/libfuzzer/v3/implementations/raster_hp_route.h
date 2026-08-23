// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_HP_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_HP_ROUTE_H

#include "../../v2/include/arithmetic_layout.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_RASTER_HP_FLAG_FAITHFUL 0x80U
#define CF_V3_RASTER_HP_ROUTE_MASK 0x0fU
#define CF_V3_RASTER_HP_ROUTE_OFFSET \
  (CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE + 79U)
#define CF_V3_RASTER_HP_FIXED_SIZE \
  (CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE + \
   CF_V2_ARITHMETIC_LAYOUT_HEADER_SIZE)
#define CF_V3_RASTER_HP_MAX_MATERIAL 4096U
#define CF_V3_RASTER_HP_MAX_INPUT \
  (CF_V3_RASTER_HP_FIXED_SIZE + CF_V3_RASTER_HP_MAX_MATERIAL)

enum cf_v3_raster_hp_route_e
{
  CF_V3_RASTER_HP_ROUTE_JOB = 0,
  CF_V3_RASTER_HP_ROUTE_CODEC,
  CF_V3_RASTER_HP_ROUTE_ROW,
  CF_V3_RASTER_HP_ROUTE_PAGE,
  CF_V3_RASTER_HP_ROUTE_TUMBLE,
  CF_V3_RASTER_HP_ROUTE_PLANAR,
  CF_V3_RASTER_HP_ROUTE_LAYOUT,
  CF_V3_RASTER_HP_ROUTE_ONE_BIT,
  CF_V3_RASTER_HP_ROUTE_COUNT
};

static inline int
cf_v3_raster_hp_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_RASTER_HP_FIXED_SIZE + 1U &&
         size <= CF_V3_RASTER_HP_MAX_INPUT &&
         !memcmp(data, CF_V2_ARITHMETIC_LAYOUT_MAGIC,
                 CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_raster_hp_header(uint8_t *data)
{
  return data + CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_raster_hp_const_header(const uint8_t *data)
{
  return data + CF_V2_ARITHMETIC_LAYOUT_MAGIC_SIZE;
}

static inline unsigned
cf_v3_raster_hp_route(const uint8_t *header)
{
  return (header[79] & CF_V3_RASTER_HP_ROUTE_MASK) %
         CF_V3_RASTER_HP_ROUTE_COUNT;
}

static inline int
cf_v3_raster_hp_faithful(const uint8_t *header)
{
  return (header[79] & CF_V3_RASTER_HP_FLAG_FAITHFUL) != 0U;
}

static inline void
cf_v3_raster_hp_set_route(uint8_t *header, unsigned route)
{
  header[79] = (uint8_t)((header[79] & CF_V3_RASTER_HP_FLAG_FAITHFUL) |
                         (route % CF_V3_RASTER_HP_ROUTE_COUNT));
}

static inline void
cf_v3_raster_hp_normalize_mutation(uint8_t *data, size_t size)
{
  uint8_t *header;

  if (!cf_v3_raster_hp_input(data, size))
    return;
  header = cf_v3_raster_hp_header(data);
  header[79] = (uint8_t)cf_v3_raster_hp_route(header);
}

#endif
