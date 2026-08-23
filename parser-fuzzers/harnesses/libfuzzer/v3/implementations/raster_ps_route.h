// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_PS_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_PS_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_RASTER_PS_MAGIC "RPSV3R01"
#define CF_V3_RASTER_PS_MAGIC_SIZE 8U
#define CF_V3_RASTER_PS_HEADER_SIZE 32U
#define CF_V3_RASTER_PS_FIXED_SIZE \
  (CF_V3_RASTER_PS_MAGIC_SIZE + CF_V3_RASTER_PS_HEADER_SIZE)
#define CF_V3_RASTER_PS_MAX_MATERIAL (2U * 1024U * 1024U)
#define CF_V3_RASTER_PS_MAX_INPUT \
  (CF_V3_RASTER_PS_FIXED_SIZE + CF_V3_RASTER_PS_MAX_MATERIAL)
#define CF_V3_RASTER_PS_FLAG_FAITHFUL 0x80U
#define CF_V3_RASTER_PS_ROUTE_MASK 0x0fU

enum cf_v3_raster_ps_route_e
{
  CF_V3_RASTER_PS_ROUTE_RAW_FRONTIER = 0,
  CF_V3_RASTER_PS_ROUTE_RAW_VALIDATED,
  CF_V3_RASTER_PS_ROUTE_JOB,
  CF_V3_RASTER_PS_ROUTE_GENERATED,
  CF_V3_RASTER_PS_ROUTE_LIFECYCLE,
  CF_V3_RASTER_PS_ROUTE_WRITE_ERROR,
  CF_V3_RASTER_PS_ROUTE_TRUNCATION_ORACLE,
  CF_V3_RASTER_PS_ROUTE_OUTPUT_ORACLE,
  CF_V3_RASTER_PS_ROUTE_COUNT
};

static inline int
cf_v3_raster_ps_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_RASTER_PS_FIXED_SIZE + 1U &&
         size <= CF_V3_RASTER_PS_MAX_INPUT &&
         !memcmp(data, CF_V3_RASTER_PS_MAGIC,
                 CF_V3_RASTER_PS_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_raster_ps_header(uint8_t *data)
{
  return data + CF_V3_RASTER_PS_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_raster_ps_const_header(const uint8_t *data)
{
  return data + CF_V3_RASTER_PS_MAGIC_SIZE;
}

static inline unsigned
cf_v3_raster_ps_route(const uint8_t *header)
{
  return (header[0] & CF_V3_RASTER_PS_ROUTE_MASK) %
         CF_V3_RASTER_PS_ROUTE_COUNT;
}

static inline int
cf_v3_raster_ps_faithful(const uint8_t *header)
{
  return (header[0] & CF_V3_RASTER_PS_FLAG_FAITHFUL) != 0U;
}

static inline void
cf_v3_raster_ps_normalize_mutation(uint8_t *data, size_t size)
{
  uint8_t *header;

  if (!cf_v3_raster_ps_input(data, size))
    return;
  header = cf_v3_raster_ps_header(data);
  header[0] = (uint8_t)cf_v3_raster_ps_route(header);
}

#endif
