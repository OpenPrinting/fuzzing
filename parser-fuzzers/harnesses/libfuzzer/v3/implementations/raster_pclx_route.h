// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_PCLX_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_PCLX_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PCLX_JOB_MAGIC "PCLXV3J1"
#define CF_V3_PCLX_JOB_MAGIC_SIZE 8U
#define CF_V3_PCLX_JOB_HEADER_SIZE 8U
#define CF_V3_PCLX_JOB_FIXED_SIZE 16U
#define CF_V3_PCLX_JOB_MAX_MATERIAL (4U * 1024U * 1024U)
#define CF_V3_PCLX_JOB_MAX_INPUT \
  (CF_V3_PCLX_JOB_FIXED_SIZE + CF_V3_PCLX_JOB_MAX_MATERIAL)

#define CF_V3_PCLX_STATE_MAGIC "PCLXV3S1"
#define CF_V3_PCLX_STATE_MAGIC_SIZE 8U
#define CF_V3_PCLX_STATE_HEADER_SIZE 64U
#define CF_V3_PCLX_STATE_CONTROL_SIZE 1U
#define CF_V3_PCLX_STATE_FIXED_SIZE \
  (CF_V3_PCLX_STATE_MAGIC_SIZE + CF_V3_PCLX_STATE_HEADER_SIZE + \
   CF_V3_PCLX_STATE_CONTROL_SIZE)
#define CF_V3_PCLX_STATE_MAX_MATERIAL (256U * 1024U)
#define CF_V3_PCLX_STATE_MAX_INPUT \
  (CF_V3_PCLX_STATE_FIXED_SIZE + CF_V3_PCLX_STATE_MAX_MATERIAL)

#define CF_V3_PCLX_FLAG_FAITHFUL 0x80U
#define CF_V3_PCLX_JOB_ROUTE_MASK 0x03U
#define CF_V3_PCLX_STATE_ROUTE_MASK 0x1fU

enum cf_v3_pclx_job_route_e
{
  CF_V3_PCLX_JOB_VALIDATED = 0,
  CF_V3_PCLX_JOB_FRONTIER,
  CF_V3_PCLX_JOB_COUPLED_PPD,
  CF_V3_PCLX_JOB_FULL,
  CF_V3_PCLX_JOB_ROUTE_COUNT
};

enum cf_v3_pclx_state_route_e
{
  CF_V3_PCLX_STATE_COLOR_TUPLE = 0,
  CF_V3_PCLX_STATE_MODE10_TUPLE,
  CF_V3_PCLX_STATE_SEVEN_INK_CHANNELS,
  CF_V3_PCLX_STATE_ENDJOB_FORMAT,
  CF_V3_PCLX_STATE_MODE3_BOUNDARY,
  CF_V3_PCLX_STATE_MODE3_DEPTH,
  CF_V3_PCLX_STATE_MODE10_BOUNDARY,
  CF_V3_PCLX_STATE_MODE10_DEPTH,
  CF_V3_PCLX_STATE_MODE3_CODEC,
  CF_V3_PCLX_STATE_MODE10_CODEC,
  CF_V3_PCLX_STATE_PACKBITS,
  CF_V3_PCLX_STATE_RLE,
  CF_V3_PCLX_STATE_COMPACT,
  CF_V3_PCLX_STATE_SIX_PLANE_CRD,
  CF_V3_PCLX_STATE_RAW_PLANE_WRITER,
  CF_V3_PCLX_STATE_ENDJOB_ORACLE,
  CF_V3_PCLX_STATE_TWO_BIT_BOUNDARY,
  CF_V3_PCLX_STATE_TWO_BIT_DEPTH,
  CF_V3_PCLX_STATE_FILTER_DATA_BOUNDARY,
  CF_V3_PCLX_STATE_RASTER_CONTRACT,
  CF_V3_PCLX_STATE_RASTER_JOB,
  CF_V3_PCLX_STATE_RASTER_JOB_DEEP,
  CF_V3_PCLX_STATE_RASTER_LAYOUT,
  CF_V3_PCLX_STATE_FORMAT_STORAGE,
  CF_V3_PCLX_STATE_PROFILE_CARDINALITY,
  CF_V3_PCLX_STATE_STORAGE_CHANNELS,
  CF_V3_PCLX_STATE_CODEC_ROW,
  CF_V3_PCLX_STATE_ENDJOB_OPAQUE,
  CF_V3_PCLX_STATE_ROUTE_COUNT
};

static inline int
cf_v3_pclx_job_input(const uint8_t *data, size_t size)
{
  return data && size > CF_V3_PCLX_JOB_FIXED_SIZE &&
         size <= CF_V3_PCLX_JOB_MAX_INPUT &&
         !memcmp(data, CF_V3_PCLX_JOB_MAGIC, CF_V3_PCLX_JOB_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_pclx_job_header(uint8_t *data)
{
  return data + CF_V3_PCLX_JOB_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_pclx_job_const_header(const uint8_t *data)
{
  return data + CF_V3_PCLX_JOB_MAGIC_SIZE;
}

static inline unsigned
cf_v3_pclx_job_route(const uint8_t *header)
{
  return (header[7] & CF_V3_PCLX_JOB_ROUTE_MASK) %
         CF_V3_PCLX_JOB_ROUTE_COUNT;
}

static inline int
cf_v3_pclx_job_faithful(const uint8_t *header)
{
  return (header[7] & CF_V3_PCLX_FLAG_FAITHFUL) != 0U;
}

static inline int
cf_v3_pclx_state_input(const uint8_t *data, size_t size)
{
  return data && size > CF_V3_PCLX_STATE_FIXED_SIZE &&
         size <= CF_V3_PCLX_STATE_MAX_INPUT &&
         !memcmp(data, CF_V3_PCLX_STATE_MAGIC,
                 CF_V3_PCLX_STATE_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_pclx_state_header(uint8_t *data)
{
  return data + CF_V3_PCLX_STATE_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_pclx_state_const_header(const uint8_t *data)
{
  return data + CF_V3_PCLX_STATE_MAGIC_SIZE;
}

static inline uint8_t *
cf_v3_pclx_state_control(uint8_t *data)
{
  return data + CF_V3_PCLX_STATE_MAGIC_SIZE +
         CF_V3_PCLX_STATE_HEADER_SIZE;
}

static inline const uint8_t *
cf_v3_pclx_state_const_control(const uint8_t *data)
{
  return data + CF_V3_PCLX_STATE_MAGIC_SIZE +
         CF_V3_PCLX_STATE_HEADER_SIZE;
}

static inline unsigned
cf_v3_pclx_state_route(const uint8_t *control)
{
  return (control[0] & CF_V3_PCLX_STATE_ROUTE_MASK) %
         CF_V3_PCLX_STATE_ROUTE_COUNT;
}

static inline int
cf_v3_pclx_state_faithful(const uint8_t *control)
{
  return (control[0] & CF_V3_PCLX_FLAG_FAITHFUL) != 0U;
}

#endif
