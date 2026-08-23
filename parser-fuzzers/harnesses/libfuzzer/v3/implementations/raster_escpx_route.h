// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_RASTER_ESCPX_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_RASTER_ESCPX_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_ESCPX_JOB_MAGIC "ESCPV3J1"
#define CF_V3_ESCPX_JOB_MAGIC_SIZE 8U
#define CF_V3_ESCPX_JOB_HEADER_SIZE 8U
#define CF_V3_ESCPX_JOB_FIXED_SIZE 16U
#define CF_V3_ESCPX_JOB_MAX_MATERIAL (4U * 1024U * 1024U)
#define CF_V3_ESCPX_JOB_MAX_INPUT \
  (CF_V3_ESCPX_JOB_FIXED_SIZE + CF_V3_ESCPX_JOB_MAX_MATERIAL)

#define CF_V3_ESCPX_STATE_MAGIC "ESCPV3S1"
#define CF_V3_ESCPX_STATE_MAGIC_SIZE 8U
#define CF_V3_ESCPX_STATE_HEADER_SIZE 64U
#define CF_V3_ESCPX_STATE_CONTROL_SIZE 1U
#define CF_V3_ESCPX_STATE_FIXED_SIZE \
  (CF_V3_ESCPX_STATE_MAGIC_SIZE + CF_V3_ESCPX_STATE_HEADER_SIZE + \
   CF_V3_ESCPX_STATE_CONTROL_SIZE)
#define CF_V3_ESCPX_STATE_MAX_MATERIAL (256U * 1024U)
#define CF_V3_ESCPX_STATE_MAX_INPUT \
  (CF_V3_ESCPX_STATE_FIXED_SIZE + CF_V3_ESCPX_STATE_MAX_MATERIAL)

#define CF_V3_ESCPX_FLAG_FAITHFUL 0x80U
#define CF_V3_ESCPX_JOB_ROUTE_MASK 0x03U
#define CF_V3_ESCPX_STATE_ROUTE_MASK 0x1fU

enum cf_v3_escpx_job_route_e
{
  CF_V3_ESCPX_JOB_VALIDATED = 0,
  CF_V3_ESCPX_JOB_FRONTIER,
  CF_V3_ESCPX_JOB_COUPLED_PPD,
  CF_V3_ESCPX_JOB_FULL,
  CF_V3_ESCPX_JOB_ROUTE_COUNT
};

enum cf_v3_escpx_state_route_e
{
  CF_V3_ESCPX_STATE_RESOLUTION_GROWTH = 0,
  CF_V3_ESCPX_STATE_ZERO_VERTICAL_RESOLUTION,
  CF_V3_ESCPX_STATE_SOFTWEAVE_PRODUCT,
  CF_V3_ESCPX_STATE_SINGLE_PAGE_SIZE,
  CF_V3_ESCPX_STATE_BAND_QUEUE,
  CF_V3_ESCPX_STATE_PACKBITS_CODEC,
  CF_V3_ESCPX_STATE_OUTPUT_BAND,
  CF_V3_ESCPX_STATE_COMPACT,
  CF_V3_ESCPX_STATE_WEAVE_PIPELINE,
  CF_V3_ESCPX_STATE_PAGE_LIFECYCLE,
  CF_V3_ESCPX_STATE_STAGGERED_HEAD,
  CF_V3_ESCPX_STATE_PPD_LUT,
  CF_V3_ESCPX_STATE_BLACK_CONTINUATION,
  CF_V3_ESCPX_STATE_BLACK_BOUNDARY,
  CF_V3_ESCPX_STATE_PAGE_SETUP,
  CF_V3_ESCPX_STATE_HORIZONTAL_RESOLUTION,
  CF_V3_ESCPX_STATE_VERTICAL_RESOLUTION,
  CF_V3_ESCPX_STATE_PAGE_CARDINALITY,
  CF_V3_ESCPX_STATE_WEAVE_LAYOUT,
  CF_V3_ESCPX_STATE_RASTER_CONTRACT,
  CF_V3_ESCPX_STATE_RASTER_JOB,
  CF_V3_ESCPX_STATE_RASTER_JOB_DEEP,
  CF_V3_ESCPX_STATE_RASTER_LAYOUT,
  CF_V3_ESCPX_STATE_ROUTE_COUNT
};

static inline int
cf_v3_escpx_job_input(const uint8_t *data, size_t size)
{
  return data && size > CF_V3_ESCPX_JOB_FIXED_SIZE &&
         size <= CF_V3_ESCPX_JOB_MAX_INPUT &&
         !memcmp(data, CF_V3_ESCPX_JOB_MAGIC, CF_V3_ESCPX_JOB_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_escpx_job_header(uint8_t *data)
{
  return data + CF_V3_ESCPX_JOB_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_escpx_job_const_header(const uint8_t *data)
{
  return data + CF_V3_ESCPX_JOB_MAGIC_SIZE;
}

static inline unsigned
cf_v3_escpx_job_route(const uint8_t *header)
{
  return (header[7] & CF_V3_ESCPX_JOB_ROUTE_MASK) %
         CF_V3_ESCPX_JOB_ROUTE_COUNT;
}

static inline int
cf_v3_escpx_job_faithful(const uint8_t *header)
{
  return (header[7] & CF_V3_ESCPX_FLAG_FAITHFUL) != 0U;
}

static inline int
cf_v3_escpx_state_input(const uint8_t *data, size_t size)
{
  return data && size > CF_V3_ESCPX_STATE_FIXED_SIZE &&
         size <= CF_V3_ESCPX_STATE_MAX_INPUT &&
         !memcmp(data, CF_V3_ESCPX_STATE_MAGIC,
                 CF_V3_ESCPX_STATE_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_escpx_state_header(uint8_t *data)
{
  return data + CF_V3_ESCPX_STATE_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_escpx_state_const_header(const uint8_t *data)
{
  return data + CF_V3_ESCPX_STATE_MAGIC_SIZE;
}

static inline uint8_t *
cf_v3_escpx_state_control(uint8_t *data)
{
  return data + CF_V3_ESCPX_STATE_MAGIC_SIZE +
         CF_V3_ESCPX_STATE_HEADER_SIZE;
}

static inline const uint8_t *
cf_v3_escpx_state_const_control(const uint8_t *data)
{
  return data + CF_V3_ESCPX_STATE_MAGIC_SIZE +
         CF_V3_ESCPX_STATE_HEADER_SIZE;
}

static inline unsigned
cf_v3_escpx_state_route(const uint8_t *control)
{
  return (control[0] & CF_V3_ESCPX_STATE_ROUTE_MASK) %
         CF_V3_ESCPX_STATE_ROUTE_COUNT;
}

static inline int
cf_v3_escpx_state_faithful(const uint8_t *control)
{
  return (control[0] & CF_V3_ESCPX_FLAG_FAITHFUL) != 0U;
}

#endif
