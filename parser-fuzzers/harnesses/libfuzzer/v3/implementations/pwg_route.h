// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PWG_ROUTE_H
#define CUPSFILTERS_FUZZ_V3_PWG_ROUTE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PWG_MAGIC "PWGV3R01"
#define CF_V3_PWG_MAGIC_SIZE 8U
#define CF_V3_PWG_HEADER_SIZE 16U
#define CF_V3_PWG_FIXED_SIZE \
  (CF_V3_PWG_MAGIC_SIZE + CF_V3_PWG_HEADER_SIZE)
#define CF_V3_PWG_MAX_MATERIAL 4096U
#define CF_V3_PWG_MAX_INPUT \
  (CF_V3_PWG_FIXED_SIZE + CF_V3_PWG_MAX_MATERIAL)

#define CF_V3_PWG_FLAG_FAITHFUL 0x80U

enum cf_v3_pwg_route_e {
  CF_V3_PWG_ROUTE_DIRECT_PDF = 0,
  CF_V3_PWG_ROUTE_DIRECT_PCLM,
  CF_V3_PWG_ROUTE_JOB_PDF,
  CF_V3_PWG_ROUTE_JOB_PCLM,
  CF_V3_PWG_ROUTE_PDF_PAGE_WRITER,
  CF_V3_PWG_ROUTE_PCLM_STRIP_PARTITION,
  CF_V3_PWG_ROUTE_PCLM_FLATE_OBJECT,
  CF_V3_PWG_ROUTE_COUNT
};

static inline int
cf_v3_pwg_route_input(const uint8_t *data, size_t size)
{
  return data && size >= CF_V3_PWG_FIXED_SIZE + 1U &&
         size <= CF_V3_PWG_MAX_INPUT &&
         !memcmp(data, CF_V3_PWG_MAGIC, CF_V3_PWG_MAGIC_SIZE);
}

static inline uint8_t *
cf_v3_pwg_route_header(uint8_t *data)
{
  return data + CF_V3_PWG_MAGIC_SIZE;
}

static inline const uint8_t *
cf_v3_pwg_route_const_header(const uint8_t *data)
{
  return data + CF_V3_PWG_MAGIC_SIZE;
}

static inline unsigned
cf_v3_pwg_route_id(const uint8_t *header)
{
  return header[0] % CF_V3_PWG_ROUTE_COUNT;
}

static inline int
cf_v3_pwg_route_faithful(const uint8_t *header)
{
  return (header[1] & CF_V3_PWG_FLAG_FAITHFUL) != 0U;
}

static inline void
cf_v3_pwg_route_normalize_mutation(uint8_t *data, size_t size)
{
  if (cf_v3_pwg_route_input(data, size))
    cf_v3_pwg_route_header(data)[1] &=
        (uint8_t)~CF_V3_PWG_FLAG_FAITHFUL;
}

#endif
