// SPDX-License-Identifier: Apache-2.0
#include "raster_pclx_route.h"
#include "raster_pclx_state_bridge.h"
#include "raster_pclx_state_lifecycle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_pclx_state_runner_t)(const uint8_t *, size_t);

extern int cf_v3_pclx_state_r0_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r1_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r2_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r3_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r4_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r6_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r8_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r9_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r10_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r11_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r12_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r13_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r14_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r15_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r16_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r17_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r18_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r19_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r20_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r21_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r22_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r23_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r24_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r25_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r26_entry(const uint8_t *, size_t);
extern int cf_v3_pclx_state_r27_entry(const uint8_t *, size_t);

extern unsigned char
    cf_v3_pclx_state_r13_harness_cf_v2_pclx6_environment_installed;
extern unsigned char
    cf_v3_pclx_state_r14_harness_cf_v2_pclxraw_environment_installed;
extern unsigned char
    cf_v3_pclx_state_r15_harness_cf_v2_pclxend_environment_installed;
extern unsigned char
    cf_v3_pclx_state_r16_harness_cf_v2_pclx2_environment_installed;
extern unsigned char
    cf_v3_pclx_state_r17_harness_cf_v2_pclx2_environment_installed;

static const char *const cf_v3_pclx_state_magics[] = {
  "RSTRPCL1", "RSTRPCL1", "RSTRPCL1", "RSTRPCL1",
  NULL, "PCLXCMP1", NULL, "PCLXCMP1",
  "PCLXCMP1", "PCLXCMP1", NULL, NULL,
  "PKRAST1\n", "PCLX6PG1", "PCLXRAW1", "PCLXEND1",
  "PCLX2BP1", "PCLX2BP1", "PKRAST1\n", "RSTRGEN1",
  "RSTRJOB1", "RSTRJOB1", "RSTRJOB1", "RSTRJOB1",
  "RSTRJOB1", "RSTRJOB1", "RSTRJOB1", "RSTRJOB1",
};

static const uint8_t cf_v3_pclx_state_selector_sizes[] = {
  8U, 8U, 8U, 8U, 0U, 12U, 0U, 12U,
  12U, 12U, 0U, 0U, 4U, 8U, 12U, 7U,
  12U, 12U, 4U, 32U, 64U, 64U, 64U, 64U,
  64U, 64U, 64U, 64U,
};

static cf_v3_pclx_state_runner_t const cf_v3_pclx_state_runners[] = {
  cf_v3_pclx_state_r0_entry,
  cf_v3_pclx_state_r1_entry,
  cf_v3_pclx_state_r2_entry,
  cf_v3_pclx_state_r3_entry,
  cf_v3_pclx_state_r4_entry,
  cf_v3_pclx_state_r4_entry,
  cf_v3_pclx_state_r6_entry,
  cf_v3_pclx_state_r6_entry,
  cf_v3_pclx_state_r8_entry,
  cf_v3_pclx_state_r9_entry,
  cf_v3_pclx_state_r10_entry,
  cf_v3_pclx_state_r11_entry,
  cf_v3_pclx_state_r12_entry,
  cf_v3_pclx_state_r13_entry,
  cf_v3_pclx_state_r14_entry,
  cf_v3_pclx_state_r15_entry,
  cf_v3_pclx_state_r16_entry,
  cf_v3_pclx_state_r17_entry,
  cf_v3_pclx_state_r18_entry,
  cf_v3_pclx_state_r19_entry,
  cf_v3_pclx_state_r20_entry,
  cf_v3_pclx_state_r21_entry,
  cf_v3_pclx_state_r22_entry,
  cf_v3_pclx_state_r23_entry,
  cf_v3_pclx_state_r24_entry,
  cf_v3_pclx_state_r25_entry,
  cf_v3_pclx_state_r26_entry,
  cf_v3_pclx_state_r27_entry,
};

static void
cf_v3_pclx_state_reset_private_environment(void)
{
  cf_v3_pclx_state_r13_harness_cf_v2_pclx6_environment_installed = 0;
  cf_v3_pclx_state_r14_harness_cf_v2_pclxraw_environment_installed = 0;
  cf_v3_pclx_state_r15_harness_cf_v2_pclxend_environment_installed = 0;
  cf_v3_pclx_state_r16_harness_cf_v2_pclx2_environment_installed = 0;
  cf_v3_pclx_state_r17_harness_cf_v2_pclx2_environment_installed = 0;
}

static void
cf_v3_pclx_state_safe_raster_job(uint8_t *header)
{
  static const uint8_t derived_offsets[] = {
    8U, 11U, 14U, 17U, 20U, 22U, 25U, 28U,
    31U, 34U, 37U, 40U, 43U, 50U, 53U, 62U,
  };
  size_t index;

  for (index = 0U; index < sizeof(derived_offsets); index ++)
    header[derived_offsets[index]] = 0U;
  header[4] = 2U;
  header[5] = 3U;
  header[6] = 0U;
  header[7] = 0U;
  header[46] = 2U;
  header[47] = 0U;
  header[48] = 1U;
  header[49] = 0U;
  header[56] = 1U;
  header[57] = 0U;
  header[58] = 0U;
  header[59] = 0U;
}

static void
cf_v3_pclx_state_safe_generic_contract(uint8_t *header)
{
  header[2] = 2U;
  header[3] = 0U;
  header[4] = 3U;
  header[5] = 0U;
  header[6] %= 3U;
  header[7] = 0U;
  header[8] = 0U;
  header[10] = 0U;
  header[11] = 2U;
  header[12] = 0U;
  header[13] = 3U;
  header[14] = 0U;
  header[15] = 4U;
  header[16] = 4U;
  header[17] = 1U;
  header[18] = 1U;
  header[19] = 1U;
  header[20] = 1U;
  header[21] = 1U;
  header[25] = 6U;
  header[26] = 7U;
}

static void
cf_v3_pclx_state_safe_route(unsigned route, uint8_t *header)
{
  if (route <= CF_V3_PCLX_STATE_ENDJOB_FORMAT)
  {
    header[4] %= 2U;
    return;
  }
  if (route == CF_V3_PCLX_STATE_RASTER_CONTRACT)
    cf_v3_pclx_state_safe_generic_contract(header);
  else if (route == CF_V3_PCLX_STATE_RASTER_JOB)
    cf_v3_pclx_state_safe_raster_job(header);
  else if (route == CF_V3_PCLX_STATE_RASTER_LAYOUT)
  {
    if (header[6] % 3U == 2U)
      header[6] = 1U;
  }
  else if (route == CF_V3_PCLX_STATE_FORMAT_STORAGE)
  {
    static const uint8_t consumer_space_indexes[] = {0U, 1U, 2U, 4U};

    header[4] = consumer_space_indexes[
        header[4] % sizeof(consumer_space_indexes)];
    header[5] = 3U;
    header[6] = 0U;
    header[7] = 0U;
    header[8] = 0U;
    header[11] = 0U;
    header[14] = 0U;
    header[20] = 0U;
    header[22] = 0U;
    header[25] = 0U;
  }
  else if (route == CF_V3_PCLX_STATE_PROFILE_CARDINALITY &&
           (header[22] & 1U))
  {
    header[23] = 10U;
    header[24] %= 6U;
  }
  else if (route == CF_V3_PCLX_STATE_STORAGE_CHANNELS)
    header[8] = 0U;
  else if (route == CF_V3_PCLX_STATE_CODEC_ROW)
    header[7] %= 3U;
}

static int
cf_v3_pclx_state_raw_route(unsigned route)
{
  return route == CF_V3_PCLX_STATE_MODE3_BOUNDARY ||
         route == CF_V3_PCLX_STATE_MODE10_BOUNDARY ||
         route == CF_V3_PCLX_STATE_PACKBITS ||
         route == CF_V3_PCLX_STATE_RLE;
}

static int
cf_v3_pclx_state_pack(unsigned route, const uint8_t *header,
                      const uint8_t *material, size_t material_size)
{
  cf_v3_pclx_state_runner_t runner = cf_v3_pclx_state_runners[route];
  unsigned packed_route = route;
  size_t selector_size;
  size_t input_size;
  uint8_t *input;
  size_t index;
  int result;

  if (route == CF_V3_PCLX_STATE_MODE3_BOUNDARY ||
      route == CF_V3_PCLX_STATE_MODE3_DEPTH)
  {
    packed_route = CF_V3_PCLX_STATE_MODE3_CODEC;
    runner = cf_v3_pclx_state_r8_entry;
  }
  else if (route == CF_V3_PCLX_STATE_MODE10_BOUNDARY ||
           route == CF_V3_PCLX_STATE_MODE10_DEPTH)
  {
    packed_route = CF_V3_PCLX_STATE_MODE10_CODEC;
    runner = cf_v3_pclx_state_r9_entry;
  }
  else if (route == CF_V3_PCLX_STATE_TWO_BIT_BOUNDARY)
  {
    packed_route = CF_V3_PCLX_STATE_TWO_BIT_DEPTH;
    runner = cf_v3_pclx_state_r17_entry;
  }
  else if (route == CF_V3_PCLX_STATE_FILTER_DATA_BOUNDARY)
  {
    packed_route = CF_V3_PCLX_STATE_COMPACT;
    runner = cf_v3_pclx_state_r12_entry;
  }
  else if (cf_v3_pclx_state_raw_route(route))
  {
    cf_v3_pclx_state_reset_private_environment();
    cf_v3_pclx_state_lifecycle_begin(0);
    result = runner(material, material_size);
    cf_v3_pclx_state_lifecycle_end();
    return result;
  }

  selector_size = cf_v3_pclx_state_selector_sizes[packed_route];
  input_size = 8U + selector_size + material_size;
  if (packed_route == CF_V3_PCLX_STATE_ENDJOB_ORACLE)
    input_size = 8U + selector_size;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  memcpy(input, cf_v3_pclx_state_magics[packed_route], 8U);
  memcpy(input + 8U, header, selector_size);
  if (input_size > 8U + selector_size)
    memcpy(input + 8U + selector_size, material, material_size);

  cf_v3_pclx_state_safe_route(route, input + 8U);
  if (route == CF_V3_PCLX_STATE_ENDJOB_OPAQUE)
    for (index = 8U + selector_size; index < input_size; index ++)
      if (input[index] == (uint8_t)'%')
        input[index] = (uint8_t)'?';

  cf_v3_pclx_state_reset_private_environment();
  cf_v3_pclx_state_lifecycle_begin(0);
  result = runner(input, input_size);
  cf_v3_pclx_state_lifecycle_end();
  free(input);
  return result;
}

int
cf_v3_pclx_state_run(const uint8_t *header, const uint8_t *control,
                     const uint8_t *material, size_t material_size)
{
  const unsigned route = cf_v3_pclx_state_route(control);
  const int faithful = cf_v3_pclx_state_faithful(control);
  int result;

  if (faithful)
  {
    cf_v3_pclx_state_reset_private_environment();
    cf_v3_pclx_state_lifecycle_begin(1);
    result = cf_v3_pclx_state_runners[route](material, material_size);
    cf_v3_pclx_state_lifecycle_end();
  }
  else
    result = cf_v3_pclx_state_pack(route, header, material, material_size);
  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "raster_to_pclx_state route=%u faithful=%d input=%zu\n",
            route, faithful, material_size);
  return result;
}
