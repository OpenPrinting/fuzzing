// SPDX-License-Identifier: Apache-2.0
#include "raster_escpx_route.h"
#include "raster_escpx_state_bridge.h"
#include "relation_program.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_escpx_state_runner_t)(const uint8_t *, size_t);

extern int cf_v3_escpx_state_r0_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r1_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r2_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r3_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r4_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r5_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r6_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r7_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r8_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r9_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r10_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r11_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r12_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r13_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r14_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r15_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r16_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r17_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r18_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r19_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r20_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r21_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_r22_entry(const uint8_t *, size_t);
extern int cf_v3_escpx_state_safe_contract_entry(const uint8_t *, size_t);
extern unsigned char
    cf_v3_escpx_state_r10_harness_cf_v2_environment_installed;
extern unsigned char
    cf_v3_escpx_state_r11_harness_cf_v2_escpx_lut_environment_installed;
extern unsigned char
    cf_v3_escpx_state_r12_harness_cf_v2_escpx_lut_environment_installed;
extern unsigned char
    cf_v3_escpx_state_r13_harness_cf_v2_escpx_lut_environment_installed;

static const char *const cf_v3_escpx_state_magics[] = {
  "RSTRESC1", "RSTRESC1", "RSTRESC1", "RSTRESC1",
  "ESCPWEV1", "ESCPPCK1", "ESCPOU1\0", "PKRAST1\n",
  "ESCPROW1", "ESCPPAG1", "ESCPSTG1", "ESCPLUT1",
  "ESCPBLK1", "ESCPBLD1", "RSTRJOB1", "RSTRJOB1",
  "RSTRJOB1", "RSTRJOB1", "RSTRJOB1", "RSTRGEN1",
  "RSTRJOB1", "RSTRJOB1", "RSTRJOB1",
};

static const uint8_t cf_v3_escpx_state_selector_sizes[] = {
  8U, 8U, 8U, 8U, 8U, 12U, 16U, 4U, 8U, 12U, 12U, 8U,
  8U, 8U, 64U, 64U, 64U, 64U, 64U, 64U, 64U, 64U, 64U,
};

static cf_v3_escpx_state_runner_t const cf_v3_escpx_state_runners[] = {
  cf_v3_escpx_state_r0_entry,
  cf_v3_escpx_state_r1_entry,
  cf_v3_escpx_state_r2_entry,
  cf_v3_escpx_state_r3_entry,
  cf_v3_escpx_state_r4_entry,
  cf_v3_escpx_state_r5_entry,
  cf_v3_escpx_state_r6_entry,
  cf_v3_escpx_state_r7_entry,
  cf_v3_escpx_state_r8_entry,
  cf_v3_escpx_state_r9_entry,
  cf_v3_escpx_state_r10_entry,
  cf_v3_escpx_state_r11_entry,
  cf_v3_escpx_state_r12_entry,
  cf_v3_escpx_state_r13_entry,
  cf_v3_escpx_state_r14_entry,
  cf_v3_escpx_state_r15_entry,
  cf_v3_escpx_state_r16_entry,
  cf_v3_escpx_state_r17_entry,
  cf_v3_escpx_state_r18_entry,
  cf_v3_escpx_state_r19_entry,
  cf_v3_escpx_state_r20_entry,
  cf_v3_escpx_state_r21_entry,
  cf_v3_escpx_state_r22_entry,
};

static void
cf_v3_escpx_state_reset_private_environment(void)
{
  cf_v3_escpx_state_r10_harness_cf_v2_environment_installed = 0;
  cf_v3_escpx_state_r11_harness_cf_v2_escpx_lut_environment_installed = 0;
  cf_v3_escpx_state_r12_harness_cf_v2_escpx_lut_environment_installed = 0;
  cf_v3_escpx_state_r13_harness_cf_v2_escpx_lut_environment_installed = 0;
}

static void
cf_v3_escpx_state_safe_raster_job(uint8_t *header)
{
  static const uint8_t derived_offsets[] = {
    8U, 11U, 14U, 17U, 20U, 22U, 25U, 28U,
    31U, 34U, 37U, 40U, 43U, 50U, 53U, 62U,
  };
  size_t index;

  for (index = 0U; index < sizeof(derived_offsets); index ++)
    header[derived_offsets[index]] = 0U;

  /* Keep the unguarded lifecycle route internally coherent. */
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
cf_v3_escpx_state_safe_resolution(uint8_t *header, size_t mode_offset)
{
  if (header[mode_offset] & 1U)
  {
    header[mode_offset + 1U] = 7U;
    header[mode_offset + 2U] %= 14U;
  }
}

static void
cf_v3_escpx_state_require_two_page_sizes(uint8_t *header)
{
  unsigned class_id = header[46] % 6U;

  if (class_id < 2U || (class_id == 4U && header[47] % 3U == 0U))
  {
    header[46] = 2U;
    header[47] = 0U;
  }
}

static unsigned
cf_v3_escpx_state_step(const uint8_t *header, size_t mode_offset)
{
  if (!(header[mode_offset] & 1U))
    return 1U;
  return (unsigned)cf_v2_boundary_bounded_unsigned(
      header[mode_offset + 1U], header[mode_offset + 2U], 128U);
}

static void
cf_v3_escpx_state_safe_softweave(uint8_t *header)
{
  unsigned row_step = cf_v3_escpx_state_step(header, 40U);
  unsigned column_step = cf_v3_escpx_state_step(header, 43U);

  if (!row_step)
  {
    header[40] = 0U;
    row_step = 1U;
  }
  if (!column_step)
  {
    header[43] = 0U;
    column_step = 1U;
  }
  if ((uint64_t)row_step * column_step > 128U)
  {
    if (row_step >= column_step)
      header[40] = 0U;
    else
      header[43] = 0U;
  }
}

static void
cf_v3_escpx_state_safe_page_setup(unsigned route, uint8_t *header)
{
  cf_v3_escpx_state_safe_softweave(header);

  if (route == CF_V3_ESCPX_STATE_PAGE_SETUP)
  {
    header[28] = 0U;
    header[31] = 0U;
  }
  else if (route == CF_V3_ESCPX_STATE_HORIZONTAL_RESOLUTION)
  {
    cf_v3_escpx_state_safe_resolution(header, 28U);
    cf_v3_escpx_state_safe_resolution(header, 31U);
  }
  else if (route == CF_V3_ESCPX_STATE_VERTICAL_RESOLUTION)
    cf_v3_escpx_state_safe_resolution(header, 31U);

  if (route == CF_V3_ESCPX_STATE_PAGE_SETUP ||
      route == CF_V3_ESCPX_STATE_PAGE_CARDINALITY)
    cf_v3_escpx_state_require_two_page_sizes(header);
  else if (route == CF_V3_ESCPX_STATE_HORIZONTAL_RESOLUTION ||
           route == CF_V3_ESCPX_STATE_VERTICAL_RESOLUTION)
    header[46] = 2U;
}

static void
cf_v3_escpx_state_safe_generic_contract(uint8_t *header)
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
cf_v3_escpx_state_safe_layout(uint8_t *header)
{
  /* ProcessLine consumes rows as packed pixels regardless of cupsColorOrder.
   * Planar and banded storage remain faithful regression states. */
  header[6] = 0U;
}

static int
cf_v3_escpx_state_pack(unsigned route, const uint8_t *header,
                       const uint8_t *material, size_t material_size)
{
  const size_t selector_size = cf_v3_escpx_state_selector_sizes[route];
  size_t input_size = 8U + selector_size + material_size;
  uint8_t *input = (uint8_t *)malloc(input_size);
  cf_v3_escpx_state_runner_t runner = cf_v3_escpx_state_runners[route];
  int result;

  if (!input)
    return 0;
  memcpy(input, cf_v3_escpx_state_magics[route], 8U);
  memcpy(input + 8U, header, selector_size);
  memcpy(input + 8U + selector_size, material, material_size);

  if (route <= CF_V3_ESCPX_STATE_SINGLE_PAGE_SIZE)
    input[12] %= 2U;
  if (route == CF_V3_ESCPX_STATE_BLACK_BOUNDARY)
  {
    memcpy(input, "ESCPBLK1", 8U);
    runner = cf_v3_escpx_state_r12_entry;
  }
  if (route == CF_V3_ESCPX_STATE_RASTER_CONTRACT)
    cf_v3_escpx_state_safe_generic_contract(input + 8U);
  else if (route >= CF_V3_ESCPX_STATE_PAGE_SETUP &&
           route <= CF_V3_ESCPX_STATE_WEAVE_LAYOUT)
    cf_v3_escpx_state_safe_page_setup(route, input + 8U);
  else if (route == CF_V3_ESCPX_STATE_RASTER_JOB)
    cf_v3_escpx_state_safe_raster_job(input + 8U);
  else if (route == CF_V3_ESCPX_STATE_RASTER_LAYOUT)
    cf_v3_escpx_state_safe_layout(input + 8U);
  if (route == CF_V3_ESCPX_STATE_RASTER_CONTRACT)
    runner = cf_v3_escpx_state_safe_contract_entry;

  cf_v3_escpx_state_reset_private_environment();
  result = runner(input, input_size);
  free(input);
  return result;
}

int
cf_v3_escpx_state_run(const uint8_t *header, const uint8_t *control,
                      const uint8_t *material, size_t material_size)
{
  const unsigned route = cf_v3_escpx_state_route(control);
  const int faithful = cf_v3_escpx_state_faithful(control);
  int result;

  if (faithful)
  {
    cf_v3_escpx_state_reset_private_environment();
    result = cf_v3_escpx_state_runners[route](material, material_size);
  }
  else
    result = cf_v3_escpx_state_pack(route, header, material, material_size);
  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "raster_to_escpx_state route=%u faithful=%d input=%zu\n",
            route, faithful, material_size);
  return result;
}
