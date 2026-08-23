// SPDX-License-Identifier: Apache-2.0
#include "ppd_semantic_bridge.h"
#include "ppd_semantic_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_PPD_STATE_MAGIC "PPDSTAT1"
#define CF_V3_PPD_STATE_FIELDS 16U
#define CF_V3_PPD_STATE_PAYLOAD 64U
#define CF_V3_PPD_CONTRACT_MAGIC "PPDGEN01"
#define CF_V3_PPD_CONTRACT_FIELDS 32U
#define CF_V3_PPD_CONTRACT_PAYLOAD 256U

extern int cf_v3_ppd_semantic_state_legacy(const uint8_t *data, size_t size);
extern int cf_v3_ppd_contract_state_legacy(const uint8_t *data, size_t size);

/* Every selector is sourced from an existing PPDGRF01 relation byte.  The
 * profile does not synthesize a bug-specific value; it gives named PPD roles
 * to graph/cardinality/reference/action bytes that were already mutable. */
static const uint8_t cf_v3_ppd_state_sources[CF_V3_PPD_STATE_FIELDS] = {
  8U, 9U, 10U, 32U, 34U, 38U, 40U, 42U,
  59U, 45U, 16U, 48U, 63U, 11U, 18U, 50U,
};

static const uint8_t cf_v3_ppd_contract_sources[CF_V3_PPD_CONTRACT_FIELDS] = {
  8U, 0U, 32U, 38U, 44U, 9U, 5U, 36U,
  34U, 6U, 42U, 40U, 46U, 48U, 50U, 52U,
  54U, 60U, 37U, 39U, 45U, 47U, 59U, 61U,
  20U, 43U, 49U, 55U, 11U, 63U, 53U, 10U,
};

static size_t
cf_v3_ppd_copy_material(uint8_t *output, size_t capacity,
                        const uint8_t *data, size_t size)
{
  const size_t fixed = CF_V2_PPD_GRAPH_MAGIC_SIZE +
                       CF_V2_PPD_GRAPH_HEADER_SIZE;
  size_t material_size = size > fixed ? size - fixed : 0U;

  if (material_size > capacity)
    material_size = capacity;
  if (material_size)
    memcpy(output, data + fixed, material_size);
  return material_size;
}

static void
cf_v3_ppd_contract_deploy_projection(uint8_t *field)
{
  /* Keep the production wrapper on a coherent PPD while the faithful profile
   * retains missing references, malformed filters, oversized lists, and
   * custom-parameter type/cardinality boundaries. */
  field[1] = (uint8_t)(1U + field[1] % 3U);
  field[2] = field[3] = field[4] = 0U;
  field[5] = 0U;
  field[7] = (uint8_t)(1U + field[7] % 4U);
  field[8] = 0U;
  field[10] = (uint8_t)(1U + field[10] % 3U);
  field[11] = 0U;
  field[12] %= 3U;
  field[13] %= 3U;
  field[14] %= 3U;
  field[15] %= 2U;
  field[16] %= 4U;
  field[18] = (uint8_t)(1U + field[18] % 4U);
  field[19] = 0U;
  field[23] %= 4U;
  field[26] %= 7U;
  field[28] %= 2U;
  field[30] %= 4U;

  if (field[20] % 6U == 4U || field[20] % 6U == 5U) {
    field[21] = 4U;
    field[22] = 0U;
  }
}

static int
cf_v3_ppd_run_semantic_state(const uint8_t *header,
                             const uint8_t *data, size_t size)
{
  uint8_t input[sizeof(CF_V3_PPD_STATE_MAGIC) - 1U +
                CF_V3_PPD_STATE_FIELDS + CF_V3_PPD_STATE_PAYLOAD];
  size_t offset = sizeof(CF_V3_PPD_STATE_MAGIC) - 1U;
  size_t payload_size;
  size_t index;

  memcpy(input, CF_V3_PPD_STATE_MAGIC, offset);
  for (index = 0U; index < CF_V3_PPD_STATE_FIELDS; index ++)
    input[offset + index] = header[cf_v3_ppd_state_sources[index]];
  offset += CF_V3_PPD_STATE_FIELDS;
  payload_size = cf_v3_ppd_copy_material(
      input + offset, CF_V3_PPD_STATE_PAYLOAD, data, size);
  return cf_v3_ppd_semantic_state_legacy(input, offset + payload_size);
}

static int
cf_v3_ppd_run_contract_state(const uint8_t *header,
                             const uint8_t *data, size_t size,
                             int faithful)
{
  uint8_t input[sizeof(CF_V3_PPD_CONTRACT_MAGIC) - 1U +
                CF_V3_PPD_CONTRACT_FIELDS + CF_V3_PPD_CONTRACT_PAYLOAD];
  size_t offset = sizeof(CF_V3_PPD_CONTRACT_MAGIC) - 1U;
  size_t payload_size;
  size_t index;

  memcpy(input, CF_V3_PPD_CONTRACT_MAGIC, offset);
  for (index = 0U; index < CF_V3_PPD_CONTRACT_FIELDS; index ++)
    input[offset + index] = header[cf_v3_ppd_contract_sources[index]];
  if (!faithful)
    cf_v3_ppd_contract_deploy_projection(input + offset);
  offset += CF_V3_PPD_CONTRACT_FIELDS;
  payload_size = cf_v3_ppd_copy_material(
      input + offset, CF_V3_PPD_CONTRACT_PAYLOAD, data, size);
  return cf_v3_ppd_contract_state_legacy(input, offset + payload_size);
}

int
cf_v3_ppd_semantic_bridge(const uint8_t *data, size_t size)
{
  const uint8_t *header;
  uint8_t profile;
  unsigned route;
  int faithful;

  if (!cf_v3_ppd_semantic_profile_input(data, size))
    return 0;
  header = data + CF_V2_PPD_GRAPH_MAGIC_SIZE;
  profile = header[CF_V3_PPD_SEMANTIC_PROFILE_HEADER_OFFSET];
  if (!(profile & CF_V3_PPD_SEMANTIC_PROFILE_ENABLE))
    return 0;

  route = profile & CF_V3_PPD_SEMANTIC_PROFILE_ROUTE_MASK;
  faithful = (profile & CF_V3_PPD_SEMANTIC_PROFILE_FAITHFUL) != 0;
  if (getenv("CF_V3_TRACE_PPD_SEMANTIC"))
    fprintf(stderr,
            "ppd-semantic-profile: graph=1 state=%u contract=%u faithful=%d\n",
            route == 0U || route >= 2U,
            route == 1U || route >= 2U, faithful);
  if (route == 0U || route >= 2U)
    (void)cf_v3_ppd_run_semantic_state(header, data, size);
  if (route == 1U || route >= 2U)
    (void)cf_v3_ppd_run_contract_state(header, data, size, faithful);
  return 0;
}
