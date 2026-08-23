// SPDX-License-Identifier: Apache-2.0
#include "../../v2/include/contract_schema.h"

#define CF_V3_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static const uint8_t cf_v3_command_route_magic[] = "CMDV3R01";

static const uint16_t cf_v3_command_route_cardinalities[] = {
  8U, 8U, 7U, 4U, 4U, 3U, 4U, 4U,
  2U, 8U, 8U, 2U, 4U, 5U, 4U, 256U,
  4U, 8U, 8U, 8U, 4U, 4U, 4U, 8U,
};

/* Sequence, lexical form, material, job controls, and route mode. */
static const uint8_t cf_v3_command_route_groups[] = {
  4U, 1U, 3U, 2U, 2U, 2U, 1U, 1U,
  4U, 3U, 3U, 2U, 1U, 3U, 2U, 3U,
  1U, 2U, 2U, 3U, 4U, 4U, 1U, 5U,
};

_Static_assert(CF_V3_ARRAY_SIZE(cf_v3_command_route_cardinalities) ==
                   CF_V3_ARRAY_SIZE(cf_v3_command_route_groups),
               "Command route schema arrays must match");

const cf_v2_contract_schema_t cf_v2_contract_schema = {
  cf_v3_command_route_magic,
  sizeof(cf_v3_command_route_magic) - 1U,
  cf_v3_command_route_cardinalities,
  cf_v3_command_route_groups,
  CF_V3_ARRAY_SIZE(cf_v3_command_route_cardinalities),
  1U,
};
