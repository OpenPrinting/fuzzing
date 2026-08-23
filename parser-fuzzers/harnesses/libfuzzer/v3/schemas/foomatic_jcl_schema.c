// SPDX-License-Identifier: Apache-2.0
#include "../../v2/include/contract_schema.h"

#define CF_V3_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static const uint8_t cf_v3_foomatic_jcl_magic[] = "JCLV3R01";

static const uint16_t cf_v3_foomatic_jcl_cardinalities[] = {
  3U, 8U, 8U, 8U, 8U, 3U, 2U, 4U,
  16U, 8U, 4U, 4U, 4U, 64U, 8U, 8U,
  8U, 8U, 8U, 8U, 8U, 8U, 8U, 8U,
};

static const uint8_t cf_v3_foomatic_jcl_groups[] = {
  1U, 2U, 3U, 2U, 4U, 4U, 2U, 3U,
  3U, 2U, 4U, 4U, 5U, 5U, 5U, 5U,
  5U, 5U, 5U, 5U, 5U, 5U, 5U, 5U,
};

_Static_assert(CF_V3_ARRAY_SIZE(cf_v3_foomatic_jcl_cardinalities) ==
                   CF_V3_ARRAY_SIZE(cf_v3_foomatic_jcl_groups),
               "Foomatic JCL schema arrays must match");

const cf_v2_contract_schema_t cf_v2_contract_schema = {
  cf_v3_foomatic_jcl_magic,
  sizeof(cf_v3_foomatic_jcl_magic) - 1U,
  cf_v3_foomatic_jcl_cardinalities,
  cf_v3_foomatic_jcl_groups,
  CF_V3_ARRAY_SIZE(cf_v3_foomatic_jcl_cardinalities),
  1U,
};
