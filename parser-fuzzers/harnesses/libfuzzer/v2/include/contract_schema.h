// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_CONTRACT_SCHEMA_H
#define CUPSFILTERS_FUZZ_V2_CONTRACT_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

typedef struct cf_v2_contract_schema_s {
  const uint8_t *magic;
  size_t magic_size;
  /* One byte per selector permits cardinalities from 1 through 256. */
  const uint16_t *cardinalities;
  const uint8_t *groups;
  size_t field_count;
  size_t min_payload;
} cf_v2_contract_schema_t;

/* Each schema source linked into a contract target defines this symbol. */
extern const cf_v2_contract_schema_t cf_v2_contract_schema;

#endif
