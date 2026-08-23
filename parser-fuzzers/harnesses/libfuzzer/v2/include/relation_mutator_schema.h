// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_RELATION_MUTATOR_SCHEMA_H
#define CUPSFILTERS_FUZZ_V2_RELATION_MUTATOR_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

typedef enum cf_v2_relation_field_kind_e {
  CF_V2_RELATION_FIELD_ENUM = 0,
  CF_V2_RELATION_FIELD_SIGNED_DELTA = 1,
  CF_V2_RELATION_FIELD_UNSIGNED_BOUNDARY = 2,
  CF_V2_RELATION_FIELD_RAW = 3
} cf_v2_relation_field_kind_t;

typedef struct cf_v2_relation_field_schema_s {
  uint16_t offset;
  uint8_t width;
  cf_v2_relation_field_kind_t kind;
  uint16_t cardinality;
  uint8_t group;
} cf_v2_relation_field_schema_t;

typedef struct cf_v2_relation_mutator_schema_s {
  const uint8_t *magic;
  size_t magic_size;
  size_t header_size;
  size_t min_payload;
  const cf_v2_relation_field_schema_t *fields;
  size_t field_count;
} cf_v2_relation_mutator_schema_t;

extern const cf_v2_relation_mutator_schema_t cf_v2_relation_mutator_schema;

#endif
