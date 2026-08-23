// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_RELATION_PROGRAM_H
#define CUPSFILTERS_FUZZ_V2_RELATION_PROGRAM_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum cf_v2_relation_mode_e {
  CF_V2_RELATION_DERIVED = 0,
  CF_V2_RELATION_EXPLICIT = 1,
  CF_V2_RELATION_MODE_COUNT = 2
} cf_v2_relation_mode_t;

typedef struct cf_v2_scalar_relation_s {
  cf_v2_relation_mode_t mode;
  int64_t derived_value;
  int64_t explicit_value;
} cf_v2_scalar_relation_t;

typedef struct cf_v2_length_relation_s {
  cf_v2_relation_mode_t mode;
  size_t base;
  int64_t signed_delta;
} cf_v2_length_relation_t;

typedef enum cf_v2_cardinality_class_e {
  CF_V2_CARDINALITY_ZERO = 0,
  CF_V2_CARDINALITY_ONE = 1,
  CF_V2_CARDINALITY_TWO = 2,
  CF_V2_CARDINALITY_SMALL = 3,
  CF_V2_CARDINALITY_BOUNDARY_NEIGHBOR = 4,
  CF_V2_CARDINALITY_LARGE = 5,
  CF_V2_CARDINALITY_CLASS_COUNT = 6
} cf_v2_cardinality_class_t;

typedef struct cf_v2_cardinality_relation_s {
  cf_v2_cardinality_class_t class_id;
  uint8_t parameter;
  size_t boundary;
  size_t limit;
} cf_v2_cardinality_relation_t;

typedef struct cf_v2_reference_relation_s {
  uint32_t object_id;
  uint32_t referenced_id;
} cf_v2_reference_relation_t;

typedef enum cf_v2_object_kind_e {
  CF_V2_OBJECT_NULL = 0,
  CF_V2_OBJECT_SCALAR = 1,
  CF_V2_OBJECT_DICTIONARY = 2,
  CF_V2_OBJECT_ARRAY = 3,
  CF_V2_OBJECT_STREAM = 4,
  CF_V2_OBJECT_OPAQUE = 5,
  CF_V2_OBJECT_KIND_COUNT = 6
} cf_v2_object_kind_t;

#define CF_V2_OBJECT_KIND_BIT(kind) \
  (UINT32_C(1) << (unsigned)(kind))
#define CF_V2_OBJECT_KIND_MASK_ALL \
  ((UINT32_C(1) << CF_V2_OBJECT_KIND_COUNT) - UINT32_C(1))

typedef struct cf_v2_object_relation_s {
  uint32_t object_id;
  cf_v2_object_kind_t kind;
} cf_v2_object_relation_t;

typedef enum cf_v2_action_kind_e {
  CF_V2_ACTION_PARSE = 0,
  CF_V2_ACTION_SELECT = 1,
  CF_V2_ACTION_EMIT = 2,
  CF_V2_ACTION_READ = 3,
  CF_V2_ACTION_FINISH = 4,
  CF_V2_ACTION_KIND_COUNT = 5
} cf_v2_action_kind_t;

typedef struct cf_v2_action_s {
  cf_v2_action_kind_t kind;
  uint8_t argument;
  uint8_t repetitions;
} cf_v2_action_t;

typedef struct cf_v2_action_program_s {
  const uint8_t *encoded;
  size_t encoded_size;
  size_t cursor;
} cf_v2_action_program_t;

typedef struct cf_v2_opaque_bytes_s {
  const uint8_t *data;
  size_t size;
} cf_v2_opaque_bytes_t;

typedef struct cf_v2_relation_stats_s {
  uint64_t scalar_modes[CF_V2_RELATION_MODE_COUNT];
  uint64_t length_modes[CF_V2_RELATION_MODE_COUNT];
  uint64_t cardinalities[CF_V2_CARDINALITY_CLASS_COUNT];
  uint64_t references[CF_V2_RELATION_MODE_COUNT];
  uint64_t objects[CF_V2_OBJECT_KIND_COUNT];
  uint64_t actions[CF_V2_ACTION_KIND_COUNT];
  uint64_t opaque_inputs;
  uint64_t opaque_bytes;
} cf_v2_relation_stats_t;

static inline cf_v2_relation_mode_t
cf_v2_relation_mode(uint8_t encoded)
{
  return (encoded & 1U) ? CF_V2_RELATION_EXPLICIT :
                          CF_V2_RELATION_DERIVED;
}

static inline int64_t
cf_v2_scalar_relation_value(const cf_v2_scalar_relation_t *relation)
{
  if (!relation)
    return 0;
  return relation->mode == CF_V2_RELATION_EXPLICIT ?
             relation->explicit_value : relation->derived_value;
}

static inline size_t
cf_v2_length_relation_value(const cf_v2_length_relation_t *relation)
{
  uint64_t positive;

  if (!relation || relation->mode == CF_V2_RELATION_DERIVED)
    return relation ? relation->base : 0U;
  if (relation->signed_delta < 0) {
    positive = (uint64_t)(-(relation->signed_delta + 1)) + 1U;
    return positive > relation->base ? 0U :
                                      relation->base - (size_t)positive;
  }
  positive = (uint64_t)relation->signed_delta;
  if (positive > (uint64_t)(SIZE_MAX - relation->base))
    return SIZE_MAX;
  return relation->base + (size_t)positive;
}

static inline size_t
cf_v2_cardinality_value(const cf_v2_cardinality_relation_t *relation)
{
  size_t value;
  int neighbor;

  if (!relation)
    return 0U;
  switch (relation->class_id) {
    case CF_V2_CARDINALITY_ZERO:
      value = 0U;
      break;
    case CF_V2_CARDINALITY_ONE:
      value = 1U;
      break;
    case CF_V2_CARDINALITY_TWO:
      value = 2U;
      break;
    case CF_V2_CARDINALITY_SMALL:
      value = 3U + (size_t)(relation->parameter % 13U);
      break;
    case CF_V2_CARDINALITY_BOUNDARY_NEIGHBOR:
      neighbor = (int)(relation->parameter % 3U) - 1;
      if (neighbor < 0)
        value = relation->boundary ? relation->boundary - 1U : 0U;
      else if (neighbor > 0 && relation->boundary < SIZE_MAX)
        value = relation->boundary + 1U;
      else
        value = relation->boundary;
      break;
    case CF_V2_CARDINALITY_LARGE:
      if (relation->limit <= 16U)
        value = relation->limit;
      else
        value = relation->limit -
                (size_t)(relation->parameter % (relation->limit / 4U + 1U));
      break;
    default:
      value = 0U;
      break;
  }
  if (relation->limit && value > relation->limit)
    value = relation->limit;
  return value;
}

static inline uint64_t
cf_v2_boundary_unsigned(uint8_t kind, uint8_t parameter, unsigned bits)
{
  uint64_t mask;
  uint64_t signed_max;
  unsigned exponent;
  uint64_t power;

  if (!bits || bits > 64U)
    bits = 64U;
  mask = bits == 64U ? UINT64_MAX : (UINT64_C(1) << bits) - 1U;
  signed_max = mask >> 1U;
  exponent = parameter % bits;
  power = UINT64_C(1) << exponent;
  switch (kind % 12U) {
    case 0U: return 0U;
    case 1U: return 1U;
    case 2U: return mask;
    case 3U: return mask ? mask - 1U : 0U;
    case 4U: return signed_max;
    case 5U: return signed_max ? signed_max - 1U : 0U;
    case 6U: return signed_max < mask ? signed_max + 1U : signed_max;
    case 7U: return power & mask;
    case 8U: return power ? (power - 1U) & mask : 0U;
    case 9U: return power == mask ? mask : (power + 1U) & mask;
    case 10U: return (uint64_t)(parameter % 17U);
    default: return (mask - (uint64_t)(parameter % 17U)) & mask;
  }
}

static inline uint64_t
cf_v2_boundary_bounded_unsigned(uint8_t kind, uint8_t parameter,
                                uint64_t maximum)
{
  uint64_t middle;
  uint64_t power;
  uint64_t offset;
  unsigned exponent;

  if (!maximum)
    return 0U;
  middle = maximum / 2U;
  exponent = parameter % 64U;
  power = UINT64_C(1) << exponent;
  if (power > maximum)
    power = maximum;
  offset = maximum == UINT64_MAX ?
               (uint64_t)parameter :
               (uint64_t)parameter % (maximum + 1U);
  switch (kind % 12U) {
    case 0U: return 0U;
    case 1U: return 1U;
    case 2U: return maximum;
    case 3U: return maximum - 1U;
    case 4U: return middle;
    case 5U: return middle ? middle - 1U : 0U;
    case 6U: return middle < maximum ? middle + 1U : middle;
    case 7U: return power;
    case 8U: return power ? power - 1U : 0U;
    case 9U: return power < maximum ? power + 1U : maximum;
    case 10U: return offset;
    default: return maximum - offset;
  }
}

static inline int64_t
cf_v2_boundary_signed(uint8_t kind, uint8_t parameter, unsigned bits)
{
  uint64_t encoded = cf_v2_boundary_unsigned(kind, parameter, bits);

  if (bits && bits < 64U && (encoded & (UINT64_C(1) << (bits - 1U))))
    encoded |= ~((UINT64_C(1) << bits) - 1U);
  return (int64_t)encoded;
}

static inline void
cf_v2_action_program_init(cf_v2_action_program_t *program,
                          const uint8_t *encoded, size_t encoded_size)
{
  if (!program)
    return;
  program->encoded = encoded;
  program->encoded_size = encoded_size;
  program->cursor = 0U;
}

static inline int
cf_v2_action_program_next(cf_v2_action_program_t *program,
                          cf_v2_action_t *action)
{
  const uint8_t *entry;

  if (!program || !action || !program->encoded ||
      program->cursor + 2U > program->encoded_size)
    return 0;
  entry = program->encoded + program->cursor;
  program->cursor += 2U;
  action->kind = (cf_v2_action_kind_t)(entry[0] % CF_V2_ACTION_KIND_COUNT);
  action->argument = entry[1];
  action->repetitions = (uint8_t)(1U + ((entry[0] >> 5U) & 3U));
  return 1;
}

static inline cf_v2_opaque_bytes_t
cf_v2_opaque_bytes(const uint8_t *data, size_t size)
{
  cf_v2_opaque_bytes_t opaque;

  opaque.data = data;
  opaque.size = data ? size : 0U;
  return opaque;
}

static inline void
cf_v2_relation_stats_scalar(cf_v2_relation_stats_t *stats,
                            cf_v2_relation_mode_t mode)
{
  if (stats && (unsigned)mode < CF_V2_RELATION_MODE_COUNT)
    stats->scalar_modes[mode] ++;
}

static inline void
cf_v2_relation_stats_length(cf_v2_relation_stats_t *stats,
                            cf_v2_relation_mode_t mode)
{
  if (stats && (unsigned)mode < CF_V2_RELATION_MODE_COUNT)
    stats->length_modes[mode] ++;
}

static inline void
cf_v2_relation_stats_cardinality(cf_v2_relation_stats_t *stats,
                                 cf_v2_cardinality_class_t class_id)
{
  if (stats && (unsigned)class_id < CF_V2_CARDINALITY_CLASS_COUNT)
    stats->cardinalities[class_id] ++;
}

static inline void
cf_v2_relation_stats_reference(cf_v2_relation_stats_t *stats,
                               cf_v2_relation_mode_t mode)
{
  if (stats && (unsigned)mode < CF_V2_RELATION_MODE_COUNT)
    stats->references[mode] ++;
}

static inline void
cf_v2_relation_stats_object(cf_v2_relation_stats_t *stats,
                            cf_v2_object_kind_t kind)
{
  if (stats && (unsigned)kind < CF_V2_OBJECT_KIND_COUNT)
    stats->objects[kind] ++;
}

static inline void
cf_v2_relation_stats_action(cf_v2_relation_stats_t *stats,
                            cf_v2_action_kind_t kind)
{
  if (stats && (unsigned)kind < CF_V2_ACTION_KIND_COUNT)
    stats->actions[kind] ++;
}

static inline void
cf_v2_relation_stats_opaque(cf_v2_relation_stats_t *stats, size_t size)
{
  if (!stats)
    return;
  stats->opaque_inputs ++;
  stats->opaque_bytes += size;
}

static cf_v2_relation_stats_t *cf_v2_registered_relation_stats;
static const char *cf_v2_registered_relation_target;

static void
cf_v2_relation_stats_dump_registered(void)
{
  static const char *const mode_names[] = {"derived", "explicit"};
  static const char *const cardinality_names[] = {
    "zero", "one", "two", "small", "boundary-neighbor", "large"
  };
  static const char *const action_names[] = {
    "parse", "select", "emit", "read", "finish"
  };
  static const char *const object_names[] = {
    "null", "scalar", "dictionary", "array", "stream", "opaque"
  };
  const char *path = getenv("CF_V2_RELATION_STATS_PATH");
  FILE *output;
  size_t index;

  if (!path || !*path || !cf_v2_registered_relation_stats)
    return;
  output = fopen(path, "a");
  if (!output)
    return;
  for (index = 0U; index < CF_V2_RELATION_MODE_COUNT; index ++) {
    fprintf(output, "%s\tscalar\t%s\t%" PRIu64 "\n",
            cf_v2_registered_relation_target, mode_names[index],
            cf_v2_registered_relation_stats->scalar_modes[index]);
    fprintf(output, "%s\tlength\t%s\t%" PRIu64 "\n",
            cf_v2_registered_relation_target, mode_names[index],
            cf_v2_registered_relation_stats->length_modes[index]);
  }
  for (index = 0U; index < CF_V2_CARDINALITY_CLASS_COUNT; index ++)
    fprintf(output, "%s\tcardinality\t%s\t%" PRIu64 "\n",
            cf_v2_registered_relation_target, cardinality_names[index],
            cf_v2_registered_relation_stats->cardinalities[index]);
  for (index = 0U; index < CF_V2_RELATION_MODE_COUNT; index ++)
    fprintf(output, "%s\treference\t%s\t%" PRIu64 "\n",
            cf_v2_registered_relation_target, mode_names[index],
            cf_v2_registered_relation_stats->references[index]);
  for (index = 0U; index < CF_V2_OBJECT_KIND_COUNT; index ++)
    fprintf(output, "%s\tobject\t%s\t%" PRIu64 "\n",
            cf_v2_registered_relation_target, object_names[index],
            cf_v2_registered_relation_stats->objects[index]);
  for (index = 0U; index < CF_V2_ACTION_KIND_COUNT; index ++)
    fprintf(output, "%s\taction\t%s\t%" PRIu64 "\n",
            cf_v2_registered_relation_target, action_names[index],
            cf_v2_registered_relation_stats->actions[index]);
  fprintf(output, "%s\topaque\tinputs\t%" PRIu64 "\n",
          cf_v2_registered_relation_target,
          cf_v2_registered_relation_stats->opaque_inputs);
  fprintf(output, "%s\topaque\tbytes\t%" PRIu64 "\n",
          cf_v2_registered_relation_target,
          cf_v2_registered_relation_stats->opaque_bytes);
  fclose(output);
}

static inline void
cf_v2_relation_stats_register(cf_v2_relation_stats_t *stats,
                              const char *target)
{
  if (!stats || cf_v2_registered_relation_stats)
    return;
  cf_v2_registered_relation_stats = stats;
  cf_v2_registered_relation_target = target ? target : "unknown";
  (void)atexit(cf_v2_relation_stats_dump_registered);
}

#endif
