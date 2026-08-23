// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_SEQUENCE_RELATION_H
#define CUPSFILTERS_FUZZ_V2_SEQUENCE_RELATION_H

#include "relation_program.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_SEQUENCE_RELATION_MAGIC "SEQREL01"
#define CF_V2_SEQUENCE_RELATION_MAGIC_SIZE 8U
#define CF_V2_SEQUENCE_RELATION_HEADER_SIZE 32U
#define CF_V2_SEQUENCE_RELATION_ACTION_OFFSET 16U
#define CF_V2_SEQUENCE_RELATION_ACTION_BYTES 16U
#define CF_V2_SEQUENCE_RELATION_ACTION_SLOTS 8U

typedef struct cf_v2_sequence_relation_s {
  cf_v2_length_relation_t marker_length;
  cf_v2_length_relation_t prefix_length;
  cf_v2_cardinality_relation_t item_count;
  cf_v2_cardinality_relation_t selection_count;
  cf_v2_scalar_relation_t termination;
  cf_v2_scalar_relation_t framing;
  cf_v2_cardinality_relation_t action_count;
  cf_v2_action_program_t actions;
  cf_v2_opaque_bytes_t opaque;
} cf_v2_sequence_relation_t;

static inline int16_t
cf_v2_sequence_relation_i16(const uint8_t *encoded)
{
  uint16_t value = (uint16_t)encoded[0] |
                   ((uint16_t)encoded[1] << 8U);

  return (int16_t)value;
}

static inline int
cf_v2_sequence_relation_decode(const uint8_t *data, size_t size,
                               size_t marker_base, size_t prefix_base,
                               size_t item_boundary, size_t item_limit,
                               cf_v2_sequence_relation_t *sequence)
{
  const size_t fixed_size = CF_V2_SEQUENCE_RELATION_MAGIC_SIZE +
                            CF_V2_SEQUENCE_RELATION_HEADER_SIZE;
  const uint8_t *header;

  if (!data || !sequence || size < fixed_size + 1U ||
      memcmp(data, CF_V2_SEQUENCE_RELATION_MAGIC,
             CF_V2_SEQUENCE_RELATION_MAGIC_SIZE))
    return 0;

  header = data + CF_V2_SEQUENCE_RELATION_MAGIC_SIZE;
  memset(sequence, 0, sizeof(*sequence));

  sequence->marker_length.mode = cf_v2_relation_mode(header[0]);
  sequence->marker_length.base = marker_base;
  sequence->marker_length.signed_delta =
      cf_v2_sequence_relation_i16(header + 1U);

  sequence->prefix_length.mode = cf_v2_relation_mode(header[3]);
  sequence->prefix_length.base = prefix_base;
  sequence->prefix_length.signed_delta =
      cf_v2_sequence_relation_i16(header + 4U);

  sequence->item_count.class_id = (cf_v2_cardinality_class_t)(
      header[6] % CF_V2_CARDINALITY_CLASS_COUNT);
  sequence->item_count.parameter = header[7];
  sequence->item_count.boundary = item_boundary;
  sequence->item_count.limit = item_limit;

  sequence->selection_count.class_id = (cf_v2_cardinality_class_t)(
      header[8] % CF_V2_CARDINALITY_CLASS_COUNT);
  sequence->selection_count.parameter = header[9];
  sequence->selection_count.boundary = item_boundary;
  sequence->selection_count.limit = item_limit;

  sequence->termination.mode = cf_v2_relation_mode(header[10]);
  sequence->termination.derived_value = 4;
  sequence->termination.explicit_value = header[11] % 5U;

  sequence->framing.mode = cf_v2_relation_mode(header[12]);
  sequence->framing.derived_value = 1;
  sequence->framing.explicit_value = header[13] % 3U;

  sequence->action_count.class_id = (cf_v2_cardinality_class_t)(
      header[14] % CF_V2_CARDINALITY_CLASS_COUNT);
  sequence->action_count.parameter = header[15];
  sequence->action_count.boundary = CF_V2_SEQUENCE_RELATION_ACTION_SLOTS;
  sequence->action_count.limit = 64U;

  cf_v2_action_program_init(
      &sequence->actions, header + CF_V2_SEQUENCE_RELATION_ACTION_OFFSET,
      CF_V2_SEQUENCE_RELATION_ACTION_BYTES);
  sequence->opaque = cf_v2_opaque_bytes(data + fixed_size,
                                        size - fixed_size);
  return sequence->opaque.size != 0U;
}

static inline int
cf_v2_sequence_relation_next_action(cf_v2_sequence_relation_t *sequence,
                                    size_t index,
                                    cf_v2_action_t *action)
{
  if (!sequence || !action)
    return 0;
  if (index && index % CF_V2_SEQUENCE_RELATION_ACTION_SLOTS == 0U)
    sequence->actions.cursor = 0U;
  return cf_v2_action_program_next(&sequence->actions, action);
}

static inline void
cf_v2_sequence_relation_record(cf_v2_relation_stats_t *stats,
                               const cf_v2_sequence_relation_t *sequence)
{
  if (!stats || !sequence)
    return;
  cf_v2_relation_stats_length(stats, sequence->marker_length.mode);
  cf_v2_relation_stats_length(stats, sequence->prefix_length.mode);
  cf_v2_relation_stats_scalar(stats, sequence->termination.mode);
  cf_v2_relation_stats_scalar(stats, sequence->framing.mode);
  cf_v2_relation_stats_cardinality(stats, sequence->item_count.class_id);
  cf_v2_relation_stats_cardinality(stats,
                                   sequence->selection_count.class_id);
  cf_v2_relation_stats_cardinality(stats, sequence->action_count.class_id);
  cf_v2_relation_stats_opaque(stats, sequence->opaque.size);
}

#endif
