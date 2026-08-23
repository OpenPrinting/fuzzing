// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_PPD_GRAPH_RELATION_H
#define CUPSFILTERS_FUZZ_V2_PPD_GRAPH_RELATION_H

#include "relation_program.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_PPD_GRAPH_MAGIC "PPDGRF01"
#define CF_V2_PPD_GRAPH_MAGIC_SIZE 8U
#define CF_V2_PPD_GRAPH_HEADER_SIZE 64U
#define CF_V2_PPD_GRAPH_NODE_COUNT 4U
#define CF_V2_PPD_GRAPH_NODE_SIZE 6U
#define CF_V2_PPD_GRAPH_ACTION_BYTES 16U

typedef struct cf_v2_ppd_graph_node_s {
  cf_v2_object_relation_t object;
  cf_v2_reference_relation_t reference;
  cf_v2_relation_mode_t reference_mode;
  cf_v2_cardinality_relation_t cardinality;
} cf_v2_ppd_graph_node_t;

typedef struct cf_v2_ppd_graph_relation_s {
  cf_v2_cardinality_relation_t object_count;
  cf_v2_scalar_relation_t foomatic;
  cf_v2_scalar_relation_t numeric_exponent;
  cf_v2_length_relation_t filter_length;
  cf_v2_cardinality_relation_t action_count;
  cf_v2_action_program_t actions;
  cf_v2_ppd_graph_node_t nodes[CF_V2_PPD_GRAPH_NODE_COUNT];
  cf_v2_length_relation_t opaque_length;
  uint8_t custom_type;
  uint8_t option_type;
  uint8_t numeric_kind;
  cf_v2_relation_mode_t opaque_mode;
  cf_v2_opaque_bytes_t opaque;
} cf_v2_ppd_graph_relation_t;

static inline int16_t
cf_v2_ppd_graph_i16(const uint8_t *data)
{
  uint16_t encoded = (uint16_t)data[0] | (uint16_t)data[1] << 8U;

  return (int16_t)encoded;
}

static inline int
cf_v2_ppd_graph_parse(const uint8_t *data, size_t size,
                      cf_v2_ppd_graph_relation_t *graph)
{
  const uint8_t *header;
  size_t index;

  if (!data || !graph ||
      size < CF_V2_PPD_GRAPH_MAGIC_SIZE + CF_V2_PPD_GRAPH_HEADER_SIZE + 1U ||
      memcmp(data, CF_V2_PPD_GRAPH_MAGIC, CF_V2_PPD_GRAPH_MAGIC_SIZE))
    return 0;
  memset(graph, 0, sizeof(*graph));
  header = data + CF_V2_PPD_GRAPH_MAGIC_SIZE;

  graph->object_count.class_id =
      (cf_v2_cardinality_class_t)(header[0] % CF_V2_CARDINALITY_CLASS_COUNT);
  graph->object_count.parameter = header[1];
  graph->object_count.boundary = CF_V2_PPD_GRAPH_NODE_COUNT;
  graph->object_count.limit = CF_V2_PPD_GRAPH_NODE_COUNT;

  graph->foomatic.mode = cf_v2_relation_mode(header[2]);
  graph->foomatic.derived_value = 0;
  graph->foomatic.explicit_value = header[3] & 1U;
  graph->numeric_exponent.mode = cf_v2_relation_mode(header[4]);
  graph->numeric_exponent.derived_value = 3;
  graph->numeric_exponent.explicit_value =
      (int64_t)cf_v2_boundary_bounded_unsigned(header[5], header[6], 38U);

  graph->filter_length.mode = cf_v2_relation_mode(header[11]);
  graph->filter_length.base = 10U;
  graph->filter_length.signed_delta = cf_v2_ppd_graph_i16(header + 12U);

  graph->action_count.class_id =
      (cf_v2_cardinality_class_t)(header[14] % CF_V2_CARDINALITY_CLASS_COUNT);
  graph->action_count.parameter = header[15];
  graph->action_count.boundary = CF_V2_PPD_GRAPH_ACTION_BYTES / 2U;
  graph->action_count.limit = CF_V2_PPD_GRAPH_ACTION_BYTES / 2U;
  cf_v2_action_program_init(&graph->actions, header + 16U,
                            CF_V2_PPD_GRAPH_ACTION_BYTES);

  for (index = 0U; index < CF_V2_PPD_GRAPH_NODE_COUNT; index ++) {
    const uint8_t *node = header + 32U + index * CF_V2_PPD_GRAPH_NODE_SIZE;
    cf_v2_ppd_graph_node_t *output = graph->nodes + index;

    output->object.object_id = node[0];
    output->object.kind =
        (cf_v2_object_kind_t)(node[1] % CF_V2_OBJECT_KIND_COUNT);
    output->reference.object_id = node[0];
    output->reference.referenced_id = node[2];
    output->reference_mode = cf_v2_relation_mode(node[3]);
    output->cardinality.class_id =
        (cf_v2_cardinality_class_t)(node[4] %
                                    CF_V2_CARDINALITY_CLASS_COUNT);
    output->cardinality.parameter = node[5];
    output->cardinality.boundary = 20U;
    output->cardinality.limit = 32U;
  }

  graph->opaque_length.mode = cf_v2_relation_mode(header[56]);
  graph->opaque_length.base = size - CF_V2_PPD_GRAPH_MAGIC_SIZE -
                              CF_V2_PPD_GRAPH_HEADER_SIZE;
  graph->opaque_length.signed_delta = cf_v2_ppd_graph_i16(header + 57U);
  graph->custom_type = header[59];
  graph->option_type = header[60];
  graph->numeric_kind = header[61] ^ header[62];
  graph->opaque_mode = cf_v2_relation_mode(header[63]);
  graph->opaque = cf_v2_opaque_bytes(
      data + CF_V2_PPD_GRAPH_MAGIC_SIZE + CF_V2_PPD_GRAPH_HEADER_SIZE,
      size - CF_V2_PPD_GRAPH_MAGIC_SIZE - CF_V2_PPD_GRAPH_HEADER_SIZE);
  return 1;
}

static inline void
cf_v2_ppd_graph_record(cf_v2_relation_stats_t *stats,
                       const cf_v2_ppd_graph_relation_t *graph)
{
  if (!stats || !graph)
    return;
  cf_v2_relation_stats_cardinality(stats, graph->object_count.class_id);
  cf_v2_relation_stats_scalar(stats, graph->foomatic.mode);
  cf_v2_relation_stats_scalar(stats, graph->numeric_exponent.mode);
  cf_v2_relation_stats_length(stats, graph->filter_length.mode);
  cf_v2_relation_stats_cardinality(stats, graph->action_count.class_id);
  cf_v2_relation_stats_length(stats, graph->opaque_length.mode);
  cf_v2_relation_stats_scalar(stats, graph->opaque_mode);
  cf_v2_relation_stats_opaque(stats, graph->opaque.size);
}

#endif
