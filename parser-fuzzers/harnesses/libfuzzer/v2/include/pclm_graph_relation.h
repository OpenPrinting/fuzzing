// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_PCLM_GRAPH_RELATION_H
#define CUPSFILTERS_FUZZ_V2_PCLM_GRAPH_RELATION_H

#include "relation_program.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V2_PCLM_GRAPH_MAGIC "PCLMGR01"
#define CF_V2_PCLM_GRAPH_MAGIC_SIZE 8U
#define CF_V2_PCLM_GRAPH_HEADER_SIZE 48U
#define CF_V2_PCLM_GRAPH_ACTION_OFFSET 28U
#define CF_V2_PCLM_GRAPH_ACTION_SIZE 16U
#define CF_V2_PCLM_GRAPH_MAX_MATERIAL 4096U
#define CF_V2_PCLM_GRAPH_FIRST_POOL_OBJECT 7U
#define CF_V2_PCLM_GRAPH_POOL_OBJECTS 6U
#define CF_V2_PCLM_GRAPH_OBJECT_COUNT 12U

typedef struct cf_v2_pclm_graph_relation_s {
  uint32_t width;
  uint32_t height;
  cf_v2_cardinality_relation_t xobjects;
  cf_v2_cardinality_relation_t pages;
  cf_v2_object_relation_t object;
  cf_v2_relation_mode_t reference_mode;
  cf_v2_reference_relation_t reference;
  cf_v2_scalar_relation_t rotate;
  cf_v2_length_relation_t image_bytes;
  cf_v2_scalar_relation_t encoding;
  cf_v2_scalar_relation_t close_after_read;
  cf_v2_length_relation_t opaque_length;
  cf_v2_action_program_t actions;
  cf_v2_opaque_bytes_t opaque;
  uint8_t material_phase;
} cf_v2_pclm_graph_relation_t;

static inline int16_t
cf_v2_pclm_graph_i16(const uint8_t *data)
{
  return (int16_t)((uint16_t)data[0] | (uint16_t)data[1] << 8U);
}

static inline int
cf_v2_pclm_graph_parse(const uint8_t *data, size_t size,
                       cf_v2_pclm_graph_relation_t *graph)
{
  static const int64_t rotations[] = {0, 90, 180, 270};
  const uint8_t *header;
  size_t base_image_bytes;

  if (!data || !graph ||
      size < CF_V2_PCLM_GRAPH_MAGIC_SIZE + CF_V2_PCLM_GRAPH_HEADER_SIZE + 1U ||
      size > CF_V2_PCLM_GRAPH_MAGIC_SIZE + CF_V2_PCLM_GRAPH_HEADER_SIZE +
                 CF_V2_PCLM_GRAPH_MAX_MATERIAL ||
      memcmp(data, CF_V2_PCLM_GRAPH_MAGIC,
             CF_V2_PCLM_GRAPH_MAGIC_SIZE))
    return 0;

  memset(graph, 0, sizeof(*graph));
  header = data + CF_V2_PCLM_GRAPH_MAGIC_SIZE;
  graph->width = (uint32_t)cf_v2_boundary_bounded_unsigned(
      header[0], header[1], 16U);
  graph->height = (uint32_t)cf_v2_boundary_bounded_unsigned(
      header[2], header[3], 16U);
  if (!graph->width)
    graph->width = 1U;
  if (!graph->height)
    graph->height = 1U;

  graph->xobjects.class_id =
      (cf_v2_cardinality_class_t)(header[4] %
                                  CF_V2_CARDINALITY_CLASS_COUNT);
  graph->xobjects.parameter = header[5];
  graph->xobjects.boundary = 1U;
  graph->xobjects.limit = 4U;
  graph->pages.class_id =
      (cf_v2_cardinality_class_t)(header[6] %
                                  CF_V2_CARDINALITY_CLASS_COUNT);
  graph->pages.parameter = header[7];
  graph->pages.boundary = 1U;
  graph->pages.limit = 3U;

  graph->object.object_id =
      CF_V2_PCLM_GRAPH_FIRST_POOL_OBJECT +
      header[8] % CF_V2_PCLM_GRAPH_POOL_OBJECTS;
  graph->object.kind =
      (cf_v2_object_kind_t)(header[9] % CF_V2_OBJECT_KIND_COUNT);
  graph->reference_mode = cf_v2_relation_mode(header[10]);
  graph->reference.object_id = graph->object.object_id;
  graph->reference.referenced_id =
      graph->reference_mode == CF_V2_RELATION_DERIVED ?
          graph->object.object_id :
          (uint32_t)cf_v2_boundary_bounded_unsigned(
              header[11], header[12],
              CF_V2_PCLM_GRAPH_OBJECT_COUNT + 1U);

  graph->rotate.mode = cf_v2_relation_mode(header[13]);
  graph->rotate.derived_value =
      rotations[header[14] % (sizeof(rotations) / sizeof(rotations[0]))];
  graph->rotate.explicit_value =
      cf_v2_boundary_signed(header[15], header[16], 16U);

  base_image_bytes =
      (size_t)graph->width * graph->height * 3U;
  graph->image_bytes.mode = cf_v2_relation_mode(header[17]);
  graph->image_bytes.base = base_image_bytes;
  graph->image_bytes.signed_delta = cf_v2_pclm_graph_i16(header + 18U);

  graph->encoding.mode = cf_v2_relation_mode(header[20]);
  graph->encoding.derived_value = header[21] % 2U;
  graph->encoding.explicit_value = header[22] % 3U;
  graph->close_after_read.mode = cf_v2_relation_mode(header[23]);
  graph->close_after_read.derived_value = 1;
  graph->close_after_read.explicit_value = header[24] & 1U;

  graph->opaque_length.mode = cf_v2_relation_mode(header[25]);
  graph->opaque_length.base =
      size - CF_V2_PCLM_GRAPH_MAGIC_SIZE - CF_V2_PCLM_GRAPH_HEADER_SIZE;
  graph->opaque_length.signed_delta =
      cf_v2_pclm_graph_i16(header + 26U);
  cf_v2_action_program_init(&graph->actions,
                            header + CF_V2_PCLM_GRAPH_ACTION_OFFSET,
                            CF_V2_PCLM_GRAPH_ACTION_SIZE);
  graph->material_phase = header[44];
  graph->opaque = cf_v2_opaque_bytes(
      data + CF_V2_PCLM_GRAPH_MAGIC_SIZE + CF_V2_PCLM_GRAPH_HEADER_SIZE,
      graph->opaque_length.base);
  return 1;
}

static inline void
cf_v2_pclm_graph_record(cf_v2_relation_stats_t *stats,
                        const cf_v2_pclm_graph_relation_t *graph)
{
  size_t opaque_size;

  if (!stats || !graph)
    return;
  cf_v2_relation_stats_cardinality(stats, graph->xobjects.class_id);
  cf_v2_relation_stats_cardinality(stats, graph->pages.class_id);
  cf_v2_relation_stats_object(stats, graph->object.kind);
  cf_v2_relation_stats_reference(stats, graph->reference_mode);
  cf_v2_relation_stats_scalar(stats, graph->rotate.mode);
  cf_v2_relation_stats_length(stats, graph->image_bytes.mode);
  cf_v2_relation_stats_scalar(stats, graph->encoding.mode);
  cf_v2_relation_stats_scalar(stats, graph->close_after_read.mode);
  cf_v2_relation_stats_length(stats, graph->opaque_length.mode);
  opaque_size = cf_v2_length_relation_value(&graph->opaque_length);
  if (opaque_size > graph->opaque.size)
    opaque_size = graph->opaque.size;
  cf_v2_relation_stats_opaque(stats, opaque_size);
}

#endif
