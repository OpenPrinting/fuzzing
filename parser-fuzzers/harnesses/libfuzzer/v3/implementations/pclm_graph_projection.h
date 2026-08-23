// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PCLM_GRAPH_PROJECTION_H
#define CUPSFILTERS_FUZZ_V3_PCLM_GRAPH_PROJECTION_H

#include "../../v2/include/pclm_graph_relation.h"

#include <stddef.h>
#include <stdint.h>

#define CF_V3_PCLM_GRAPH_FAITHFUL_OFFSET \
  (CF_V2_PCLM_GRAPH_MAGIC_SIZE + 47U)
#define CF_V3_PCLM_GRAPH_LAST_ACTION_OFFSET \
  (CF_V2_PCLM_GRAPH_ACTION_OFFSET + CF_V2_PCLM_GRAPH_ACTION_SIZE - 2U)

/* Keep the deploy lane beyond the known malformed-image blockers while the
 * high-bit route remains an exact held-out projection of the source behavior. */
static inline void
cf_v3_pclm_graph_deploy_repair(uint8_t *data, size_t size)
{
  cf_v2_pclm_graph_relation_t graph;
  uint8_t *header;

  if (!data || size <= CF_V3_PCLM_GRAPH_FAITHFUL_OFFSET ||
      !cf_v2_pclm_graph_parse(data, size, &graph))
    return;

  header = data + CF_V2_PCLM_GRAPH_MAGIC_SIZE;
  data[CF_V3_PCLM_GRAPH_FAITHFUL_OFFSET] &= 0x7fU;

  /* Keep both top-level cardinalities non-zero.  Action repetitions can still
   * select one through four pages/XObjects, but a deploy graph must always
   * exercise a real page and image route. */
  if (header[4] % CF_V2_CARDINALITY_CLASS_COUNT ==
      CF_V2_CARDINALITY_ZERO)
    header[4] = CF_V2_CARDINALITY_ONE;
  if (header[6] % CF_V2_CARDINALITY_CLASS_COUNT ==
      CF_V2_CARDINALITY_ZERO)
    header[6] = CF_V2_CARDINALITY_ONE;

  /* Pool object 12 is opaque by default even when another object is selected.
   * Make it the selected stream so every emitted top-level value has normal
   * PDF ownership.  Explicit references can still select the stream,
   * dictionary, array, scalar, and null pool objects. */
  header[8] = CF_V2_PCLM_GRAPH_POOL_OBJECTS - 1U;
  header[9] = CF_V2_OBJECT_STREAM;
  header[10] &= 0xfeU;

  /* A deep image state starts with a supported rotation, exact decoded byte
   * count, and a valid Flate stream.  Flate keeps arbitrary decoded pixels out
   * of PDF's lexical startxref search.  Raw/explicit mismatches remain in the
   * faithful boundary projection and in the separate raw target. */
  header[13] &= 0xfeU;
  header[17] &= 0xfeU;
  header[20] &= 0xfeU;
  header[21] = 1U;
  header[23] &= 0xfeU;

  /* Current pclmtoraster drains and closes image streams itself.  READ keeps
   * the historical wrapper from closing after the first chunk; the V3 native
   * lifecycle compile mode enforces that ownership for every route.  Earlier
   * actions remain freely reorderable. */
  header[CF_V3_PCLM_GRAPH_LAST_ACTION_OFFSET] = CF_V2_ACTION_READ;

  /* Bit 6 enables output-state exploration.  Deploy combinations retain
   * RGB/Device3 at 8/16 bpc and all three output orders; the faithful high-bit
   * projection owns Device2/4/6/15 and packed 1/2/4-bpc boundaries. */
  if (header[47] & 0x40U) {
    header[45] = (uint8_t)((header[45] & 1U) ? 2U : 0U);
    header[46] = (uint8_t)(3U + (header[46] & 1U));
  }
}

#endif
