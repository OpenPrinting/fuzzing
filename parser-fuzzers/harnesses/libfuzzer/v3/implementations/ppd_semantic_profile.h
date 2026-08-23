// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PPD_SEMANTIC_PROFILE_H
#define CUPSFILTERS_FUZZ_V3_PPD_SEMANTIC_PROFILE_H

#include "../../v2/include/ppd_graph_relation.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CF_V3_PPD_SEMANTIC_PROFILE_HEADER_OFFSET 7U
#define CF_V3_PPD_SEMANTIC_PROFILE_OFFSET \
  (CF_V2_PPD_GRAPH_MAGIC_SIZE + CF_V3_PPD_SEMANTIC_PROFILE_HEADER_OFFSET)
#define CF_V3_PPD_SEMANTIC_PROFILE_ENABLE 0x40U
#define CF_V3_PPD_SEMANTIC_PROFILE_FAITHFUL 0x80U
#define CF_V3_PPD_SEMANTIC_PROFILE_ROUTE_MASK 0x03U

static inline int
cf_v3_ppd_semantic_profile_input(const uint8_t *data, size_t size)
{
  return data && size > CF_V3_PPD_SEMANTIC_PROFILE_OFFSET &&
         size >= CF_V2_PPD_GRAPH_MAGIC_SIZE +
                     CF_V2_PPD_GRAPH_HEADER_SIZE + 1U &&
         !memcmp(data, CF_V2_PPD_GRAPH_MAGIC,
                 CF_V2_PPD_GRAPH_MAGIC_SIZE);
}

static inline void
cf_v3_ppd_semantic_mutation_normalize(uint8_t *data, size_t size)
{
  if (cf_v3_ppd_semantic_profile_input(data, size))
    data[CF_V3_PPD_SEMANTIC_PROFILE_OFFSET] &=
        (uint8_t)~CF_V3_PPD_SEMANTIC_PROFILE_FAITHFUL;
}

#endif
