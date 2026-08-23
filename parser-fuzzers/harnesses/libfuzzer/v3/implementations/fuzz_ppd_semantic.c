// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * The deploy projection keeps the typed graph and action language intact while
 * bounding the five known shallow blockers.  Validators can compile the same
 * V3 entry point with CF_V3_PPD_SEMANTIC_FAITHFUL to restore those relations.
 */
#ifndef CF_V3_PPD_SEMANTIC_FAITHFUL
#define CF_V2_PPD_GRAPH_DEEP
#define CF_V2_PPD_GRAPH_UNIQUE_REFERENCES 1
#endif

#include "../../v2/implementations/fuzz_ppd_graph_action.c"

#include "ppd_semantic_bridge.h"
#include "ppd_semantic_profile.h"
#include "ppd_record_contract.h"

#include <stdlib.h>
#include <string.h>

extern int __real_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
__wrap_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed = CF_V2_PPD_GRAPH_MAGIC_SIZE +
                       CF_V2_PPD_GRAPH_HEADER_SIZE;
  const unsigned int generated_singletons =
      CF_V3_PPD_SINGLETON_LANGUAGE_ENCODING |
      CF_V3_PPD_SINGLETON_NICKNAME;
  const uint8_t *active_data = data;
  size_t active_size = size;
  uint8_t *normalized = NULL;
  int faithful = 0;
  int result;

  if (cf_v3_ppd_semantic_profile_input(data, size))
    faithful = (data[CF_V3_PPD_SEMANTIC_PROFILE_OFFSET] &
                CF_V3_PPD_SEMANTIC_PROFILE_FAITHFUL) != 0U;

#ifndef CF_V3_PPD_SEMANTIC_FAITHFUL
  if (!faithful && size > fixed &&
      cf_v3_ppd_records_need_projection(
          data + fixed, size - fixed, generated_singletons))
  {
    size_t material_size;

    normalized = (uint8_t *)malloc(size);
    if (!normalized)
      return 0;
    memcpy(normalized, data, fixed);
    material_size = cf_v3_ppd_copy_deploy_records(
        normalized + fixed, data + fixed, size - fixed,
        generated_singletons);
    active_data = normalized;
    active_size = fixed + material_size;
  }
#endif

  result = __real_LLVMFuzzerTestOneInput(active_data, active_size);

  if (!result)
    result = cf_v3_ppd_semantic_bridge(active_data, active_size);
  free(normalized);
  if (result)
    return result;
  return 0;
}
