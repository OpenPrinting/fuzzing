// SPDX-License-Identifier: Apache-2.0
/* Reuse PCLMGR01 while keeping the deploy projection inside PDF's XObject
 * contract.  The held-out high bit bypasses only this current-PDFio blocker. */
#define LLVMFuzzerTestOneInput cf_v3_pclm_graph_inner
#include "../../v2/boundaries/fuzz_pclm_graph_program.c"
#undef LLVMFuzzerTestOneInput

#include "pclm_graph_projection.h"
#include "pclm_output_adapter.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t safe[CF_V2_PCLM_GRAPH_MAGIC_SIZE +
               CF_V2_PCLM_GRAPH_HEADER_SIZE +
               CF_V2_PCLM_GRAPH_MAX_MATERIAL];
  if (!data || size > sizeof(safe) ||
      size <= CF_V3_PCLM_GRAPH_FAITHFUL_OFFSET) {
    return 0;
  }
  if (data[CF_V3_PCLM_GRAPH_FAITHFUL_OFFSET] & 0x80U) {
    int result;

    cf_v3_pclm_output_begin(data, size);
    result = cf_v3_pclm_graph_inner(data, size);
    cf_v3_pclm_output_end();
    return result;
  }
  memcpy(safe, data, size);
  cf_v3_pclm_graph_deploy_repair(safe, size);
  cf_v3_pclm_output_begin(safe, size);
  {
    int result = cf_v3_pclm_graph_inner(safe, size);

    cf_v3_pclm_output_end();
    return result;
  }
}
