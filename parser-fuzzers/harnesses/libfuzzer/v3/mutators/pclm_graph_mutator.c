// SPDX-License-Identifier: Apache-2.0
#include "../implementations/pclm_graph_projection.h"

#include <stddef.h>
#include <stdint.h>

#define LLVMFuzzerCustomMutator cf_v3_pclm_graph_inner_mutator
#define LLVMFuzzerCustomCrossOver cf_v3_pclm_graph_inner_crossover
#include "../../v2/mutators/relation_program_mutator.c"
#undef LLVMFuzzerCustomCrossOver
#undef LLVMFuzzerCustomMutator

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  size = cf_v3_pclm_graph_inner_mutator(data, size, max_size, seed);
  cf_v3_pclm_graph_deploy_repair(data, size);
  return size;
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                                 const uint8_t *data2, size_t size2,
                                 uint8_t *output, size_t max_output_size,
                                 unsigned int seed) {
  size_t size = cf_v3_pclm_graph_inner_crossover(
      data1, size1, data2, size2, output, max_output_size, seed);
  cf_v3_pclm_graph_deploy_repair(output, size);
  return size;
}
