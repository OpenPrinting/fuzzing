// SPDX-License-Identifier: Apache-2.0
#include "../implementations/ppd_semantic_profile.h"

#include <stddef.h>
#include <stdint.h>

#define LLVMFuzzerCustomMutator cf_v3_ppd_semantic_inner_mutator
#define LLVMFuzzerCustomCrossOver cf_v3_ppd_semantic_inner_crossover
#include "../../v2/mutators/relation_program_mutator.c"
#undef LLVMFuzzerCustomCrossOver
#undef LLVMFuzzerCustomMutator

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                        unsigned int seed)
{
  size = cf_v3_ppd_semantic_inner_mutator(data, size, max_size, seed);
  if (cf_v3_ppd_semantic_profile_input(data, size) && (seed & 7U) == 0U) {
    uint8_t *profile = data + CF_V3_PPD_SEMANTIC_PROFILE_OFFSET;
    unsigned route = (seed >> 3U) % 4U;

    *profile &= 0x3cU;
    if (route < 3U)
      *profile |= (uint8_t)(CF_V3_PPD_SEMANTIC_PROFILE_ENABLE | route);
  }
  cf_v3_ppd_semantic_mutation_normalize(data, size);
  return size;
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                         const uint8_t *data2, size_t size2,
                         uint8_t *output, size_t max_output_size,
                         unsigned int seed)
{
  size_t size = cf_v3_ppd_semantic_inner_crossover(
      data1, size1, data2, size2, output, max_output_size, seed);

  cf_v3_ppd_semantic_mutation_normalize(output, size);
  return size;
}
