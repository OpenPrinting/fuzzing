// SPDX-License-Identifier: Apache-2.0
#include "../implementations/raster_ps_route.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  uint8_t *header;
  size_t material_size;
  size_t mutated_size;

  if (!cf_v3_raster_ps_input(data, size) ||
      max_size < CF_V3_RASTER_PS_FIXED_SIZE + 1U)
    return LLVMFuzzerMutate(data, size, max_size);
  header = cf_v3_raster_ps_header(data);
  if ((seed & 3U) != 0U)
  {
    const size_t slot = (seed >> 2U) % CF_V3_RASTER_PS_HEADER_SIZE;
    const uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      header[slot] ^= delta;
    else
      header[slot] += delta;
    cf_v3_raster_ps_normalize_mutation(data, size);
    return size;
  }
  material_size = size - CF_V3_RASTER_PS_FIXED_SIZE;
  mutated_size = LLVMFuzzerMutate(data + CF_V3_RASTER_PS_FIXED_SIZE,
                                  material_size,
                                  max_size - CF_V3_RASTER_PS_FIXED_SIZE);
  if (!mutated_size)
  {
    data[CF_V3_RASTER_PS_FIXED_SIZE] = (uint8_t)seed;
    mutated_size = 1U;
  }
  cf_v3_raster_ps_normalize_mutation(data,
      CF_V3_RASTER_PS_FIXED_SIZE + mutated_size);
  return CF_V3_RASTER_PS_FIXED_SIZE + mutated_size;
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *out, size_t max_out_size,
                          unsigned int seed)
{
  const uint8_t *first_header;
  const uint8_t *second_header;
  const uint8_t *material;
  size_t material_size;

  if (!out || max_out_size < CF_V3_RASTER_PS_FIXED_SIZE + 1U ||
      !cf_v3_raster_ps_input(data1, size1) ||
      !cf_v3_raster_ps_input(data2, size2))
    return 0U;
  first_header = cf_v3_raster_ps_const_header(data1);
  second_header = cf_v3_raster_ps_const_header(data2);
  if (seed & 1U)
  {
    material = data2 + CF_V3_RASTER_PS_FIXED_SIZE;
    material_size = size2 - CF_V3_RASTER_PS_FIXED_SIZE;
  }
  else
  {
    material = data1 + CF_V3_RASTER_PS_FIXED_SIZE;
    material_size = size1 - CF_V3_RASTER_PS_FIXED_SIZE;
  }
  if (!material_size ||
      material_size > max_out_size - CF_V3_RASTER_PS_FIXED_SIZE)
    return 0U;
  memcpy(out, CF_V3_RASTER_PS_MAGIC, CF_V3_RASTER_PS_MAGIC_SIZE);
  for (size_t index = 0; index < CF_V3_RASTER_PS_HEADER_SIZE; index++)
    out[CF_V3_RASTER_PS_MAGIC_SIZE + index] =
        ((seed >> (index % 24U)) & 1U)
            ? second_header[index] : first_header[index];
  memcpy(out + CF_V3_RASTER_PS_FIXED_SIZE, material, material_size);
  cf_v3_raster_ps_normalize_mutation(
      out, CF_V3_RASTER_PS_FIXED_SIZE + material_size);
  return CF_V3_RASTER_PS_FIXED_SIZE + material_size;
}
