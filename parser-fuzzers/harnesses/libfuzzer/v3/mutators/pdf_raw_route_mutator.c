// SPDX-License-Identifier: Apache-2.0
#include "../implementations/pdf_raw_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t
cf_v3_pdf_raw_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static int
cf_v3_pdf_raw_allow_faithful(void)
{
  const char *value = getenv("CF_V3_PDF_RAW_MUTATE_FAITHFUL");

  return value && value[0] && strcmp(value, "0");
}

static void
cf_v3_pdf_raw_normalize(uint8_t *data, size_t size)
{
  uint8_t *header;
  uint8_t route;
  uint8_t faithful;

  if (!cf_v3_pdf_raw_input(data, size))
    return;
  header = cf_v3_pdf_raw_header(data);
  route = (uint8_t)cf_v3_pdf_raw_route(header);
  faithful = cf_v3_pdf_raw_allow_faithful() &&
                     cf_v3_pdf_raw_faithful(header)
                 ? CF_V3_PDF_RAW_FLAG_FAITHFUL : 0U;
  header[CF_V3_PDF_RAW_ROUTE_OFFSET] = faithful | route;
}

static size_t
cf_v3_pdf_raw_initialize(uint8_t *data, size_t max_size, uint32_t *state)
{
  static const uint8_t minimal[] = "%PDF-1.4\n%%EOF\n";

  if (!data || max_size < CF_V3_PDF_RAW_FIXED_SIZE + sizeof(minimal) - 1U)
    return 0U;
  memcpy(data, CF_V3_PDF_RAW_MAGIC, CF_V3_PDF_RAW_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V3_PDF_RAW_HEADER_SIZE; index++)
    data[CF_V3_PDF_RAW_MAGIC_SIZE + index] =
        (uint8_t)cf_v3_pdf_raw_random(state);
  data[CF_V3_PDF_RAW_MAGIC_SIZE + CF_V3_PDF_RAW_ROUTE_OFFSET] =
      (uint8_t)(cf_v3_pdf_raw_random(state) % CF_V3_PDF_RAW_ROUTE_COUNT);
  memcpy(data + CF_V3_PDF_RAW_FIXED_SIZE, minimal, sizeof(minimal) - 1U);
  return CF_V3_PDF_RAW_FIXED_SIZE + sizeof(minimal) - 1U;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  uint32_t state = seed;

  if (!cf_v3_pdf_raw_input(data, size))
  {
    size_t mutated_size = LLVMFuzzerMutate(data, size, max_size);

    if (mutated_size)
      return mutated_size;
    return cf_v3_pdf_raw_initialize(data, max_size, &state);
  }
  if ((cf_v3_pdf_raw_random(&state) & 3U) == 0U)
  {
    uint8_t *header = cf_v3_pdf_raw_header(data);
    size_t slot = cf_v3_pdf_raw_random(&state) %
                  CF_V3_PDF_RAW_HEADER_SIZE;

    header[slot] ^= (uint8_t)(1U + (cf_v3_pdf_raw_random(&state) & 0xffU));
    if ((cf_v3_pdf_raw_random(&state) & 15U) == 0U)
      header[CF_V3_PDF_RAW_ROUTE_OFFSET] =
          (uint8_t)(cf_v3_pdf_raw_random(&state) %
                    CF_V3_PDF_RAW_ROUTE_COUNT);
    if (cf_v3_pdf_raw_allow_faithful() &&
        (cf_v3_pdf_raw_random(&state) & 31U) == 0U)
      header[CF_V3_PDF_RAW_ROUTE_OFFSET] ^=
          CF_V3_PDF_RAW_FLAG_FAITHFUL;
    cf_v3_pdf_raw_normalize(data, size);
    return size;
  }

  {
    size_t material_size = size - CF_V3_PDF_RAW_FIXED_SIZE;
    size_t mutated_size = LLVMFuzzerMutate(
        data + CF_V3_PDF_RAW_FIXED_SIZE, material_size,
        max_size - CF_V3_PDF_RAW_FIXED_SIZE);

    if (!mutated_size)
    {
      data[CF_V3_PDF_RAW_FIXED_SIZE] = '%';
      mutated_size = 1U;
    }
    size = CF_V3_PDF_RAW_FIXED_SIZE + mutated_size;
    cf_v3_pdf_raw_normalize(data, size);
    return size;
  }
}

size_t
LLVMFuzzerCustomCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *output, size_t max_output_size,
                          unsigned int seed)
{
  const uint8_t *first_header;
  const uint8_t *second_header;
  const uint8_t *material;
  size_t material_size;

  if (!output || !cf_v3_pdf_raw_input(data1, size1) ||
      !cf_v3_pdf_raw_input(data2, size2) ||
      max_output_size < CF_V3_PDF_RAW_FIXED_SIZE + 1U)
    return 0U;
  first_header = cf_v3_pdf_raw_const_header(data1);
  second_header = cf_v3_pdf_raw_const_header(data2);
  if (seed & 1U)
  {
    material = data2 + CF_V3_PDF_RAW_FIXED_SIZE;
    material_size = size2 - CF_V3_PDF_RAW_FIXED_SIZE;
  }
  else
  {
    material = data1 + CF_V3_PDF_RAW_FIXED_SIZE;
    material_size = size1 - CF_V3_PDF_RAW_FIXED_SIZE;
  }
  if (!material_size ||
      material_size > max_output_size - CF_V3_PDF_RAW_FIXED_SIZE)
    return 0U;
  memcpy(output, CF_V3_PDF_RAW_MAGIC, CF_V3_PDF_RAW_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V3_PDF_RAW_HEADER_SIZE; index++)
    output[CF_V3_PDF_RAW_MAGIC_SIZE + index] =
        ((seed >> (index % 24U)) & 1U) ?
            second_header[index] : first_header[index];
  memcpy(output + CF_V3_PDF_RAW_FIXED_SIZE, material, material_size);
  cf_v3_pdf_raw_normalize(
      output, CF_V3_PDF_RAW_FIXED_SIZE + material_size);
  return CF_V3_PDF_RAW_FIXED_SIZE + material_size;
}
