// SPDX-License-Identifier: Apache-2.0
#include "../implementations/text_pdf_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

enum cf_v3_text_pdf_faithful_mode_e
{
  CF_V3_TEXT_PDF_FAITHFUL_NONE = 0,
  CF_V3_TEXT_PDF_FAITHFUL_ALL,
  CF_V3_TEXT_PDF_FAITHFUL_JOB,
  CF_V3_TEXT_PDF_FAITHFUL_COLUMN,
  CF_V3_TEXT_PDF_FAITHFUL_COMMENT,
  CF_V3_TEXT_PDF_FAITHFUL_TITLE,
  CF_V3_TEXT_PDF_FAITHFUL_NOWRAP,
  CF_V3_TEXT_PDF_FAITHFUL_DUPLEX
};

static uint32_t
cf_v3_text_pdf_random(uint32_t *state)
{
  uint32_t value = *state ? *state : UINT32_C(0x9e3779b9);

  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  *state = value;
  return value;
}

static int
cf_v3_text_pdf_faithful_mode(void)
{
  const char *value = getenv("CF_V3_TEXT_PDF_MUTATE_FAITHFUL");

  if (!value || !value[0] || !strcmp(value, "0"))
    return CF_V3_TEXT_PDF_FAITHFUL_NONE;
  if (!strcmp(value, "job"))
    return CF_V3_TEXT_PDF_FAITHFUL_JOB;
  if (!strcmp(value, "column"))
    return CF_V3_TEXT_PDF_FAITHFUL_COLUMN;
  if (!strcmp(value, "comment"))
    return CF_V3_TEXT_PDF_FAITHFUL_COMMENT;
  if (!strcmp(value, "title"))
    return CF_V3_TEXT_PDF_FAITHFUL_TITLE;
  if (!strcmp(value, "nowrap"))
    return CF_V3_TEXT_PDF_FAITHFUL_NOWRAP;
  if (!strcmp(value, "duplex"))
    return CF_V3_TEXT_PDF_FAITHFUL_DUPLEX;
  return CF_V3_TEXT_PDF_FAITHFUL_ALL;
}

static int
cf_v3_text_pdf_faithful_allowed(int mode, const uint8_t *header)
{
  unsigned route = cf_v3_text_pdf_route(header);
  unsigned violation = header[23] % 8U;

  switch (mode)
  {
    case CF_V3_TEXT_PDF_FAITHFUL_ALL:
      return 1;
    case CF_V3_TEXT_PDF_FAITHFUL_JOB:
      return route == CF_V3_TEXT_PDF_ROUTE_JOB_PLAIN ||
             route == CF_V3_TEXT_PDF_ROUTE_JOB_C;
    case CF_V3_TEXT_PDF_FAITHFUL_COLUMN:
      return (route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_PLAIN ||
              route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_C) && violation == 2U;
    case CF_V3_TEXT_PDF_FAITHFUL_COMMENT:
      return route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_C && violation == 6U;
    case CF_V3_TEXT_PDF_FAITHFUL_TITLE:
      return route == CF_V3_TEXT_PDF_ROUTE_TITLE_UTF8 ||
             route == CF_V3_TEXT_PDF_ROUTE_TITLE_RELATION ||
             ((route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_PLAIN ||
               route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_C) &&
              violation == 5U);
    case CF_V3_TEXT_PDF_FAITHFUL_NOWRAP:
      return (route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_PLAIN ||
              route == CF_V3_TEXT_PDF_ROUTE_BOUNDARY_C) && violation == 4U;
    case CF_V3_TEXT_PDF_FAITHFUL_DUPLEX:
      return route == CF_V3_TEXT_PDF_ROUTE_DUPLEX_BOUNDARY;
    default:
      return 0;
  }
}

static void
cf_v3_text_pdf_normalize(uint8_t *data, size_t size, int faithful_mode)
{
  uint8_t *header;
  unsigned route;
  uint8_t policy;

  if (!cf_v3_text_pdf_input(data, size))
    return;
  header = cf_v3_text_pdf_header(data);
  route = cf_v3_text_pdf_route(header);
  policy = cf_v3_text_pdf_faithful_allowed(faithful_mode, header) &&
                   cf_v3_text_pdf_faithful(header)
               ? CF_V3_TEXT_PDF_FLAG_FAITHFUL : 0U;
  header[CF_V3_TEXT_PDF_ROUTE_OFFSET] = (uint8_t)(policy | route);
}

static size_t
cf_v3_text_pdf_initialize(uint8_t *data, size_t max_size, uint32_t *state)
{
  size_t available;
  size_t material_size;

  if (!data || max_size < CF_V3_TEXT_PDF_FIXED_SIZE + 1U)
    return 0U;
  memcpy(data, CF_V3_TEXT_PDF_MAGIC, CF_V3_TEXT_PDF_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V3_TEXT_PDF_HEADER_SIZE; index++)
    data[CF_V3_TEXT_PDF_MAGIC_SIZE + index] =
        (uint8_t)cf_v3_text_pdf_random(state);
  data[CF_V3_TEXT_PDF_MAGIC_SIZE + CF_V3_TEXT_PDF_ROUTE_OFFSET] =
      (uint8_t)(cf_v3_text_pdf_random(state) % CF_V3_TEXT_PDF_ROUTE_COUNT);
  available = max_size - CF_V3_TEXT_PDF_FIXED_SIZE;
  material_size = 1U + cf_v3_text_pdf_random(state) %
      (available < 64U ? available : 64U);
  for (size_t index = 0U; index < material_size; index++)
    data[CF_V3_TEXT_PDF_FIXED_SIZE + index] =
        (uint8_t)cf_v3_text_pdf_random(state);
  return CF_V3_TEXT_PDF_FIXED_SIZE + material_size;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  uint32_t state = seed;
  int faithful_mode = cf_v3_text_pdf_faithful_mode();

  if (!cf_v3_text_pdf_input(data, size))
    return cf_v3_text_pdf_initialize(data, max_size, &state);

  if ((cf_v3_text_pdf_random(&state) & 3U) != 0U)
  {
    uint8_t *header = cf_v3_text_pdf_header(data);
    size_t slot = cf_v3_text_pdf_random(&state) %
                  CF_V3_TEXT_PDF_HEADER_SIZE;
    uint8_t delta =
        (uint8_t)(1U + (cf_v3_text_pdf_random(&state) & 0xffU));

    if (cf_v3_text_pdf_random(&state) & 1U)
      header[slot] ^= delta;
    else
      header[slot] += delta;
    if ((cf_v3_text_pdf_random(&state) & 15U) == 0U)
      cf_v3_text_pdf_set_route(
          header, cf_v3_text_pdf_random(&state) %
                      CF_V3_TEXT_PDF_ROUTE_COUNT);
    if (cf_v3_text_pdf_faithful_allowed(faithful_mode, header) &&
        (cf_v3_text_pdf_random(&state) & 31U) == 0U)
      header[CF_V3_TEXT_PDF_ROUTE_OFFSET] ^=
          CF_V3_TEXT_PDF_FLAG_FAITHFUL;
    cf_v3_text_pdf_normalize(data, size, faithful_mode);
    return size;
  }

  {
    size_t material_size = size - CF_V3_TEXT_PDF_FIXED_SIZE;
    size_t mutated_size = LLVMFuzzerMutate(
        data + CF_V3_TEXT_PDF_FIXED_SIZE, material_size,
        max_size - CF_V3_TEXT_PDF_FIXED_SIZE);

    if (!mutated_size)
    {
      data[CF_V3_TEXT_PDF_FIXED_SIZE] =
          (uint8_t)cf_v3_text_pdf_random(&state);
      mutated_size = 1U;
    }
    size = CF_V3_TEXT_PDF_FIXED_SIZE + mutated_size;
    cf_v3_text_pdf_normalize(data, size, faithful_mode);
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

  if (!output || max_output_size < CF_V3_TEXT_PDF_FIXED_SIZE + 1U ||
      !cf_v3_text_pdf_input(data1, size1) ||
      !cf_v3_text_pdf_input(data2, size2))
    return 0U;
  first_header = cf_v3_text_pdf_const_header(data1);
  second_header = cf_v3_text_pdf_const_header(data2);
  if (seed & 1U)
  {
    material = data2 + CF_V3_TEXT_PDF_FIXED_SIZE;
    material_size = size2 - CF_V3_TEXT_PDF_FIXED_SIZE;
  }
  else
  {
    material = data1 + CF_V3_TEXT_PDF_FIXED_SIZE;
    material_size = size1 - CF_V3_TEXT_PDF_FIXED_SIZE;
  }
  if (!material_size ||
      material_size > max_output_size - CF_V3_TEXT_PDF_FIXED_SIZE)
    return 0U;

  memcpy(output, CF_V3_TEXT_PDF_MAGIC, CF_V3_TEXT_PDF_MAGIC_SIZE);
  for (size_t index = 0U; index < CF_V3_TEXT_PDF_HEADER_SIZE; index++)
    output[CF_V3_TEXT_PDF_MAGIC_SIZE + index] =
        ((seed >> (index % 24U)) & 1U) ?
            second_header[index] : first_header[index];
  memcpy(output + CF_V3_TEXT_PDF_FIXED_SIZE, material, material_size);
  cf_v3_text_pdf_normalize(
      output, CF_V3_TEXT_PDF_FIXED_SIZE + material_size,
      cf_v3_text_pdf_faithful_mode());
  return CF_V3_TEXT_PDF_FIXED_SIZE + material_size;
}
