// SPDX-License-Identifier: Apache-2.0
#include "pdf_raw_route.h"
#include "pdf_raw_route_bridge.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int cf_v3_pdf_raw_direct_legacy(const uint8_t *data, size_t size);
extern int cf_v3_pdf_raw_job_legacy(const uint8_t *data, size_t size);

static int
cf_v3_pdf_raw_call(unsigned route, int faithful,
                   int (*runner)(const uint8_t *, size_t),
                   const uint8_t *data, size_t size)
{
  int result = runner(data, size);

  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "pdf_to_pdf_raw route=%u faithful=%d input=%zu\n",
            route, faithful, size);
  return result;
}

static int
cf_v3_pdf_raw_direct(const uint8_t *header, const uint8_t *material,
                     size_t material_size, int faithful)
{
  uint8_t *input;
  size_t input_size;
  int result;

  if (faithful)
    return cf_v3_pdf_raw_call(CF_V3_PDF_RAW_ROUTE_DIRECT, 1,
                              cf_v3_pdf_raw_direct_legacy,
                              material, material_size);
  if (material_size > SIZE_MAX - CF_V2_CONTROL_SIZE)
    return 0;
  input_size = material_size + CF_V2_CONTROL_SIZE;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  memcpy(input, material, material_size);
  memcpy(input + material_size, header, CF_V2_CONTROL_SIZE);
  result = cf_v3_pdf_raw_call(CF_V3_PDF_RAW_ROUTE_DIRECT, 0,
                              cf_v3_pdf_raw_direct_legacy,
                              input, input_size);
  free(input);
  return result;
}

static int
cf_v3_pdf_raw_job(const uint8_t *header, const uint8_t *material,
                  size_t material_size, int faithful)
{
  static const char *const scaling[] = {"none", "fit", "fill", "auto"};
  static const char *const sides[] = {
      "one-sided", "two-sided-long-edge", "two-sided-short-edge"};
  uint8_t *input;
  char options[256];
  char title[48];
  int option_length;
  int title_length;
  size_t input_size;
  size_t offset;
  int result;

  if (faithful)
    return cf_v3_pdf_raw_call(CF_V3_PDF_RAW_ROUTE_JOB, 1,
                              cf_v3_pdf_raw_job_legacy,
                              material, material_size);
  option_length = snprintf(
      options, sizeof(options),
      "number-up=%u print-scaling=%s sides=%s output-order=%s emit-jcl=false",
      1U << (header[0] % 5U),
      scaling[header[1] % (sizeof(scaling) / sizeof(scaling[0]))],
      sides[header[2] % (sizeof(sides) / sizeof(sides[0]))],
      header[3] & 1U ? "reverse" : "normal");
  title_length = snprintf(title, sizeof(title), "pdf-v3-%02x%02x",
                          header[4], header[5]);
  if (option_length <= 0 || (size_t)option_length >= sizeof(options) ||
      title_length <= 0 || (size_t)title_length >= sizeof(title) ||
      material_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE -
                          (size_t)option_length - (size_t)title_length)
    return 0;
  input_size = CF_V2_JOB_FIXED_SIZE + (size_t)option_length +
               (size_t)title_length + material_size;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  cf_v2_job_store_u32le(input, 0U);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)option_length);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_length);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)material_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, header, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, options, (size_t)option_length);
  offset += (size_t)option_length;
  memcpy(input + offset, title, (size_t)title_length);
  offset += (size_t)title_length;
  memcpy(input + offset, material, material_size);
  result = cf_v3_pdf_raw_call(CF_V3_PDF_RAW_ROUTE_JOB, 0,
                              cf_v3_pdf_raw_job_legacy,
                              input, input_size);
  free(input);
  return result;
}

int
cf_v3_pdf_raw_run(const uint8_t *header, const uint8_t *material,
                  size_t material_size)
{
  const unsigned route = cf_v3_pdf_raw_route(header);
  const int faithful = cf_v3_pdf_raw_faithful(header);

  if (route == CF_V3_PDF_RAW_ROUTE_JOB)
    return cf_v3_pdf_raw_job(header, material, material_size, faithful);
  return cf_v3_pdf_raw_direct(header, material, material_size, faithful);
}
