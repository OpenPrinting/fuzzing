// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "raster_ps_bridge.h"
#include "raster_ps_oracle.h"
#include "raster_ps_route.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"
#include "../../v2/include/profiles.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_raster_ps_runner_t)(const uint8_t *, size_t);

extern int cf_v3_raster_ps_frontier_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_ps_validated_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_ps_job_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_ps_state_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_ps_lifecycle_legacy(const uint8_t *, size_t);
extern int cf_v3_raster_ps_write_legacy(const uint8_t *, size_t);

static int
cf_v3_raster_ps_call(unsigned route, cf_v3_raster_ps_runner_t runner,
                     const uint8_t *data, size_t size)
{
  int result = runner(data, size);

  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "raster_ps route=%u input=%zu\n", route, size);
  return result;
}

static int
cf_v3_raster_ps_raw(unsigned route, cf_v3_raster_ps_runner_t runner,
                    const uint8_t *header, const uint8_t *material,
                    size_t material_size)
{
  uint8_t *input;
  size_t input_size;
  int result;

  if (!material_size || material_size > CF_V3_RASTER_PS_MAX_MATERIAL)
    return 0;
  input_size = material_size + CF_V2_CONTROL_SIZE;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  memcpy(input, material, material_size);
  memcpy(input + material_size, header + 9U, CF_V2_CONTROL_SIZE);
  result = cf_v3_raster_ps_call(route, runner, input, input_size);
  free(input);
  return result;
}

static int
cf_v3_raster_ps_state(unsigned route, const char magic[8],
                      cf_v3_raster_ps_runner_t runner,
                      const uint8_t *header, const uint8_t *material,
                      size_t material_size)
{
  uint8_t input[8U + 8U + 4096U];
  size_t payload_size = material_size < 4096U ? material_size : 4096U;
  size_t input_size = 16U + payload_size;

  memcpy(input, magic, 8U);
  memcpy(input + 8U, header + 1U, 8U);
  if (payload_size)
    memcpy(input + 16U, material, payload_size);
  return cf_v3_raster_ps_call(route, runner, input, input_size);
}

static int
cf_v3_raster_ps_job(const uint8_t *header, const uint8_t *material,
                    size_t material_size)
{
  static const char *const titles[] = {
    "raster-v3", "gray-page", "color-page", "duplex-page"
  };
  cf_v2_control_t control;
  char options[1024];
  char *ppd = NULL;
  size_t ppd_size = 0U;
  FILE *stream;
  const char *title;
  size_t options_size;
  size_t title_size;
  size_t input_size;
  size_t offset;
  uint8_t *input;
  int result = 0;

  if (!material_size || material_size > CF_V3_RASTER_PS_MAX_MATERIAL)
    return 0;
  memcpy(&control, header + 9U, sizeof(control));
  if (cf_v2_build_options(options, sizeof(options), &control) != 0)
    return 0;
  stream = open_memstream(&ppd, &ppd_size);
  if (!stream)
    return 0;
  if (cf_v2_write_ppd(stream, &control, "rastertops") != 0 ||
      fclose(stream) != 0)
  {
    free(ppd);
    return 0;
  }
  title = titles[header[25] %
                 (sizeof(titles) / sizeof(titles[0]))];
  options_size = strlen(options);
  title_size = strlen(title);
  if (ppd_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE ||
      options_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE - ppd_size ||
      title_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE - ppd_size - options_size ||
      material_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE - ppd_size -
                          options_size - title_size)
  {
    free(ppd);
    return 0;
  }
  input_size = CF_V2_JOB_FIXED_SIZE + ppd_size + options_size +
               title_size + material_size;
  input = (uint8_t *)malloc(input_size);
  if (!input)
  {
    free(ppd);
    return 0;
  }
  cf_v2_job_store_u32le(input, (uint32_t)ppd_size);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)options_size);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_size);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)material_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, header + 9U, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, ppd, ppd_size);
  offset += ppd_size;
  memcpy(input + offset, options, options_size);
  offset += options_size;
  memcpy(input + offset, title, title_size);
  offset += title_size;
  memcpy(input + offset, material, material_size);
  result = cf_v3_raster_ps_call(CF_V3_RASTER_PS_ROUTE_JOB,
                                cf_v3_raster_ps_job_legacy,
                                input, input_size);
  free(input);
  free(ppd);
  return result;
}

int
cf_v3_raster_ps_run(const uint8_t *header, const uint8_t *material,
                    size_t material_size)
{
  const unsigned route = cf_v3_raster_ps_route(header);

  switch (route)
  {
    case CF_V3_RASTER_PS_ROUTE_RAW_FRONTIER:
      return cf_v3_raster_ps_raw(route, cf_v3_raster_ps_frontier_legacy,
                                 header, material, material_size);
    case CF_V3_RASTER_PS_ROUTE_RAW_VALIDATED:
      return cf_v3_raster_ps_raw(route, cf_v3_raster_ps_validated_legacy,
                                 header, material, material_size);
    case CF_V3_RASTER_PS_ROUTE_JOB:
      return cf_v3_raster_ps_job(header, material, material_size);
    case CF_V3_RASTER_PS_ROUTE_GENERATED:
      return cf_v3_raster_ps_state(route, "ROSTATE1",
                                   cf_v3_raster_ps_state_legacy,
                                   header, material, material_size);
    case CF_V3_RASTER_PS_ROUTE_LIFECYCLE:
      return cf_v3_raster_ps_state(route, "PSLIFE01",
                                   cf_v3_raster_ps_lifecycle_legacy,
                                   header, material, material_size);
    case CF_V3_RASTER_PS_ROUTE_WRITE_ERROR:
      if (cf_v3_raster_ps_faithful(header))
        return cf_v3_raster_ps_state(route, "PSWRITE1",
                                     cf_v3_raster_ps_write_legacy,
                                     header, material, material_size);
      else
      {
        uint8_t safe_header[CF_V3_RASTER_PS_HEADER_SIZE];

        memcpy(safe_header, header, sizeof(safe_header));
        safe_header[7] = 0U;
        return cf_v3_raster_ps_state(route, "PSLIFE01",
                                     cf_v3_raster_ps_lifecycle_legacy,
                                     safe_header, material, material_size);
      }
    case CF_V3_RASTER_PS_ROUTE_TRUNCATION_ORACLE:
      if (getenv("CF_V3_TRACE_ROUTE"))
        fprintf(stderr, "raster_ps route=%u input=%zu\n", route,
                material_size);
      return cf_v3_raster_ps_truncation_oracle(
          header, material, material_size,
          cf_v3_raster_ps_faithful(header));
    case CF_V3_RASTER_PS_ROUTE_OUTPUT_ORACLE:
      if (getenv("CF_V3_TRACE_ROUTE"))
        fprintf(stderr, "raster_ps route=%u input=%zu\n", route,
                material_size);
      return cf_v3_raster_ps_output_oracle(header, material, material_size);
    default:
      return 0;
  }
}
