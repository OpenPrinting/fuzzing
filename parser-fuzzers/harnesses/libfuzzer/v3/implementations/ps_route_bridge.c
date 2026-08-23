// SPDX-License-Identifier: Apache-2.0
#include "ps_route.h"
#include "ps_route_bridge.h"
#include "ps_wrapper_bridge.h"

#include "../../v2/include/control.h"
#include "../../v2/include/job.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_ps_runner_t)(const uint8_t *, size_t);

extern int cf_v3_ps_job_legacy(const uint8_t *, size_t);
extern int cf_v3_ps_raw_legacy(const uint8_t *, size_t);
extern int cf_v3_ps_dsc_legacy(const uint8_t *, size_t);
extern int cf_v3_ps_page_legacy(const uint8_t *, size_t);
extern int cf_v3_ps_sequence_legacy(const uint8_t *, size_t);
extern int cf_v3_ps_sequence_deep_legacy(const uint8_t *, size_t);

static const char cf_v3_ps_ppd[] =
    "*PPD-Adobe: \"4.3\"\n"
    "*FormatVersion: \"4.3\"\n"
    "*FileVersion: \"1.0\"\n"
    "*LanguageVersion: English\n"
    "*LanguageEncoding: ISOLatin1\n"
    "*Manufacturer: \"OpenPrinting\"\n"
    "*ModelName: \"cups-filters V3 PS\"\n"
    "*NickName: \"cups-filters V3 PS\"\n"
    "*ShortNickName: \"cups-filters V3 PS\"\n"
    "*PCFileName: \"V3PS.PPD\"\n"
    "*Product: \"(cups-filters V3 PS)\"\n"
    "*PSVersion: \"(3010) 0\"\n"
    "*LanguageLevel: \"2\"\n"
    "*ColorDevice: False\n"
    "*DefaultColorSpace: Gray\n"
    "*cupsManualCopies: False\n"
    "*OpenUI *PageSize: PickOne\n"
    "*DefaultPageSize: A4\n"
    "*PageSize A4/A4: \"<</PageSize[595 842]/ImagingBBox null>>setpagedevice\"\n"
    "*PageSize Letter/Letter: \"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
    "*CloseUI: *PageSize\n"
    "*DefaultImageableArea: A4\n"
    "*ImageableArea A4: \"12 12 583 830\"\n"
    "*ImageableArea Letter: \"18 36 594 756\"\n"
    "*DefaultPaperDimension: A4\n"
    "*PaperDimension A4: \"595 842\"\n"
    "*PaperDimension Letter: \"612 792\"\n"
    "*OpenUI *Resolution: PickOne\n"
    "*DefaultResolution: 300dpi\n"
    "*Resolution 300dpi/300 dpi: \"<</HWResolution[300 300]>>setpagedevice\"\n"
    "*Resolution 600dpi/600 dpi: \"<</HWResolution[600 600]>>setpagedevice\"\n"
    "*CloseUI: *Resolution\n";

static int
cf_v3_ps_call(unsigned logical_route, unsigned wrapper_route, int faithful,
              cf_v3_ps_runner_t runner, const uint8_t *data, size_t size)
{
  int result;

  cf_v3_ps_wrapper_enter(wrapper_route, faithful);
  result = runner(data, size);
  cf_v3_ps_wrapper_leave();
  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "ps_to_ps route=%u faithful=%d input=%zu\n",
            logical_route, faithful, size);
  return result;
}

static int
cf_v3_ps_pack_raw(unsigned route, int faithful, const uint8_t *header,
                  const uint8_t *material, size_t material_size)
{
  uint8_t *input;
  size_t input_size;
  int result;

  if (!material_size || material_size > CF_V3_PS_MAX_MATERIAL ||
      material_size > SIZE_MAX - CF_V2_CONTROL_SIZE)
    return 0;
  input_size = material_size + CF_V2_CONTROL_SIZE;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  memcpy(input, material, material_size);
  memcpy(input + material_size, header, CF_V2_CONTROL_SIZE);
  result = cf_v3_ps_call(route, route, faithful, cf_v3_ps_raw_legacy,
                         input, input_size);
  free(input);
  return result;
}

static size_t
cf_v3_ps_job_options(char *buffer, size_t capacity, const uint8_t *header)
{
  static const unsigned number_up[] = {1U, 2U, 4U, 6U, 9U, 16U};
  static const char *const layouts[] =
      {"lrtb", "lrbt", "rltb", "rlbt", "tblr", "tbrl", "btlr", "btrl"};
  static const char *const ranges[] = {"1-99", "1", "1-2", "2-4"};
  static const char *const page_sets[] = {"all", "odd", "even"};
  int length = snprintf(
      buffer, capacity,
      "PageSize=%s number-up=%u number-up-layout=%s page-ranges=%s "
      "page-set=%s OutputOrder=%s Collate=%s copies=%u emit-jcl=false "
      "fit-to-page=%s mirror=%s page-border=%s sides=%s",
      header[0] & 1U ? "Letter" : "A4",
      number_up[header[1] % 6U], layouts[header[2] % 8U],
      ranges[header[3] % 4U], page_sets[header[4] % 3U],
      header[5] & 1U ? "reverse" : "normal",
      header[6] & 1U ? "true" : "false", 1U + header[7] % 4U,
      header[8] & 1U ? "true" : "false",
      header[9] & 1U ? "true" : "false",
      header[10] % 3U == 0U ? "none" :
          (header[10] % 3U == 1U ? "single" : "double"),
      header[11] % 3U == 0U ? "one-sided" :
          (header[11] % 3U == 1U ? "two-sided-long-edge" :
                                   "two-sided-short-edge"));

  return length > 0 && (size_t)length < capacity ? (size_t)length : 0U;
}

static int
cf_v3_ps_pack_job(unsigned route, int faithful, const uint8_t *header,
                  const uint8_t *material, size_t material_size)
{
  static const char title[] = "V3 PostScript route";
  char options[512];
  size_t options_size = cf_v3_ps_job_options(options, sizeof(options), header);
  const size_t ppd_size = sizeof(cf_v3_ps_ppd) - 1U;
  const size_t title_size = sizeof(title) - 1U;
  size_t input_size;
  size_t offset;
  uint8_t *input;
  int result;

  if (!material_size || !options_size ||
      material_size > CF_V3_PS_MAX_MATERIAL ||
      ppd_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE - options_size - title_size ||
      material_size > SIZE_MAX - CF_V2_JOB_FIXED_SIZE - ppd_size -
                          options_size - title_size)
    return 0;
  input_size = CF_V2_JOB_FIXED_SIZE + ppd_size + options_size + title_size +
               material_size;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  cf_v2_job_store_u32le(input, (uint32_t)ppd_size);
  cf_v2_job_store_u32le(input + 4U, (uint32_t)options_size);
  cf_v2_job_store_u32le(input + 8U, (uint32_t)title_size);
  cf_v2_job_store_u32le(input + 12U, (uint32_t)material_size);
  memcpy(input + CF_V2_JOB_HEADER_SIZE, header, CF_V2_CONTROL_SIZE);
  offset = CF_V2_JOB_FIXED_SIZE;
  memcpy(input + offset, cf_v3_ps_ppd, ppd_size);
  offset += ppd_size;
  memcpy(input + offset, options, options_size);
  offset += options_size;
  memcpy(input + offset, title, title_size);
  offset += title_size;
  memcpy(input + offset, material, material_size);
  result = cf_v3_ps_call(route, route, faithful, cf_v3_ps_job_legacy,
                         input, input_size);
  free(input);
  return result;
}

static int
cf_v3_ps_pack_state(unsigned logical_route, unsigned wrapper_route,
                    int faithful, const char magic[8], size_t selector_size,
                    size_t max_payload, cf_v3_ps_runner_t runner,
                    const uint8_t *header, const uint8_t *material,
                    size_t material_size)
{
  size_t payload_size = material_size < max_payload ? material_size : max_payload;
  size_t input_size = 8U + selector_size + payload_size;
  uint8_t *input;
  int result;

  if (!payload_size || selector_size > CF_V3_PS_HEADER_SIZE)
    return 0;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  memcpy(input, magic, 8U);
  memcpy(input + 8U, header, selector_size);
  memcpy(input + 8U + selector_size, material, payload_size);
  result = cf_v3_ps_call(logical_route, wrapper_route, faithful, runner,
                         input, input_size);
  free(input);
  return result;
}

int
cf_v3_ps_run(const uint8_t *header, const uint8_t *material,
             size_t material_size)
{
  const unsigned route = cf_v3_ps_route(header);
  const int faithful = cf_v3_ps_faithful(header);

  switch (route)
  {
    case CF_V3_PS_ROUTE_JOB:
      return cf_v3_ps_pack_job(route, faithful, header,
                               material, material_size);
    case CF_V3_PS_ROUTE_RAW:
      return cf_v3_ps_pack_raw(route, faithful, header,
                               material, material_size);
    case CF_V3_PS_ROUTE_DSC:
      return cf_v3_ps_pack_state(route, route, faithful, "PSDSC001", 16U,
                                 1024U, cf_v3_ps_dsc_legacy, header,
                                 material, material_size);
    case CF_V3_PS_ROUTE_PAGE_RANGE_EOF:
      return cf_v3_ps_pack_state(route, route, faithful, "PSPGEOF1", 8U,
                                 128U, cf_v3_ps_page_legacy, header,
                                 material, material_size);
    case CF_V3_PS_ROUTE_SEQUENCE:
      return cf_v3_ps_pack_state(
          route, route, faithful, "SEQREL01", 32U, 512U,
          cf_v3_ps_sequence_legacy, header, material, material_size);
    case CF_V3_PS_ROUTE_SEQUENCE_DEEP:
      return cf_v3_ps_pack_state(
          route, route, faithful, "SEQREL01", 32U, 512U,
          cf_v3_ps_sequence_deep_legacy, header, material, material_size);
    default:
      return 0;
  }
}
