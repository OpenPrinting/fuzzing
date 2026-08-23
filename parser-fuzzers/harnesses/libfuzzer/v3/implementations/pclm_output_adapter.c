// SPDX-License-Identifier: Apache-2.0
#include "pclm_output_adapter.h"

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/filter.h>
#include <cupsfilters/raster.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V3_PCLM_OUTPUT_MODEL_OFFSET 53U
#define CF_V3_PCLM_OUTPUT_BPC_OFFSET 54U
#define CF_V3_PCLM_OUTPUT_FLAGS_OFFSET 55U
#define CF_V3_PCLM_OUTPUT_ENABLE 0x40U
#define CF_V3_PCLM_OUTPUT_MAX_OWNERS 16U

typedef struct cf_v3_pclm_options_owner_s {
  cups_option_t *options;
  int count;
} cf_v3_pclm_options_owner_t;

static cf_v3_pclm_options_owner_t
    cf_v3_pclm_output_owners[CF_V3_PCLM_OUTPUT_MAX_OWNERS];
static size_t cf_v3_pclm_output_owner_count;
static int cf_v3_pclm_output_enabled;
static unsigned cf_v3_pclm_output_model;
static unsigned cf_v3_pclm_output_bpc;
static cups_order_t cf_v3_pclm_output_order = CUPS_ORDER_CHUNKED;

extern int __real_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data,
                                           int num_options,
                                           cups_option_t **options);
extern void __real_cupsFreeOptions(int num_options, cups_option_t *options);
extern int __real_cfRasterPrepareHeader(
    cups_page_header_t *header, cf_filter_data_t *data,
    cf_filter_out_format_t final_outformat,
    cf_filter_out_format_t header_outformat, int no_high_depth,
    cups_cspace_t *cspace);

static void
cf_v3_pclm_output_forget(cups_option_t *options)
{
  size_t index;

  for (index = 0U; index < cf_v3_pclm_output_owner_count; index++) {
    if (cf_v3_pclm_output_owners[index].options != options)
      continue;
    cf_v3_pclm_output_owner_count--;
    cf_v3_pclm_output_owners[index] =
        cf_v3_pclm_output_owners[cf_v3_pclm_output_owner_count];
    memset(&cf_v3_pclm_output_owners[cf_v3_pclm_output_owner_count], 0,
           sizeof(cf_v3_pclm_output_owners[0]));
    return;
  }
}

static void
cf_v3_pclm_output_release(void)
{
  while (cf_v3_pclm_output_owner_count) {
    cf_v3_pclm_options_owner_t *owner =
        &cf_v3_pclm_output_owners[--cf_v3_pclm_output_owner_count];

    __real_cupsFreeOptions(owner->count, owner->options);
    memset(owner, 0, sizeof(*owner));
  }
}

void
cf_v3_pclm_output_begin(const uint8_t *data, size_t size)
{
  static const cups_order_t orders[] = {
    CUPS_ORDER_CHUNKED, CUPS_ORDER_BANDED, CUPS_ORDER_PLANAR
  };

  cf_v3_pclm_output_release();
  cf_v3_pclm_output_enabled = 0;
  cf_v3_pclm_output_order = CUPS_ORDER_CHUNKED;
  if (!data || size <= CF_V3_PCLM_OUTPUT_FLAGS_OFFSET ||
      !(data[CF_V3_PCLM_OUTPUT_FLAGS_OFFSET] & CF_V3_PCLM_OUTPUT_ENABLE))
    return;

  cf_v3_pclm_output_enabled = 1;
  cf_v3_pclm_output_model = data[CF_V3_PCLM_OUTPUT_MODEL_OFFSET] % 6U;
  cf_v3_pclm_output_bpc = data[CF_V3_PCLM_OUTPUT_BPC_OFFSET] % 5U;
  cf_v3_pclm_output_order =
      orders[data[CF_V3_PCLM_OUTPUT_FLAGS_OFFSET] %
             (sizeof(orders) / sizeof(orders[0]))];
  if (getenv("CF_V3_TRACE_PCLM_OUTPUT"))
    fprintf(stderr, "pclm-output: model=%u bpc=%u order=%u\n",
            cf_v3_pclm_output_model, cf_v3_pclm_output_bpc,
            (unsigned)cf_v3_pclm_output_order);
}

void
cf_v3_pclm_output_end(void)
{
  cf_v3_pclm_output_release();
  cf_v3_pclm_output_enabled = 0;
  cf_v3_pclm_output_order = CUPS_ORDER_CHUNKED;
}

int
__wrap_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data, int num_options,
                               cups_option_t **options)
{
  int count = __real_cfJoinJobOptionsAndAttrs(data, num_options, options);

  if (options && *options) {
    if (cf_v3_pclm_output_owner_count >= CF_V3_PCLM_OUTPUT_MAX_OWNERS)
      __builtin_trap();
    cf_v3_pclm_output_owners[cf_v3_pclm_output_owner_count++] =
        (cf_v3_pclm_options_owner_t){*options, count};
  }
  return count;
}

void
__wrap_cupsFreeOptions(int num_options, cups_option_t *options)
{
  cf_v3_pclm_output_forget(options);
  __real_cupsFreeOptions(num_options, options);
}

int
__wrap_cfRasterPrepareHeader(cups_page_header_t *header,
                             cf_filter_data_t *data,
                             cf_filter_out_format_t final_outformat,
                             cf_filter_out_format_t header_outformat,
                             int no_high_depth, cups_cspace_t *cspace)
{
  static const char *models[] = {
    "RGB", "Device2", "Device3", "Device4", "Device6", "Device15"
  };
  static const unsigned bpcs[] = {1U, 2U, 4U, 8U, 16U};
  cups_option_t *projected_options = NULL;
  cf_filter_data_t projected;
  char color_model[32];
  int projected_count = 0;
  int result;

  if (cf_v3_pclm_output_enabled && data) {
    snprintf(color_model, sizeof(color_model), "%s_%u",
             models[cf_v3_pclm_output_model],
             bpcs[cf_v3_pclm_output_bpc]);
    projected_count = cupsAddOption(
        "PageSize", "Letter", projected_count, &projected_options);
    projected_count = cupsAddOption(
        "ColorModel", color_model, projected_count, &projected_options);
    projected = *data;
    projected.header = NULL;
    projected.num_options = projected_count;
    projected.options = projected_options;
    result = __real_cfRasterPrepareHeader(
        header, &projected, final_outformat, header_outformat,
        no_high_depth, cspace);
    __real_cupsFreeOptions(projected_count, projected_options);
  } else {
    result = __real_cfRasterPrepareHeader(
        header, data, final_outformat, header_outformat,
        no_high_depth, cspace);
  }

  if (getenv("CF_V3_TRACE_PCLM_OUTPUT"))
    fprintf(stderr,
            "pclm-output-header: result=%d bpc=%u bpp=%u colors=%u "
            "cspace=%u order=%u width=%u bpl=%u\n",
            result, header->cupsBitsPerColor, header->cupsBitsPerPixel,
            header->cupsNumColors, header->cupsColorSpace,
            header->cupsColorOrder, header->cupsWidth,
            header->cupsBytesPerLine);

  if (result || !cf_v3_pclm_output_enabled ||
      cf_v3_pclm_output_order == CUPS_ORDER_CHUNKED)
    return result;

  header->cupsColorOrder = cf_v3_pclm_output_order;
  header->cupsBitsPerPixel = header->cupsBitsPerColor;
  header->cupsBytesPerLine =
      (header->cupsWidth * header->cupsBitsPerPixel + 7U) / 8U;
  if (cf_v3_pclm_output_order == CUPS_ORDER_BANDED)
    header->cupsBytesPerLine *= header->cupsNumColors;
  return result;
}
