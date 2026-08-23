// SPDX-License-Identifier: Apache-2.0
#include "raster_pclx_state_lifecycle.h"

#include <cups/cups.h>
#include <cupsfilters/filter.h>

#include <stddef.h>
#include <string.h>

#define CF_V3_PCLX_OPTIONS_MAX 64U

typedef struct cf_v3_pclx_options_s
{
  cups_option_t *options;
  int count;
} cf_v3_pclx_options_t;

static cf_v3_pclx_options_t cf_v3_pclx_options[CF_V3_PCLX_OPTIONS_MAX];
static size_t cf_v3_pclx_options_count;
static int cf_v3_pclx_lifecycle_active;
static int cf_v3_pclx_lifecycle_faithful;

extern int __real_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data,
                                            int num_options,
                                            cups_option_t **options);
extern int __real_cupsParseOptions(const char *arg, int num_options,
                                   cups_option_t **options);
extern void __real_cupsFreeOptions(int num_options, cups_option_t *options);

static void
cf_v3_pclx_forget_options(cups_option_t *options)
{
  size_t index;

  for (index = 0U; index < cf_v3_pclx_options_count; index ++)
    if (cf_v3_pclx_options[index].options == options)
    {
      cf_v3_pclx_options[index] =
          cf_v3_pclx_options[--cf_v3_pclx_options_count];
      memset(&cf_v3_pclx_options[cf_v3_pclx_options_count], 0,
             sizeof(cf_v3_pclx_options[0]));
      return;
    }
}

static void
cf_v3_pclx_remember_options(cups_option_t *options, int count)
{
  size_t index;

  if (!cf_v3_pclx_lifecycle_active || !options)
    return;
  for (index = 0U; index < cf_v3_pclx_options_count; index ++)
    if (cf_v3_pclx_options[index].options == options)
    {
      cf_v3_pclx_options[index].count = count;
      return;
    }
  if (cf_v3_pclx_options_count < CF_V3_PCLX_OPTIONS_MAX)
    cf_v3_pclx_options[cf_v3_pclx_options_count ++] =
        (cf_v3_pclx_options_t){options, count};
}

int
__wrap_cupsParseOptions(const char *arg, int num_options,
                        cups_option_t **options)
{
  cups_option_t *initial = options ? *options : NULL;
  int result;

  cf_v3_pclx_forget_options(initial);
  result = __real_cupsParseOptions(arg, num_options, options);
  if (options)
    cf_v3_pclx_remember_options(*options, result);
  return result;
}

int
__wrap_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data, int num_options,
                                cups_option_t **options)
{
  cups_option_t *initial = options ? *options : NULL;
  cf_filter_data_t initialized;
  cf_filter_data_t *effective = data;
  int result;

  if (cf_v3_pclx_lifecycle_active && !cf_v3_pclx_lifecycle_faithful)
  {
    memset(&initialized, 0, sizeof(initialized));
    if (data)
    {
      initialized.printer = data->printer;
      initialized.logfunc = data->logfunc;
      initialized.logdata = data->logdata;
    }
    effective = &initialized;
  }
  cf_v3_pclx_forget_options(initial);
  result = __real_cfJoinJobOptionsAndAttrs(effective, num_options, options);
  if (options)
    cf_v3_pclx_remember_options(*options, result);
  return result;
}

void
__wrap_cupsFreeOptions(int num_options, cups_option_t *options)
{
  cf_v3_pclx_forget_options(options);
  __real_cupsFreeOptions(num_options, options);
}

void
cf_v3_pclx_state_lifecycle_begin(int faithful)
{
  memset(cf_v3_pclx_options, 0, sizeof(cf_v3_pclx_options));
  cf_v3_pclx_options_count = 0U;
  cf_v3_pclx_lifecycle_faithful = faithful;
  cf_v3_pclx_lifecycle_active = 1;
}

void
cf_v3_pclx_state_lifecycle_end(void)
{
  cf_v3_pclx_lifecycle_active = 0;
  if (cf_v3_pclx_lifecycle_faithful)
  {
    memset(cf_v3_pclx_options, 0, sizeof(cf_v3_pclx_options));
    cf_v3_pclx_options_count = 0U;
    return;
  }
  while (cf_v3_pclx_options_count)
  {
    cf_v3_pclx_options_t *owner =
        &cf_v3_pclx_options[--cf_v3_pclx_options_count];

    __real_cupsFreeOptions(owner->count, owner->options);
    memset(owner, 0, sizeof(*owner));
  }
}
