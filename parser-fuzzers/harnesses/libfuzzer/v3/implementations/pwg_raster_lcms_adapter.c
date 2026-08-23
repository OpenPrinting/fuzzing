// SPDX-License-Identifier: Apache-2.0
#include "pwg_raster_lcms_adapter.h"

#include <lcms2.h>

#include <stddef.h>

#define CF_V3_PWG_RASTER_TONE_CURVES 32U

static cmsToneCurve *
    cf_v3_pwg_raster_tone_curves[CF_V3_PWG_RASTER_TONE_CURVES];
static size_t cf_v3_pwg_raster_tone_curve_count;
static int cf_v3_pwg_raster_lcms_active;
static int cf_v3_pwg_raster_lcms_overflow;

extern cmsToneCurve *__real_cmsBuildGamma(cmsContext context,
                                          cmsFloat64Number gamma);
extern void __real_cmsFreeToneCurve(cmsToneCurve *curve);

static void
cf_v3_pwg_raster_forget_curve(cmsToneCurve *curve)
{
  for (size_t index = 0U; index < cf_v3_pwg_raster_tone_curve_count; index ++)
  {
    if (cf_v3_pwg_raster_tone_curves[index] != curve)
      continue;
    cf_v3_pwg_raster_tone_curves[index] =
        cf_v3_pwg_raster_tone_curves[--cf_v3_pwg_raster_tone_curve_count];
    cf_v3_pwg_raster_tone_curves[cf_v3_pwg_raster_tone_curve_count] = NULL;
    return;
  }
}

cmsToneCurve *
__wrap_cmsBuildGamma(cmsContext context, cmsFloat64Number gamma)
{
  cmsToneCurve *curve = __real_cmsBuildGamma(context, gamma);

  if (cf_v3_pwg_raster_lcms_active && curve)
  {
    if (cf_v3_pwg_raster_tone_curve_count < CF_V3_PWG_RASTER_TONE_CURVES)
      cf_v3_pwg_raster_tone_curves[cf_v3_pwg_raster_tone_curve_count ++] =
          curve;
    else
      cf_v3_pwg_raster_lcms_overflow = 1;
  }
  return curve;
}

void
__wrap_cmsFreeToneCurve(cmsToneCurve *curve)
{
  cf_v3_pwg_raster_forget_curve(curve);
  __real_cmsFreeToneCurve(curve);
}

void
cf_v3_pwg_raster_lcms_begin(void)
{
  cf_v3_pwg_raster_lcms_overflow = 0;
  cf_v3_pwg_raster_lcms_active = 1;
}

void
cf_v3_pwg_raster_lcms_end(void)
{
  cf_v3_pwg_raster_lcms_active = 0;
  while (cf_v3_pwg_raster_tone_curve_count)
  {
    cmsToneCurve *curve = cf_v3_pwg_raster_tone_curves[
        --cf_v3_pwg_raster_tone_curve_count];

    cf_v3_pwg_raster_tone_curves[cf_v3_pwg_raster_tone_curve_count] = NULL;
    __real_cmsFreeToneCurve(curve);
  }
}

int
cf_v3_pwg_raster_lcms_overflowed(void)
{
  return cf_v3_pwg_raster_lcms_overflow;
}
