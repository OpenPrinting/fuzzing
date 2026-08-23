// SPDX-License-Identifier: Apache-2.0
#include "raster_pwg_route.h"
#include "raster_pwg_wrapper_bridge.h"

#include <cups/raster.h>

#include <limits.h>

extern unsigned __real_cupsRasterWriteHeader2(cups_raster_t *,
                                               cups_page_header2_t *);
extern unsigned cf_v3_raster_pwg_backside_pwg_write_header(
    cups_raster_t *, cups_page_header2_t *);
extern unsigned cf_v3_raster_pwg_backside_apple_write_header(
    cups_raster_t *, cups_page_header2_t *);
extern unsigned cf_v3_raster_pwg_backside_native_write_header(
    cups_raster_t *, cups_page_header2_t *);
extern unsigned cf_v3_raster_pwg_backside_manual_write_header(
    cups_raster_t *, cups_page_header2_t *);
extern unsigned cf_v3_raster_pwg_metadata_write_header(
    cups_raster_t *, cups_page_header2_t *);
extern unsigned cf_v3_raster_pwg_name_write_header(
    cups_raster_t *, cups_page_header2_t *);

static unsigned cf_v3_raster_pwg_active_route = UINT_MAX;

void
cf_v3_raster_pwg_wrapper_enter(unsigned route)
{
  cf_v3_raster_pwg_active_route = route;
}

void
cf_v3_raster_pwg_wrapper_leave(void)
{
  cf_v3_raster_pwg_active_route = UINT_MAX;
}

unsigned
__wrap_cupsRasterWriteHeader2(cups_raster_t *raster,
                              cups_page_header2_t *header)
{
  switch (cf_v3_raster_pwg_active_route)
  {
    case CF_V3_RASTER_PWG_ROUTE_BACKSIDE_PWG:
      return cf_v3_raster_pwg_backside_pwg_write_header(raster, header);
    case CF_V3_RASTER_PWG_ROUTE_BACKSIDE_APPLE:
      return cf_v3_raster_pwg_backside_apple_write_header(raster, header);
    case CF_V3_RASTER_PWG_ROUTE_BACKSIDE_NATIVE_BOUNDARY:
      return cf_v3_raster_pwg_backside_native_write_header(raster, header);
    case CF_V3_RASTER_PWG_ROUTE_BACKSIDE_MANUAL_BOUNDARY:
      return cf_v3_raster_pwg_backside_manual_write_header(raster, header);
    case CF_V3_RASTER_PWG_ROUTE_METADATA:
      return cf_v3_raster_pwg_metadata_write_header(raster, header);
    case CF_V3_RASTER_PWG_ROUTE_PAGE_NAME:
      return cf_v3_raster_pwg_name_write_header(raster, header);
    default:
      return __real_cupsRasterWriteHeader2(raster, header);
  }
}
