// SPDX-License-Identifier: Apache-2.0
#include "ps_route.h"
#include "ps_wrapper_bridge.h"

#include <cups/cups.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

extern pid_t __real_fork(void);
extern void __real_exit(int) __attribute__((noreturn));
extern const char *__real_cupsGetOption(const char *, int,
                                        cups_option_t *);

extern pid_t cf_v3_ps_page_wrap_fork(void);
extern void cf_v3_ps_page_wrap_exit(int) __attribute__((noreturn));
extern pid_t cf_v3_ps_sequence_legacy_wrap_fork(void);
extern void cf_v3_ps_sequence_legacy_wrap_exit(int)
    __attribute__((noreturn));
extern pid_t cf_v3_ps_sequence_deep_legacy_wrap_fork(void);
extern void cf_v3_ps_sequence_deep_legacy_wrap_exit(int)
    __attribute__((noreturn));

static unsigned cf_v3_ps_active_route = UINT_MAX;
static int cf_v3_ps_active_faithful;

void
cf_v3_ps_wrapper_enter(unsigned route, int faithful)
{
  cf_v3_ps_active_route = route;
  cf_v3_ps_active_faithful = faithful;
}

void
cf_v3_ps_wrapper_leave(void)
{
  cf_v3_ps_active_route = UINT_MAX;
  cf_v3_ps_active_faithful = 0;
}

const char *
__wrap_cupsGetOption(const char *name, int num_options,
                     cups_option_t *options)
{
  if (!cf_v3_ps_active_faithful &&
      cf_v3_ps_active_route >= CF_V3_PS_ROUTE_PAGE_RANGE_EOF &&
      cf_v3_ps_active_route <= CF_V3_PS_ROUTE_SEQUENCE_DEEP && name &&
      !strcmp(name, "input-page-ranges"))
    return NULL;
  return __real_cupsGetOption(name, num_options, options);
}

pid_t
__wrap_fork(void)
{
  switch (cf_v3_ps_active_route)
  {
    case CF_V3_PS_ROUTE_PAGE_RANGE_EOF:
      return cf_v3_ps_page_wrap_fork();
    case CF_V3_PS_ROUTE_SEQUENCE:
      return cf_v3_ps_sequence_legacy_wrap_fork();
    case CF_V3_PS_ROUTE_SEQUENCE_DEEP:
      return cf_v3_ps_sequence_deep_legacy_wrap_fork();
    default:
      return __real_fork();
  }
}

void
__wrap_exit(int status)
{
  switch (cf_v3_ps_active_route)
  {
    case CF_V3_PS_ROUTE_PAGE_RANGE_EOF:
      cf_v3_ps_page_wrap_exit(status);
    case CF_V3_PS_ROUTE_SEQUENCE:
      cf_v3_ps_sequence_legacy_wrap_exit(status);
    case CF_V3_PS_ROUTE_SEQUENCE_DEEP:
      cf_v3_ps_sequence_deep_legacy_wrap_exit(status);
    default:
      __real_exit(status);
  }
}
