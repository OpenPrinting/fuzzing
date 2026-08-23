// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PWG_FILTER_ADAPTER_H
#define CUPSFILTERS_FUZZ_V3_PWG_FILTER_ADAPTER_H

#include <cupsfilters/filter.h>

int cf_v3_pwg_filter(int inputfd, int outputfd, int inputseekable,
                     cf_filter_data_t *data, void *parameters);
int cf_v3_pwg_post_ppd_load(cf_filter_data_t *data);
void cf_v3_pwg_filter_release(void);
int cf_v3_pwg_filter_tracker_overflowed(void);

#endif
