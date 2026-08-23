// SPDX-License-Identifier: Apache-2.0
/*
 * V2 gives the mature packed-Raster grammar a stable state-machine target
 * identity while keeping its implementation shared with the original lane.
 */
#include "../../fuzz_cupsfilters_packed_raster_semantic.c"

#ifdef CF_V2_FILTER_DATA_CONTINUATION
extern int __real_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data,
                                            int num_options,
                                            cups_option_t **options);

int __wrap_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data, int num_options,
                                    cups_option_t **options) {
  cf_filter_data_t initialized;

  memset(&initialized, 0, sizeof(initialized));
  if (data) {
    initialized.printer = data->printer;
    initialized.logfunc = data->logfunc;
    initialized.logdata = data->logdata;
  }
  return __real_cfJoinJobOptionsAndAttrs(&initialized, num_options, options);
}
#endif
