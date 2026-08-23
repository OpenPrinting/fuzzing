// SPDX-License-Identifier: Apache-2.0
#include "../include/direct_route.h"
#include "../include/job.h"

#include <stddef.h>
#include <stdint.h>

#ifndef CF_V2_JOB_MAX_PPD
#define CF_V2_JOB_MAX_PPD (256U * 1024U)
#endif
#ifndef CF_V2_JOB_MAX_OPTIONS
#define CF_V2_JOB_MAX_OPTIONS (16U * 1024U)
#endif
#ifndef CF_V2_JOB_MAX_TITLE
#define CF_V2_JOB_MAX_TITLE (4U * 1024U)
#endif
#ifndef CF_V2_JOB_MAX_DOCUMENT
#define CF_V2_JOB_MAX_DOCUMENT (4U * 1024U * 1024U)
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_job_input_t input;
  cf_v2_run_result_t result;

  if (!cf_v2_parse_job_input(data, size, CF_V2_JOB_MAX_PPD,
                             CF_V2_JOB_MAX_OPTIONS, CF_V2_JOB_MAX_TITLE,
                             CF_V2_JOB_MAX_DOCUMENT, &input)) {
    return 0;
  }
  (void)cf_v2_execute_direct_job(&input, 0, &result);
  cf_v2_free_run_result(&result);
  return 0;
}
