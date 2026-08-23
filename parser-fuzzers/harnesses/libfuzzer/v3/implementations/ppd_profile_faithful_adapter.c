// SPDX-License-Identifier: Apache-2.0
#define LLVMFuzzerTestOneInput cf_v3_ppd_profile_faithful_raw
#define LIBPPD_PROFILES_MAX_INPUT (32U * 1024U)
#include "../../fuzz_libppd_profiles.c"
#undef LIBPPD_PROFILES_MAX_INPUT
#undef LLVMFuzzerTestOneInput
