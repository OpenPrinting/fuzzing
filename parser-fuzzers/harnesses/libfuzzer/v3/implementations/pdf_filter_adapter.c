// SPDX-License-Identifier: Apache-2.0
#include "pdf_filter_lifecycle.h"

#include <stdlib.h>

/* Track only allocations made by the filter implementation. Library and
 * sanitizer runtimes may retain process-lifetime allocations legitimately. */
#define malloc cf_v3_pdf_filter_malloc
#define free cf_v3_pdf_filter_free
#include <cupsfilters/pdftopdf.c>
#undef free
#undef malloc
