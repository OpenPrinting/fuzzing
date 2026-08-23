// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PDF_FILTER_LIFECYCLE_H
#define CUPSFILTERS_FUZZ_V3_PDF_FILTER_LIFECYCLE_H

#include <stddef.h>

void *cf_v3_pdf_filter_malloc(size_t size);
void cf_v3_pdf_filter_free(void *pointer);
void cf_v3_pdf_filter_lifecycle_begin(int faithful);
void cf_v3_pdf_filter_lifecycle_end(void);

#endif
