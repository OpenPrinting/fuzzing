// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_IMAGE_PDF_ORACLE_H
#define CUPSFILTERS_FUZZ_V3_IMAGE_PDF_ORACLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CF_V3_IMAGE_PDF_ORACLE_MAX_PAGES 64U

typedef struct cf_v3_image_pdf_oracle_s {
  const uint8_t *pixels;
  size_t pixel_size;
  unsigned width;
  unsigned height;
  unsigned components;
  unsigned xpages;
  unsigned ypages;
  long double page_width;
  long double page_height;
  int pages[CF_V3_IMAGE_PDF_ORACLE_MAX_PAGES];
  size_t page_count;
  bool exact_pixels;
} cf_v3_image_pdf_oracle_t;

bool cf_v3_image_pdf_validate(const uint8_t *pdf_bytes, size_t pdf_size,
                              const cf_v3_image_pdf_oracle_t *expect,
                              const char **failure);

#endif
