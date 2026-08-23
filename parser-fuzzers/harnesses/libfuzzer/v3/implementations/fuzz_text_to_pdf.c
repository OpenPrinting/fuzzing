// SPDX-License-Identifier: Apache-2.0
#include "text_pdf_lifecycle.h"
#include "text_pdf_route.h"
#include "text_pdf_route_bridge.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  int result;

  if (!cf_v3_text_pdf_input(data, size))
    return 0;
  cf_v3_text_pdf_lifecycle_begin();
  result = cf_v3_text_pdf_run(
      cf_v3_text_pdf_const_header(data),
      data + CF_V3_TEXT_PDF_FIXED_SIZE,
      size - CF_V3_TEXT_PDF_FIXED_SIZE);
  cf_v3_text_pdf_lifecycle_end();
  return result;
}
