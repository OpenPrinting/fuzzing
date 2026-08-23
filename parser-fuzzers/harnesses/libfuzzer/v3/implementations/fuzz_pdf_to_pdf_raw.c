// SPDX-License-Identifier: Apache-2.0
#include "pdf_filter_lifecycle.h"
#include "pdf_raw_route.h"
#include "pdf_raw_route_bridge.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static const uint8_t compatibility_header[CF_V3_PDF_RAW_HEADER_SIZE] = {0};
  const uint8_t *header;
  const uint8_t *material;
  size_t material_size;
  int compatibility_input;
  int result;

  if (!data || !size)
    return 0;
  compatibility_input = !cf_v3_pdf_raw_input(data, size);
  if (!compatibility_input)
  {
    header = cf_v3_pdf_raw_const_header(data);
    material = data + CF_V3_PDF_RAW_FIXED_SIZE;
    material_size = size - CF_V3_PDF_RAW_FIXED_SIZE;
  }
  else
  {
    if (size > CF_V3_PDF_RAW_MAX_MATERIAL)
      return 0;
    /* Keep the established OSS-Fuzz fuzz_pdf corpus as raw PDF bytes. */
    header = compatibility_header;
    material = data;
    material_size = size;
  }
  /* Raw OSS-Fuzz inputs need generated controls, but arbitrary malloc
   * ownership cannot be inferred across library-global caches. */
  cf_v3_pdf_filter_lifecycle_begin(cf_v3_pdf_raw_faithful(header));
  result = cf_v3_pdf_raw_run(header, material, material_size);
  cf_v3_pdf_filter_lifecycle_end();
  return result;
}
