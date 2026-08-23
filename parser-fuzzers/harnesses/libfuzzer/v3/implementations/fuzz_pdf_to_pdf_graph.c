// SPDX-License-Identifier: Apache-2.0
#include "pdf_filter_lifecycle.h"
#include "pdf_graph_route.h"
#include "pdf_graph_route_bridge.h"

#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const uint8_t *header;
  int result;

  if (!cf_v3_pdf_graph_input(data, size))
    return 0;
  header = cf_v3_pdf_graph_const_header(data);
  cf_v3_pdf_filter_lifecycle_begin(cf_v3_pdf_graph_faithful(header));
  result = cf_v3_pdf_graph_run(
      header, data + CF_V3_PDF_GRAPH_FIXED_SIZE,
      size - CF_V3_PDF_GRAPH_FIXED_SIZE);
  cf_v3_pdf_filter_lifecycle_end();
  return result;
}
