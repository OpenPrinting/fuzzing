// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V3_PDF_GRAPH_ROUTE_BRIDGE_H
#define CUPSFILTERS_FUZZ_V3_PDF_GRAPH_ROUTE_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

int cf_v3_pdf_graph_run(const uint8_t *header, const uint8_t *material,
                        size_t material_size);

#endif
