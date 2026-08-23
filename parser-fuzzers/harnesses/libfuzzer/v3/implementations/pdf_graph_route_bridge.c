// SPDX-License-Identifier: Apache-2.0
#include "pdf_graph_route.h"
#include "pdf_graph_route_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cf_v3_pdf_graph_runner_t)(const uint8_t *, size_t);

extern int cf_v3_pdf_graph_annotation_direct_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_booklet_empty_direct_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_layout_direct_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_nup_direct_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_object_valid_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_page_layout_valid_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_booklet_order_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_nup_order_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_remap_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_continuation_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_value_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_cross_type_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_refill_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_lexical_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_resource_long_name_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_ascii85_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_annotation_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_flatten_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_output_capacity_legacy(const uint8_t *, size_t);
extern int cf_v3_pdf_graph_parent_legacy(const uint8_t *, size_t);

static int
cf_v3_pdf_graph_call(unsigned route, int faithful,
                     cf_v3_pdf_graph_runner_t runner,
                     const uint8_t *data, size_t size)
{
  int result = runner(data, size);

  if (getenv("CF_V3_TRACE_ROUTE"))
    fprintf(stderr, "pdf_to_pdf_graph route=%u faithful=%d input=%zu\n",
            route, faithful, size);
  return result;
}

static int
cf_v3_pdf_graph_pack(unsigned route, int faithful,
                     const char magic[8], size_t selector_size,
                     size_t max_material, cf_v3_pdf_graph_runner_t runner,
                     const uint8_t *header, const uint8_t *material,
                     size_t material_size)
{
  size_t payload_size = material_size < max_material ?
      material_size : max_material;
  size_t input_size;
  uint8_t *input;
  int result;

  if (!payload_size || selector_size > CF_V3_PDF_GRAPH_HEADER_SIZE)
    return 0;
  input_size = 8U + selector_size + payload_size;
  input = (uint8_t *)malloc(input_size);
  if (!input)
    return 0;
  memcpy(input, magic, 8U);
  memcpy(input + 8U, header, selector_size);
  memcpy(input + 8U + selector_size, material, payload_size);
  result = cf_v3_pdf_graph_call(route, faithful, runner, input, input_size);
  free(input);
  return result;
}

static int
cf_v3_pdf_graph_pack_relation(
    unsigned route, int faithful, cf_v3_pdf_graph_runner_t runner,
    const uint8_t *header, const uint8_t *material, size_t material_size)
{
  uint8_t selectors[8];
  size_t payload_size = material_size < 64U ? material_size : 64U;
  uint8_t input[8U + 8U + 64U];

  if (!payload_size)
    return 0;
  memcpy(selectors, header, sizeof(selectors));
  selectors[4] = faithful ? 2U : (uint8_t)(header[4] & 1U);
  memcpy(input, "PDFGRPH1", 8U);
  memcpy(input + 8U, selectors, sizeof(selectors));
  memcpy(input + 16U, material, payload_size);
  return cf_v3_pdf_graph_call(route, faithful, runner,
                              input, 16U + payload_size);
}

static int
cf_v3_pdf_graph_direct_or_safe(
    unsigned route, int faithful, cf_v3_pdf_graph_runner_t direct_runner,
    cf_v3_pdf_graph_runner_t safe_runner, const char safe_magic[8],
    size_t safe_selectors, size_t safe_material,
    const uint8_t *header, const uint8_t *material, size_t material_size)
{
  if (faithful)
    return cf_v3_pdf_graph_call(route, 1, direct_runner,
                                material, material_size);
  return cf_v3_pdf_graph_pack(route, 0, safe_magic, safe_selectors,
                              safe_material, safe_runner,
                              header, material, material_size);
}

int
cf_v3_pdf_graph_run(const uint8_t *header, const uint8_t *material,
                    size_t material_size)
{
  const unsigned route = cf_v3_pdf_graph_route(header);
  const int faithful = cf_v3_pdf_graph_faithful(header);

  switch (route)
  {
    case CF_V3_PDF_GRAPH_ROUTE_ANNOTATION_DIRECT:
      if (faithful)
        return cf_v3_pdf_graph_call(
            route, 1, cf_v3_pdf_graph_annotation_direct_legacy,
            material, material_size);
      return cf_v3_pdf_graph_pack_relation(
          route, 0, cf_v3_pdf_graph_annotation_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_BOOKLET_EMPTY_DIRECT:
      return cf_v3_pdf_graph_direct_or_safe(
          route, faithful, cf_v3_pdf_graph_booklet_empty_direct_legacy,
          cf_v3_pdf_graph_booklet_order_legacy, "P2PBOOK1", 8U, 256U,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_LAYOUT_DIRECT:
      return cf_v3_pdf_graph_direct_or_safe(
          route, faithful, cf_v3_pdf_graph_layout_direct_legacy,
          cf_v3_pdf_graph_page_layout_valid_legacy, "P2PLAY01", 24U,
          4096U, header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_OBJECT_VALID:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2POBJ01", 24U, 4096U,
          cf_v3_pdf_graph_object_valid_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_PAGE_LAYOUT_VALID:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PLAY01", 24U, 4096U,
          cf_v3_pdf_graph_page_layout_valid_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_BOOKLET_ORDER:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PBOOK1", 8U, 256U,
          cf_v3_pdf_graph_booklet_order_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_NUP_ORDER:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PNUP01", 8U, 256U,
          cf_v3_pdf_graph_nup_order_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_REMAP:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PRES01", 10U, 256U,
          faithful ? cf_v3_pdf_graph_resource_remap_legacy :
                     cf_v3_pdf_graph_resource_continuation_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_CONTINUATION:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PRES01", 10U, 256U,
          cf_v3_pdf_graph_resource_continuation_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_VALUE:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PVAL01", 8U, 128U,
          cf_v3_pdf_graph_resource_value_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_CROSS_TYPE:
      return cf_v3_pdf_graph_pack(
          route, faithful, faithful ? "P2PXTY01" : "P2PVAL01", 8U, 128U,
          faithful ? cf_v3_pdf_graph_resource_cross_type_legacy :
                     cf_v3_pdf_graph_resource_value_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_REFILL:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PREF01", 10U, 256U,
          cf_v3_pdf_graph_resource_refill_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_LEXICAL:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PRES01", 10U, 256U,
          faithful ? cf_v3_pdf_graph_resource_lexical_legacy :
                     cf_v3_pdf_graph_resource_continuation_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_RESOURCE_LONG_NAME:
      return cf_v3_pdf_graph_pack(
          route, faithful, "P2PRES01", 10U, 256U,
          faithful ? cf_v3_pdf_graph_resource_long_name_legacy :
                     cf_v3_pdf_graph_resource_continuation_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_NUP_DIRECT:
      return cf_v3_pdf_graph_direct_or_safe(
          route, faithful, cf_v3_pdf_graph_nup_direct_legacy,
          cf_v3_pdf_graph_nup_order_legacy, "P2PNUP01", 8U, 256U,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_ASCII85_RELATION:
      return cf_v3_pdf_graph_pack_relation(
          route, faithful, cf_v3_pdf_graph_ascii85_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_ANNOTATION_RELATION:
      return cf_v3_pdf_graph_pack_relation(
          route, faithful, cf_v3_pdf_graph_annotation_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_FLATTEN_RELATION:
      return cf_v3_pdf_graph_pack_relation(
          route, faithful, cf_v3_pdf_graph_flatten_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_OUTPUT_CAPACITY_RELATION:
      return cf_v3_pdf_graph_pack_relation(
          route, faithful, cf_v3_pdf_graph_output_capacity_legacy,
          header, material, material_size);
    case CF_V3_PDF_GRAPH_ROUTE_PARENT_RELATION:
      return cf_v3_pdf_graph_pack_relation(
          route, faithful, cf_v3_pdf_graph_parent_legacy,
          header, material, material_size);
    default:
      return 0;
  }
}
