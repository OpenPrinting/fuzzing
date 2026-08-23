// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

static int cf_v2_pclm_graph_close_stream = 1;
#define CUPSFILTERS_PCLM_SHOULD_CLOSE_TRACKED_STREAM() (cf_v2_pclm_graph_close_stream)
#define CUPSFILTERS_PCLM_SEMANTIC_ORACLE_SUPPORT_ONLY
#include "../../fuzz_cupsfilters_pclmtoraster_semantic_oracle.c"

#include "../include/pclm_graph_relation.h"
#include "../parsers/pdf-to-pdf/pdf_graph_builder.h"

#include <zlib.h>

#ifndef CF_V2_TARGET_NAME
#define CF_V2_TARGET_NAME "fuzz_v2_cupsfilters_boundary_pclm_graph_lifecycle"
#endif

typedef struct cf_v2_pclm_graph_plan_s {
  size_t pages;
  size_t xobjects;
  size_t selected_slot;
  uint32_t reference_id;
  int close_after_read;
} cf_v2_pclm_graph_plan_t;

static cf_v2_relation_stats_t cf_v2_pclm_graph_stats;

static int
cf_v2_pclm_graph_supported_rotation(int64_t rotate)
{
  return rotate == 0 || rotate == 90 || rotate == 180 || rotate == 270;
}

static void
cf_v2_pclm_graph_apply_actions(
    const cf_v2_pclm_graph_relation_t *graph,
    cf_v2_pclm_graph_plan_t *plan,
    cf_v2_relation_stats_t *stats)
{
  cf_v2_action_program_t program = graph->actions;
  cf_v2_action_t action;

  while (cf_v2_action_program_next(&program, &action)) {
    size_t repetitions = action.repetitions;

    cf_v2_relation_stats_action(stats, action.kind);
    switch (action.kind) {
      case CF_V2_ACTION_PARSE:
        plan->pages = repetitions > 3U ? 3U : repetitions;
        break;
      case CF_V2_ACTION_SELECT:
        plan->selected_slot =
            plan->xobjects ? action.argument % plan->xobjects : 0U;
        break;
      case CF_V2_ACTION_EMIT:
        plan->xobjects = repetitions > 4U ? 4U : repetitions;
        if (plan->xobjects && plan->selected_slot >= plan->xobjects)
          plan->selected_slot %= plan->xobjects;
        break;
      case CF_V2_ACTION_READ:
        plan->close_after_read = 0;
        break;
      case CF_V2_ACTION_FINISH:
        plan->close_after_read = 1;
        break;
      default:
        break;
    }
  }
}

static void
cf_v2_pclm_graph_record_actions(
    const cf_v2_pclm_graph_relation_t *graph,
    cf_v2_relation_stats_t *stats)
{
  cf_v2_action_program_t program = graph->actions;
  cf_v2_action_t action;

  while (cf_v2_action_program_next(&program, &action))
    cf_v2_relation_stats_action(stats, action.kind);
}

static cf_v2_object_kind_t
cf_v2_pclm_graph_default_kind(uint32_t object_id)
{
  static const cf_v2_object_kind_t kinds[] = {
    CF_V2_OBJECT_STREAM,
    CF_V2_OBJECT_DICTIONARY,
    CF_V2_OBJECT_ARRAY,
    CF_V2_OBJECT_SCALAR,
    CF_V2_OBJECT_NULL,
    CF_V2_OBJECT_OPAQUE,
  };

  return kinds[(object_id - CF_V2_PCLM_GRAPH_FIRST_POOL_OBJECT) %
               CF_V2_PCLM_GRAPH_POOL_OBJECTS];
}

static int
cf_v2_pclm_graph_make_pixels(const cf_v2_pclm_graph_relation_t *graph,
                             size_t image_bytes, uint8_t **pixels_out)
{
  size_t opaque_size = cf_v2_length_relation_value(&graph->opaque_length);
  uint8_t *pixels;

  if (opaque_size > graph->opaque.size)
    opaque_size = graph->opaque.size;
  if (image_bytes > CF_V2_PCLM_GRAPH_MAX_MATERIAL)
    image_bytes = CF_V2_PCLM_GRAPH_MAX_MATERIAL;
  if (!image_bytes) {
    *pixels_out = NULL;
    return 1;
  }
  if (!(pixels = (uint8_t *)malloc(image_bytes)))
    return 0;
  for (size_t index = 0U; index < image_bytes; index++) {
    uint8_t value =
        opaque_size ?
            graph->opaque.data[(index + graph->material_phase) % opaque_size] :
            (uint8_t)(index + graph->material_phase);
    pixels[index] = value;
  }
  *pixels_out = pixels;
  return 1;
}

static int
cf_v2_pclm_graph_prepare_stream(
    const cf_v2_pclm_graph_relation_t *graph,
    const uint8_t *pixels, size_t pixel_bytes,
    uint8_t **stream_out, size_t *stream_size_out,
    int *flate_out)
{
  int encoding = (int)cf_v2_scalar_relation_value(&graph->encoding);
  uint8_t *stream = NULL;
  size_t stream_size = pixel_bytes;
  int flate = encoding != 0;

  if (encoding == 1) {
    uLongf capacity = compressBound((uLong)pixel_bytes);

    if (!(stream = (uint8_t *)malloc((size_t)capacity)) ||
        compress2(stream, &capacity, pixels, (uLong)pixel_bytes,
                  Z_BEST_SPEED) != Z_OK) {
      free(stream);
      return 0;
    }
    stream_size = (size_t)capacity;
  } else {
    if (stream_size && !(stream = (uint8_t *)malloc(stream_size)))
      return 0;
    if (stream_size)
      memcpy(stream, pixels, stream_size);
  }

  *stream_out = stream;
  *stream_size_out = stream_size;
  *flate_out = flate;
  return 1;
}

static int
cf_v2_pclm_graph_emit_pool_object(
    cf_v2_pdf_graph_writer_t *writer, uint32_t object_id,
    cf_v2_object_kind_t kind, const cf_v2_pclm_graph_relation_t *graph,
    const uint8_t *stream, size_t stream_size, int flate)
{
  if (!cf_v2_pdf_graph_begin_object(writer, object_id))
    return 0;
  switch (kind) {
    case CF_V2_OBJECT_NULL:
      CF_V2_PDF_GRAPH_LITERAL(writer, "null\n");
      break;
    case CF_V2_OBJECT_SCALAR:
      CF_V2_PDF_GRAPH_LITERAL(writer, "42\n");
      break;
    case CF_V2_OBJECT_DICTIONARY:
      CF_V2_PDF_GRAPH_LITERAL(writer, "<< /Type /Other >>\n");
      break;
    case CF_V2_OBJECT_ARRAY:
      CF_V2_PDF_GRAPH_LITERAL(writer, "[0 1 2]\n");
      break;
    case CF_V2_OBJECT_STREAM:
      if (!cf_v2_pdf_graph_printf(
              writer,
              "<< /Type /image /Subtype /Image /Width %u /Height %u "
              "/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length %zu%s >>\n"
              "stream\n",
              graph->width, graph->height, stream_size,
              flate ? " /Filter /FlateDecode" : "") ||
          !cf_v2_pdf_graph_append(writer, stream, stream_size) ||
          !CF_V2_PDF_GRAPH_LITERAL(writer, "\nendstream\n"))
        return 0;
      break;
    case CF_V2_OBJECT_OPAQUE:
      if (!CF_V2_PDF_GRAPH_LITERAL(writer, "<"))
        return 0;
      for (size_t index = 0U; index < graph->opaque.size && index < 64U;
           index++) {
        if (!cf_v2_pdf_graph_printf(writer, "%02x",
                                    graph->opaque.data[index]))
          return 0;
      }
      if (!CF_V2_PDF_GRAPH_LITERAL(writer, ">\n"))
        return 0;
      break;
    default:
      return 0;
  }
  return cf_v2_pdf_graph_end_object(writer);
}

static uint8_t *
cf_v2_pclm_graph_build(const cf_v2_pclm_graph_relation_t *graph,
                       const cf_v2_pclm_graph_plan_t *plan,
                       size_t *document_size)
{
  cf_v2_pdf_graph_writer_t writer;
  uint8_t *pixels = NULL;
  uint8_t *stream = NULL;
  uint8_t *document = NULL;
  size_t image_bytes = cf_v2_length_relation_value(&graph->image_bytes);
  size_t stream_size = 0U;
  int flate = 0;

  if (image_bytes > CF_V2_PCLM_GRAPH_MAX_MATERIAL)
    image_bytes = CF_V2_PCLM_GRAPH_MAX_MATERIAL;
  if (!cf_v2_pclm_graph_make_pixels(graph, image_bytes, &pixels) ||
      !cf_v2_pclm_graph_prepare_stream(
          graph, pixels, image_bytes, &stream, &stream_size, &flate) ||
      !cf_v2_pdf_graph_init(&writer, CF_V2_PCLM_GRAPH_OBJECT_COUNT))
    goto done;

  cf_v2_pdf_graph_begin_object(&writer, 1U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Type /Catalog /Pages 2 0 R >>\n");
  cf_v2_pdf_graph_end_object(&writer);

  cf_v2_pdf_graph_begin_object(&writer, 2U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Type /Pages /Kids [");
  for (size_t page = 0U; page < plan->pages; page++)
    cf_v2_pdf_graph_printf(&writer, "%zu 0 R ", 3U + page);
  cf_v2_pdf_graph_printf(
      &writer,
      "] /Count %zu /MediaBox [0 0 612 792] >>\n",
      plan->pages);
  cf_v2_pdf_graph_end_object(&writer);

  for (size_t page = 0U; page < 3U; page++) {
    cf_v2_pdf_graph_begin_object(&writer, 3U + page);
    cf_v2_pdf_graph_printf(
        &writer,
        "<< /Type /Page /Parent 2 0 R /Rotate %" PRId64 " "
        "/Resources << /XObject << ",
        cf_v2_scalar_relation_value(&graph->rotate));
    for (size_t index = 0U; index < plan->xobjects; index++) {
      uint32_t reference =
          index == plan->selected_slot ? plan->reference_id :
                                         CF_V2_PCLM_GRAPH_FIRST_POOL_OBJECT;
      cf_v2_pdf_graph_printf(
          &writer, "/Strip%02zu %u 0 R ", index, reference);
    }
    CF_V2_PDF_GRAPH_LITERAL(
        &writer, ">> >> /Contents 6 0 R >>\n");
    cf_v2_pdf_graph_end_object(&writer);
  }

  cf_v2_pdf_graph_begin_object(&writer, 6U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Length 4 >>\nstream\nq Q\nendstream\n");
  cf_v2_pdf_graph_end_object(&writer);

  for (uint32_t object_id = CF_V2_PCLM_GRAPH_FIRST_POOL_OBJECT;
       object_id <= CF_V2_PCLM_GRAPH_OBJECT_COUNT; object_id++) {
    cf_v2_object_kind_t kind =
        object_id == graph->object.object_id ?
            graph->object.kind :
            cf_v2_pclm_graph_default_kind(object_id);
    if (!cf_v2_pclm_graph_emit_pool_object(
            &writer, object_id, kind, graph,
            stream, stream_size, flate))
      goto discard;
  }

  document = cf_v2_pdf_graph_finish(&writer, 1U, document_size);
  if (!document)
    goto discard;
  goto done;

discard:
  cf_v2_pdf_graph_discard(&writer);
done:
  free(stream);
  free(pixels);
  return document;
}

static int
cf_v2_pclm_graph_write_all(int fd, const uint8_t *data, size_t size)
{
  size_t offset = 0U;

  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);

    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return 0;
    offset += (size_t)written;
  }
  return lseek(fd, 0, SEEK_SET) >= 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  cf_v2_pclm_graph_relation_t graph;
  cf_v2_pclm_graph_plan_t plan;
  cf_filter_data_t filter_data;
  cf_filter_out_format_t output_format = CF_FILTER_OUT_FORMAT_CUPS_RASTER;
  cups_page_header_t sample_header;
  uint8_t *document = NULL;
  size_t document_size = 0U;
  char input_name[] = "/tmp/pclm-graph-input.XXXXXX";
  char output_name[] = "/tmp/pclm-graph-output.XXXXXX";
  int inputfd = -1;
  int outputfd = -1;
  int trace = getenv("CF_V2_TRACE_PCLM_GRAPH") != NULL;

  if (!cf_v2_pclm_graph_parse(data, size, &graph))
    return 0;
  memset(&plan, 0, sizeof(plan));
  plan.pages = cf_v2_cardinality_value(&graph.pages);
  plan.xobjects = cf_v2_cardinality_value(&graph.xobjects);
  plan.reference_id = graph.reference.referenced_id;
  plan.close_after_read =
      cf_v2_scalar_relation_value(&graph.close_after_read) != 0;
  cf_v2_pclm_graph_apply_actions(&graph, &plan, NULL);

#if defined(CF_V2_PCLM_GRAPH_DEEP) || \
    defined(CF_V2_PCLM_GRAPH_ROTATION_BOUNDARY)
  if (!plan.pages || !plan.xobjects ||
      graph.object.kind != CF_V2_OBJECT_STREAM ||
      plan.reference_id != graph.object.object_id ||
      cf_v2_length_relation_value(&graph.image_bytes) !=
          graph.image_bytes.base ||
      cf_v2_scalar_relation_value(&graph.encoding) != 1 ||
      !plan.close_after_read)
    return 0;
#endif
#ifdef CF_V2_PCLM_GRAPH_DEEP
  if (!cf_v2_pclm_graph_supported_rotation(
          cf_v2_scalar_relation_value(&graph.rotate)))
    return 0;
#endif

  cf_v2_relation_stats_register(&cf_v2_pclm_graph_stats,
                                CF_V2_TARGET_NAME);
  cf_v2_pclm_graph_record(&cf_v2_pclm_graph_stats, &graph);
  cf_v2_pclm_graph_record_actions(&graph, &cf_v2_pclm_graph_stats);
  if (!(document = cf_v2_pclm_graph_build(
            &graph, &plan, &document_size)))
    goto done;

  inputfd = mkstemp(input_name);
  outputfd = mkstemp(output_name);
  if (inputfd < 0 || outputfd < 0 ||
      ftruncate(outputfd, 0) < 0 ||
      !cf_v2_pclm_graph_write_all(
          inputfd, document, document_size))
    goto done;

  tracked_image_stream = NULL;
  cf_v2_pclm_graph_close_stream = plan.close_after_read;
  init_filter_data(&filter_data, &sample_header);
  filter_data.job_title = (char *)"pclm-graph-program";
  (void)cfFilterPCLmToRaster(inputfd, outputfd, 1, &filter_data,
                             &output_format);
  inputfd = -1;

done:
  tracked_image_stream = NULL;
  cf_v2_pclm_graph_close_stream = 1;
  if (inputfd >= 0)
    close(inputfd);
  if (outputfd >= 0)
    close(outputfd);
  if (trace) {
    fprintf(stderr,
            "pclm-graph: pages=%zu xobjects=%zu object=%u kind=%u "
            "reference=%u rotate=%" PRId64 " close=%d input=%s output=%s\n",
            plan.pages, plan.xobjects, graph.object.object_id,
            (unsigned)graph.object.kind, plan.reference_id,
            cf_v2_scalar_relation_value(&graph.rotate),
            plan.close_after_read, input_name, output_name);
  } else {
    unlink(output_name);
    unlink(input_name);
  }
  free(document);
  return 0;
}
