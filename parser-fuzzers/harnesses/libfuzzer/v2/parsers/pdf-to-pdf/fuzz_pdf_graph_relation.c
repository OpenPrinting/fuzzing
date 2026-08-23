// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define CF_V2_FILTER_FUNCTION cfFilterPDFToPDF
#define CF_V2_INPUT_MIME "application/pdf"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_FILTER_OPTIONS_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v2_pdf_graph_unused_entrypoint
#include "../../implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include "pdf_graph_builder.h"

#include <zlib.h>

#define CF_V2_PDF_GRAPH_MAGIC "PDFGRPH1"
#define CF_V2_PDF_GRAPH_MAGIC_SIZE 8U
#define CF_V2_PDF_GRAPH_SELECTORS 8U
#define CF_V2_PDF_GRAPH_MAX_MATERIAL 64U
#define CF_V2_PDF_GRAPH_TRACK_CAPACITY (1U << 18)

static void *cf_v2_pdf_graph_allocations[CF_V2_PDF_GRAPH_TRACK_CAPACITY];
static int cf_v2_pdf_graph_tracking;
static void *const cf_v2_pdf_graph_tombstone = (void *)(uintptr_t)1U;

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t count, size_t size);
extern void *__real_realloc(void *pointer, size_t size);
extern char *__real_strdup(const char *value);
extern void __real_free(void *pointer);

static size_t cf_v2_pdf_graph_pointer_hash(const void *pointer) {
  uintptr_t value = (uintptr_t)pointer >> 4;
  return (size_t)((value * UINT64_C(11400714819323198485)) &
                  (CF_V2_PDF_GRAPH_TRACK_CAPACITY - 1U));
}

static void cf_v2_pdf_graph_track(void *pointer) {
  size_t index;
  size_t available = SIZE_MAX;

  if (!cf_v2_pdf_graph_tracking || !pointer) {
    return;
  }
  index = cf_v2_pdf_graph_pointer_hash(pointer);
  for (size_t probe = 0; probe < CF_V2_PDF_GRAPH_TRACK_CAPACITY; probe++) {
    void *entry = cf_v2_pdf_graph_allocations[index];

    if (entry == pointer) {
      return;
    }
    if (entry == cf_v2_pdf_graph_tombstone && available == SIZE_MAX) {
      available = index;
    } else if (!entry) {
      cf_v2_pdf_graph_allocations[
          available == SIZE_MAX ? index : available] = pointer;
      return;
    }
    index = (index + 1U) & (CF_V2_PDF_GRAPH_TRACK_CAPACITY - 1U);
  }
}

static void cf_v2_pdf_graph_forget(void *pointer) {
  size_t index;

  if (!pointer) {
    return;
  }
  index = cf_v2_pdf_graph_pointer_hash(pointer);
  for (size_t probe = 0; probe < CF_V2_PDF_GRAPH_TRACK_CAPACITY; probe++) {
    void *entry = cf_v2_pdf_graph_allocations[index];

    if (!entry) {
      return;
    }
    if (entry == pointer) {
      cf_v2_pdf_graph_allocations[index] = cf_v2_pdf_graph_tombstone;
      return;
    }
    index = (index + 1U) & (CF_V2_PDF_GRAPH_TRACK_CAPACITY - 1U);
  }
}

void *__wrap_malloc(size_t size) {
  void *pointer = __real_malloc(size);
  cf_v2_pdf_graph_track(pointer);
  return pointer;
}

void *__wrap_calloc(size_t count, size_t size) {
  void *pointer = __real_calloc(count, size);
  cf_v2_pdf_graph_track(pointer);
  return pointer;
}

void *__wrap_realloc(void *pointer, size_t size) {
  void *result = __real_realloc(pointer, size);

  if (result) {
    cf_v2_pdf_graph_forget(pointer);
    cf_v2_pdf_graph_track(result);
  }
  return result;
}

char *__wrap_strdup(const char *value) {
  char *copy = __real_strdup(value);
  cf_v2_pdf_graph_track(copy);
  return copy;
}

void __wrap_free(void *pointer) {
  cf_v2_pdf_graph_forget(pointer);
  __real_free(pointer);
}

static void cf_v2_pdf_graph_release_allocations(void) {
  cf_v2_pdf_graph_tracking = 0;
  for (size_t index = 0; index < CF_V2_PDF_GRAPH_TRACK_CAPACITY; index++) {
    void *pointer = cf_v2_pdf_graph_allocations[index];

    if (pointer && pointer != cf_v2_pdf_graph_tombstone) {
      __real_free(pointer);
    }
    cf_v2_pdf_graph_allocations[index] = NULL;
  }
}

static void cf_v2_pdf_graph_warm_options(const char *options) {
  static int initialized;
  cups_option_t *parsed = NULL;
  int count;

  if (initialized) {
    return;
  }
  count = cupsParseOptions(options, NULL, 0, &parsed);
  cupsFreeOptions(count, parsed);
  (void)pwgMediaForPWG("iso_a4_210x297mm");
  initialized = 1;
}

#ifndef CF_V2_PDF_GRAPH_LANE
#error "CF_V2_PDF_GRAPH_LANE must select one PDF relation"
#endif

#if CF_V2_PDF_GRAPH_LANE < 1 || CF_V2_PDF_GRAPH_LANE > 5
#error "unsupported CF_V2_PDF_GRAPH_LANE"
#endif

static uint8_t *cf_v2_pdf_graph_ascii85(const uint8_t *input,
                                        size_t input_size,
                                        size_t *output_size) {
  size_t groups = (input_size + 3U) / 4U;
  uint8_t *output = (uint8_t *)malloc(groups * 5U + 2U);
  size_t produced = 0;

  if (!output) {
    return NULL;
  }
  for (size_t offset = 0; offset < input_size; offset += 4U) {
    size_t available = input_size - offset;
    size_t bytes = available < 4U ? available : 4U;
    uint32_t value = 0;
    uint8_t encoded[5];

    for (size_t index = 0; index < 4U; index++) {
      value <<= 8;
      if (index < bytes) {
        value |= input[offset + index];
      }
    }
    for (size_t index = 5U; index > 0; index--) {
      encoded[index - 1U] = (uint8_t)(value % 85U + '!');
      value /= 85U;
    }
    memcpy(output + produced, encoded, bytes == 4U ? 5U : bytes + 1U);
    produced += bytes == 4U ? 5U : bytes + 1U;
  }
  output[produced++] = '~';
  output[produced++] = '>';
  *output_size = produced;
  return output;
}

static uint8_t *cf_v2_pdf_graph_build_ascii85(
    unsigned relation, const uint8_t *material, size_t material_size,
    size_t *document_size) {
  const size_t decoded_sizes[3] = {4147U, 4148U, 4149U};
  size_t decoded_size = decoded_sizes[relation];
  uint8_t *decoded = NULL;
  uint8_t *compressed = NULL;
  uint8_t *encoded = NULL;
  uLongf compressed_size;
  size_t encoded_size = 0;
  cf_v2_pdf_graph_writer_t writer;
  uint8_t *document = NULL;

  if (!(decoded = (uint8_t *)malloc(decoded_size))) {
    return NULL;
  }
  for (size_t index = 0; index < decoded_size; index++) {
    uint8_t source = material[index % material_size];
    decoded[index] = (index % 79U == 78U) ? '\n' :
                     (uint8_t)(' ' + (source % 95U));
  }
  compressed_size = compressBound((uLong)decoded_size);
  if (!(compressed = (uint8_t *)malloc((size_t)compressed_size)) ||
      compress2(compressed, &compressed_size, decoded, (uLong)decoded_size,
                Z_NO_COMPRESSION) != Z_OK ||
      !(encoded = cf_v2_pdf_graph_ascii85(compressed,
                                          (size_t)compressed_size,
                                          &encoded_size)) ||
      !cf_v2_pdf_graph_init(&writer, 4U)) {
    goto done;
  }

  cf_v2_pdf_graph_begin_object(&writer, 1U);
  CF_V2_PDF_GRAPH_LITERAL(&writer,
                          "<< /Type /Catalog /Pages 2 0 R >>\n");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 2U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 3U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer,
      "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
      "/Resources << >> /Contents 4 0 R >>\n");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 4U);
  cf_v2_pdf_graph_printf(
      &writer,
      "<< /Length %zu /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n",
      encoded_size);
  cf_v2_pdf_graph_append(&writer, encoded, encoded_size);
  CF_V2_PDF_GRAPH_LITERAL(&writer, "\nendstream\n");
  cf_v2_pdf_graph_end_object(&writer);
  document = cf_v2_pdf_graph_finish(&writer, 1U, document_size);
  if (!document) {
    cf_v2_pdf_graph_discard(&writer);
  }

done:
  free(encoded);
  free(compressed);
  free(decoded);
  return document;
}

static uint8_t *cf_v2_pdf_graph_build_pages(
    size_t page_count, bool with_form, const uint8_t *material,
    size_t material_size, size_t *document_size) {
  size_t content_object = 3U + page_count;
  size_t field_object = content_object + 1U;
  size_t object_count = content_object + (with_form ? 1U : 0U);
  cf_v2_pdf_graph_writer_t writer;
  uint8_t *document;

  if (!page_count || page_count > 10001U ||
      !cf_v2_pdf_graph_init(&writer, object_count)) {
    return NULL;
  }
  cf_v2_pdf_graph_begin_object(&writer, 1U);
  cf_v2_pdf_graph_printf(
      &writer, "<< /Type /Catalog /Pages 2 0 R%s",
      with_form ? " /AcroForm << /Fields [" : "");
  if (with_form) {
    cf_v2_pdf_graph_printf(&writer, "%zu 0 R] >>", field_object);
  }
  CF_V2_PDF_GRAPH_LITERAL(&writer, " >>\n");
  cf_v2_pdf_graph_end_object(&writer);

  cf_v2_pdf_graph_begin_object(&writer, 2U);
  CF_V2_PDF_GRAPH_LITERAL(&writer, "<< /Type /Pages /Kids [");
  for (size_t page = 0; page < page_count; page++) {
    cf_v2_pdf_graph_printf(&writer, "%zu 0 R ", 3U + page);
  }
  cf_v2_pdf_graph_printf(&writer, "] /Count %zu >>\n", page_count);
  cf_v2_pdf_graph_end_object(&writer);

  for (size_t page = 0; page < page_count; page++) {
    unsigned side = 72U + material[page % material_size] % 9U;
    cf_v2_pdf_graph_begin_object(&writer, 3U + page);
    cf_v2_pdf_graph_printf(
        &writer,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %u %u] "
        "/Resources << >> /Contents %zu 0 R >>\n",
        side, side, content_object);
    cf_v2_pdf_graph_end_object(&writer);
  }
  cf_v2_pdf_graph_begin_object(&writer, content_object);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Length 4 >>\nstream\nq Q\nendstream\n");
  cf_v2_pdf_graph_end_object(&writer);
  if (with_form) {
    cf_v2_pdf_graph_begin_object(&writer, field_object);
    CF_V2_PDF_GRAPH_LITERAL(&writer,
                            "<< /FT /Tx /T (PDFGRAPH) >>\n");
    cf_v2_pdf_graph_end_object(&writer);
  }
  document = cf_v2_pdf_graph_finish(&writer, 1U, document_size);
  if (!document) {
    cf_v2_pdf_graph_discard(&writer);
  }
  return document;
}

static uint8_t *cf_v2_pdf_graph_build_annotation(
    unsigned relation, const uint8_t *material, size_t material_size,
    size_t *document_size) {
  bool has_annotation = relation != 0U;
  bool has_appearance = relation == 1U;
  size_t object_count = has_annotation ? (has_appearance ? 6U : 5U) : 4U;
  cf_v2_pdf_graph_writer_t writer;
  uint8_t *document;
  unsigned edge = 20U + material[0] % 30U;

  (void)material_size;
  if (!cf_v2_pdf_graph_init(&writer, object_count)) {
    return NULL;
  }
  cf_v2_pdf_graph_begin_object(&writer, 1U);
  CF_V2_PDF_GRAPH_LITERAL(&writer,
                          "<< /Type /Catalog /Pages 2 0 R >>\n");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 2U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 3U);
  cf_v2_pdf_graph_printf(
      &writer,
      "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
      "/Resources << >> /Contents 4 0 R%s >>\n",
      has_annotation ? " /Annots [5 0 R]" : "");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 4U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Length 4 >>\nstream\nq Q\nendstream\n");
  cf_v2_pdf_graph_end_object(&writer);
  if (has_annotation) {
    cf_v2_pdf_graph_begin_object(&writer, 5U);
    cf_v2_pdf_graph_printf(
        &writer,
        "<< /Type /Annot /Subtype /Square /Rect [10 10 %u %u] /F 4%s >>\n",
        edge, edge, has_appearance ? " /AP << /N 6 0 R >>" : "");
    cf_v2_pdf_graph_end_object(&writer);
  }
  if (has_appearance) {
    cf_v2_pdf_graph_begin_object(&writer, 6U);
    cf_v2_pdf_graph_printf(
        &writer,
        "<< /Type /XObject /Subtype /Form /BBox [0 0 %u %u] /Length 4 >>\n"
        "stream\nq Q\nendstream\n",
        edge - 10U, edge - 10U);
    cf_v2_pdf_graph_end_object(&writer);
  }
  document = cf_v2_pdf_graph_finish(&writer, 1U, document_size);
  if (!document) {
    cf_v2_pdf_graph_discard(&writer);
  }
  return document;
}

static uint8_t *cf_v2_pdf_graph_build_parent(
    unsigned relation, const uint8_t *material, size_t material_size,
    size_t *document_size) {
  cf_v2_pdf_graph_writer_t writer;
  uint8_t *document;
  unsigned side = 180U + material[0] % 40U;

  (void)material_size;
  if (!cf_v2_pdf_graph_init(&writer, 5U)) {
    return NULL;
  }
  cf_v2_pdf_graph_begin_object(&writer, 1U);
  CF_V2_PDF_GRAPH_LITERAL(&writer,
                          "<< /Type /Catalog /Pages 2 0 R >>\n");
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 2U);
  if (relation == 2U) {
    CF_V2_PDF_GRAPH_LITERAL(
        &writer, "<< /Type /Pages /Kids [4 0 R 4 0 R] /Count 2 >>\n");
  } else {
    CF_V2_PDF_GRAPH_LITERAL(
        &writer, "<< /Type /Pages /Kids [4 0 R] /Count 1 >>\n");
  }
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 3U);
  if (relation == 2U) {
    CF_V2_PDF_GRAPH_LITERAL(
        &writer, "<< /Type /Pages /Parent 2 0 R /Broken >>\n");
  } else {
    cf_v2_pdf_graph_printf(
        &writer,
        "<< /Type /Pages /Parent 2 0 R /MediaBox [0 0 %u %u] >>\n",
        side, side);
  }
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 4U);
  cf_v2_pdf_graph_printf(
      &writer,
      "<< /Type /Page /Parent %u 0 R /MediaBox [0 0 %u %u] "
      "/Resources << >> /Contents %u 0 R >>\n",
      relation == 0U ? 2U : 3U, side, side, relation == 2U ? 4U : 5U);
  cf_v2_pdf_graph_end_object(&writer);
  cf_v2_pdf_graph_begin_object(&writer, 5U);
  CF_V2_PDF_GRAPH_LITERAL(
      &writer, "<< /Length 4 >>\nstream\nq Q\nendstream\n");
  cf_v2_pdf_graph_end_object(&writer);
  document = cf_v2_pdf_graph_finish(&writer, 1U, document_size);
  if (!document) {
    cf_v2_pdf_graph_discard(&writer);
  }
  return document;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t fixed_size =
      CF_V2_PDF_GRAPH_MAGIC_SIZE + CF_V2_PDF_GRAPH_SELECTORS;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;
  unsigned relation;
  uint8_t *document = NULL;
  size_t document_size = 0;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  cf_v2_control_t control;
  const char *options =
      "number-up=1 print-scaling=none page-border=none "
      "orientation-requested=7 emit-jcl=false";

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_PDF_GRAPH_MAX_MATERIAL ||
      memcmp(data, CF_V2_PDF_GRAPH_MAGIC, CF_V2_PDF_GRAPH_MAGIC_SIZE)) {
    return 0;
  }
  selector = data + CF_V2_PDF_GRAPH_MAGIC_SIZE;
  material = data + fixed_size;
  material_size = size - fixed_size;
  relation = selector[4] % 3U;

#if CF_V2_PDF_GRAPH_LANE == 1
  document = cf_v2_pdf_graph_build_ascii85(
      relation, material, material_size, &document_size);
  options = "PageSize=A4 number-up=2 print-scaling=fit emit-jcl=false";
#elif CF_V2_PDF_GRAPH_LANE == 2
  document = cf_v2_pdf_graph_build_annotation(
      relation, material, material_size, &document_size);
#elif CF_V2_PDF_GRAPH_LANE == 3
  document = cf_v2_pdf_graph_build_pages(
      relation == 2U ? 19U : (relation == 1U ? 16U : 8U), true,
      material, material_size, &document_size);
#elif CF_V2_PDF_GRAPH_LANE == 4
  document = cf_v2_pdf_graph_build_pages(
      relation == 2U ? 10001U : (relation == 1U ? 32U : 8U), false,
      material, material_size, &document_size);
#elif CF_V2_PDF_GRAPH_LANE == 5
  document = cf_v2_pdf_graph_build_parent(
      relation, material, material_size, &document_size);
#endif
  if (!document || document_size > CF_V2_PDF_GRAPH_MAX_BYTES) {
    free(document);
    return 0;
  }

  memset(&control, 0, sizeof(control));
  control.page_size = selector[0];
  control.orientation = selector[1];
  control.scaling = selector[2];
  control.output_order = selector[3];
  control.route_mode = selector[5];
  control.reserved = selector[6];
  memset(&job, 0, sizeof(job));
  memset(&result, 0, sizeof(result));
  job.control = control;
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = (const uint8_t *)"pdf-graph-relation";
  job.title_size = 18U;
  job.document = document;
  job.document_size = document_size;
  cf_v2_pdf_graph_warm_options(options);
  cf_v2_pdf_graph_tracking = 1;
  (void)cf_v2_execute_direct_job(&job, 0, &result);
  cf_v2_release_filter_options();
  cf_v2_free_run_result(&result);
  cf_v2_pdf_graph_release_allocations();
  free(document);
  return 0;
}
