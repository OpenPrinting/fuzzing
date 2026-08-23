// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_V2_PDF_GRAPH_BUILDER_H
#define CUPSFILTERS_V2_PDF_GRAPH_BUILDER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CF_V2_PDF_GRAPH_MAX_BYTES (4U * 1024U * 1024U)
#define CF_V2_PDF_GRAPH_LITERAL(writer, literal)                            \
  cf_v2_pdf_graph_append((writer), (literal), sizeof(literal) - 1U)

typedef struct cf_v2_pdf_graph_writer_s {
  uint8_t *data;
  size_t size;
  size_t capacity;
  size_t object_count;
  size_t *offsets;
  bool failed;
} cf_v2_pdf_graph_writer_t;

static bool cf_v2_pdf_graph_reserve(cf_v2_pdf_graph_writer_t *writer,
                                    size_t extra) {
  size_t required;
  size_t capacity;
  uint8_t *data;

  if (writer->failed || extra > CF_V2_PDF_GRAPH_MAX_BYTES - writer->size) {
    writer->failed = true;
    return false;
  }
  required = writer->size + extra;
  if (required <= writer->capacity) {
    return true;
  }
  capacity = writer->capacity ? writer->capacity : 4096U;
  while (capacity < required) {
    if (capacity > CF_V2_PDF_GRAPH_MAX_BYTES / 2U) {
      capacity = CF_V2_PDF_GRAPH_MAX_BYTES;
      break;
    }
    capacity *= 2U;
  }
  if (!(data = (uint8_t *)realloc(writer->data, capacity))) {
    writer->failed = true;
    return false;
  }
  writer->data = data;
  writer->capacity = capacity;
  return true;
}

static bool cf_v2_pdf_graph_append(cf_v2_pdf_graph_writer_t *writer,
                                   const void *data, size_t size) {
  if (!cf_v2_pdf_graph_reserve(writer, size)) {
    return false;
  }
  memcpy(writer->data + writer->size, data, size);
  writer->size += size;
  return true;
}

static bool cf_v2_pdf_graph_printf(cf_v2_pdf_graph_writer_t *writer,
                                   const char *format, ...) {
  va_list arguments;
  va_list copy;
  int length;

  va_start(arguments, format);
  va_copy(copy, arguments);
  length = vsnprintf(NULL, 0, format, copy);
  va_end(copy);
  if (length < 0 || !cf_v2_pdf_graph_reserve(writer, (size_t)length + 1U)) {
    va_end(arguments);
    return false;
  }
  (void)vsnprintf((char *)writer->data + writer->size,
                  writer->capacity - writer->size, format, arguments);
  va_end(arguments);
  writer->size += (size_t)length;
  return true;
}

static bool cf_v2_pdf_graph_init(cf_v2_pdf_graph_writer_t *writer,
                                 size_t object_count) {
  memset(writer, 0, sizeof(*writer));
  if (!object_count || object_count > 20000U ||
      !(writer->offsets =
            (size_t *)calloc(object_count + 1U, sizeof(size_t)))) {
    writer->failed = true;
    return false;
  }
  writer->object_count = object_count;
  return CF_V2_PDF_GRAPH_LITERAL(writer, "%PDF-1.4\n");
}

static bool cf_v2_pdf_graph_begin_object(cf_v2_pdf_graph_writer_t *writer,
                                         size_t number) {
  if (!number || number > writer->object_count || writer->offsets[number]) {
    writer->failed = true;
    return false;
  }
  writer->offsets[number] = writer->size;
  return cf_v2_pdf_graph_printf(writer, "%zu 0 obj\n", number);
}

static bool cf_v2_pdf_graph_end_object(cf_v2_pdf_graph_writer_t *writer) {
  return CF_V2_PDF_GRAPH_LITERAL(writer, "endobj\n");
}

static uint8_t *cf_v2_pdf_graph_finish(cf_v2_pdf_graph_writer_t *writer,
                                       size_t root_object,
                                       size_t *document_size) {
  size_t xref;

  if (writer->failed || !root_object || root_object > writer->object_count) {
    return NULL;
  }
  for (size_t number = 1; number <= writer->object_count; number++) {
    if (!writer->offsets[number]) {
      writer->failed = true;
      return NULL;
    }
  }
  xref = writer->size;
  if (!cf_v2_pdf_graph_printf(writer, "xref\n0 %zu\n", writer->object_count + 1U) ||
      !CF_V2_PDF_GRAPH_LITERAL(writer, "0000000000 65535 f \n")) {
    return NULL;
  }
  for (size_t number = 1; number <= writer->object_count; number++) {
    if (!cf_v2_pdf_graph_printf(writer, "%010zu 00000 n \n",
                                writer->offsets[number])) {
      return NULL;
    }
  }
  if (!cf_v2_pdf_graph_printf(
          writer,
          "trailer\n<< /Size %zu /Root %zu 0 R >>\nstartxref\n%zu\n%%%%EOF\n",
          writer->object_count + 1U, root_object, xref)) {
    return NULL;
  }
  free(writer->offsets);
  writer->offsets = NULL;
  *document_size = writer->size;
  return writer->data;
}

static void cf_v2_pdf_graph_discard(cf_v2_pdf_graph_writer_t *writer) {
  free(writer->offsets);
  free(writer->data);
  memset(writer, 0, sizeof(*writer));
}

#endif
