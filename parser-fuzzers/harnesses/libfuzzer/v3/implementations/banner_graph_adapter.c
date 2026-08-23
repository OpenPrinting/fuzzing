// SPDX-License-Identifier: Apache-2.0
#include "banner_graph_adapter.h"

/* Reuse the already-audited bounded PDF object generator without running its
 * helper-only fuzzer entry.  V3 feeds the generated graph through the public
 * Banner filter below, so the graph and control language share one lifecycle. */
#define LLVMFuzzerTestOneInput cf_v3_banner_graph_unused_entry
#define __wrap_fprintf cf_v3_banner_graph_unused_fprintf
#include "../../v2/oracles/fuzz_banner_template_object_graph.c"
#undef __wrap_fprintf
#undef LLVMFuzzerTestOneInput

static bool cf_v3_banner_contains(const uint8_t *haystack,
                                  size_t haystack_size,
                                  const uint8_t *needle,
                                  size_t needle_size) {
  if (!needle_size) {
    return true;
  }
  if (!haystack || !needle || needle_size > haystack_size) {
    return false;
  }
  for (size_t offset = 0; offset + needle_size <= haystack_size; offset++) {
    if (memcmp(haystack + offset, needle, needle_size) == 0) {
      return true;
    }
  }
  return false;
}

bool cf_v3_banner_graph_build(const uint8_t *data, size_t size,
                              char path[1024], uint8_t *expected,
                              size_t expected_capacity,
                              size_t *expected_length,
                              bool *valid_media_box) {
  cf_v2_banner_object_case_t test_case;
  static const size_t synthetic_prefix_size =
      sizeof("q 1 0 0 1 0 0 cm\n") - 1U;

  cf_v2_banner_object_decode(data, size, &test_case);
  *valid_media_box = test_case.valid_media_box;
  if (!cf_v2_banner_object_build_template(
          &test_case, path, expected, expected_capacity, expected_length) ||
      *expected_length < synthetic_prefix_size) {
    return false;
  }
  *expected_length -= synthetic_prefix_size;
  memmove(expected, expected + synthetic_prefix_size, *expected_length);
  return true;
}

bool cf_v3_banner_graph_validate(const char *path, const uint8_t *data,
                                 size_t size, const uint8_t *expected,
                                 size_t expected_length,
                                 unsigned expected_pages) {
  cf_v2_banner_object_case_t test_case;
  cf_v2_banner_object_error_t error = {false};
  pdfio_file_t *pdf = NULL;
  uint8_t *content = NULL;
  bool valid = false;

  cf_v2_banner_object_decode(data, size, &test_case);
  pdf = pdfioFileOpen(path, NULL, NULL, cf_v2_banner_object_pdf_error, &error);
  if (!pdf || error.saw_error ||
      pdfioFileGetNumObjs(pdf) > CF_V2_BANNER_OBJECT_MAX_OBJECTS ||
      pdfioFileGetNumPages(pdf) != expected_pages) {
    goto done;
  }
  content = (uint8_t *)malloc(CF_V3_BANNER_GRAPH_MAX_CONTENT);
  if (!content) {
    goto done;
  }

  for (unsigned page_index = 0; page_index < expected_pages; page_index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, page_index);
    pdfio_dict_t *page_dict = page ? pdfioObjGetDict(page) : NULL;
    pdfio_dict_t *resources =
        cf_v2_banner_object_dict(page_dict, "Resources");
    pdfio_dict_t *fonts = cf_v2_banner_object_dict(resources, "Font");
    pdfio_dict_t *banner_font =
        cf_v2_banner_object_dict(fonts, "bannertopdf-font");
    size_t content_length = 0U;
    const size_t stream_count = page ? pdfioPageGetNumStreams(page) : 0U;

    if (!page || !page_dict || stream_count == 0U || stream_count > 16U ||
        !banner_font || !pdfioDictGetName(banner_font, "Subtype") ||
        strcmp(pdfioDictGetName(banner_font, "Subtype"), "Type1") != 0 ||
        !pdfioDictGetName(banner_font, "BaseFont") ||
        strcmp(pdfioDictGetName(banner_font, "BaseFont"), "Courier") != 0) {
      goto done;
    }
    if (cf_v2_banner_object_expect_f0(&test_case)) {
      pdfio_dict_t *f0 = cf_v2_banner_object_dict(fonts, "F0");
      if (!f0 || !pdfioDictGetName(f0, "BaseFont") ||
          strcmp(pdfioDictGetName(f0, "BaseFont"), "Helvetica") != 0) {
        goto done;
      }
    }
    for (size_t stream_index = 0; stream_index < stream_count; stream_index++) {
      pdfio_stream_t *stream = pdfioPageOpenStream(page, stream_index, true);
      if (!stream) {
        goto done;
      }
      while (content_length < CF_V3_BANNER_GRAPH_MAX_CONTENT) {
        ssize_t count = pdfioStreamRead(
            stream, content + content_length,
            CF_V3_BANNER_GRAPH_MAX_CONTENT - content_length);
        if (count < 0) {
          pdfioStreamClose(stream);
          goto done;
        }
        if (!count) {
          break;
        }
        content_length += (size_t)count;
      }
      if (!pdfioStreamClose(stream) ||
          content_length == CF_V3_BANNER_GRAPH_MAX_CONTENT) {
        goto done;
      }
    }
    if (!cf_v3_banner_contains(content, content_length, expected,
                               expected_length)) {
      goto done;
    }
  }
  valid = true;

done:
  free(content);
  if (pdf && !pdfioFileClose(pdf)) {
    valid = false;
  }
  return valid && !error.saw_error;
}
