// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <config.h>

#include <arpa/inet.h>
#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/colormanager.h>
#include <cupsfilters/filter.h>
#include <cupsfilters/image.h>
#include <cupsfilters/ipp.h>
#include <cupsfilters/libcups2-private.h>
#include <fcntl.h>
#include <lcms2.h>
#include <limits.h>
#include <pdfio-content.h>
#include <pdfio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

/* Owner: semantic-facts/parsers/pwg-to-pdf.
 * This sidecar covers only the real PCLm Flate Image XObject helper. It does
 * not model the public bridge, page assembly, or page-resource lifecycle. */
#define CF_V2_PCLM_OBJECT_TARGET                                      \
  "fuzz_v2_cupsfilters_state_pwg_to_pclm_flate_object_oracle"
#define CF_V2_PCLM_OBJECT_SELECTOR_BYTES 8U
#define CF_V2_PCLM_OBJECT_MAX_MATERIAL 4096U
#define CF_V2_PCLM_OBJECT_MAX_STRIPS 16U
#define CF_V2_PCLM_OBJECT_MAX_DECODED (64U * 1024U)

#ifndef CF_V2_PWG_TO_PDF_SOURCE
#error "CF_V2_PWG_TO_PDF_SOURCE must name the current pwgtopdf.c"
#endif

/* Compile the current helper in-place. Renaming externally visible symbols
 * prevents collisions with the linked library; no upstream behavior is
 * patched and no source allocator is intercepted. */
#define init_pdf_info cf_v2_pclm_object_unused_init_pdf_info
#define free_pdf_info cf_v2_pclm_object_unused_free_pdf_info
#define split_strings cf_v2_pclm_object_split_strings
#define int_to_fwstring cf_v2_pclm_object_int_to_fwstring
#define cfFilterPWGToPDF cf_v2_pclm_object_unused_filter
#include CF_V2_PWG_TO_PDF_SOURCE
#undef cfFilterPWGToPDF
#undef int_to_fwstring
#undef split_strings
#undef free_pdf_info
#undef init_pdf_info

typedef struct cf_v2_pclm_object_model_s {
  unsigned width;
  unsigned strip_count;
  unsigned components;
  unsigned pattern;
  unsigned phase;
  size_t read_chunk;
  cups_cspace_t color_space;
  unsigned heights[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  size_t sizes[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  size_t offsets[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  size_t decoded_size;
} cf_v2_pclm_object_model_t;

typedef struct cf_v2_pclm_object_error_s {
  bool saw_error;
} cf_v2_pclm_object_error_t;

static const unsigned cf_v2_pclm_object_widths[] = {
    1U, 2U, 7U, 8U, 15U, 16U, 31U, 32U, 63U, 128U,
};
static const unsigned cf_v2_pclm_object_strip_counts[] = {
    1U, 2U, 3U, 4U, 8U, 16U,
};
static const unsigned cf_v2_pclm_object_strip_heights[] = {
    1U, 2U, 7U, 15U, 16U, 17U, 31U, 32U,
};
static const unsigned cf_v2_pclm_object_phases[] = {
    0U, 1U, 7U, 31U, 127U, 255U, 256U, 1023U, 4095U, 65535U,
};
static const size_t cf_v2_pclm_object_read_chunks[] = {
    1U, 2U, 7U, 31U, 127U, 1024U, 2048U, 4096U,
};

static uint8_t cf_v2_pclm_object_selector(const uint8_t *data, size_t size,
                                          size_t index, uint8_t fallback) {
  return data && index < size ? data[index] : fallback;
}

static void cf_v2_pclm_object_decode(const uint8_t *data, size_t size,
                                     cf_v2_pclm_object_model_t *model) {
  unsigned requested_strips;
  unsigned base_height;
  unsigned last_height;
  unsigned max_strips;
  size_t line_bytes;
  size_t max_rows;

  memset(model, 0, sizeof(*model));
  model->width = cf_v2_pclm_object_widths[
      cf_v2_pclm_object_selector(data, size, 0U, 7U) %
      (sizeof(cf_v2_pclm_object_widths) /
       sizeof(cf_v2_pclm_object_widths[0]))];
  requested_strips = cf_v2_pclm_object_strip_counts[
      cf_v2_pclm_object_selector(data, size, 1U, 4U) %
      (sizeof(cf_v2_pclm_object_strip_counts) /
       sizeof(cf_v2_pclm_object_strip_counts[0]))];
  base_height = cf_v2_pclm_object_strip_heights[
      cf_v2_pclm_object_selector(data, size, 2U, 4U) %
      (sizeof(cf_v2_pclm_object_strip_heights) /
       sizeof(cf_v2_pclm_object_strip_heights[0]))];
  switch (cf_v2_pclm_object_selector(data, size, 3U, 0U) % 5U) {
    case 1U:
      last_height = 1U;
      break;
    case 2U:
      last_height = base_height > 1U ? base_height - 1U : 1U;
      break;
    case 3U:
      last_height = 1U + (base_height - 1U) / 2U;
      break;
    case 4U:
      last_height =
          1U + (cf_v2_pclm_object_selector(data, size, 6U, 0U) % base_height);
      break;
    default:
      last_height = base_height;
      break;
  }
  model->components =
      (cf_v2_pclm_object_selector(data, size, 4U, 1U) & 1U) ? 3U : 1U;
  model->color_space =
      model->components == 3U ? CUPS_CSPACE_RGB : CUPS_CSPACE_K;
  model->pattern = cf_v2_pclm_object_selector(data, size, 5U, 4U) % 6U;
  model->phase = cf_v2_pclm_object_phases[
      cf_v2_pclm_object_selector(data, size, 6U, 0U) %
      (sizeof(cf_v2_pclm_object_phases) /
       sizeof(cf_v2_pclm_object_phases[0]))];
  model->read_chunk = cf_v2_pclm_object_read_chunks[
      cf_v2_pclm_object_selector(data, size, 7U, 0U) %
      (sizeof(cf_v2_pclm_object_read_chunks) /
       sizeof(cf_v2_pclm_object_read_chunks[0]))];

  line_bytes = (size_t)model->width * model->components;
  max_rows = CF_V2_PCLM_OBJECT_MAX_DECODED / line_bytes;
  max_strips = 1U;
  if (max_rows > last_height) {
    max_strips += (unsigned)((max_rows - last_height) / base_height);
  }
  if (max_strips > CF_V2_PCLM_OBJECT_MAX_STRIPS) {
    max_strips = CF_V2_PCLM_OBJECT_MAX_STRIPS;
  }
  model->strip_count =
      requested_strips < max_strips ? requested_strips : max_strips;

  for (unsigned strip = 0U; strip < model->strip_count; strip++) {
    model->heights[strip] =
        strip + 1U == model->strip_count ? last_height : base_height;
    model->sizes[strip] = line_bytes * model->heights[strip];
    model->offsets[strip] = model->decoded_size;
    model->decoded_size += model->sizes[strip];
  }
}

static uint8_t cf_v2_pclm_object_material(const uint8_t *material,
                                          size_t material_size,
                                          const cf_v2_pclm_object_model_t *model,
                                          size_t offset) {
  uint8_t input = material_size
                      ? material[(offset + model->phase) % material_size]
                      : (uint8_t)(offset * 131U + model->phase * 17U);

  switch (model->pattern) {
    case 0U:
      return 0U;
    case 1U:
      return 0xffU;
    case 2U:
      return ((offset + model->phase) & 1U) ? 0xaaU : 0x55U;
    case 3U:
      return (uint8_t)(offset + model->phase);
    case 4U:
      return input;
    default:
      return (uint8_t)(input ^ (uint8_t)(offset * 29U) ^
                       (uint8_t)(model->phase >> 3U));
  }
}

static bool cf_v2_pclm_object_pdf_error(pdfio_file_t *pdf,
                                        const char *message, void *data) {
  cf_v2_pclm_object_error_t *error =
      (cf_v2_pclm_object_error_t *)data;

  (void)pdf;
  (void)message;
  error->saw_error = true;
  return false;
}

static bool cf_v2_pclm_object_name_is(pdfio_dict_t *dict, const char *key,
                                      const char *expected) {
  const char *actual = dict ? pdfioDictGetName(dict, key) : NULL;

  return actual && strcmp(actual, expected) == 0;
}

static bool cf_v2_pclm_object_validate_stream(
    pdfio_obj_t *object, const uint8_t *expected, size_t expected_size,
    size_t read_chunk, const char **failure) {
  pdfio_stream_t *stream = pdfioObjOpenStream(object, true);
  uint8_t buffer[4096];
  size_t offset = 0U;
  ssize_t count = 0;
  bool valid = false;

  if (!stream) {
    *failure = "stream-open";
    return false;
  }
  while ((count = pdfioStreamRead(stream, buffer, read_chunk)) > 0) {
    if ((size_t)count > expected_size - offset ||
        memcmp(buffer, expected + offset, (size_t)count) != 0) {
      *failure = "decoded-bytes";
      goto done;
    }
    offset += (size_t)count;
  }
  if (count < 0) {
    *failure = "stream-read";
  } else if (offset != expected_size) {
    *failure = "decoded-length";
  } else {
    valid = true;
  }

done:
  if (!pdfioStreamClose(stream)) {
    *failure = "stream-close";
    valid = false;
  }
  return valid;
}

static bool cf_v2_pclm_object_validate_file(
    const char *path, const cf_v2_pclm_object_model_t *model,
    const size_t *object_numbers, const uint8_t *expected,
    const char **failure) {
  cf_v2_pclm_object_error_t error = {false};
  pdfio_file_t *pdf =
      pdfioFileOpen(path, NULL, NULL, cf_v2_pclm_object_pdf_error, &error);
  bool valid = false;

  if (!pdf || error.saw_error) {
    *failure = "strict-reopen";
    goto done;
  }
  for (unsigned strip = 0U; strip < model->strip_count; strip++) {
    pdfio_obj_t *object = pdfioFileFindObj(pdf, object_numbers[strip]);
    pdfio_dict_t *dict = object ? pdfioObjGetDict(object) : NULL;

    if (!cf_v2_pclm_object_name_is(dict, "Type", "XObject") ||
        !cf_v2_pclm_object_name_is(dict, "Subtype", "Image") ||
        !cf_v2_pclm_object_name_is(dict, "Filter", "FlateDecode") ||
        !cf_v2_pclm_object_name_is(
            dict, "ColorSpace",
            model->components == 3U ? "DeviceRGB" : "DeviceGray") ||
        pdfioDictGetNumber(dict, "Width") != (double)model->width ||
        pdfioDictGetNumber(dict, "Height") !=
            (double)model->heights[strip] ||
        pdfioDictGetNumber(dict, "BitsPerComponent") != 8.0) {
      *failure = "xobject-dictionary";
      goto done;
    }
    if (!cf_v2_pclm_object_validate_stream(
            object, expected + model->offsets[strip], model->sizes[strip],
            model->read_chunk, failure)) {
      goto done;
    }
  }
  if (error.saw_error) {
    *failure = "pdfio-read-error";
    goto done;
  }
  valid = true;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    *failure = "reader-close";
    valid = false;
  }
  return valid;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_pclm_object_model_t model;
  cf_v2_pclm_object_error_t writer_error = {false};
  struct pdf_info info;
  pwgtopdf_doc_t doc;
  unsigned strip_heights[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  size_t strip_sizes[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  char *strip_data[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  compression_method_t compression[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  size_t object_numbers[CF_V2_PCLM_OBJECT_MAX_STRIPS];
  pdfio_obj_t **objects = NULL;
  uint8_t *decoded = NULL;
  const uint8_t *material = NULL;
  size_t material_size = 0U;
  char path[1024] = "";
  const char *failure = NULL;
  bool trap_after_cleanup = false;

  memset(&info, 0, sizeof(info));
  memset(&doc, 0, sizeof(doc));
  memset(strip_data, 0, sizeof(strip_data));
  memset(object_numbers, 0, sizeof(object_numbers));
  cf_v2_pclm_object_decode(data, size, &model);
  if (data && size > CF_V2_PCLM_OBJECT_SELECTOR_BYTES) {
    material = data + CF_V2_PCLM_OBJECT_SELECTOR_BYTES;
    material_size = size - CF_V2_PCLM_OBJECT_SELECTOR_BYTES;
    if (material_size > CF_V2_PCLM_OBJECT_MAX_MATERIAL) {
      material_size = CF_V2_PCLM_OBJECT_MAX_MATERIAL;
    }
  }
  if (model.decoded_size == 0U ||
      model.decoded_size > CF_V2_PCLM_OBJECT_MAX_DECODED) {
    fprintf(stderr, "pwg-pclm-flate-object-oracle: model-budget\n");
    __builtin_trap();
  }
  if (!(decoded = (uint8_t *)malloc(model.decoded_size))) {
    goto cleanup;
  }
  for (size_t offset = 0U; offset < model.decoded_size; offset++) {
    decoded[offset] = cf_v2_pclm_object_material(
        material, material_size, &model, offset);
  }
  for (unsigned strip = 0U; strip < model.strip_count; strip++) {
    strip_heights[strip] = model.heights[strip];
    strip_sizes[strip] = model.sizes[strip];
    strip_data[strip] = (char *)(decoded + model.offsets[strip]);
    compression[strip] = FLATE_DECODE;
  }

  info.pdf = pdfioFileCreateTemporary(
      path, sizeof(path), "PCLm-1.0", NULL, NULL,
      cf_v2_pclm_object_pdf_error, &writer_error);
  if (!info.pdf || writer_error.saw_error) {
    goto cleanup;
  }
  info.width = model.width;
  info.bpc = 8U;
  info.color_space = model.color_space;
  info.pclm_num_strips = model.strip_count;
  info.pclm_strip_height = strip_heights;
  info.pclm_strip_data = strip_data;
  info.pclm_strip_data_size = strip_sizes;
  info.pclm_compression_method_preferred = compression;

  objects = make_pclm_strips(
      info.pdf, info.pclm_num_strips, info.pclm_strip_data,
      info.pclm_strip_data_size, info.pclm_compression_method_preferred,
      info.width, info.pclm_strip_height, info.color_space, info.bpc, &doc);
  if (!objects || writer_error.saw_error) {
    failure = "make-pclm-strips";
    trap_after_cleanup = true;
    goto cleanup;
  }
  for (unsigned strip = 0U; strip < model.strip_count; strip++) {
    if (!objects[strip] ||
        !(object_numbers[strip] = pdfioObjGetNumber(objects[strip]))) {
      failure = "xobject-number";
      trap_after_cleanup = true;
      goto cleanup;
    }
  }
  free(objects);
  objects = NULL;
  {
    bool closed = pdfioFileClose(info.pdf);
    info.pdf = NULL;
    if (!closed || writer_error.saw_error) {
      failure = "writer-close";
      trap_after_cleanup = true;
      goto cleanup;
    }
  }
  if (!cf_v2_pclm_object_validate_file(path, &model, object_numbers, decoded,
                                       &failure)) {
    trap_after_cleanup = true;
  }

cleanup:
  free(objects);
  if (info.pdf) {
    (void)pdfioFileClose(info.pdf);
    info.pdf = NULL;
  }
  if (path[0]) {
    unlink(path);
  }
  free(decoded);
  if (trap_after_cleanup) {
    fprintf(stderr, "pwg-pclm-flate-object-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
