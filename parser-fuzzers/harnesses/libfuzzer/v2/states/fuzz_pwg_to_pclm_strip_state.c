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

#define CF_V2_PCLM_STRIP_SELECTOR_BYTES 10U
#define CF_V2_PCLM_STRIP_MAX_INPUT_MATERIAL 4096U
#define CF_V2_PCLM_STRIP_MAX_STRIPS 64U
#define CF_V2_PCLM_STRIP_MAX_HEIGHT 255U
#define CF_V2_PCLM_STRIP_MAX_LINE_BYTES (32U * 3U)
#define CF_V2_PCLM_STRIP_MAX_PAGE_BYTES                               \
  (CF_V2_PCLM_STRIP_MAX_HEIGHT * CF_V2_PCLM_STRIP_MAX_LINE_BYTES)
#define CF_V2_PCLM_STRIP_MAX_TRACKED 4096U

#ifndef CF_V2_PWG_TO_PDF_SOURCE
#error "CF_V2_PWG_TO_PDF_SOURCE must name the current pwgtopdf.c"
#endif

typedef struct cf_v2_pclm_strip_model_s {
  unsigned width;
  unsigned height;
  unsigned preferred_height;
  unsigned strip_count;
  unsigned last_height;
  unsigned components;
  unsigned line_bytes;
  unsigned dpi;
  cups_cspace_t color_space;
  unsigned order;
  unsigned pattern;
  unsigned phase;
} cf_v2_pclm_strip_model_t;

static void *cf_v2_pclm_source_allocations[CF_V2_PCLM_STRIP_MAX_TRACKED];
static size_t cf_v2_pclm_source_allocation_count;
static bool cf_v2_pclm_source_tracker_overflow;

static size_t cf_v2_pclm_source_find(void *pointer) {
  for (size_t index = 0; index < cf_v2_pclm_source_allocation_count; index++) {
    if (cf_v2_pclm_source_allocations[index] == pointer) {
      return index;
    }
  }
  return SIZE_MAX;
}

static void cf_v2_pclm_source_track(void *pointer) {
  if (!pointer || cf_v2_pclm_source_find(pointer) != SIZE_MAX) {
    return;
  }
  if (cf_v2_pclm_source_allocation_count >= CF_V2_PCLM_STRIP_MAX_TRACKED) {
    cf_v2_pclm_source_tracker_overflow = true;
    return;
  }
  cf_v2_pclm_source_allocations[cf_v2_pclm_source_allocation_count++] =
      pointer;
}

static void cf_v2_pclm_source_forget(void *pointer) {
  size_t index = cf_v2_pclm_source_find(pointer);

  if (index == SIZE_MAX) {
    return;
  }
  cf_v2_pclm_source_allocations[index] =
      cf_v2_pclm_source_allocations[--cf_v2_pclm_source_allocation_count];
  cf_v2_pclm_source_allocations[cf_v2_pclm_source_allocation_count] = NULL;
}

static void *cf_v2_pclm_source_malloc(size_t size) {
  void *pointer = malloc(size);

  cf_v2_pclm_source_track(pointer);
  return pointer;
}

static void *cf_v2_pclm_source_calloc(size_t count, size_t size) {
  void *pointer = calloc(count, size);

  cf_v2_pclm_source_track(pointer);
  return pointer;
}

static void *cf_v2_pclm_source_realloc(void *pointer, size_t size) {
  size_t index = cf_v2_pclm_source_find(pointer);
  void *replacement = realloc(pointer, size);

  if (!replacement) {
    if (size == 0U) {
      cf_v2_pclm_source_forget(pointer);
    }
    return NULL;
  }
  if (index == SIZE_MAX) {
    cf_v2_pclm_source_track(replacement);
  } else {
    cf_v2_pclm_source_allocations[index] = replacement;
  }
  return replacement;
}

static char *cf_v2_pclm_source_strdup(const char *value) {
  size_t length = strlen(value) + 1U;
  char *copy = (char *)malloc(length);

  if (copy) {
    memcpy(copy, value, length);
    cf_v2_pclm_source_track(copy);
  }
  return copy;
}

static void cf_v2_pclm_source_free(void *pointer) {
  cf_v2_pclm_source_forget(pointer);
  free(pointer);
}

static void cf_v2_pclm_source_release_all(void) {
  while (cf_v2_pclm_source_allocation_count) {
    free(cf_v2_pclm_source_allocations[--cf_v2_pclm_source_allocation_count]);
    cf_v2_pclm_source_allocations[cf_v2_pclm_source_allocation_count] = NULL;
  }
}

/* Compile the current source directly. Symbol and allocator renames only
 * isolate ownership. The public route cannot reach make_pclm_strips on a
 * populated page, so this target continues at the real page-preparation and
 * row-placement helpers without patching upstream. */
#define init_pdf_info cf_v2_pclm_init_pdf_info
#define free_pdf_info cf_v2_pclm_free_pdf_info
#define split_strings cf_v2_pclm_split_strings
#define int_to_fwstring cf_v2_pclm_int_to_fwstring
#define cfFilterPWGToPDF cf_v2_pclm_filter
#define malloc cf_v2_pclm_source_malloc
#define calloc cf_v2_pclm_source_calloc
#define realloc cf_v2_pclm_source_realloc
#define strdup cf_v2_pclm_source_strdup
#define free cf_v2_pclm_source_free
#include CF_V2_PWG_TO_PDF_SOURCE
#undef free
#undef strdup
#undef realloc
#undef calloc
#undef malloc
#undef cfFilterPWGToPDF
#undef int_to_fwstring
#undef split_strings
#undef free_pdf_info
#undef init_pdf_info

static const unsigned cf_v2_pclm_widths[] = {
    1U, 2U, 3U, 7U, 8U, 15U, 16U, 17U, 31U, 32U,
};
static const unsigned cf_v2_pclm_preferred_heights[] = {
    1U, 2U, 3U, 7U, 8U, 15U, 16U, 17U, 31U, 32U,
};
static const unsigned cf_v2_pclm_dpi[] = {72U, 150U, 300U, 600U};

static uint8_t cf_v2_pclm_selector(const uint8_t *data, size_t size,
                                   size_t index, uint8_t fallback) {
  return data && index < size ? data[index] : fallback;
}

static void cf_v2_pclm_decode(const uint8_t *data, size_t size,
                              cf_v2_pclm_strip_model_t *model) {
  unsigned requested_strips;
  unsigned maximum_strips;
  unsigned remainder_selector;

  memset(model, 0, sizeof(*model));
  model->width = cf_v2_pclm_widths[
      cf_v2_pclm_selector(data, size, 0U, 7U) %
      (sizeof(cf_v2_pclm_widths) / sizeof(cf_v2_pclm_widths[0]))];
  model->preferred_height = cf_v2_pclm_preferred_heights[
      cf_v2_pclm_selector(data, size, 1U, 8U) %
      (sizeof(cf_v2_pclm_preferred_heights) /
       sizeof(cf_v2_pclm_preferred_heights[0]))];
  remainder_selector = cf_v2_pclm_selector(data, size, 3U, 3U);
  switch (remainder_selector % 5U) {
    case 0U:
      model->last_height = model->preferred_height;
      break;
    case 1U:
      model->last_height = 1U;
      break;
    case 2U:
      model->last_height =
          model->preferred_height > 1U ? model->preferred_height - 1U : 1U;
      break;
    case 3U:
      model->last_height = 1U + (model->preferred_height - 1U) / 2U;
      break;
    default:
      model->last_height =
          1U + (remainder_selector >> 3U) % model->preferred_height;
      break;
  }
  maximum_strips =
      1U + (CF_V2_PCLM_STRIP_MAX_HEIGHT - model->last_height) /
               model->preferred_height;
  if (maximum_strips > CF_V2_PCLM_STRIP_MAX_STRIPS) {
    maximum_strips = CF_V2_PCLM_STRIP_MAX_STRIPS;
  }
  requested_strips =
      1U + cf_v2_pclm_selector(data, size, 2U, 15U) % maximum_strips;
  model->strip_count = requested_strips;
  model->height = (requested_strips - 1U) * model->preferred_height +
                  model->last_height;
  model->components =
      (cf_v2_pclm_selector(data, size, 4U, 1U) & 1U) ? 3U : 1U;
  model->color_space =
      model->components == 3U ? CUPS_CSPACE_RGB : CUPS_CSPACE_K;
  model->line_bytes = model->width * model->components;
  model->dpi = cf_v2_pclm_dpi[
      cf_v2_pclm_selector(data, size, 5U, 2U) %
      (sizeof(cf_v2_pclm_dpi) / sizeof(cf_v2_pclm_dpi[0]))];
  model->order = cf_v2_pclm_selector(data, size, 6U, 0U) % 4U;
  model->pattern = cf_v2_pclm_selector(data, size, 7U, 5U) % 6U;
  model->phase = (unsigned)cf_v2_pclm_selector(data, size, 8U, 0U) |
                 ((unsigned)cf_v2_pclm_selector(data, size, 9U, 0U) << 8U);
}

static unsigned cf_v2_pclm_row_for_step(
    const cf_v2_pclm_strip_model_t *model, unsigned step) {
  switch (model->order) {
    case 1U:
      return model->height - 1U - step;
    case 2U: {
      unsigned even_count = (model->height + 1U) / 2U;
      return step < even_count ? step * 2U : (step - even_count) * 2U + 1U;
    }
    case 3U:
      return (step + model->phase % model->height) % model->height;
    default:
      return step;
  }
}

static uint8_t cf_v2_pclm_material(const uint8_t *material,
                                   size_t material_size, unsigned pattern,
                                   unsigned phase, unsigned row,
                                   unsigned byte_index) {
  uint8_t input = material_size
                      ? material[((size_t)row * 131U + byte_index + phase) %
                                 material_size]
                      : (uint8_t)(row * 73U + byte_index * 29U + phase);

  switch (pattern) {
    case 0U:
      return (uint8_t)(row + byte_index + phase);
    case 1U:
      return (uint8_t)(row ^ (byte_index * 17U) ^ phase);
    case 2U:
      return (uint8_t)((row & 1U ? 0xaaU : 0x55U) ^ byte_index ^ phase);
    case 3U:
      return input;
    case 4U:
      return (uint8_t)(input ^ row ^ (byte_index * 31U));
    default:
      return (uint8_t)(input + row * 13U + byte_index * 7U + phase);
  }
}

static bool cf_v2_pclm_partition_matches(
    const struct pdf_info *info, const cf_v2_pclm_strip_model_t *model,
    bool require_full_sizes) {
  unsigned height_sum = 0U;

  if (info->pclm_num_strips != model->strip_count ||
      info->width != model->width || info->height != model->height ||
      info->line_bytes != model->line_bytes || info->bpp != model->components * 8U ||
      info->bpc != 8U || info->color_space != model->color_space ||
      !info->pclm_strip_height || !info->pclm_strip_data ||
      !info->pclm_strip_data_size) {
    return false;
  }
  for (unsigned strip = 0U; strip < model->strip_count; strip++) {
    unsigned expected_height = strip + 1U == model->strip_count
                                   ? model->last_height
                                   : model->preferred_height;
    size_t expected_size = (size_t)expected_height * model->line_bytes;

    if (info->pclm_strip_height[strip] != expected_height ||
        !info->pclm_strip_data[strip] ||
        (require_full_sizes &&
         info->pclm_strip_data_size[strip] != expected_size)) {
      return false;
    }
    height_sum += info->pclm_strip_height[strip];
  }
  return height_sum == model->height;
}

static void cf_v2_pclm_cleanup(struct pdf_info *info) {
  if (info->pdf) {
    (void)pdfioFileClose(info->pdf);
    info->pdf = NULL;
  }
  if (info->temp_filename) {
    unlink(info->temp_filename);
  }
  cf_v2_pclm_source_release_all();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_pclm_strip_model_t model;
  struct pdf_info info;
  pwgtopdf_doc_t doc;
  uint8_t *expected = NULL;
  uint8_t *line = NULL;
  const uint8_t *material = NULL;
  size_t material_size = 0U;
  size_t strip_offsets[CF_V2_PCLM_STRIP_MAX_STRIPS];
  size_t page_bytes;
  bool initialized = false;
  bool trap_after_cleanup = false;
  const char *failure = NULL;

  memset(&info, 0, sizeof(info));
  memset(&doc, 0, sizeof(doc));
  memset(strip_offsets, 0, sizeof(strip_offsets));
  cf_v2_pclm_decode(data, size, &model);
  page_bytes = (size_t)model.height * model.line_bytes;
  if (page_bytes == 0U || page_bytes > CF_V2_PCLM_STRIP_MAX_PAGE_BYTES ||
      model.strip_count == 0U ||
      model.strip_count > CF_V2_PCLM_STRIP_MAX_STRIPS) {
    __builtin_trap();
  }
  if (data && size > CF_V2_PCLM_STRIP_SELECTOR_BYTES) {
    material = data + CF_V2_PCLM_STRIP_SELECTOR_BYTES;
    material_size = size - CF_V2_PCLM_STRIP_SELECTOR_BYTES;
    if (material_size > CF_V2_PCLM_STRIP_MAX_INPUT_MATERIAL) {
      material_size = CF_V2_PCLM_STRIP_MAX_INPUT_MATERIAL;
    }
  }
  expected = (uint8_t *)calloc(1U, page_bytes);
  line = (uint8_t *)malloc(model.line_bytes);
  if (!expected || !line) {
    goto cleanup;
  }

  cf_v2_pclm_init_pdf_info(&info);
  initialized = true;
  info.pclm_strip_height_preferred = model.preferred_height;
  info.outformat = CF_FILTER_OUT_FORMAT_PCLM;
  if (cf_v2_pclm_source_tracker_overflow ||
      create_pdf_file(&info, CF_FILTER_OUT_FORMAT_PCLM, NULL) != 0 ||
      add_pdf_page(&info, 1, model.width, model.height,
                   model.components * 8U, 8U, model.line_bytes,
                   (char *)"Perceptual", model.color_space, model.dpi,
                   model.dpi, &doc) != 0) {
    goto cleanup;
  }
  if (!cf_v2_pclm_partition_matches(&info, &model, true)) {
    failure = "initial-partition";
    trap_after_cleanup = true;
    goto cleanup;
  }
  for (unsigned strip = 1U; strip < model.strip_count; strip++) {
    strip_offsets[strip] =
        strip_offsets[strip - 1U] +
        (size_t)model.line_bytes * info.pclm_strip_height[strip - 1U];
  }

  for (unsigned step = 0U; step < model.height; step++) {
    unsigned row = cf_v2_pclm_row_for_step(&model, step);
    unsigned strip = row / model.preferred_height;
    unsigned row_in_strip = row % model.preferred_height;
    size_t page_offset = (size_t)row * model.line_bytes;
    size_t strip_offset = (size_t)row_in_strip * model.line_bytes;
    size_t strip_capacity =
        (size_t)info.pclm_strip_height[strip] * model.line_bytes;

    for (unsigned byte_index = 0U; byte_index < model.line_bytes;
         byte_index++) {
      line[byte_index] = cf_v2_pclm_material(
          material, material_size, model.pattern, model.phase, row, byte_index);
    }
    memcpy(expected + page_offset, line, model.line_bytes);
    pdf_set_line(&info, row, line, &doc);
    if (memcmp(info.pclm_strip_data[strip] + strip_offset, line,
               model.line_bytes) != 0) {
      failure = "row-offset-or-bytes";
      trap_after_cleanup = true;
      goto cleanup;
    }
    /* Current upstream overwrites capacity with one row here. Restore the
     * independently calculated capacity so this continuation can exercise
     * every row. Faithful/boundary targets retain the original behavior. */
    if (info.pclm_strip_data_size[strip] != model.line_bytes &&
        info.pclm_strip_data_size[strip] != strip_capacity) {
      failure = "unexpected-size-transition";
      trap_after_cleanup = true;
      goto cleanup;
    }
    info.pclm_strip_data_size[strip] = strip_capacity;
  }

  if (!cf_v2_pclm_partition_matches(&info, &model, true)) {
    failure = "final-partition";
    trap_after_cleanup = true;
    goto cleanup;
  }
  for (unsigned strip = 0U; strip < model.strip_count; strip++) {
    size_t strip_size =
        (size_t)info.pclm_strip_height[strip] * model.line_bytes;

    if (memcmp(info.pclm_strip_data[strip], expected + strip_offsets[strip],
               strip_size) != 0) {
      failure = "decoded-strip-bytes";
      trap_after_cleanup = true;
      goto cleanup;
    }
  }

cleanup:
  if (cf_v2_pclm_source_tracker_overflow) {
    failure = "source-allocation-tracker-overflow";
    trap_after_cleanup = true;
  }
  if (initialized) {
    cf_v2_pclm_cleanup(&info);
  } else {
    cf_v2_pclm_source_release_all();
  }
  cf_v2_pclm_source_tracker_overflow = false;
  free(line);
  free(expected);
  if (trap_after_cleanup) {
    fprintf(stderr, "pwg-pclm-strip-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
