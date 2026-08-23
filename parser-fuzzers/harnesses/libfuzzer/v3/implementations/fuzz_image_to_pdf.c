// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <cupsfilters/filter.h>

static int cf_v3_image_pdf_post_ppd(cf_filter_data_t *data);

#define CF_V2_FILTER_FUNCTION cfFilterImageToPDF
#define CF_V2_TARGET_NAME "fuzz_v3_cupsfilters_image_to_pdf"
#define CF_V2_INPUT_MIME "image/png"
#define CF_V2_OUTPUT_MIME "application/pdf"
#define CF_V2_POST_PPD_LOAD_HOOK cf_v3_image_pdf_post_ppd
#define LLVMFuzzerTestOneInput cf_v3_image_pdf_unused_direct_entrypoint
#include "../../v2/implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include "image_pdf_formats.h"
#include "image_pdf_oracle.h"
#include "image_pdf_state.h"
#include "image_raw_png.h"

#include <cupsfilters/image-private.h>
#include <stdbool.h>
#include <tiffio.h>

#define CF_V3_IMAGE_PDF_TRACKED_STREAMS 16U
#define CF_V3_IMAGE_PDF_TRACKED_OPTIONS 32U

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
extern FILE *__real_fdopen(int fd, const char *mode);
extern int __real_fclose(FILE *stream);
extern void __real_cfImageClose(cf_image_t *image);
extern int __real_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data,
                                           int num_options,
                                           cups_option_t **options);
extern void __real_cupsFreeOptions(int num_options, cups_option_t *options);
extern TIFF *__real_TIFFFdOpen(int fd, const char *name, const char *mode);

typedef struct cf_v3_image_pdf_options_owner_s {
  cups_option_t *options;
  int count;
} cf_v3_image_pdf_options_owner_t;

static int cf_v3_image_pdf_faithful;
static const char *cf_v3_image_pdf_mime = "image/png";
static unsigned cf_v3_image_pdf_hardware_copies_policy;
static unsigned cf_v3_image_pdf_hardware_collate_policy;
static FILE *cf_v3_image_pdf_streams[CF_V3_IMAGE_PDF_TRACKED_STREAMS];
static size_t cf_v3_image_pdf_stream_count;
static cf_v3_image_pdf_options_owner_t
    cf_v3_image_pdf_options[CF_V3_IMAGE_PDF_TRACKED_OPTIONS];
static size_t cf_v3_image_pdf_options_count;

static void cf_v3_image_pdf_rebuild_cache(cf_image_t *image) {
  cf_ic_t *first = NULL;
  cf_ic_t *last = NULL;
  size_t columns;
  size_t rows;

  if (!image || !image->tiles) {
    return;
  }
  columns = image->xsize / CF_TILE_SIZE +
            (image->xsize % CF_TILE_SIZE != 0U);
  rows = image->ysize / CF_TILE_SIZE +
         (image->ysize % CF_TILE_SIZE != 0U);
  if (!columns || !rows || columns > 65536U || rows > 65536U ||
      columns > 1048576U / rows) {
    return;
  }
  for (size_t y = 0; y < rows; y++) {
    for (size_t x = 0; x < columns; x++) {
      cf_ic_t *entry = image->tiles[y][x].ic;
      cf_ic_t *known = first;

      while (known && known != entry) {
        known = known->next;
      }
      if (!entry || known) {
        continue;
      }
      entry->prev = last;
      entry->next = NULL;
      if (last) {
        last->next = entry;
      } else {
        first = entry;
      }
      last = entry;
    }
  }
  image->first = first;
  image->last = last;
}

void __wrap_cfImageClose(cf_image_t *image) {
  if (!cf_v3_image_pdf_faithful) {
    cf_v3_image_pdf_rebuild_cache(image);
  }
  __real_cfImageClose(image);
}

FILE *__wrap_fdopen(int fd, const char *mode) {
  FILE *stream = __real_fdopen(fd, mode);

  if (stream &&
      cf_v3_image_pdf_stream_count < CF_V3_IMAGE_PDF_TRACKED_STREAMS) {
    cf_v3_image_pdf_streams[cf_v3_image_pdf_stream_count++] = stream;
  }
  return stream;
}

static void cf_v3_image_pdf_forget_stream(FILE *stream) {
  for (size_t index = 0; index < cf_v3_image_pdf_stream_count; index++) {
    if (cf_v3_image_pdf_streams[index] != stream) {
      continue;
    }
    cf_v3_image_pdf_streams[index] =
        cf_v3_image_pdf_streams[--cf_v3_image_pdf_stream_count];
    cf_v3_image_pdf_streams[cf_v3_image_pdf_stream_count] = NULL;
    return;
  }
}

int __wrap_fclose(FILE *stream) {
  cf_v3_image_pdf_forget_stream(stream);
  return __real_fclose(stream);
}

static void cf_v3_image_pdf_release_streams(bool faithful) {
  if (!faithful) {
    while (cf_v3_image_pdf_stream_count) {
      FILE *stream =
          cf_v3_image_pdf_streams[--cf_v3_image_pdf_stream_count];
      cf_v3_image_pdf_streams[cf_v3_image_pdf_stream_count] = NULL;
      (void)__real_fclose(stream);
    }
  } else {
    memset(cf_v3_image_pdf_streams, 0, sizeof(cf_v3_image_pdf_streams));
    cf_v3_image_pdf_stream_count = 0;
  }
}

static void cf_v3_image_pdf_forget_options(cups_option_t *options) {
  for (size_t index = 0; index < cf_v3_image_pdf_options_count; index++) {
    if (cf_v3_image_pdf_options[index].options != options) {
      continue;
    }
    cf_v3_image_pdf_options[index] =
        cf_v3_image_pdf_options[--cf_v3_image_pdf_options_count];
    memset(&cf_v3_image_pdf_options[cf_v3_image_pdf_options_count], 0,
           sizeof(cf_v3_image_pdf_options[0]));
    return;
  }
}

int __wrap_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data, int num_options,
                                    cups_option_t **options) {
  cups_option_t *initial = options ? *options : NULL;
  int result = __real_cfJoinJobOptionsAndAttrs(data, num_options, options);

  if (options && *options && *options != initial &&
      cf_v3_image_pdf_options_count < CF_V3_IMAGE_PDF_TRACKED_OPTIONS) {
    cf_v3_image_pdf_options[cf_v3_image_pdf_options_count++] =
        (cf_v3_image_pdf_options_owner_t){*options, result};
  }
  return result;
}

void __wrap_cupsFreeOptions(int num_options, cups_option_t *options) {
  cf_v3_image_pdf_forget_options(options);
  __real_cupsFreeOptions(num_options, options);
}

static void cf_v3_image_pdf_release_options(bool faithful) {
  if (!faithful) {
    while (cf_v3_image_pdf_options_count) {
      cf_v3_image_pdf_options_owner_t *owner =
          &cf_v3_image_pdf_options[--cf_v3_image_pdf_options_count];
      __real_cupsFreeOptions(owner->count, owner->options);
      memset(owner, 0, sizeof(*owner));
    }
  } else {
    memset(cf_v3_image_pdf_options, 0, sizeof(cf_v3_image_pdf_options));
    cf_v3_image_pdf_options_count = 0;
  }
}

TIFF *__wrap_TIFFFdOpen(int fd, const char *name, const char *mode) {
  int duplicate = dup(fd);
  TIFF *tiff;

  if (duplicate < 0) {
    return NULL;
  }
  tiff = __real_TIFFFdOpen(duplicate, name, mode);
  if (!tiff) {
    (void)close(duplicate);
  }
  return tiff;
}

static int cf_v3_image_pdf_post_ppd(cf_filter_data_t *data) {
  static const char *const policies[] = {NULL, "false", "true"};

  if (!data) {
    return -1;
  }
  data->content_type = (char *)cf_v3_image_pdf_mime;
  data->num_options = cupsRemoveOption("hardware-copies", data->num_options,
                                       &data->options);
  data->num_options = cupsRemoveOption("hardware-collate", data->num_options,
                                       &data->options);
  if (policies[cf_v3_image_pdf_hardware_copies_policy]) {
    data->num_options = cupsAddOption(
        "hardware-copies",
        policies[cf_v3_image_pdf_hardware_copies_policy], data->num_options,
        &data->options);
  }
  if (policies[cf_v3_image_pdf_hardware_collate_policy]) {
    data->num_options = cupsAddOption(
        "hardware-collate",
        policies[cf_v3_image_pdf_hardware_collate_policy], data->num_options,
        &data->options);
  }
  return 0;
}

static char *cf_v3_image_pdf_build_ppd(const cf_v2_control_t *control,
                                       unsigned components,
                                       bool complete_size_range,
                                       size_t *size) {
  char *ppd = NULL;
  FILE *stream = open_memstream(&ppd, size);

  if (!stream) {
    return NULL;
  }
  if (cf_v2_write_ppd(stream, control, CF_V2_TARGET_NAME) != 0 ||
      fprintf(stream, "*ColorDevice: %s\n",
              components > 1U ? "True" : "False") < 0 ||
      (complete_size_range &&
       fprintf(stream,
               "*VariablePaperSize: True\n"
               "*ParamCustomPageSize Width: 1 points 72 1000\n"
               "*ParamCustomPageSize Height: 2 points 72 1400\n"
               "*ParamCustomPageSize WidthOffset: 3 points 0 0\n"
               "*ParamCustomPageSize HeightOffset: 4 points 0 0\n"
               "*ParamCustomPageSize Orientation: 5 int 0 3\n"
               "*HWMargins: 12 12 12 12\n"
               "*CustomPageSize True: \"pop pop pop pop pop\"\n") < 0) ||
      fclose(stream) != 0) {
    free(ppd);
    return NULL;
  }
  return ppd;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  size_t mode_limit;
  size_t limit;
  size_t suffix_size;

  (void)seed;
  if (!data || max_size < CF_V3_IMAGE_PDF_MIN_INPUT) {
    return 0;
  }
  mode_limit = size > CF_V3_IMAGE_PDF_MAGIC_SIZE + 2U &&
                       (data[CF_V3_IMAGE_PDF_MAGIC_SIZE + 2U] &
                        CF_V3_IMAGE_PDF_RAW_PNG_FLAG)
                   ? CF_V3_IMAGE_PDF_MAX_INPUT
                   : CF_V3_IMAGE_PDF_STRUCTURED_MAX_INPUT;
  limit = max_size < mode_limit ? max_size : mode_limit;
  if (size > limit) {
    size = limit;
  }
  if (size < CF_V3_IMAGE_PDF_MIN_INPUT) {
    memset(data + size, 0, CF_V3_IMAGE_PDF_MIN_INPUT - size);
    size = CF_V3_IMAGE_PDF_MIN_INPUT;
  }
  suffix_size = LLVMFuzzerMutate(
      data + CF_V3_IMAGE_PDF_MAGIC_SIZE,
      size - CF_V3_IMAGE_PDF_MAGIC_SIZE,
      limit - CF_V3_IMAGE_PDF_MAGIC_SIZE);
  size = CF_V3_IMAGE_PDF_MAGIC_SIZE + suffix_size;
  if (size < CF_V3_IMAGE_PDF_MIN_INPUT) {
    memset(data + size, 0, CF_V3_IMAGE_PDF_MIN_INPUT - size);
    size = CF_V3_IMAGE_PDF_MIN_INPUT;
  }
  memcpy(data, CF_V3_IMAGE_PDF_MAGIC, CF_V3_IMAGE_PDF_MAGIC_SIZE);
  data[CF_V3_IMAGE_PDF_MAGIC_SIZE + 1U] &= 0x7fU;
  if (!(data[CF_V3_IMAGE_PDF_MAGIC_SIZE + 2U] &
        CF_V3_IMAGE_PDF_RAW_PNG_FLAG) &&
      size > CF_V3_IMAGE_PDF_STRUCTURED_MAX_INPUT) {
    size = CF_V3_IMAGE_PDF_STRUCTURED_MAX_INPUT;
  }
  return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selector;
  cf_v3_image_pdf_state_t state;
  cf_v3_image_raw_png_info_t raw_info;
  cf_v3_image_pdf_format_request_t format_request;
  cf_v3_image_pdf_format_result_t image;
  cf_v3_image_pdf_oracle_t oracle;
  cf_v2_control_t control;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char options[1024];
  char title[96];
  char *ppd = NULL;
  size_t ppd_size = 0;
  bool capture_output;
  bool raw_png;
  bool trap_after_cleanup = false;
  const char *failure = NULL;
  int executed = 0;

  if (!data || size < CF_V3_IMAGE_PDF_MIN_INPUT ||
      size > CF_V3_IMAGE_PDF_MAX_INPUT ||
      memcmp(data, CF_V3_IMAGE_PDF_MAGIC, CF_V3_IMAGE_PDF_MAGIC_SIZE) != 0) {
    return 0;
  }
  selector = data + CF_V3_IMAGE_PDF_MAGIC_SIZE;
  raw_png = (selector[2] & CF_V3_IMAGE_PDF_RAW_PNG_FLAG) != 0U;
  cf_v3_image_pdf_decode_state(selector, &state);

  memset(&raw_info, 0, sizeof(raw_info));
  memset(&format_request, 0, sizeof(format_request));
  memset(&image, 0, sizeof(image));
  if (raw_png) {
    if (!cf_v3_image_raw_png_validate(
            data + CF_V3_IMAGE_PDF_HEADER_SIZE,
            size - CF_V3_IMAGE_PDF_HEADER_SIZE, &raw_info)) {
      return 0;
    }
    image.mime = "image/png";
    image.format = CF_V3_IMAGE_PDF_FORMAT_PNG;
    image.width = (uint16_t)raw_info.width;
    image.height = (uint16_t)raw_info.height;
    image.xppi = 72U;
    image.yppi = 72U;
    image.reference_components = (uint8_t)raw_info.components;
  } else {
    format_request.format_selector = (uint8_t)state.format_selector;
    format_request.source_selector = (uint8_t)state.source_selector;
    format_request.color_selector = (uint8_t)state.color_selector;
    format_request.geometry_selector = (uint8_t)state.geometry_selector;
    for (size_t index = 0; index < sizeof(format_request.codec_selectors);
         index++) {
      format_request.codec_selectors[index] = state.codec_controls[index];
    }
    format_request.pattern = (uint8_t)state.pattern;
    format_request.phase = (uint8_t)state.phase;
    format_request.stride = (uint8_t)state.stride;
    format_request.material = data + CF_V3_IMAGE_PDF_HEADER_SIZE;
    format_request.material_size = size - CF_V3_IMAGE_PDF_HEADER_SIZE;
    format_request.explicit_width = (uint16_t)state.explicit_width;
    format_request.explicit_height = (uint16_t)state.explicit_height;
    format_request.xppi = (uint16_t)state.xppi;
    format_request.yppi = (uint16_t)state.yppi;
    format_request.allow_known_boundaries = state.faithful;
    if (cf_v3_image_pdf_format_build(&format_request, &image) != 0) {
      return 0;
    }
  }
  state.xppi = image.xppi;
  state.yppi = image.yppi;
  if (!cf_v3_image_pdf_model(&state, image.width, image.height, &oracle)) {
    cf_v3_image_pdf_format_free(&image);
    return 0;
  }
  if (getenv("CF_V3_ORACLE_TRACE")) {
    fprintf(stderr,
            "image-pdf-v3 state: profile=%u raw=%u format=%u source=%u "
            "geometry=%ux%u ppi=%ux%u scaling=%u topology=%ux%u "
            "pages=%zu copies=%u collate=%d duplex=%d reverse=%d "
            "position=%u page-size=%u ppd=%u color=%u\n",
            (unsigned)state.profile, (unsigned)raw_png,
            (unsigned)image.format,
            state.source_selector, image.width, image.height, state.xppi,
            state.yppi, state.natural_scaling, state.topology_x,
            state.topology_y, oracle.page_count, state.copies, state.collate,
            state.duplex, state.reverse, state.position, state.page_size,
            state.ppd_profile, image.reference_components);
  }
  oracle.pixels = image.reference_pixels;
  oracle.pixel_size = image.reference_size;
  oracle.width = image.width;
  oracle.height = image.height;
  oracle.components = image.reference_components;
  /* Hue/saturation are exercised through the real decoder, but an exact
   * comparison there would duplicate libcupsfilters' own matrix algorithm. */
  oracle.exact_pixels = state.saturation == 100U && state.hue == 0;
  capture_output = !raw_png && oracle.page_count > 0U;

  memset(&control, 0, sizeof(control));
  control.ppd_profile = (uint8_t)state.ppd_profile;
  control.page_size = (uint8_t)state.page_size;
  control.color_model = image.reference_components == 1U
                            ? 0U
                            : image.reference_components == 4U ? 2U : 1U;
  control.resolution = 0U;
  control.sides = state.duplex ? 1U : 0U;
  control.orientation = (uint8_t)state.orientation;
  control.scaling = (uint8_t)state.natural_scaling;
  control.copies = (uint8_t)(state.copies - 1U);
  control.position = (uint8_t)state.position;
  control.output_order = state.reverse ? 1U : 0U;
  control.mirror = state.mirror ? 1U : 0U;
  control.route_mode = (uint8_t)state.profile;
  if (cf_v3_image_pdf_build_options(&state, image.reference_components,
                                    options, sizeof(options)) != 0 ||
      !(ppd = cf_v3_image_pdf_build_ppd(
            &control, image.reference_components, !state.faithful,
            &ppd_size))) {
    cf_v3_image_pdf_format_free(&image);
    free(ppd);
    return 0;
  }
  if (getenv("CF_V3_ORACLE_TRACE")) {
    fprintf(stderr, "image-pdf-v3 options: %s\n", options);
    if (!raw_png && image.format == CF_V3_IMAGE_PDF_FORMAT_PNG &&
        image.encoded_size >= 24U) {
      const uint8_t *png = image.encoded_bytes;
      const uint32_t png_width = ((uint32_t)png[16] << 24U) |
                                 ((uint32_t)png[17] << 16U) |
                                 ((uint32_t)png[18] << 8U) | png[19];
      const uint32_t png_height = ((uint32_t)png[20] << 24U) |
                                  ((uint32_t)png[21] << 16U) |
                                  ((uint32_t)png[22] << 8U) | png[23];
      fprintf(stderr, "image-pdf-v3 PNG IHDR: %ux%u\n", png_width,
              png_height);
    }
  }
  snprintf(title, sizeof(title), "image-pdf-v3-%u-%u-%u-%08x",
           (unsigned)state.profile, (unsigned)image.format,
           (unsigned)image.reference_components, image.relation_flags);

  memset(&job, 0, sizeof(job));
  memset(&result, 0, sizeof(result));
  job.control = control;
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = (const uint8_t *)title;
  job.title_size = strlen(title);
  job.document = raw_png ? data + CF_V3_IMAGE_PDF_HEADER_SIZE
                         : image.encoded_bytes;
  job.document_size = raw_png ? size - CF_V3_IMAGE_PDF_HEADER_SIZE
                              : image.encoded_size;

  cf_v3_image_pdf_faithful = state.faithful;
  cf_v3_image_pdf_mime = image.mime;
  cf_v3_image_pdf_hardware_copies_policy =
      state.hardware_copies_policy;
  cf_v3_image_pdf_hardware_collate_policy =
      state.hardware_collate_policy;
  executed = cf_v2_execute_direct_job(&job, capture_output, &result);
  cf_v3_image_pdf_release_streams(state.faithful);
  cf_v3_image_pdf_release_options(state.faithful);
  cf_v3_image_pdf_faithful = 0;

  if (!raw_png) {
    if (!executed) {
      failure = "filter-not-executed";
      trap_after_cleanup = !state.faithful;
    } else if (result.status != 0) {
      failure = "filter-status";
      trap_after_cleanup = !state.faithful;
    } else if (capture_output &&
               (!result.captured || !result.output_size ||
                !cf_v3_image_pdf_validate(result.output, result.output_size,
                                          &oracle, &failure))) {
      trap_after_cleanup = true;
    }
  }

  cf_v2_free_run_result(&result);
  free(ppd);
  cf_v3_image_pdf_format_free(&image);
  cf_v3_image_pdf_mime = "image/png";
  cf_v3_image_pdf_hardware_copies_policy = 0U;
  cf_v3_image_pdf_hardware_collate_policy = 0U;
  if (trap_after_cleanup) {
    fprintf(stderr, "image-pdf-v3-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
