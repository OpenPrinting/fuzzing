// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include <cupsfilters/filter.h>
#include <cupsfilters/ipp.h>

static int cf_v3_image_raster_post_ppd(cf_filter_data_t *data);

#define CF_V2_FILTER_FUNCTION cfFilterImageToRaster
#define CF_V2_TARGET_NAME "fuzz_v3_cupsfilters_image_to_raster"
#define CF_V2_INPUT_MIME "image/png"
#define CF_V2_OUTPUT_MIME "application/vnd.cups-raster"
#define CF_V2_POST_PPD_LOAD_HOOK cf_v3_image_raster_post_ppd
#define CF_V2_STDIO_STREAM_CONTINUATION 1
#define LLVMFuzzerTestOneInput cf_v3_image_raster_unused_direct_entrypoint
#include "../../v2/implementations/fuzz_direct_filter.c"
#undef LLVMFuzzerTestOneInput

#include "image_pdf_formats.h"
#include "image_raw_png.h"
#include "image_raster_oracle.h"
#include "image_raster_source.h"
#include "image_raster_state.h"

#include <cupsfilters/image-private.h>
#include <limits.h>
#include <stdbool.h>
#include <tiffio.h>

#define CF_V3_IMAGE_RASTER_TRACKED_OPTIONS 32U

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
extern void __real_cfImageClose(cf_image_t *image);
extern int __real_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data,
                                           int num_options,
                                           cups_option_t **options);
extern void __real_cupsFreeOptions(int num_options, cups_option_t *options);
extern TIFF *__real_TIFFFdOpen(int fd, const char *name, const char *mode);
extern void __real_cfGenerateSizes(
    ipp_t *response, cf_gen_sizes_mode_t mode, cups_array_t **sizes,
    ipp_attribute_t **defattr, int *width, int *length, int *left,
    int *bottom, int *right, int *top, int *min_width, int *min_length,
    int *max_width, int *max_length, int *custom_left, int *custom_bottom,
    int *custom_right, int *custom_top, char *size_name,
    ipp_t **media_col_entry);

typedef struct cf_v3_image_raster_options_owner_s {
  cups_option_t *options;
  int count;
} cf_v3_image_raster_options_owner_t;

static const cf_v3_image_raster_state_t *cf_v3_image_raster_active_state;
static const char *cf_v3_image_raster_mime = "image/png";
static cf_v3_image_raster_options_owner_t
    cf_v3_image_raster_options[CF_V3_IMAGE_RASTER_TRACKED_OPTIONS];
static size_t cf_v3_image_raster_options_count;

void __wrap_cfGenerateSizes(
    ipp_t *response, cf_gen_sizes_mode_t mode, cups_array_t **sizes,
    ipp_attribute_t **defattr, int *width, int *length, int *left,
    int *bottom, int *right, int *top, int *min_width, int *min_length,
    int *max_width, int *max_length, int *custom_left, int *custom_bottom,
    int *custom_right, int *custom_top, char *size_name,
    ipp_t **media_col_entry) {
  const bool initialize_ranges =
      cf_v3_image_raster_active_state &&
      !cf_v3_image_raster_active_state->faithful &&
      mode == CF_GEN_SIZES_DEFAULT;

  if (initialize_ranges) {
    if (min_width) {
      *min_width = INT_MAX;
    }
    if (min_length) {
      *min_length = INT_MAX;
    }
    if (max_width) {
      *max_width = 0;
    }
    if (max_length) {
      *max_length = 0;
    }
  }
  __real_cfGenerateSizes(response, mode, sizes, defattr, width, length, left,
                         bottom, right, top, min_width, min_length, max_width,
                         max_length, custom_left, custom_bottom, custom_right,
                         custom_top, size_name, media_col_entry);
  if (initialize_ranges) {
    if (min_width && *min_width == INT_MAX) {
      *min_width = 0;
    }
    if (min_length && *min_length == INT_MAX) {
      *min_length = 0;
    }
  }
}

static void cf_v3_image_raster_rebuild_cache(cf_image_t *image) {
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
  for (size_t y = 0U; y < rows; y++) {
    for (size_t x = 0U; x < columns; x++) {
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
  if (!cf_v3_image_raster_active_state ||
      !cf_v3_image_raster_active_state->faithful) {
    cf_v3_image_raster_rebuild_cache(image);
  }
  __real_cfImageClose(image);
}

static void cf_v3_image_raster_forget_options(cups_option_t *options) {
  for (size_t index = 0U; index < cf_v3_image_raster_options_count; index++) {
    if (cf_v3_image_raster_options[index].options != options) {
      continue;
    }
    cf_v3_image_raster_options[index] =
        cf_v3_image_raster_options[--cf_v3_image_raster_options_count];
    memset(&cf_v3_image_raster_options[cf_v3_image_raster_options_count], 0,
           sizeof(cf_v3_image_raster_options[0]));
    return;
  }
}

int __wrap_cfJoinJobOptionsAndAttrs(cf_filter_data_t *data, int num_options,
                                    cups_option_t **options) {
  cups_option_t *initial = options ? *options : NULL;
  int result = __real_cfJoinJobOptionsAndAttrs(data, num_options, options);

  if (options && *options && *options != initial &&
      cf_v3_image_raster_options_count <
          CF_V3_IMAGE_RASTER_TRACKED_OPTIONS) {
    cf_v3_image_raster_options[cf_v3_image_raster_options_count++] =
        (cf_v3_image_raster_options_owner_t){*options, result};
  }
  return result;
}

void __wrap_cupsFreeOptions(int num_options, cups_option_t *options) {
  cf_v3_image_raster_forget_options(options);
  __real_cupsFreeOptions(num_options, options);
}

static void cf_v3_image_raster_release_options(void) {
  while (cf_v3_image_raster_options_count) {
    cf_v3_image_raster_options_owner_t *owner =
        &cf_v3_image_raster_options[--cf_v3_image_raster_options_count];

    __real_cupsFreeOptions(owner->count, owner->options);
    memset(owner, 0, sizeof(*owner));
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

static int cf_v3_image_raster_post_ppd(cf_filter_data_t *data) {
  const cf_v3_image_raster_state_t *state = cf_v3_image_raster_active_state;
  cups_page_header2_t *header;

  if (!data || !state || !(header = data->header)) {
    return -1;
  }
  data->content_type = (char *)cf_v3_image_raster_mime;
  header->cupsColorSpace = state->output.color_space;
  header->cupsColorOrder = state->output.color_order;
  header->cupsNumColors = state->output.num_colors;
  header->cupsBitsPerColor = state->output.bits_per_color;
  header->cupsBitsPerPixel = state->output.bits_per_pixel;
  header->HWResolution[0] = state->output_resolution_x;
  header->HWResolution[1] = state->output_resolution_y;
  header->Orientation = state->orientation;
  header->Duplex = state->duplex;
  header->Tumble = state->duplex && (state->orientation & 1U);
  return 0;
}

static char *cf_v3_image_raster_build_ppd(
    const cf_v3_image_raster_state_t *state, size_t *ppd_size) {
  char *ppd = NULL;
  FILE *stream = open_memstream(&ppd, ppd_size);
  double imageable_right = state->page_width - state->margin_right;
  double imageable_top = state->page_height - state->margin_top;
  int close_status;
  int status;

  if (!stream || !(state->page_width > 0.0) ||
      !(state->page_height > 0.0) ||
      !(imageable_right > state->margin_left) ||
      !(imageable_top > state->margin_bottom)) {
    if (stream) {
      fclose(stream);
    }
    free(ppd);
    return NULL;
  }
  status = fprintf(
      stream,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"3.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"cups-filters image raster v3\"\n"
      "*ShortNickName: \"cups-filters image raster v3\"\n"
      "*NickName: \"cups-filters image raster v3\"\n"
      "*PCFileName: \"IMGRA3.PPD\"\n"
      "*Product: \"(cups-filters image raster v3)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 2.0\n"
      "*cupsManualCopies: False\n"
      "*ColorDevice: %s\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 %s\"\n"
      "*OpenUI *PageSize: PickOne\n"
      "*DefaultPageSize: Fuzz\n"
      "*PageSize Fuzz/Fuzz: \"<</PageSize[%.8f %.8f]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*DefaultImageableArea: Fuzz\n"
      "*ImageableArea Fuzz: \"%.8f %.8f %.8f %.8f\"\n"
      "*DefaultPaperDimension: Fuzz\n"
      "*PaperDimension Fuzz: \"%.8f %.8f\"\n"
      "*OpenUI *ColorModel: PickOne\n"
      "*DefaultColorModel: Fuzz\n"
      "*ColorModel Fuzz/Fuzz: \"<</cupsColorSpace %u/cupsBitsPerColor %u/cupsBitsPerPixel %u/cupsColorOrder %u>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *Resolution: PickOne\n"
      "*DefaultResolution: Fuzz\n"
      "*Resolution Fuzz/Fuzz: \"<</HWResolution[%u %u]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n",
      state->output.num_colors > 1U ? "True" : "False",
      CF_V2_TARGET_NAME, state->page_width, state->page_height,
      state->margin_left, state->margin_bottom, imageable_right,
      imageable_top, state->page_width, state->page_height,
      (unsigned)state->output.color_space,
      state->output.bits_per_color, state->output.bits_per_pixel,
      (unsigned)state->output.color_order, state->output_resolution_x,
      state->output_resolution_y);
  if (status >= 0 && !state->faithful) {
    status = fprintf(stream,
                     "*VariablePaperSize: True\n"
                     "*ParamCustomPageSize Width: 1 points 72 1000\n"
                     "*ParamCustomPageSize Height: 2 points 72 1400\n"
                     "*ParamCustomPageSize WidthOffset: 3 points 0 0\n"
                     "*ParamCustomPageSize HeightOffset: 4 points 0 0\n"
                     "*ParamCustomPageSize Orientation: 5 int 0 3\n"
                     "*HWMargins: 12 12 12 12\n"
                     "*CustomPageSize True: \"pop pop pop pop pop\"\n");
  }
  close_status = fclose(stream);
  if (status < 0 || close_status != 0) {
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
  if (!data || max_size < CF_V3_IMAGE_RASTER_MIN_INPUT) {
    return 0U;
  }
  mode_limit = size > CF_V3_IMAGE_RASTER_MAGIC_SIZE + 2U &&
                       (data[CF_V3_IMAGE_RASTER_MAGIC_SIZE + 2U] &
                        CF_V3_IMAGE_RASTER_RAW_PNG_FLAG)
                   ? CF_V3_IMAGE_RASTER_MAX_INPUT
                   : CF_V3_IMAGE_RASTER_STRUCTURED_MAX_INPUT;
  limit = max_size < mode_limit ? max_size : mode_limit;
  if (size > limit) {
    size = limit;
  }
  if (size < CF_V3_IMAGE_RASTER_MIN_INPUT) {
    memset(data + size, 0, CF_V3_IMAGE_RASTER_MIN_INPUT - size);
    size = CF_V3_IMAGE_RASTER_MIN_INPUT;
  }
  suffix_size = LLVMFuzzerMutate(
      data + CF_V3_IMAGE_RASTER_MAGIC_SIZE,
      size - CF_V3_IMAGE_RASTER_MAGIC_SIZE,
      limit - CF_V3_IMAGE_RASTER_MAGIC_SIZE);
  size = CF_V3_IMAGE_RASTER_MAGIC_SIZE + suffix_size;
  if (size < CF_V3_IMAGE_RASTER_MIN_INPUT) {
    memset(data + size, 0, CF_V3_IMAGE_RASTER_MIN_INPUT - size);
    size = CF_V3_IMAGE_RASTER_MIN_INPUT;
  }
  memcpy(data, CF_V3_IMAGE_RASTER_MAGIC, CF_V3_IMAGE_RASTER_MAGIC_SIZE);
  data[CF_V3_IMAGE_RASTER_MAGIC_SIZE + 1U] &= 0x7fU;
  if (!(data[CF_V3_IMAGE_RASTER_MAGIC_SIZE + 2U] &
        CF_V3_IMAGE_RASTER_RAW_PNG_FLAG) &&
      size > CF_V3_IMAGE_RASTER_STRUCTURED_MAX_INPUT) {
    size = CF_V3_IMAGE_RASTER_STRUCTURED_MAX_INPUT;
  }
  return size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *selectors;
  const uint8_t *material;
  size_t material_size;
  cf_v3_image_raster_state_t state;
  cf_v3_image_raw_png_info_t raw_info;
  cf_v3_image_pdf_format_request_t format_request;
  cf_v3_image_pdf_format_result_t image;
  cf_v2_control_t control;
  cf_v2_job_input_t job;
  cf_v2_run_result_t result;
  char options[1024];
  char title[128];
  char *ppd = NULL;
  size_t ppd_size = 0U;
  bool capture_output;
  bool raw_png;
  bool trap_after_cleanup = false;
  const char *failure = NULL;
  int special;
  int executed = 0;

  if (!data || size < CF_V3_IMAGE_RASTER_MIN_INPUT ||
      size > CF_V3_IMAGE_RASTER_MAX_INPUT ||
      memcmp(data, CF_V3_IMAGE_RASTER_MAGIC,
             CF_V3_IMAGE_RASTER_MAGIC_SIZE) != 0) {
    return 0;
  }
  selectors = data + CF_V3_IMAGE_RASTER_MAGIC_SIZE;
  material = data + CF_V3_IMAGE_RASTER_HEADER_SIZE;
  material_size = size - CF_V3_IMAGE_RASTER_HEADER_SIZE;
  raw_png = (selectors[2] & CF_V3_IMAGE_RASTER_RAW_PNG_FLAG) != 0U;
  cf_v3_image_raster_decode_state(selectors, &state);
  memset(&raw_info, 0, sizeof(raw_info));
  memset(&format_request, 0, sizeof(format_request));
  memset(&image, 0, sizeof(image));
  if (raw_png) {
    if (!cf_v3_image_raw_png_validate(material, material_size, &raw_info)) {
      return 0;
    }
    image.mime = "image/png";
    image.format = CF_V3_IMAGE_PDF_FORMAT_PNG;
    image.width = (uint16_t)raw_info.width;
    image.height = (uint16_t)raw_info.height;
    image.xppi = 72U;
    image.yppi = 72U;
    image.reference_components = (uint8_t)raw_info.components;
    special = 0;
  } else {
    special = cf_v3_image_raster_build_special_source(
        &state, material, material_size, &image);
    if (special < 0) {
      return 0;
    }
  }
  if (!raw_png && !special) {
    format_request.format_selector = (uint8_t)state.format_selector;
    format_request.source_selector = (uint8_t)state.source_selector;
    format_request.color_selector =
        (uint8_t)(state.source_selector ? 1U : 0U);
    format_request.geometry_selector = (uint8_t)state.geometry_selector;
    memcpy(format_request.codec_selectors, state.codec_controls,
           sizeof(format_request.codec_selectors));
    format_request.pattern = (uint8_t)state.pattern;
    format_request.phase = (uint8_t)state.phase;
    format_request.stride = (uint8_t)state.material_stride;
    format_request.material = material;
    format_request.material_size = material_size;
    format_request.explicit_width = (uint16_t)state.explicit_width;
    format_request.explicit_height = (uint16_t)state.explicit_height;
    format_request.xppi = (uint16_t)state.xppi;
    format_request.yppi = (uint16_t)state.yppi;
    format_request.allow_known_boundaries = state.faithful;
    if (cf_v3_image_pdf_format_build(&format_request, &image) != 0) {
      return 0;
    }
  }
  if (state.profile == CF_V3_IMAGE_RASTER_NATURAL &&
      image.reference_components != state.output.num_colors) {
    cf_v3_image_pdf_format_free(&image);
    return 0;
  }
  cf_v3_image_raster_normalize_layout(
      &state, image.width, image.height, image.xppi, image.yppi);
  if (cf_v3_image_raster_build_options(&state, options, sizeof(options)) !=
          0 ||
      !(ppd = cf_v3_image_raster_build_ppd(&state, &ppd_size))) {
    cf_v3_image_pdf_format_free(&image);
    free(ppd);
    return 0;
  }
  snprintf(title, sizeof(title),
           "image-raster-v3-p%u-f%u-s%u-%ux%u-b%u-o%u-c%u",
           (unsigned)state.profile, (unsigned)image.format,
           state.source_selector, image.width, image.height,
           state.output.bits_per_color, (unsigned)state.output.color_order,
           (unsigned)state.output.color_space);

  memset(&control, 0, sizeof(control));
  control.ppd_profile = (uint8_t)state.profile;
  control.page_size = (uint8_t)state.page_policy;
  control.color_model = (uint8_t)state.output.color_space;
  control.resolution = (uint8_t)state.output_resolution_x;
  control.sides = state.duplex ? 1U : 0U;
  control.orientation = (uint8_t)state.orientation;
  control.scaling = (uint8_t)state.scale_policy;
  control.copies = (uint8_t)(state.copies - 1U);
  control.position = (uint8_t)state.position;
  control.output_order = state.reverse ? 1U : 0U;
  control.mirror = state.mirror ? 1U : 0U;
  control.route_mode = (uint8_t)state.profile;

  memset(&job, 0, sizeof(job));
  memset(&result, 0, sizeof(result));
  job.control = control;
  job.ppd = (const uint8_t *)ppd;
  job.ppd_size = ppd_size;
  job.options = (const uint8_t *)options;
  job.options_size = strlen(options);
  job.title = (const uint8_t *)title;
  job.title_size = strlen(title);
  job.document = raw_png ? material : image.encoded_bytes;
  job.document_size = raw_png ? material_size : image.encoded_size;
  capture_output = !raw_png &&
                   !(state.faithful &&
                     state.profile == CF_V3_IMAGE_RASTER_ARITHMETIC &&
                     (state.arithmetic_stride ||
                      state.natural_scaling > 10000U));

  if (getenv("CF_V3_ORACLE_TRACE")) {
    fprintf(stderr,
            "image-raster-v3 state: profile=%u faithful=%u raw=%u format=%u "
            "source=%u image=%ux%u ppi=%ux%u scale=%u topology=%ux%u "
            "page=%.3fx%.3f margins=%.3f/%.3f/%.3f/%.3f "
            "output=%u/%u/%u/%u/%u dpi=%ux%u stage=%u\n",
            (unsigned)state.profile, (unsigned)state.faithful,
            (unsigned)raw_png, (unsigned)image.format,
            state.source_selector, image.width,
            image.height, state.xppi, state.yppi, state.natural_scaling,
            state.topology_x, state.topology_y, state.page_width,
            state.page_height, state.margin_left, state.margin_bottom,
            state.margin_right, state.margin_top,
            (unsigned)state.output.color_space,
            state.output.bits_per_color, state.output.bits_per_pixel,
            (unsigned)state.output.color_order, state.output.num_colors,
            state.output_resolution_x, state.output_resolution_y,
            state.cmy_relation_stage);
  }

  cf_v3_image_raster_active_state = &state;
  cf_v3_image_raster_mime = image.mime;
  executed = cf_v2_execute_direct_job(&job, capture_output, &result);
  cf_v3_image_raster_release_options();
  cf_v3_image_raster_active_state = NULL;
  cf_v3_image_raster_mime = "image/png";

  if (!raw_png) {
    if (!executed) {
      failure = "filter-not-executed";
      trap_after_cleanup = true;
    } else if (result.status != 0) {
      failure = "filter-status";
      trap_after_cleanup = true;
    } else if (capture_output &&
               (!result.captured || !result.output_size ||
                !cf_v3_image_raster_validate(result.output,
                                             result.output_size, &state,
                                             &image, &failure))) {
      trap_after_cleanup = true;
    }
  }

  cf_v2_free_run_result(&result);
  free(ppd);
  cf_v3_image_pdf_format_free(&image);
  if (trap_after_cleanup) {
    fprintf(stderr, "image-raster-v3-oracle: %s\n",
            failure ? failure : "unspecified");
    __builtin_trap();
  }
  return 0;
}
