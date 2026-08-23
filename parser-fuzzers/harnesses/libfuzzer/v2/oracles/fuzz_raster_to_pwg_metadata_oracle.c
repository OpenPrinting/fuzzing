// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * RPWGMETA1: finite Raster-to-PWG metadata/capability state oracle.
 *
 * The exact 21-byte language selects only bounded options and coherent IPP
 * capability collections.  It generates complete CUPS Raster pages, executes
 * cfFilterRasterToPWG in process, and reparses every emitted PWG page.
 */

#include <cups/cups.h>
#include <cups/ipp.h>
#include <cups/raster.h>
#include <cupsfilters/filter.h>

static int cf_v2_rpwg_meta_setup(cf_filter_data_t *filter_data);

#define CF_V2_FILTER_FUNCTION cfFilterRasterToPWG
#define CF_V2_TARGET_NAME \
  "fuzz_v2_cupsfilters_state_raster_to_pwg_metadata_oracle"
#define CF_V2_INPUT_MIME "application/vnd.cups-raster"
#define CF_V2_OUTPUT_MIME "image/pwg-raster"
/* Give direct_route ownership of a temporary attrs object.  PPD loading
 * replaces it, and the post-load hook replaces/frees the PPD-derived attrs. */
#define CF_V2_NEEDS_PCLM_ATTRS 1
#define CF_V2_POST_PPD_LOAD_HOOK cf_v2_rpwg_meta_setup
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define CF_V2_RPWG_META_MAGIC "RPWGMETA1"
#define CF_V2_RPWG_META_MAGIC_SIZE 9U
#define CF_V2_RPWG_META_SELECTOR_SIZE 12U
#define CF_V2_RPWG_META_INPUT_SIZE 21U
#define CF_V2_RPWG_META_MAX_PAGES 2U
#define CF_V2_RPWG_META_MAX_ROW_BYTES 128U

enum {
  CF_V2_META_A4 = 0,
  CF_V2_META_LETTER = 1,
  CF_V2_META_PHOTO = 2,
};

enum {
  CF_V2_META_CAP_DATABASE = 0,
  CF_V2_META_CAP_SIZE_SUPPORTED = 1,
  CF_V2_META_CAP_MARGIN_VARIANTS = 2,
  CF_V2_META_CAP_NONE = 3,
};

enum {
  CF_V2_META_NAME_PPD = 0,
  CF_V2_META_NAME_PWG = 1,
  CF_V2_META_NAME_EMPTY = 2,
  CF_V2_META_NAME_BORDERLESS = 3,
};

enum {
  CF_V2_META_MARGIN_STANDARD = 0,
  CF_V2_META_MARGIN_BORDERLESS = 1,
  CF_V2_META_MARGIN_ASYMMETRIC = 2,
};

typedef struct cf_v2_rpwg_meta_media_s {
  unsigned width_points;
  unsigned height_points;
  int width_2540;
  int height_2540;
  const char *ppd_name;
  const char *pwg_name;
} cf_v2_rpwg_meta_media_t;

typedef struct cf_v2_rpwg_meta_margin_s {
  unsigned left_points;
  unsigned bottom_points;
  unsigned right_points;
  unsigned top_points;
  int left_2540;
  int bottom_2540;
  int right_2540;
  int top_2540;
} cf_v2_rpwg_meta_margin_t;

typedef struct cf_v2_rpwg_meta_intent_profile_s {
  const char *supported[6];
  unsigned count;
  const char *default_value;
} cf_v2_rpwg_meta_intent_profile_t;

typedef struct cf_v2_rpwg_meta_program_s {
  uint8_t selector[CF_V2_RPWG_META_SELECTOR_SIZE];
  unsigned optimize;
  unsigned quality;
  unsigned intent;
  unsigned intent_profile;
  unsigned media;
  unsigned capability;
  unsigned name_mode;
  unsigned margin;
  unsigned page_count;
  unsigned pattern;
  unsigned page_variation;
  unsigned phase;
} cf_v2_rpwg_meta_program_t;

typedef struct cf_v2_rpwg_meta_page_s {
  const cf_v2_rpwg_meta_media_t *media;
  const cf_v2_rpwg_meta_margin_t *margin;
  unsigned media_index;
  unsigned content_width;
  unsigned content_height;
  unsigned input_bytes_per_line;
  unsigned output_bytes_per_line;
  char input_page_size_name[64];
  char expected_page_size_name[64];
} cf_v2_rpwg_meta_page_t;

static const cf_v2_rpwg_meta_media_t cf_v2_rpwg_meta_media[] = {
    {595U, 842U, 21000, 29700, "A4", "iso_a4_210x297mm"},
    {612U, 792U, 21590, 27940, "Letter", "na_letter_8.5x11in"},
    {288U, 432U, 10160, 15240, "4x6", "na_index-4x6_4x6in"},
};

static const cf_v2_rpwg_meta_margin_t cf_v2_rpwg_meta_margins[] = {
    {18U, 36U, 18U, 36U, 635, 1270, 635, 1270},
    {0U, 0U, 0U, 0U, 0, 0, 0, 0},
    {9U, 18U, 27U, 36U, 317, 635, 952, 1270},
};

static const char *const cf_v2_rpwg_meta_optimize_options[] = {
    NULL,          "automatic",        "graphics",
    "graphic",   "photo",            "text",
    "text-and-graphics", "text-and-graphic", "unsupported",
};

static const char *const cf_v2_rpwg_meta_optimize_expected[] = {
    "InputType", "Automatic", "Graphics", "Graphics", "Photo",
    "Text",      "TextAndGraphics", "TextAndGraphics", "",
};

static const char *const cf_v2_rpwg_meta_quality_options[] = {
    NULL, "3", "4", "5", "2", "6",
};

static const unsigned cf_v2_rpwg_meta_quality_expected[] = {
    0U, IPP_QUALITY_DRAFT, IPP_QUALITY_NORMAL, IPP_QUALITY_HIGH, 0U, 0U,
};

static const char *const cf_v2_rpwg_meta_intent_options[] = {
    NULL,        "absolute",   "auto",       "perceptual",
    "relative", "relative-bpc", "saturation", "unsupported",
};

static const char *const cf_v2_rpwg_meta_intent_normalized[] = {
    NULL,       "Absolute",    "Automatic", "Perceptual",
    "Relative", "RelativeBpc", "Saturation", NULL,
};

static const cf_v2_rpwg_meta_intent_profile_t
    cf_v2_rpwg_meta_intent_profiles[] = {
        {{"absolute", "auto", "perceptual", "relative", "relative-bpc",
          "saturation"},
         6U,
         "auto"},
        {{"perceptual", "relative", NULL, NULL, NULL, NULL}, 2U,
         "relative"},
        {{"auto", "saturation", NULL, NULL, NULL, NULL}, 2U,
         "saturation"},
        {{"absolute", "relative-bpc", NULL, NULL, NULL, NULL}, 2U, NULL},
};

static cf_v2_rpwg_meta_program_t cf_v2_rpwg_meta_current;
static cups_page_header2_t
    cf_v2_rpwg_meta_handoff[CF_V2_RPWG_META_MAX_PAGES];
static unsigned cf_v2_rpwg_meta_handoff_count;
static unsigned cf_v2_rpwg_meta_handoff_overflow;

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
extern unsigned __real_cupsRasterWriteHeader2(cups_raster_t *raster,
                                               cups_page_header2_t *header);

unsigned __wrap_cupsRasterWriteHeader2(cups_raster_t *raster,
                                       cups_page_header2_t *header) {
  if (header) {
    if (cf_v2_rpwg_meta_handoff_count < CF_V2_RPWG_META_MAX_PAGES) {
      cf_v2_rpwg_meta_handoff[cf_v2_rpwg_meta_handoff_count++] = *header;
    } else {
      cf_v2_rpwg_meta_handoff_overflow = 1U;
    }
  }
  return __real_cupsRasterWriteHeader2(raster, header);
}

static void cf_v2_rpwg_meta_decode(const uint8_t *data,
                                   cf_v2_rpwg_meta_program_t *program) {
  memcpy(program->selector, data + CF_V2_RPWG_META_MAGIC_SIZE,
         sizeof(program->selector));
  program->optimize = program->selector[0] % 9U;
  program->quality = program->selector[1] % 6U;
  program->intent = program->selector[2] % 8U;
  program->intent_profile = program->selector[3] % 4U;
  program->media = program->selector[4] % 3U;
  program->capability = program->selector[5] % 4U;
  program->name_mode = program->selector[6] % 4U;
  program->margin = program->selector[7] % 3U;
  program->page_count = 1U + program->selector[8] % 2U;
  program->pattern = program->selector[9] % 6U;
  program->page_variation = program->selector[10] % 2U;
  program->phase = program->selector[11] % 8U;

  if (program->name_mode == CF_V2_META_NAME_BORDERLESS) {
    program->margin = CF_V2_META_MARGIN_BORDERLESS;
  }
  if (program->media == CF_V2_META_PHOTO ||
      program->capability == CF_V2_META_CAP_NONE) {
    program->name_mode = CF_V2_META_NAME_EMPTY;
  }
}

static unsigned cf_v2_rpwg_meta_page_media(
    const cf_v2_rpwg_meta_program_t *program, unsigned page) {
  if (!page || !program->page_variation) {
    return program->media;
  }
  if (program->media == CF_V2_META_A4) {
    return CF_V2_META_LETTER;
  }
  return CF_V2_META_A4;
}

static int cf_v2_rpwg_meta_media_supported(
    const cf_v2_rpwg_meta_program_t *program, unsigned media_index) {
  return program->capability != CF_V2_META_CAP_NONE &&
         media_index != CF_V2_META_PHOTO;
}

static void cf_v2_rpwg_meta_page_state(
    const cf_v2_rpwg_meta_program_t *program, unsigned page,
    cf_v2_rpwg_meta_page_t *state) {
  const unsigned media_index = cf_v2_rpwg_meta_page_media(program, page);
  const cf_v2_rpwg_meta_media_t *media =
      &cf_v2_rpwg_meta_media[media_index];
  const cf_v2_rpwg_meta_margin_t *margin =
      &cf_v2_rpwg_meta_margins[program->margin];

  memset(state, 0, sizeof(*state));
  state->media = media;
  state->margin = margin;
  state->media_index = media_index;
  state->content_width =
      media->width_points - margin->left_points - margin->right_points;
  state->content_height =
      media->height_points - margin->top_points - margin->bottom_points;
  state->input_bytes_per_line = (state->content_width + 7U) / 8U;
  state->output_bytes_per_line = (media->width_points + 7U) / 8U;

  if (cf_v2_rpwg_meta_media_supported(program, media_index)) {
    if (program->name_mode == CF_V2_META_NAME_PPD) {
      snprintf(state->input_page_size_name,
               sizeof(state->input_page_size_name), "%s", media->ppd_name);
    } else if (program->name_mode == CF_V2_META_NAME_PWG) {
      snprintf(state->input_page_size_name,
               sizeof(state->input_page_size_name), "%s", media->pwg_name);
    } else if (program->name_mode == CF_V2_META_NAME_BORDERLESS) {
      snprintf(state->input_page_size_name,
               sizeof(state->input_page_size_name), "%s.Borderless",
               media->ppd_name);
    }
    if (program->name_mode == CF_V2_META_NAME_PWG &&
        media_index == CF_V2_META_LETTER) {
      snprintf(state->expected_page_size_name,
               sizeof(state->expected_page_size_name), "%s",
               state->input_page_size_name);
    } else {
      const int direct_variant_first =
          program->capability == CF_V2_META_CAP_MARGIN_VARIANTS &&
          (program->name_mode == CF_V2_META_NAME_PPD ||
           program->name_mode == CF_V2_META_NAME_PWG);
      snprintf(
          state->expected_page_size_name,
          sizeof(state->expected_page_size_name), "%s%s", media->ppd_name,
          program->margin == CF_V2_META_MARGIN_BORDERLESS &&
                  !direct_variant_first
              ? ".Borderless"
              : "");
    }
  }
}

static uint8_t cf_v2_rpwg_meta_material(
    const cf_v2_rpwg_meta_program_t *program, unsigned page, unsigned row,
    unsigned offset) {
  switch (program->pattern) {
    case 0U:
      return 0x00U;
    case 1U:
      return 0xffU;
    case 2U:
      return ((page + row + offset + program->phase) & 1U) ? 0xaaU : 0x55U;
    case 3U:
      return (uint8_t)(row * 29U + offset * 17U + program->phase);
    case 4U:
      return (uint8_t)(page * 61U + row * 13U + offset * 7U +
                       program->phase);
    default:
      return (uint8_t)(1U << ((page + row + offset + program->phase) & 7U));
  }
}

static uint8_t *cf_v2_rpwg_meta_document(
    const cf_v2_rpwg_meta_program_t *program,
    cf_v2_rpwg_meta_page_t pages[CF_V2_RPWG_META_MAX_PAGES],
    size_t *document_size) {
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;

  for (unsigned page = 0U; page < program->page_count; page++) {
    cf_v2_rpwg_meta_page_state(program, page, &pages[page]);
    total += sizeof(cups_page_header2_t) +
             (size_t)pages[page].content_height *
                 pages[page].input_bytes_per_line;
  }
  document = (uint8_t *)malloc(total);
  if (!document) {
    return NULL;
  }
  memcpy(document, "3SaR", 4U);

  for (unsigned page = 0U; page < program->page_count; page++) {
    const cf_v2_rpwg_meta_page_t *state = &pages[page];
    const cf_v2_rpwg_meta_media_t *media = state->media;
    const cf_v2_rpwg_meta_margin_t *margin = state->margin;
    cups_page_header2_t header;

    memset(&header, 0, sizeof(header));
    snprintf(header.MediaClass, sizeof(header.MediaClass), "PwgRaster");
    snprintf(header.MediaType, sizeof(header.MediaType), "stationery");
    snprintf(header.OutputType, sizeof(header.OutputType), "InputType");
    snprintf(header.cupsRenderingIntent, sizeof(header.cupsRenderingIntent),
             "InputIntent");
    snprintf(header.cupsPageSizeName, sizeof(header.cupsPageSizeName), "%s",
             state->input_page_size_name);
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = media->width_points;
    header.PageSize[1] = media->height_points;
    header.ImagingBoundingBox[0] = margin->left_points;
    header.ImagingBoundingBox[1] = margin->bottom_points;
    header.ImagingBoundingBox[2] =
        media->width_points - margin->right_points;
    header.ImagingBoundingBox[3] =
        media->height_points - margin->top_points;
    header.cupsPageSize[0] = (float)media->width_points;
    header.cupsPageSize[1] = (float)media->height_points;
    header.cupsImagingBBox[0] = (float)margin->left_points;
    header.cupsImagingBBox[1] = (float)margin->bottom_points;
    header.cupsImagingBBox[2] =
        (float)(media->width_points - margin->right_points);
    header.cupsImagingBBox[3] =
        (float)(media->height_points - margin->top_points);
    header.cupsWidth = state->content_width;
    header.cupsHeight = state->content_height;
    header.cupsBitsPerColor = 1U;
    header.cupsBitsPerPixel = 1U;
    header.cupsBytesPerLine = state->input_bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = CUPS_CSPACE_K;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = 1U;
    header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] = program->page_count;
    header.cupsInteger[8] = 0U;
    header.cupsInteger[14] = 0x12345678U;
    header.cupsInteger[15] = 0x87654321U;
    header.NumCopies = 1U;
    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);

    for (unsigned row = 0U; row < state->content_height; row++) {
      for (unsigned column = 0U; column < state->input_bytes_per_line;
           column++) {
        document[offset++] =
            cf_v2_rpwg_meta_material(program, page, row, column);
      }
    }
  }
  *document_size = total;
  return document;
}

static int cf_v2_rpwg_meta_add_option(cf_filter_data_t *filter_data,
                                      const char *name, const char *value) {
  int count = cupsAddOption(name, value, filter_data->num_options,
                            &filter_data->options);
  if (count < filter_data->num_options) {
    return -1;
  }
  filter_data->num_options = count;
  return 0;
}

static void cf_v2_rpwg_meta_remove_option(cf_filter_data_t *filter_data,
                                          const char *name) {
  filter_data->num_options =
      cupsRemoveOption(name, filter_data->num_options, &filter_data->options);
}

static ipp_t *cf_v2_rpwg_meta_make_size(
    const cf_v2_rpwg_meta_media_t *media) {
  ipp_t *size = ippNew();

  if (!size ||
      !ippAddInteger(size, IPP_TAG_ZERO, IPP_TAG_INTEGER, "x-dimension",
                     media->width_2540) ||
      !ippAddInteger(size, IPP_TAG_ZERO, IPP_TAG_INTEGER, "y-dimension",
                     media->height_2540)) {
    if (size) {
      ippDelete(size);
    }
    return NULL;
  }
  return size;
}

static ipp_t *cf_v2_rpwg_meta_make_col(
    const cf_v2_rpwg_meta_media_t *media,
    const cf_v2_rpwg_meta_margin_t *margin) {
  ipp_t *size = cf_v2_rpwg_meta_make_size(media);
  ipp_t *col = ippNew();

  if (!size || !col ||
      !ippAddCollection(col, IPP_TAG_ZERO, "media-size", size) ||
      !ippAddString(col, IPP_TAG_ZERO, IPP_TAG_KEYWORD, "media-size-name",
                    NULL, media->pwg_name) ||
      !ippAddInteger(col, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                     "media-left-margin", margin->left_2540) ||
      !ippAddInteger(col, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                     "media-bottom-margin", margin->bottom_2540) ||
      !ippAddInteger(col, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                     "media-right-margin", margin->right_2540) ||
      !ippAddInteger(col, IPP_TAG_ZERO, IPP_TAG_INTEGER, "media-top-margin",
                     margin->top_2540)) {
    if (size) {
      ippDelete(size);
    }
    if (col) {
      ippDelete(col);
    }
    return NULL;
  }
  ippDelete(size);
  return col;
}

static int cf_v2_rpwg_meta_append_collection(ipp_t *attributes,
                                             const char *name,
                                             ipp_attribute_t **attribute,
                                             ipp_t *collection) {
  if (!*attribute) {
    *attribute = ippAddCollection(attributes, IPP_TAG_PRINTER, name,
                                  collection);
    return *attribute ? 0 : -1;
  }
  return ippSetCollection(attributes, attribute, ippGetCount(*attribute),
                          collection)
             ? 0
             : -1;
}

static int cf_v2_rpwg_meta_add_database(
    ipp_t *attributes, const cf_v2_rpwg_meta_program_t *program) {
  ipp_attribute_t *database = NULL;
  unsigned first_margin = program->margin;
  unsigned margin_count = 1U;

  if (program->capability == CF_V2_META_CAP_MARGIN_VARIANTS) {
    first_margin = 0U;
    margin_count = 3U;
  }
  for (unsigned media_index = 0U; media_index < 2U; media_index++) {
    for (unsigned index = 0U; index < margin_count; index++) {
      const unsigned margin_index = first_margin + index;
      ipp_t *collection = cf_v2_rpwg_meta_make_col(
          &cf_v2_rpwg_meta_media[media_index],
          &cf_v2_rpwg_meta_margins[margin_index]);
      int status;

      if (!collection) {
        return -1;
      }
      status = cf_v2_rpwg_meta_append_collection(
          attributes, "media-col-database", &database, collection);
      ippDelete(collection);
      if (status != 0) {
        return -1;
      }
    }
  }
  return 0;
}

static int cf_v2_rpwg_meta_add_size_supported(ipp_t *attributes) {
  ipp_attribute_t *supported = NULL;

  for (unsigned media_index = 0U; media_index < 2U; media_index++) {
    ipp_t *size = cf_v2_rpwg_meta_make_size(
        &cf_v2_rpwg_meta_media[media_index]);
    int status;

    if (!size) {
      return -1;
    }
    status = cf_v2_rpwg_meta_append_collection(
        attributes, "media-size-supported", &supported, size);
    ippDelete(size);
    if (status != 0) {
      return -1;
    }
  }
  return 0;
}

static int cf_v2_rpwg_meta_setup(cf_filter_data_t *filter_data) {
  const cf_v2_rpwg_meta_program_t *program = &cf_v2_rpwg_meta_current;
  const cf_v2_rpwg_meta_intent_profile_t *intent_profile =
      &cf_v2_rpwg_meta_intent_profiles[program->intent_profile];
  const cf_v2_rpwg_meta_margin_t *margin =
      &cf_v2_rpwg_meta_margins[program->margin];
  ipp_t *attributes = ippNew();

  if (!attributes) {
    return -1;
  }
  if (filter_data->printer_attrs) {
    ippDelete(filter_data->printer_attrs);
  }
  filter_data->printer_attrs = attributes;
  filter_data->final_content_type = (char *)CF_V2_OUTPUT_MIME;

  cf_v2_rpwg_meta_remove_option(filter_data, "print-content-optimize");
  cf_v2_rpwg_meta_remove_option(filter_data, "print-quality");
  cf_v2_rpwg_meta_remove_option(filter_data, "print-rendering-intent");
  cf_v2_rpwg_meta_remove_option(filter_data, "PrintRenderingIntent");
  cf_v2_rpwg_meta_remove_option(filter_data, "RenderingIntent");
  if ((cf_v2_rpwg_meta_optimize_options[program->optimize] &&
       cf_v2_rpwg_meta_add_option(
           filter_data, "print-content-optimize",
           cf_v2_rpwg_meta_optimize_options[program->optimize]) != 0) ||
      (cf_v2_rpwg_meta_quality_options[program->quality] &&
       cf_v2_rpwg_meta_add_option(
           filter_data, "print-quality",
           cf_v2_rpwg_meta_quality_options[program->quality]) != 0) ||
      (cf_v2_rpwg_meta_intent_options[program->intent] &&
       cf_v2_rpwg_meta_add_option(
           filter_data, "print-rendering-intent",
           cf_v2_rpwg_meta_intent_options[program->intent]) != 0)) {
    return -1;
  }

  if (!ippAddStrings(attributes, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
                     "print-rendering-intent-supported",
                     (int)intent_profile->count, NULL,
                     intent_profile->supported) ||
      (intent_profile->default_value &&
       !ippAddString(attributes, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
                     "print-rendering-intent-default", NULL,
                     intent_profile->default_value)) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-left-margin-supported", margin->left_2540) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-bottom-margin-supported", margin->bottom_2540) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-right-margin-supported", margin->right_2540) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-top-margin-supported", margin->top_2540)) {
    return -1;
  }

  if ((program->capability == CF_V2_META_CAP_DATABASE ||
       program->capability == CF_V2_META_CAP_MARGIN_VARIANTS) &&
      cf_v2_rpwg_meta_add_database(attributes, program) != 0) {
    return -1;
  }
  if (program->capability == CF_V2_META_CAP_SIZE_SUPPORTED &&
      cf_v2_rpwg_meta_add_size_supported(attributes) != 0) {
    return -1;
  }
  return 0;
}

static const char *cf_v2_rpwg_meta_expected_intent(
    const cf_v2_rpwg_meta_program_t *program) {
  const cf_v2_rpwg_meta_intent_profile_t *profile =
      &cf_v2_rpwg_meta_intent_profiles[program->intent_profile];
  const char *candidate =
      cf_v2_rpwg_meta_intent_normalized[program->intent];
  int has_auto = 0;

  for (unsigned index = 0U; index < profile->count; index++) {
    if (!strcasecmp(profile->supported[index], "auto")) {
      has_auto = 1;
    }
    if (candidate && !strcasecmp(candidate, profile->supported[index])) {
      return candidate;
    }
  }
  if (profile->default_value) {
    return profile->default_value;
  }
  return has_auto ? "auto" : "";
}

static void cf_v2_rpwg_meta_expected_row(
    uint8_t *row, const cf_v2_rpwg_meta_program_t *program,
    const cf_v2_rpwg_meta_page_t *state, unsigned page,
    unsigned output_row) {
  const unsigned top = state->margin->top_points;
  const unsigned content_end = top + state->content_height;
  const unsigned offset = state->margin->left_points / 8U;

  memset(row, 0, state->output_bytes_per_line);
  if (output_row >= top && output_row < content_end) {
    const unsigned source_row = output_row - top;
    for (unsigned column = 0U; column < state->input_bytes_per_line;
         column++) {
      row[offset + column] =
          cf_v2_rpwg_meta_material(program, page, source_row, column);
    }
  }
}

static int cf_v2_rpwg_meta_float_equal(float actual, float expected) {
  return actual >= expected - 0.01f && actual <= expected + 0.01f;
}

static int cf_v2_rpwg_meta_check_header(
    const cups_page_header2_t *header,
    const cf_v2_rpwg_meta_program_t *program,
    const cf_v2_rpwg_meta_page_t *state, int wire, const char **failure) {
  const cf_v2_rpwg_meta_media_t *media = state->media;
  const cf_v2_rpwg_meta_margin_t *margin = state->margin;
  const char *expected_intent = cf_v2_rpwg_meta_expected_intent(program);

  if (strcmp(header->OutputType,
             cf_v2_rpwg_meta_optimize_expected[program->optimize]) != 0) {
    *failure = wire ? "wire-output-type" : "handoff-output-type";
    return 0;
  }
  if (header->cupsInteger[8] !=
      (wire ? 0U : cf_v2_rpwg_meta_quality_expected[program->quality])) {
    *failure = wire ? "wire-print-quality" : "handoff-print-quality";
    return 0;
  }
  if (strcmp(header->cupsRenderingIntent, expected_intent) != 0) {
    *failure = wire ? "wire-rendering-intent" : "handoff-rendering-intent";
    return 0;
  }
  if (strcmp(header->cupsPageSizeName, state->expected_page_size_name) != 0) {
    fprintf(stderr, "%s: %s page-size actual=%s expected=%s input=%s\n",
            CF_V2_TARGET_NAME, wire ? "wire" : "handoff",
            header->cupsPageSizeName, state->expected_page_size_name,
            state->input_page_size_name);
    *failure = wire ? "wire-page-size-name" : "handoff-page-size-name";
    return 0;
  }
  if (header->cupsInteger[14] != 0U || header->cupsInteger[15] != 0U) {
    *failure = wire ? "wire-vendor-fields" : "handoff-vendor-fields";
    return 0;
  }
  if (header->cupsWidth != media->width_points ||
      header->cupsHeight != media->height_points ||
      header->cupsBitsPerColor != 1U || header->cupsBitsPerPixel != 1U ||
      header->cupsBytesPerLine != state->output_bytes_per_line ||
      header->cupsColorOrder != CUPS_ORDER_CHUNKED ||
      header->cupsColorSpace != CUPS_CSPACE_K ||
      header->cupsNumColors != 1U || header->HWResolution[0] != 72U ||
      header->HWResolution[1] != 72U ||
      header->PageSize[0] != media->width_points ||
      header->PageSize[1] != media->height_points ||
      !cf_v2_rpwg_meta_float_equal(
          header->cupsPageSize[0], wire ? 0.0f : (float)media->width_points) ||
      !cf_v2_rpwg_meta_float_equal(
          header->cupsPageSize[1], wire ? 0.0f : (float)media->height_points)) {
    fprintf(stderr,
            "%s: geometry actual=[%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,"
            "%.3f,%.3f] expected=[%u,%u,1,1,%u,%u,%u,1,72,72,%.3f,%.3f]\n",
            CF_V2_TARGET_NAME, header->cupsWidth, header->cupsHeight,
            header->cupsBitsPerColor, header->cupsBitsPerPixel,
            header->cupsBytesPerLine, header->cupsColorOrder,
            header->cupsColorSpace, header->cupsNumColors,
            header->HWResolution[0], header->HWResolution[1],
            header->cupsPageSize[0], header->cupsPageSize[1],
            media->width_points, media->height_points,
            state->output_bytes_per_line, (unsigned)CUPS_ORDER_CHUNKED,
            (unsigned)CUPS_CSPACE_K,
            wire ? 0.0f : (float)media->width_points,
            wire ? 0.0f : (float)media->height_points);
    *failure = wire ? "wire-geometry" : "handoff-geometry";
    return 0;
  }
  if (header->ImagingBoundingBox[0] != margin->left_points ||
      header->ImagingBoundingBox[1] != margin->bottom_points ||
      header->ImagingBoundingBox[2] !=
          media->width_points - margin->right_points ||
      header->ImagingBoundingBox[3] !=
          media->height_points - margin->top_points ||
      header->cupsInteger[CUPS_RASTER_PWG_ImageBoxLeft] !=
          margin->left_points ||
      header->cupsInteger[CUPS_RASTER_PWG_ImageBoxTop] !=
          (wire ? margin->bottom_points : margin->top_points) ||
      header->cupsInteger[CUPS_RASTER_PWG_ImageBoxRight] !=
          media->width_points - margin->right_points ||
      header->cupsInteger[CUPS_RASTER_PWG_ImageBoxBottom] !=
          media->height_points -
              (wire ? margin->top_points : margin->bottom_points)) {
    *failure = wire ? "wire-image-box" : "handoff-image-box";
    return 0;
  }
  if (header->cupsInteger[CUPS_RASTER_PWG_TotalPageCount] !=
          program->page_count ||
      header->cupsInteger[1] != 1U || header->cupsInteger[2] != 1U) {
    *failure = wire ? "wire-pwg-metadata" : "handoff-pwg-metadata";
    return 0;
  }
  return 1;
}

static int cf_v2_rpwg_meta_check_handoff(
    const cf_v2_rpwg_meta_program_t *program,
    const cf_v2_rpwg_meta_page_t pages[CF_V2_RPWG_META_MAX_PAGES],
    const char **failure) {
  if (cf_v2_rpwg_meta_handoff_overflow ||
      cf_v2_rpwg_meta_handoff_count != program->page_count) {
    *failure = "handoff-count";
    return 0;
  }
  for (unsigned page = 0U; page < program->page_count; page++) {
    if (!cf_v2_rpwg_meta_check_header(&cf_v2_rpwg_meta_handoff[page], program,
                                      &pages[page], 0, failure)) {
      return 0;
    }
  }
  return 1;
}

static int cf_v2_rpwg_meta_check_output(
    const cf_v2_run_result_t *result,
    const cf_v2_rpwg_meta_program_t *program,
    const cf_v2_rpwg_meta_page_t pages[CF_V2_RPWG_META_MAX_PAGES],
    const char **failure) {
  uint8_t actual[CF_V2_RPWG_META_MAX_ROW_BYTES];
  uint8_t expected[CF_V2_RPWG_META_MAX_ROW_BYTES];
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  FILE *file = NULL;
  int fd = -1;
  int valid = 0;

  if (!result->captured || result->status != 0 || !result->output ||
      !result->output_size) {
    *failure = "route-output";
    goto done;
  }
  file = tmpfile();
  if (!file || fwrite(result->output, 1U, result->output_size, file) !=
                   result->output_size ||
      fflush(file) != 0 || fseek(file, 0, SEEK_SET) != 0 ||
      (fd = dup(fileno(file))) < 0 ||
      !(raster = cupsRasterOpen(fd, CUPS_RASTER_READ))) {
    *failure = "reader-open";
    goto done;
  }

  for (unsigned page = 0U; page < program->page_count; page++) {
    const cf_v2_rpwg_meta_page_t *state = &pages[page];

    if (!cupsRasterReadHeader2(raster, &header)) {
      *failure = "page-count-short";
      goto done;
    }
    if (!cf_v2_rpwg_meta_check_header(&header, program, state, 1, failure)) {
      fprintf(stderr,
              "%s: page=%u optimize=%u quality=%u intent=%u/%u "
              "media=%u capability=%u name=%u margin=%u "
              "actual=[%s,%u,%s,%s] expected=[%s,%u,%s,%s]\n",
              CF_V2_TARGET_NAME, page + 1U, program->optimize,
              program->quality, program->intent, program->intent_profile,
              state->media_index, program->capability, program->name_mode,
              program->margin, header.OutputType, header.cupsInteger[8],
              header.cupsRenderingIntent, header.cupsPageSizeName,
              cf_v2_rpwg_meta_optimize_expected[program->optimize],
              cf_v2_rpwg_meta_quality_expected[program->quality],
              cf_v2_rpwg_meta_expected_intent(program),
              state->expected_page_size_name);
      goto done;
    }
    if (state->output_bytes_per_line > sizeof(actual)) {
      *failure = "row-bound";
      goto done;
    }
    for (unsigned row = 0U; row < state->media->height_points; row++) {
      if (cupsRasterReadPixels(raster, actual,
                               state->output_bytes_per_line) !=
          state->output_bytes_per_line) {
        *failure = "short-row";
        goto done;
      }
      cf_v2_rpwg_meta_expected_row(expected, program, state, page, row);
      if (memcmp(actual, expected, state->output_bytes_per_line) != 0) {
        *failure = row < state->margin->top_points ||
                           row >= state->margin->top_points +
                                      state->content_height
                       ? "padding-row"
                       : "content-row";
        goto done;
      }
    }
  }
  if (cupsRasterReadHeader2(raster, &header)) {
    *failure = "page-count-long";
    goto done;
  }
  valid = 1;

done:
  if (raster) {
    cupsRasterClose(raster);
  }
  if (fd >= 0) {
    close(fd);
  }
  if (file) {
    fclose(file);
  }
  return valid;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                               unsigned int seed) {
  size_t selector_size;

  (void)seed;
  if (!data || max_size < CF_V2_RPWG_META_INPUT_SIZE) {
    return 0U;
  }
  if (size < CF_V2_RPWG_META_INPUT_SIZE) {
    memset(data + size, 0, CF_V2_RPWG_META_INPUT_SIZE - size);
  }
  memcpy(data, CF_V2_RPWG_META_MAGIC, CF_V2_RPWG_META_MAGIC_SIZE);
  selector_size = LLVMFuzzerMutate(
      data + CF_V2_RPWG_META_MAGIC_SIZE, CF_V2_RPWG_META_SELECTOR_SIZE,
      CF_V2_RPWG_META_SELECTOR_SIZE);
  if (selector_size < CF_V2_RPWG_META_SELECTOR_SIZE) {
    memset(data + CF_V2_RPWG_META_MAGIC_SIZE + selector_size, 0,
           CF_V2_RPWG_META_SELECTOR_SIZE - selector_size);
  }
  memcpy(data, CF_V2_RPWG_META_MAGIC, CF_V2_RPWG_META_MAGIC_SIZE);
  return CF_V2_RPWG_META_INPUT_SIZE;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_rpwg_meta_page_t pages[CF_V2_RPWG_META_MAX_PAGES];
  cf_v2_control_t control;
  cf_v2_run_result_t result = {0};
  uint8_t *document = NULL;
  size_t document_size = 0U;
  const char *failure = NULL;
  int failed = 0;

  if (!data || size != CF_V2_RPWG_META_INPUT_SIZE ||
      memcmp(data, CF_V2_RPWG_META_MAGIC,
             CF_V2_RPWG_META_MAGIC_SIZE) != 0) {
    return 0;
  }
  cf_v2_rpwg_meta_decode(data, &cf_v2_rpwg_meta_current);
  document = cf_v2_rpwg_meta_document(&cf_v2_rpwg_meta_current, pages,
                                      &document_size);
  if (!document) {
    return 0;
  }

  memset(&control, 0, sizeof(control));
  control.ppd_profile = 0U;
  control.page_size = 0U;
  control.color_model = 0U;
  control.resolution = 0U;
  cf_v2_rpwg_meta_handoff_count = 0U;
  cf_v2_rpwg_meta_handoff_overflow = 0U;
  if (!cf_v2_execute_direct(document, document_size, &control, 1, &result) ||
      !cf_v2_rpwg_meta_check_handoff(&cf_v2_rpwg_meta_current, pages,
                                     &failure) ||
      !cf_v2_rpwg_meta_check_output(&result, &cf_v2_rpwg_meta_current,
                                    pages, &failure)) {
    failed = 1;
  }

  cf_v2_free_run_result(&result);
  free(document);
  if (failed) {
    fprintf(stderr, "%s: %s\n", CF_V2_TARGET_NAME,
            failure ? failure : "route-not-executed");
    __builtin_trap();
  }
  return 0;
}
