#ifndef CUPSFILTERS_FUZZ_PROFILES_H
#define CUPSFILTERS_FUZZ_PROFILES_H

#include "control.h"

#include <stddef.h>
#include <stdio.h>

#ifdef CF_FUZZ_TEXTTOTEXT_STATE_OPTIONS
typedef struct cf_fuzz_texttotext_state_s {
  unsigned width;
  unsigned height;
  unsigned left;
  unsigned right;
  unsigned top;
  unsigned bottom;
  unsigned text_width;
  unsigned text_height;
  unsigned tab_width;
  const char *encoding;
  const char *overlong;
  const char *pagination;
  const char *send_ff;
  const char *newline;
  const char *page_ranges;
  const char *page_set;
  const char *output_order;
  const char *collate;
} cf_fuzz_texttotext_state_t;

static inline unsigned cf_fuzz_texttotext_min(unsigned first,
                                             unsigned second) {
  return first < second ? first : second;
}

static inline void cf_fuzz_decode_texttotext_state(
    const cf_fuzz_control_t *control, cf_fuzz_texttotext_state_t *state) {
  static const char *const encodings[] = {
      "ASCII", "UTF-8", "ISO-8859-1", "CP1252"};
  static const char *const overlong[] = {
      "truncate", "word-wrap", "wrap-at-width"};
  static const char *const newlines[] = {"lf", "cr", "crlf"};
  static const char *const ranges[] = {
      "1-1", "1-2", "2-3", "1-4", "2-4", "1,3", "1-99"};
  static const char *const page_sets[] = {"all", "odd", "even"};
  unsigned horizontal_room;
  unsigned vertical_room;

  state->width = 8U + control->page_size % 41U;
  state->height = 4U + control->sides % 17U;

  horizontal_room = state->width - 4U;
  state->left = control->color_model %
                (cf_fuzz_texttotext_min(horizontal_room, 6U) + 1U);
  horizontal_room -= state->left;
  state->right = control->resolution %
                 (cf_fuzz_texttotext_min(horizontal_room, 6U) + 1U);

  vertical_room = state->height - 2U;
  state->top = control->orientation %
               (cf_fuzz_texttotext_min(vertical_room, 3U) + 1U);
  vertical_room -= state->top;
  state->bottom = control->scaling %
                  (cf_fuzz_texttotext_min(vertical_room, 3U) + 1U);

  state->text_width = state->width - state->left - state->right;
  state->text_height = state->height - state->top - state->bottom;
  state->tab_width = 1U + control->position %
                     cf_fuzz_texttotext_min(state->text_width, 8U);
  state->encoding = encodings[control->media_type % 4U];
  state->overlong = overlong[control->quality % 3U];
  state->pagination = control->route_mode & 1U ? "true" : "false";
  state->send_ff = control->route_mode & 2U ? "true" : "false";
  state->newline = newlines[control->mirror % 3U];
  state->page_ranges = ranges[control->number_up % 7U];
  state->page_set = page_sets[control->ppd_profile % 3U];
  state->output_order = control->output_order & 1U ? "reverse" : "normal";
  state->collate = control->reserved & 1U ? "true" : "false";
}
#endif

#ifdef CF_FUZZ_PS_DSC_STATE_OPTIONS
typedef struct cf_fuzz_ps_dsc_state_s {
  unsigned page_count;
  unsigned sheet_count;
  unsigned number_up;
  unsigned copies;
  unsigned section_mode;
  unsigned binary_mode;
  unsigned trailer_mode;
  const char *number_up_layout;
  const char *page_set;
  const char *output_order;
  const char *collate;
  const char *sides;
  const char *fit_to_page;
  const char *mirror;
  const char *page_border;
  unsigned orientation_requested;
  char page_ranges[32];
} cf_fuzz_ps_dsc_state_t;

static inline void cf_fuzz_decode_ps_dsc_state(
    const cf_fuzz_control_t *control, cf_fuzz_ps_dsc_state_t *state) {
  static const unsigned number_up[] = {1U, 2U, 4U, 6U, 9U, 16U};
  static const char *const layouts[] = {
      "lrtb", "lrbt", "rltb", "rlbt", "tblr", "tbrl", "btlr", "btrl"};
  static const char *const page_sets[] = {"all", "odd", "even"};
  static const char *const sides[] = {
      "one-sided", "two-sided-long-edge", "two-sided-short-edge"};
  static const char *const borders[] = {
      "none", "single", "single-thick", "double", "double-thick"};
  const unsigned range_mode = control->quality % 6U;

  state->page_count = 1U + control->page_size % 8U;
  state->number_up = number_up[control->number_up % 6U];
  state->sheet_count =
      (state->page_count + state->number_up - 1U) / state->number_up;
  state->copies = 1U + control->copies % 4U;
  state->section_mode = control->ppd_profile;
  state->binary_mode = control->color_model % 4U;
  state->trailer_mode = control->resolution % 4U;
  state->number_up_layout = layouts[control->position % 8U];
  state->page_set = page_sets[control->media_type % 3U];
  state->output_order = control->output_order & 1U ? "Reverse" : "Normal";
  state->collate = control->reserved & 1U ? "true" : "false";
  state->sides = sides[control->sides % 3U];
  state->fit_to_page = control->scaling & 1U ? "true" : "false";
  state->mirror = control->mirror & 1U ? "true" : "false";
  state->page_border = borders[control->route_mode % 5U];
  state->orientation_requested = 3U + control->orientation % 4U;

  switch (range_mode) {
    case 0U:
      snprintf(state->page_ranges, sizeof(state->page_ranges), "1-%u",
               state->sheet_count);
      break;
    case 1U:
      snprintf(state->page_ranges, sizeof(state->page_ranges), "1-1");
      break;
    case 2U:
      snprintf(state->page_ranges, sizeof(state->page_ranges), "%u-%u",
               state->sheet_count, state->sheet_count);
      break;
    case 3U:
      snprintf(state->page_ranges, sizeof(state->page_ranges), "2-%u",
               state->sheet_count > 1U ? state->sheet_count : 2U);
      break;
    case 4U:
      snprintf(state->page_ranges, sizeof(state->page_ranges), "1,%u",
               state->sheet_count > 1U ? state->sheet_count : 1U);
      break;
    default:
      snprintf(state->page_ranges, sizeof(state->page_ranges), "1-99");
      break;
  }
}
#endif

static inline int cf_fuzz_build_options(char *buffer, size_t buffer_size,
                                      const cf_fuzz_control_t *control) {
  static const char *const page_sizes[] = {"A4", "Letter"};
  static const char *const color_models[] = {"Gray", "RGB", "CMYK"};
  static const char *const resolutions[] = {"300dpi", "600dpi"};
  static const char *const sides[] = {
      "one-sided", "two-sided-long-edge", "two-sided-short-edge"};
  static const char *const scaling_modes[] = {
      "auto-fit", "fit", "fill", "none"};
  static const char *const positions[] = {
      "center", "top-left", "top-right", "bottom-left", "bottom-right"};
  static const char *const output_orders[] = {"normal", "reverse"};
  static const char *const media_types[] = {"Plain", "Glossy", "Transparency"};
#ifdef CF_FUZZ_OPTIONS_PDF_NUP_BOUNDARY
  static const unsigned number_up[] = {17, 18, 19, 20, 32, 255};
#else
  static const unsigned number_up[] = {1, 2, 4, 6, 9, 16};
#endif
  unsigned copies = 1U + control->copies % 4U;
  unsigned scaling = 25U + control->scaling % 176U;
  unsigned ppi = 72U + ((unsigned)control->quality * 1128U) / 255U;
  int length;
  int extra;

#ifdef CF_FUZZ_TEXTTOTEXT_STATE_OPTIONS
  {
    cf_fuzz_texttotext_state_t state;

    cf_fuzz_decode_texttotext_state(control, &state);
    length = snprintf(
        buffer, buffer_size,
        "PageWidth=%u PageHeight=%u PageLeft=%u PageRight=%u "
        "PageTop=%u PageBottom=%u PrinterEncoding=%s "
        "OverLongLines=%s TabWidth=%u Pagination=%s SendFF=%s "
        "NewlineCharacters=%s page-ranges=%s page-set=%s "
        "OutputOrder=%s Collate=%s",
        state.width, state.height, state.left, state.right, state.top,
        state.bottom, state.encoding, state.overlong, state.tab_width,
        state.pagination, state.send_ff, state.newline, state.page_ranges,
        state.page_set, state.output_order, state.collate);
    return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
  }
#endif

#ifdef CF_FUZZ_PS_DSC_STATE_OPTIONS
  {
    cf_fuzz_ps_dsc_state_t state;

    cf_fuzz_decode_ps_dsc_state(control, &state);
    length = snprintf(
        buffer, buffer_size,
        "PageSize=A4 sides=%s orientation-requested=%u "
        "number-up=%u number-up-layout=%s page-ranges=%s page-set=%s "
        "OutputOrder=%s Collate=%s copies=%u emit-jcl=false "
        "fit-to-page=%s mirror=%s page-border=%s",
        state.sides, state.orientation_requested, state.number_up,
        state.number_up_layout, state.page_ranges, state.page_set,
        state.output_order, state.collate, state.copies, state.fit_to_page,
        state.mirror, state.page_border);
    return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
  }
#endif

#if (defined(CF_FUZZ_IMAGE_SCALING_PRINT) + \
     defined(CF_FUZZ_IMAGE_SCALING_PPI) + \
     defined(CF_FUZZ_IMAGE_SCALING_PERCENT) + \
     defined(CF_FUZZ_IMAGE_SCALING_MULTIPAGE) + \
     defined(CF_FUZZ_IMAGE_SCALING_FITPLOT) + \
     defined(CF_FUZZ_IMAGE_SCALING_NATURAL) + \
     defined(CF_FUZZ_IMAGE_SCALING_FILL) + \
     defined(CF_FUZZ_IMAGE_SCALING_CROP) + \
     defined(CF_FUZZ_IMAGE_SCALING_DEFAULT)) > 1
#error "Select at most one image scaling option contract"
#endif

  length = snprintf(
      buffer, buffer_size,
      "PageSize=%s ColorModel=%s Resolution=%s sides=%s "
      "orientation-requested=%u "
      "number-up=%u position=%s copies=%u output-order=%s MediaType=%s "
      "mirror=%s emit-jcl=false",
      page_sizes[control->page_size % 2U],
      color_models[control->color_model % 3U],
      resolutions[control->resolution % 2U], sides[control->sides % 3U],
      3U + control->orientation % 4U,
      number_up[control->number_up % 6U],
      positions[control->position % 5U], copies,
      output_orders[control->output_order % 2U],
      media_types[control->media_type % 3U],
      control->mirror & 1U ? "true" : "false");
  if (length < 0 || (size_t)length >= buffer_size) {
    return -1;
  }
#if defined(CF_FUZZ_IMAGE_SCALING_PRINT)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " print-scaling=%s",
                   scaling_modes[control->scaling % 4U]);
#elif defined(CF_FUZZ_IMAGE_SCALING_PPI)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " ppi=%u", ppi);
#elif defined(CF_FUZZ_IMAGE_SCALING_PERCENT)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " scaling=%u", 25U + control->scaling % 76U);
#elif defined(CF_FUZZ_IMAGE_SCALING_MULTIPAGE)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " scaling=%u", 101U + control->scaling % 100U);
#elif defined(CF_FUZZ_IMAGE_SCALING_FITPLOT)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " fitplot=%s", control->scaling & 1U ? "true" : "false");
#elif defined(CF_FUZZ_IMAGE_SCALING_NATURAL)
  {
    static const unsigned natural_scaling[] = {0U, 50U, 100U, 200U};
    extra = snprintf(buffer + length, buffer_size - (size_t)length,
                     " natural-scaling=%u",
                     natural_scaling[control->scaling % 4U]);
  }
#elif defined(CF_FUZZ_IMAGE_SCALING_FILL)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " fill=%s", control->scaling & 1U ? "true" : "false");
#elif defined(CF_FUZZ_IMAGE_SCALING_CROP)
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " crop-to-fit=%s",
                   control->scaling & 1U ? "true" : "false");
#elif defined(CF_FUZZ_IMAGE_SCALING_DEFAULT)
  extra = 0;
#else
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " print-scaling=%s scaling=%u ppi=%u",
                   scaling_modes[control->scaling % 4U], scaling, ppi);
#endif
  if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
    return -1;
  }
  length += extra;
#ifdef CF_FUZZ_OPTIONS_CM_CALIBRATION
  extra = snprintf(buffer + length, buffer_size - (size_t)length,
                   " cm-calibration=true");
  if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
    return -1;
  }
  length += extra;
#endif
#ifdef CF_FUZZ_OPTIONS_PDF_DEPTH
  {
    static const char *const page_sets[] = {"all", "odd", "even"};
    static const char *const page_ranges[] = {
        "1-1", "1-2", "2-4", "1-16"};
    int booklet = control->route_mode % 2U;
    const char *page_set = booklet ? "all" : page_sets[control->reserved % 3U];
    const char *page_range =
        booklet ? "1-16" : page_ranges[(control->reserved / 3U) % 4U];
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " page-set=%s page-ranges=%s%s",
                         page_set, page_range,
                         booklet ? " imposition-template=booklet" : "");
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
  }
#endif
#ifdef CF_FUZZ_OPTIONS_PDF_BOOKLET_EMPTY_BOUNDARY
  {
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " page-set=even page-ranges=2-4 "
                         "imposition-template=booklet");
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
  }
#endif
#ifdef CF_FUZZ_TEXT_LAYOUT_OPTIONS
  {
    static const unsigned columns[] = {1U, 2U, 3U, 4U};
    static const unsigned cpi[] = {6U, 8U, 10U, 12U, 15U};
    static const unsigned lpi[] = {4U, 6U, 8U, 10U};
    int text_extra = snprintf(
        buffer + length, buffer_size - (size_t)length,
        " columns=%u cpi=%u lpi=%u wrap=%s prettyprint=%s",
        columns[control->number_up %
                (sizeof(columns) / sizeof(columns[0]))],
        cpi[control->quality % (sizeof(cpi) / sizeof(cpi[0]))],
        lpi[control->reserved % (sizeof(lpi) / sizeof(lpi[0]))],
        control->scaling & 1U ? "true" : "false",
        control->route_mode & 1U ? "true" : "false");
    if (text_extra < 0 ||
        (size_t)text_extra >= buffer_size - (size_t)length) {
      return -1;
    }
    length += text_extra;
  }
#endif
  return 0;
}

static inline int cf_fuzz_write_ppd(FILE *file,
                                  const cf_fuzz_control_t *control,
                                  const char *filter_name) {
  static const int model_numbers[] = {0, 2, 0x1130, 0x40};
  unsigned profile = control->ppd_profile % 4U;

  return fprintf(
             file,
             "*PPD-Adobe: \"4.3\"\n"
             "*FormatVersion: \"4.3\"\n"
             "*FileVersion: \"2.0\"\n"
             "*LanguageVersion: English\n"
             "*LanguageEncoding: ISOLatin1\n"
             "*Manufacturer: \"OpenPrinting\"\n"
             "*ModelName: \"cups-filters fuzz\"\n"
             "*ShortNickName: \"cups-filters fuzz\"\n"
             "*NickName: \"cups-filters fuzz\"\n"
             "*PCFileName: \"FUZZ.PPD\"\n"
             "*Product: \"(cups-filters fuzz)\"\n"
             "*PSVersion: \"(3010) 0\"\n"
             "*cupsVersion: 2.0\n"
             "*cupsModelNumber: %d\n"
             "*cupsManualCopies: False\n"
             "*cupsFilter: \"application/octet-stream 0 %s\"\n"
             "*OpenUI *PageSize: PickOne\n"
             "*DefaultPageSize: A4\n"
             "*PageSize A4/A4: \"<</PageSize[595 842]/ImagingBBox null>>setpagedevice\"\n"
             "*PageSize Letter/Letter: \"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
             "*CloseUI: *PageSize\n"
             "*DefaultImageableArea: A4\n"
             "*ImageableArea A4: \"12 12 583 830\"\n"
             "*ImageableArea Letter: \"18 36 594 756\"\n"
             "*DefaultPaperDimension: A4\n"
             "*PaperDimension A4: \"595 842\"\n"
             "*PaperDimension Letter: \"612 792\"\n"
             "*OpenUI *ColorModel: PickOne\n"
             "*DefaultColorModel: Gray\n"
             "*ColorModel Gray/Gray: \"<</cupsColorSpace 18/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice\"\n"
             "*ColorModel RGB/RGB: \"<</cupsColorSpace 1/cupsBitsPerColor 8/cupsBitsPerPixel 24>>setpagedevice\"\n"
             "*ColorModel CMYK/CMYK: \"<</cupsColorSpace 6/cupsBitsPerColor 8/cupsBitsPerPixel 32>>setpagedevice\"\n"
             "*CloseUI: *ColorModel\n"
             "*OpenUI *Resolution: PickOne\n"
             "*DefaultResolution: 300dpi\n"
             "*Resolution 300dpi/300 dpi: \"<</HWResolution[300 300]>>setpagedevice\"\n"
             "*Resolution 600dpi/600 dpi: \"<</HWResolution[600 600]>>setpagedevice\"\n"
             "*CloseUI: *Resolution\n",
             model_numbers[profile], filter_name) < 0
             ? -1
             : 0;
}

#endif
