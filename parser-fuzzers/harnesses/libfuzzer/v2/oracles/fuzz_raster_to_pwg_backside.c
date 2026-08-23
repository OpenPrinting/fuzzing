// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * Finite CUPS Raster -> PWG/Apple duplex-backside state oracle.
 *
 * RPWGBK01 is an exact 20-byte program. The first eight bytes are fixed and
 * the remaining twelve selectors generate complete two- or four-page CUPS
 * Raster jobs, coherent printer capabilities, and bounded asymmetric page
 * geometry. The oracle observes the filter-to-writer handoff and then reparses
 * the emitted wire format with the public CUPS Raster reader.
 */

#include "../include/control.h"

#include <cups/cups.h>
#include <cups/ipp.h>
#include <cups/raster.h>
#include <cupsfilters/filter.h>
#include <cupsfilters/ipp.h>

static int cf_v2_backside_setup(cf_filter_data_t *filter_data);

#define CF_V2_POST_PPD_LOAD_HOOK cf_v2_backside_setup
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V2_BACKSIDE_INPUT_SIZE 20U
#define CF_V2_BACKSIDE_SELECTOR_SIZE 12U
#define CF_V2_BACKSIDE_MAX_PAGES 4U
#define CF_V2_BACKSIDE_MAX_ROW_BYTES 384U

enum {
  CF_V2_BACKSIDE_NORMAL = 0,
  CF_V2_BACKSIDE_FLIPPED = 1,
  CF_V2_BACKSIDE_ROTATED = 2,
  CF_V2_BACKSIDE_MANUAL = 3
};

enum {
  CF_V2_DECL_NATIVE = 0,
  CF_V2_DECL_GENERIC = 1,
  CF_V2_DECL_BOTH = 2
};

enum {
  CF_V2_MARGIN_ABSENT = 0,
  CF_V2_MARGIN_FALSE = 1,
  CF_V2_MARGIN_TRUE = 2
};

typedef struct cf_v2_backside_profile_s {
  cups_cspace_t color_space;
  unsigned colors;
  unsigned bits_per_color;
} cf_v2_backside_profile_t;

typedef struct cf_v2_backside_margin_s {
  unsigned left;
  unsigned right;
  unsigned top;
  unsigned bottom;
} cf_v2_backside_margin_t;

typedef struct cf_v2_backside_page_s {
  const cf_v2_backside_profile_t *profile;
  cf_v2_backside_margin_t margin;
  unsigned width;
  unsigned height;
  unsigned input_bytes_per_line;
  unsigned output_bytes_per_line;
} cf_v2_backside_page_t;

typedef struct cf_v2_backside_program_s {
  uint8_t selector[CF_V2_BACKSIDE_SELECTOR_SIZE];
  unsigned orientation;
  unsigned declaration;
  unsigned margin_option;
  unsigned tumble;
  unsigned mime_spelling;
  unsigned page_count;
} cf_v2_backside_program_t;

typedef struct cf_v2_backside_transform_s {
  unsigned cross_feed;
  unsigned feed;
  unsigned image_box[4];
} cf_v2_backside_transform_t;

static const cf_v2_backside_profile_t cf_v2_backside_profiles[] = {
    {CUPS_CSPACE_W, 1U, 1U},
    {CUPS_CSPACE_W, 1U, 8U},
    {CUPS_CSPACE_RGB, 3U, 8U},
    {CUPS_CSPACE_CMYK, 4U, 8U},
};

static const cf_v2_backside_margin_t cf_v2_backside_margins[] = {
    {8U, 16U, 1U, 3U},
    {16U, 8U, 2U, 5U},
    {8U, 24U, 3U, 1U},
    {24U, 8U, 4U, 2U},
};

static const unsigned cf_v2_backside_widths[] = {8U, 16U, 32U, 64U};
static const unsigned cf_v2_backside_heights[] = {1U, 2U, 4U, 8U, 16U};

static cf_v2_backside_program_t cf_v2_backside_current;
static cups_page_header2_t
    cf_v2_backside_handoff[CF_V2_BACKSIDE_MAX_PAGES];
static unsigned cf_v2_backside_handoff_count;
static unsigned cf_v2_backside_handoff_overflow;
static int cf_v2_backside_capability_value;

extern unsigned __real_cupsRasterWriteHeader2(cups_raster_t *raster,
                                               cups_page_header2_t *header);

unsigned __wrap_cupsRasterWriteHeader2(cups_raster_t *raster,
                                       cups_page_header2_t *header) {
  if (header) {
    if (cf_v2_backside_handoff_count < CF_V2_BACKSIDE_MAX_PAGES) {
      cf_v2_backside_handoff[cf_v2_backside_handoff_count++] = *header;
    } else {
      cf_v2_backside_handoff_overflow = 1U;
    }
  }
  return __real_cupsRasterWriteHeader2(raster, header);
}

static const char *cf_v2_backside_keyword(unsigned orientation) {
  static const char *const keywords[] = {
      "normal", "flipped", "rotated", "manual-tumble",
  };
  return keywords[orientation % 4U];
}

#ifdef CF_V2_BACKSIDE_APPLE
static const char *cf_v2_backside_native_keyword(unsigned orientation) {
  static const char *const keywords[] = {"DM1", "DM2", "DM3", "DM4"};
  return keywords[orientation % 4U];
}
#endif

static int cf_v2_backside_add_option(cf_filter_data_t *filter_data,
                                     const char *name, const char *value) {
  int count;

  count = cupsAddOption(name, value, filter_data->num_options,
                        &filter_data->options);
  if (count < filter_data->num_options) {
    return -1;
  }
  filter_data->num_options = count;
  return 0;
}

static void cf_v2_backside_delete_attribute(ipp_t *attributes,
                                            const char *name) {
  ipp_attribute_t *attribute;

  while ((attribute = ippFindAttribute(attributes, name, IPP_TAG_ZERO)) !=
         NULL) {
    ippDeleteAttribute(attributes, attribute);
  }
}

static int cf_v2_backside_setup(cf_filter_data_t *filter_data) {
  const cf_v2_backside_program_t *program = &cf_v2_backside_current;

  if (!filter_data->printer_attrs) {
    filter_data->printer_attrs = ippNew();
  }
  if (!filter_data->printer_attrs) {
    return -1;
  }
  cf_v2_backside_delete_attribute(filter_data->printer_attrs,
                                  "sides-supported");
  if (
      !ippAddString(filter_data->printer_attrs, IPP_TAG_PRINTER,
                    IPP_TAG_KEYWORD,
                    "sides-supported", NULL, "two-sided-long-edge")) {
    return -1;
  }

#ifdef CF_V2_BACKSIDE_APPLE
  filter_data->final_content_type = (char *)"image/urf";
  if (program->declaration == CF_V2_DECL_NATIVE ||
      program->declaration == CF_V2_DECL_BOTH) {
    cf_v2_backside_delete_attribute(filter_data->printer_attrs,
                                    "urf-supported");
    if (!ippAddString(filter_data->printer_attrs, IPP_TAG_PRINTER,
                      IPP_TAG_KEYWORD,
                      "urf-supported", NULL,
                      cf_v2_backside_native_keyword(program->orientation))) {
      return -1;
    }
  }
#else
  filter_data->final_content_type =
      program->mime_spelling ? (char *)"image/vnd.pwg-raster"
                             : (char *)"image/pwg-raster";
  if (program->declaration == CF_V2_DECL_NATIVE ||
      program->declaration == CF_V2_DECL_BOTH) {
    cf_v2_backside_delete_attribute(
        filter_data->printer_attrs, "pwg-raster-document-sheet-back");
    if (!ippAddString(filter_data->printer_attrs, IPP_TAG_PRINTER,
                      IPP_TAG_KEYWORD,
                      "pwg-raster-document-sheet-back", NULL,
                      cf_v2_backside_keyword(program->orientation))) {
      return -1;
    }
  }
#endif

  if ((program->declaration == CF_V2_DECL_GENERIC ||
       program->declaration == CF_V2_DECL_BOTH) &&
      cf_v2_backside_add_option(filter_data, "back-side-orientation",
                                cf_v2_backside_keyword(
                                    program->orientation)) != 0) {
    return -1;
  }
  if (program->margin_option != CF_V2_MARGIN_ABSENT &&
      cf_v2_backside_add_option(
          filter_data, "duplex-requires-flipped-margin",
          program->margin_option == CF_V2_MARGIN_TRUE ? "true" : "false") !=
          0) {
    return -1;
  }
  cf_v2_backside_capability_value = cfGetBackSideOrientation(filter_data);
  return 0;
}

static void cf_v2_backside_decode(const uint8_t *data,
                                  cf_v2_backside_program_t *program) {
  memcpy(program->selector, data + 8U, sizeof(program->selector));
  program->orientation = program->selector[0] % 4U;
  program->declaration = program->selector[1] % 3U;
  program->margin_option = program->selector[2] % 3U;
  program->tumble = program->selector[3] & 1U;
  program->mime_spelling = program->selector[9] & 1U;
  program->page_count = program->selector[10] & 1U ? 4U : 2U;

#ifdef CF_V2_BACKSIDE_NATIVE_BOUNDARY
  program->orientation = 1U + program->selector[0] % 3U;
  program->declaration = CF_V2_DECL_NATIVE;
  program->margin_option = CF_V2_MARGIN_FALSE;
  program->mime_spelling = 0U;
#elif defined(CF_V2_BACKSIDE_MANUAL_BOUNDARY)
  program->orientation = CF_V2_BACKSIDE_MANUAL;
  program->declaration = CF_V2_DECL_GENERIC;
  program->margin_option = CF_V2_MARGIN_ABSENT;
  program->mime_spelling = 0U;
#else
#ifndef CF_V2_BACKSIDE_APPLE
  if (!program->mime_spelling &&
      program->declaration == CF_V2_DECL_NATIVE) {
    program->declaration = CF_V2_DECL_BOTH;
  }
#endif
  if (program->orientation == CF_V2_BACKSIDE_MANUAL &&
      program->margin_option == CF_V2_MARGIN_ABSENT) {
    program->margin_option = CF_V2_MARGIN_FALSE;
  }
#endif
}

static void cf_v2_backside_page_state(
    const cf_v2_backside_program_t *program, unsigned page,
    cf_v2_backside_page_t *state) {
  const unsigned variation = program->selector[11] % 4U;
  const unsigned margin_index =
      (program->selector[4] + page * (1U + variation)) %
      (sizeof(cf_v2_backside_margins) / sizeof(cf_v2_backside_margins[0]));
  const unsigned profile_index =
      (program->selector[5] + page * (variation & 1U)) %
      (sizeof(cf_v2_backside_profiles) /
       sizeof(cf_v2_backside_profiles[0]));
  const unsigned bits_per_pixel =
      cf_v2_backside_profiles[profile_index].colors *
      cf_v2_backside_profiles[profile_index].bits_per_color;

  memset(state, 0, sizeof(*state));
  state->profile = &cf_v2_backside_profiles[profile_index];
  state->margin = cf_v2_backside_margins[margin_index];
  state->width = cf_v2_backside_widths[
      (program->selector[6] + page * ((variation >> 1U) & 1U)) %
      (sizeof(cf_v2_backside_widths) / sizeof(cf_v2_backside_widths[0]))];
  state->height = cf_v2_backside_heights[
      (program->selector[7] + page * (variation & 1U)) %
      (sizeof(cf_v2_backside_heights) / sizeof(cf_v2_backside_heights[0]))];
  state->input_bytes_per_line =
      (state->width * bits_per_pixel + 7U) / 8U;
  state->output_bytes_per_line =
      ((state->width + state->margin.left + state->margin.right) *
           bits_per_pixel +
       7U) /
      8U;
}

static uint8_t cf_v2_backside_material(unsigned pattern, unsigned page,
                                       unsigned row, unsigned offset) {
  switch (pattern % 6U) {
    case 0U:
      return 0x00U;
    case 1U:
      return 0xffU;
    case 2U:
      return ((page + row + offset) & 1U) ? 0xaaU : 0x55U;
    case 3U:
      return (uint8_t)(row * 29U + offset * 17U);
    case 4U:
      return (uint8_t)(page * 61U + row * 13U + offset * 7U);
    default:
      return (uint8_t)(1U << ((page + row + offset) & 7U));
  }
}

static unsigned cf_v2_backside_white(
    const cf_v2_backside_profile_t *profile) {
  return profile->color_space == CUPS_CSPACE_W ||
                 profile->color_space == CUPS_CSPACE_RGB
             ? 0xffU
             : 0U;
}

static uint8_t *cf_v2_backside_document(
    const cf_v2_backside_program_t *program,
    cf_v2_backside_page_t pages[CF_V2_BACKSIDE_MAX_PAGES],
    size_t *document_size) {
  size_t total = 4U;
  size_t offset = 4U;
  uint8_t *document;

  for (unsigned page = 0U; page < program->page_count; page++) {
    cf_v2_backside_page_state(program, page, &pages[page]);
    total += sizeof(cups_page_header2_t) +
             (size_t)pages[page].height * pages[page].input_bytes_per_line;
  }
  document = (uint8_t *)malloc(total);
  if (!document) {
    return NULL;
  }
  memcpy(document, "3SaR", 4U);

  for (unsigned page = 0U; page < program->page_count; page++) {
    const cf_v2_backside_page_t *state = &pages[page];
    const unsigned outer_width =
        state->width + state->margin.left + state->margin.right;
    const unsigned outer_height =
        state->height + state->margin.top + state->margin.bottom;
    const unsigned bits_per_pixel =
        state->profile->colors * state->profile->bits_per_color;
    cups_page_header2_t header;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "stationery", sizeof("stationery"));
    header.HWResolution[0] = 72U;
    header.HWResolution[1] = 72U;
    header.PageSize[0] = outer_width;
    header.PageSize[1] = outer_height;
    header.ImagingBoundingBox[0] = state->margin.left;
    header.ImagingBoundingBox[1] = state->margin.bottom;
    header.ImagingBoundingBox[2] = state->margin.left + state->width;
    header.ImagingBoundingBox[3] = state->margin.bottom + state->height;
    header.cupsPageSize[0] = (float)outer_width;
    header.cupsPageSize[1] = (float)outer_height;
    header.cupsImagingBBox[0] = (float)state->margin.left;
    header.cupsImagingBBox[1] = (float)state->margin.bottom;
    header.cupsImagingBBox[2] =
        (float)(state->margin.left + state->width);
    header.cupsImagingBBox[3] =
        (float)(state->margin.bottom + state->height);
    header.cupsWidth = state->width;
    header.cupsHeight = state->height;
    header.cupsBitsPerColor = state->profile->bits_per_color;
    header.cupsBitsPerPixel = bits_per_pixel;
    header.cupsBytesPerLine = state->input_bytes_per_line;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = state->profile->color_space;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = state->profile->colors;
    header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] =
        program->page_count;
    header.NumCopies = 1U;
    header.Duplex = 1U;
    header.Tumble = program->tumble;
    memcpy(document + offset, &header, sizeof(header));
    offset += sizeof(header);

    for (unsigned row = 0U; row < state->height; row++) {
      for (unsigned column = 0U; column < state->input_bytes_per_line;
           column++) {
        document[offset++] = cf_v2_backside_material(
            program->selector[8], page, row, column);
      }
    }
  }
  *document_size = total;
  return document;
}

static void cf_v2_backside_expected_transform(
    const cf_v2_backside_program_t *program,
    const cf_v2_backside_page_t *state, unsigned page,
    cf_v2_backside_transform_t *transform) {
  const unsigned outer_width =
      state->width + state->margin.left + state->margin.right;
  const unsigned outer_height =
      state->height + state->margin.top + state->margin.bottom;

  transform->cross_feed = 1U;
  transform->feed = 1U;
  transform->image_box[0] = state->margin.left;
  transform->image_box[1] = state->margin.top;
  transform->image_box[2] = state->margin.left + state->width;
  transform->image_box[3] = outer_height - state->margin.bottom;

  if ((page & 1U) == 0U || program->orientation == CF_V2_BACKSIDE_NORMAL) {
    return;
  }
  if (program->orientation == CF_V2_BACKSIDE_FLIPPED) {
    if (program->tumble) {
      transform->cross_feed = ~0U;
      transform->image_box[0] = state->margin.right;
      transform->image_box[2] = outer_width - state->margin.left;
    } else {
      transform->feed = ~0U;
      transform->image_box[1] = state->margin.bottom;
      transform->image_box[3] = outer_height - state->margin.top;
    }
  } else if (program->orientation == CF_V2_BACKSIDE_MANUAL) {
    if (program->tumble) {
      transform->cross_feed = ~0U;
      transform->feed = ~0U;
      transform->image_box[0] =
          outer_width - state->margin.left - state->width;
      transform->image_box[1] = state->margin.bottom;
      transform->image_box[2] = outer_width - state->margin.left;
      transform->image_box[3] = outer_height - state->margin.top;
    }
  } else if (program->orientation == CF_V2_BACKSIDE_ROTATED &&
             program->tumble) {
    transform->cross_feed = ~0U;
    transform->feed = ~0U;
    transform->image_box[0] = state->margin.right;
    transform->image_box[1] = state->margin.bottom;
    transform->image_box[2] = outer_width - state->margin.left;
    transform->image_box[3] = outer_height - state->margin.top;
  }
}

static int cf_v2_backside_check_handoff(
    const cf_v2_backside_program_t *program,
    const cf_v2_backside_page_t pages[CF_V2_BACKSIDE_MAX_PAGES],
    const char **failure) {
  if (cf_v2_backside_handoff_overflow ||
      cf_v2_backside_handoff_count != program->page_count) {
    *failure = "handoff-count";
    return 0;
  }

  for (unsigned page = 0U; page < program->page_count; page++) {
    const cf_v2_backside_page_t *state = &pages[page];
    const cups_page_header2_t *header = &cf_v2_backside_handoff[page];
    const unsigned outer_width =
        state->width + state->margin.left + state->margin.right;
    const unsigned outer_height =
        state->height + state->margin.top + state->margin.bottom;
    cf_v2_backside_transform_t expected;

    cf_v2_backside_expected_transform(program, state, page, &expected);
    if (header->cupsWidth != outer_width ||
        header->cupsHeight != outer_height || !header->Duplex ||
        header->Tumble != program->tumble ||
        header->cupsInteger[1] != expected.cross_feed ||
        header->cupsInteger[2] != expected.feed ||
        header->cupsInteger[3] != expected.image_box[0] ||
        header->cupsInteger[4] != expected.image_box[1] ||
        header->cupsInteger[5] != expected.image_box[2] ||
        header->cupsInteger[6] != expected.image_box[3]) {
      fprintf(stderr,
              "%s: page=%u orientation=%u declaration=%u margin=%u "
              "tumble=%u mime=%u actual=[%u,%u,%u,%u,%u,%u] "
              "expected=[%u,%u,%u,%u,%u,%u] capability=%d\n",
              CF_V2_TARGET_NAME, page + 1U, program->orientation,
              program->declaration, program->margin_option, program->tumble,
              program->mime_spelling, header->cupsInteger[1],
              header->cupsInteger[2], header->cupsInteger[3],
              header->cupsInteger[4], header->cupsInteger[5],
              header->cupsInteger[6], expected.cross_feed, expected.feed,
              expected.image_box[0], expected.image_box[1],
              expected.image_box[2], expected.image_box[3],
              cf_v2_backside_capability_value);
      *failure = (page & 1U) ? "backside-handoff" : "frontside-handoff";
      return 0;
    }
  }
  return 1;
}

static void cf_v2_backside_expected_row(
    uint8_t *row, const cf_v2_backside_program_t *program,
    const cf_v2_backside_page_t *state, unsigned page, unsigned output_row) {
  const unsigned content_end = state->margin.top + state->height;
  const unsigned left_bytes =
      state->margin.left * state->profile->colors *
      state->profile->bits_per_color / 8U;

  memset(row, (int)cf_v2_backside_white(state->profile),
         state->output_bytes_per_line);
  if (output_row >= state->margin.top && output_row < content_end) {
    const unsigned source_row = output_row - state->margin.top;
    for (unsigned column = 0U; column < state->input_bytes_per_line;
         column++) {
      row[left_bytes + column] = cf_v2_backside_material(
          program->selector[8], page, source_row, column);
    }
  }
}

static int cf_v2_backside_check_wire(
    const cf_v2_run_result_t *result,
    const cf_v2_backside_program_t *program,
    const cf_v2_backside_page_t pages[CF_V2_BACKSIDE_MAX_PAGES],
    const char **failure) {
  uint8_t actual[CF_V2_BACKSIDE_MAX_ROW_BYTES];
  uint8_t expected[CF_V2_BACKSIDE_MAX_ROW_BYTES];
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
    const cf_v2_backside_page_t *state = &pages[page];
    const unsigned outer_width =
        state->width + state->margin.left + state->margin.right;
    const unsigned outer_height =
        state->height + state->margin.top + state->margin.bottom;
    const unsigned bits_per_pixel =
        state->profile->colors * state->profile->bits_per_color;

    if (!cupsRasterReadHeader2(raster, &header)) {
      *failure = "wire-page-count-short";
      goto done;
    }
    if (header.cupsWidth != outer_width ||
        header.cupsHeight != outer_height ||
        header.cupsBitsPerColor != state->profile->bits_per_color ||
        header.cupsBitsPerPixel != bits_per_pixel ||
        header.cupsBytesPerLine != state->output_bytes_per_line ||
        header.cupsColorOrder != CUPS_ORDER_CHUNKED ||
        header.cupsColorSpace != state->profile->color_space ||
        header.cupsNumColors != state->profile->colors ||
        header.HWResolution[0] != 72U || header.HWResolution[1] != 72U) {
      *failure = "wire-header";
      goto done;
    }
#ifndef CF_V2_BACKSIDE_APPLE
    {
      cf_v2_backside_transform_t handoff;
      cf_v2_backside_expected_transform(program, state, page, &handoff);
      if (header.cupsInteger[1] != handoff.cross_feed ||
          header.cupsInteger[2] != handoff.feed ||
          header.cupsInteger[3] != state->margin.left ||
          header.cupsInteger[4] != state->margin.bottom ||
          header.cupsInteger[5] != state->margin.left + state->width ||
          header.cupsInteger[6] != state->margin.bottom + state->height) {
        *failure = "pwg-wire-transform-or-imagebox";
        goto done;
      }
    }
#endif
    if (state->output_bytes_per_line > sizeof(actual)) {
      *failure = "wire-row-bound";
      goto done;
    }
    for (unsigned row = 0U; row < outer_height; row++) {
      if (cupsRasterReadPixels(raster, actual,
                               state->output_bytes_per_line) !=
          state->output_bytes_per_line) {
        *failure = "wire-short-row";
        goto done;
      }
      cf_v2_backside_expected_row(expected, program, state, page, row);
      if (memcmp(actual, expected, state->output_bytes_per_line) != 0) {
        size_t first = 0U;
        while (first < state->output_bytes_per_line &&
               actual[first] == expected[first]) {
          first++;
        }
        fprintf(stderr,
                "%s: wire pixel page=%u row=%u first=%zu actual=%u "
                "expected=%u space=%u bpc=%u left=%u top=%u width=%u "
                "height=%u\n",
                CF_V2_TARGET_NAME, page + 1U, row, first,
                first < state->output_bytes_per_line ? actual[first] : 0U,
                first < state->output_bytes_per_line ? expected[first] : 0U,
                (unsigned)state->profile->color_space,
                state->profile->bits_per_color, state->margin.left,
                state->margin.top, state->width, state->height);
        *failure = "wire-pixel";
        goto done;
      }
    }
  }
  if (cupsRasterReadHeader2(raster, &header)) {
    *failure = "wire-page-count-long";
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_backside_page_t pages[CF_V2_BACKSIDE_MAX_PAGES];
  cf_v2_control_t control;
  cf_v2_run_result_t result;
  size_t document_size = 0U;
  uint8_t *document;
  const char *failure = NULL;
  int executed;

  if (!data || size != CF_V2_BACKSIDE_INPUT_SIZE ||
      memcmp(data, "RPWGBK01", 8U) != 0) {
    return 0;
  }
  cf_v2_backside_decode(data, &cf_v2_backside_current);
  document = cf_v2_backside_document(&cf_v2_backside_current, pages,
                                     &document_size);
  if (!document) {
    return 0;
  }

  memset(&control, 0, sizeof(control));
  control.sides = 1U;
  cf_v2_backside_handoff_count = 0U;
  cf_v2_backside_handoff_overflow = 0U;
  executed =
      cf_v2_execute_direct(document, document_size, &control, 1, &result);
  if (!executed ||
      !cf_v2_backside_check_handoff(&cf_v2_backside_current, pages,
                                    &failure) ||
      !cf_v2_backside_check_wire(&result, &cf_v2_backside_current, pages,
                                 &failure)) {
    fprintf(stderr, "%s: %s\n", CF_V2_TARGET_NAME,
            failure ? failure : "route-not-executed");
    cf_v2_free_run_result(&result);
    free(document);
    __builtin_trap();
  }
  cf_v2_free_run_result(&result);
  free(document);
  return 0;
}
