// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * RPWGNAME1: finite control/boundary language for Raster-to-PWG page names.
 *
 * The target compares supported exact/alias controls with unsupported known
 * and opaque non-empty names.  Every input creates one complete CUPS Raster
 * page, runs cfFilterRasterToPWG, and checks both the writer handoff and the
 * public-reader PWG header against the advertised A4 capability.
 */

#include <cups/cups.h>
#include <cups/ipp.h>
#include <cups/raster.h>
#include <cupsfilters/filter.h>

static int cf_v2_rpwg_name_setup(cf_filter_data_t *filter_data);

#define CF_V2_FILTER_FUNCTION cfFilterRasterToPWG
#define CF_V2_TARGET_NAME \
  "fuzz_v2_cupsfilters_boundary_raster_to_pwg_unsupported_page_size_name"
#define CF_V2_INPUT_MIME "application/vnd.cups-raster"
#define CF_V2_OUTPUT_MIME "image/pwg-raster"
#define CF_V2_NEEDS_PCLM_ATTRS 1
#define CF_V2_POST_PPD_LOAD_HOOK cf_v2_rpwg_name_setup
#include "../include/direct_route.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V2_RPWG_NAME_MAGIC "RPWGNAME1"
#define CF_V2_RPWG_NAME_MAGIC_SIZE 9U
#define CF_V2_RPWG_NAME_SELECTOR_SIZE 4U
#define CF_V2_RPWG_NAME_INPUT_SIZE 13U
#define CF_V2_RPWG_NAME_MAX_ROW_BYTES 80U

enum {
  CF_V2_RPWG_NAME_RETAIN = 0,
  CF_V2_RPWG_NAME_CANONICALIZE = 1,
  CF_V2_RPWG_NAME_FALLBACK = 2,
};

typedef struct cf_v2_rpwg_name_program_s {
  uint8_t selector[CF_V2_RPWG_NAME_SELECTOR_SIZE];
  unsigned scenario;
  unsigned carrier;
  unsigned margin;
  unsigned pattern;
} cf_v2_rpwg_name_program_t;

typedef struct cf_v2_rpwg_name_scenario_s {
  const char *input_name;
  unsigned width_points;
  unsigned height_points;
  unsigned expected_route;
} cf_v2_rpwg_name_scenario_t;

typedef struct cf_v2_rpwg_name_geometry_s {
  unsigned left_points;
  unsigned bottom_points;
  unsigned right_points;
  unsigned top_points;
  int left_2540;
  int bottom_2540;
  int right_2540;
  int top_2540;
} cf_v2_rpwg_name_geometry_t;

static const cf_v2_rpwg_name_scenario_t cf_v2_rpwg_name_scenarios[] = {
    /* Supported controls. */
    {"A4", 595U, 842U, CF_V2_RPWG_NAME_RETAIN},
    {"iso_a4_210x297mm", 595U, 842U, CF_V2_RPWG_NAME_CANONICALIZE},
    /* Empty-name control proving that the dimensions fallback is reachable. */
    {"", 595U, 842U, CF_V2_RPWG_NAME_FALLBACK},
    /* Unsupported non-empty names with supported A4 geometry. */
    {"Letter", 595U, 842U, CF_V2_RPWG_NAME_FALLBACK},
    {"x-vendor-unlisted", 595U, 842U, CF_V2_RPWG_NAME_FALLBACK},
    /* Unsupported non-empty names with unsupported 4x6 geometry. */
    {"Letter", 288U, 432U, CF_V2_RPWG_NAME_FALLBACK},
    {"x-vendor-unlisted", 288U, 432U, CF_V2_RPWG_NAME_FALLBACK},
};

static const cf_v2_rpwg_name_geometry_t cf_v2_rpwg_name_margins[] = {
    {18U, 36U, 18U, 36U, 635, 1270, 635, 1270},
    {0U, 0U, 0U, 0U, 0, 0, 0, 0},
};

static cf_v2_rpwg_name_program_t cf_v2_rpwg_name_current;
static cups_page_header2_t cf_v2_rpwg_name_handoff;
static unsigned cf_v2_rpwg_name_handoff_count;

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
extern unsigned __real_cupsRasterWriteHeader2(cups_raster_t *raster,
                                               cups_page_header2_t *header);

unsigned __wrap_cupsRasterWriteHeader2(cups_raster_t *raster,
                                       cups_page_header2_t *header) {
  if (header) {
    cf_v2_rpwg_name_handoff_count++;
    if (cf_v2_rpwg_name_handoff_count == 1U) {
      cf_v2_rpwg_name_handoff = *header;
    }
  }
  return __real_cupsRasterWriteHeader2(raster, header);
}

static void cf_v2_rpwg_name_decode(const uint8_t *data,
                                   cf_v2_rpwg_name_program_t *program) {
  memcpy(program->selector, data + CF_V2_RPWG_NAME_MAGIC_SIZE,
         sizeof(program->selector));
  program->scenario = program->selector[0] % 7U;
  program->carrier = program->selector[1] % 2U;
  program->margin = program->selector[2] % 2U;
  program->pattern = program->selector[3] % 4U;
}

static const char *cf_v2_rpwg_name_expected(
    const cf_v2_rpwg_name_program_t *program) {
  const cf_v2_rpwg_name_scenario_t *scenario =
      &cf_v2_rpwg_name_scenarios[program->scenario];

  if (scenario->width_points != 595U || scenario->height_points != 842U) {
    return "";
  }
  return program->margin ? "A4.Borderless" : "A4";
}

static const char *cf_v2_rpwg_name_route_name(unsigned route) {
  switch (route) {
    case CF_V2_RPWG_NAME_RETAIN:
      return "retain";
    case CF_V2_RPWG_NAME_CANONICALIZE:
      return "canonicalize";
    default:
      return "fallback";
  }
}

static uint8_t cf_v2_rpwg_name_material(
    const cf_v2_rpwg_name_program_t *program, unsigned row,
    unsigned column) {
  switch (program->pattern) {
    case 0U:
      return 0x00U;
    case 1U:
      return 0xffU;
    case 2U:
      return ((row + column) & 1U) ? 0xaaU : 0x55U;
    default:
      return (uint8_t)(row * 29U + column * 17U);
  }
}

static uint8_t *cf_v2_rpwg_name_document(
    const cf_v2_rpwg_name_program_t *program, size_t *document_size) {
  const cf_v2_rpwg_name_scenario_t *scenario =
      &cf_v2_rpwg_name_scenarios[program->scenario];
  const cf_v2_rpwg_name_geometry_t *margin =
      &cf_v2_rpwg_name_margins[program->margin];
  const unsigned content_width =
      scenario->width_points - margin->left_points - margin->right_points;
  const unsigned content_height =
      scenario->height_points - margin->top_points - margin->bottom_points;
  const unsigned bytes_per_line = (content_width + 7U) / 8U;
  const size_t total = 4U + sizeof(cups_page_header2_t) +
                       (size_t)content_height * bytes_per_line;
  cups_page_header2_t header;
  uint8_t *document = (uint8_t *)malloc(total);
  size_t offset = 4U;

  if (!document) {
    return NULL;
  }
  memset(&header, 0, sizeof(header));
  snprintf(header.MediaClass, sizeof(header.MediaClass), "PwgRaster");
  snprintf(header.MediaType, sizeof(header.MediaType), "stationery");
  snprintf(header.cupsPageSizeName, sizeof(header.cupsPageSizeName), "%s",
           scenario->input_name);
  header.HWResolution[0] = 72U;
  header.HWResolution[1] = 72U;
  header.PageSize[0] = scenario->width_points;
  header.PageSize[1] = scenario->height_points;
  header.ImagingBoundingBox[0] = margin->left_points;
  header.ImagingBoundingBox[1] = margin->bottom_points;
  header.ImagingBoundingBox[2] =
      scenario->width_points - margin->right_points;
  header.ImagingBoundingBox[3] =
      scenario->height_points - margin->top_points;
  header.cupsPageSize[0] = (float)scenario->width_points;
  header.cupsPageSize[1] = (float)scenario->height_points;
  header.cupsImagingBBox[0] = (float)header.ImagingBoundingBox[0];
  header.cupsImagingBBox[1] = (float)header.ImagingBoundingBox[1];
  header.cupsImagingBBox[2] = (float)header.ImagingBoundingBox[2];
  header.cupsImagingBBox[3] = (float)header.ImagingBoundingBox[3];
  header.cupsWidth = content_width;
  header.cupsHeight = content_height;
  header.cupsBitsPerColor = 1U;
  header.cupsBitsPerPixel = 1U;
  header.cupsBytesPerLine = bytes_per_line;
  header.cupsColorOrder = CUPS_ORDER_CHUNKED;
  header.cupsColorSpace = CUPS_CSPACE_K;
  header.cupsRowCount = 1U;
  header.cupsRowFeed = 1U;
  header.cupsRowStep = 1U;
  header.cupsNumColors = 1U;
  header.cupsInteger[CUPS_RASTER_PWG_TotalPageCount] = 1U;
  header.NumCopies = 1U;

  memcpy(document, "3SaR", 4U);
  memcpy(document + offset, &header, sizeof(header));
  offset += sizeof(header);
  for (unsigned row = 0U; row < content_height; row++) {
    for (unsigned column = 0U; column < bytes_per_line; column++) {
      document[offset++] =
          cf_v2_rpwg_name_material(program, row, column);
    }
  }
  *document_size = total;
  return document;
}

static ipp_t *cf_v2_rpwg_name_make_size(void) {
  ipp_t *size = ippNew();

  if (!size ||
      !ippAddInteger(size, IPP_TAG_ZERO, IPP_TAG_INTEGER, "x-dimension",
                     21000) ||
      !ippAddInteger(size, IPP_TAG_ZERO, IPP_TAG_INTEGER, "y-dimension",
                     29700)) {
    if (size) {
      ippDelete(size);
    }
    return NULL;
  }
  return size;
}

static int cf_v2_rpwg_name_add_database(
    ipp_t *attributes, const cf_v2_rpwg_name_geometry_t *margin) {
  ipp_t *size = cf_v2_rpwg_name_make_size();
  ipp_t *collection = ippNew();
  int valid = 0;

  if (size && collection &&
      ippAddCollection(collection, IPP_TAG_ZERO, "media-size", size) &&
      ippAddString(collection, IPP_TAG_ZERO, IPP_TAG_KEYWORD,
                   "media-size-name", NULL, "iso_a4_210x297mm") &&
      ippAddInteger(collection, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                    "media-left-margin", margin->left_2540) &&
      ippAddInteger(collection, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                    "media-bottom-margin", margin->bottom_2540) &&
      ippAddInteger(collection, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                    "media-right-margin", margin->right_2540) &&
      ippAddInteger(collection, IPP_TAG_ZERO, IPP_TAG_INTEGER,
                    "media-top-margin", margin->top_2540) &&
      ippAddCollection(attributes, IPP_TAG_PRINTER, "media-col-database",
                       collection)) {
    valid = 1;
  }
  if (size) {
    ippDelete(size);
  }
  if (collection) {
    ippDelete(collection);
  }
  return valid ? 0 : -1;
}

static int cf_v2_rpwg_name_add_size_supported(ipp_t *attributes) {
  ipp_t *size = cf_v2_rpwg_name_make_size();
  int valid = size &&
              ippAddCollection(attributes, IPP_TAG_PRINTER,
                               "media-size-supported", size);

  if (size) {
    ippDelete(size);
  }
  return valid ? 0 : -1;
}

static int cf_v2_rpwg_name_setup(cf_filter_data_t *filter_data) {
  const cf_v2_rpwg_name_program_t *program = &cf_v2_rpwg_name_current;
  const cf_v2_rpwg_name_geometry_t *margin =
      &cf_v2_rpwg_name_margins[program->margin];
  ipp_t *attributes = ippNew();

  if (!attributes) {
    return -1;
  }
  if (filter_data->printer_attrs) {
    ippDelete(filter_data->printer_attrs);
  }
  filter_data->printer_attrs = attributes;
  filter_data->final_content_type = (char *)CF_V2_OUTPUT_MIME;

  if (!ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-left-margin-supported", margin->left_2540) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-bottom-margin-supported", margin->bottom_2540) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-right-margin-supported", margin->right_2540) ||
      !ippAddInteger(attributes, IPP_TAG_PRINTER, IPP_TAG_INTEGER,
                     "media-top-margin-supported", margin->top_2540)) {
    return -1;
  }
  return program->carrier == 0U
             ? cf_v2_rpwg_name_add_database(attributes, margin)
             : cf_v2_rpwg_name_add_size_supported(attributes);
}

static const char *cf_v2_rpwg_name_observed_route(
    const cf_v2_rpwg_name_program_t *program, const char *actual) {
  const cf_v2_rpwg_name_scenario_t *scenario =
      &cf_v2_rpwg_name_scenarios[program->scenario];
  const char *expected = cf_v2_rpwg_name_expected(program);

  if (scenario->input_name[0] && !strcmp(actual, scenario->input_name)) {
    return scenario->expected_route == CF_V2_RPWG_NAME_RETAIN
               ? "retain"
               : "unexpected-retain";
  }
  if (!strcmp(actual, expected)) {
    return cf_v2_rpwg_name_route_name(scenario->expected_route);
  }
  if (!actual[0]) {
    return "empty";
  }
  return "other";
}

static int cf_v2_rpwg_name_check_name(
    const cups_page_header2_t *header,
    const cf_v2_rpwg_name_program_t *program, const char *surface,
    const char **failure) {
  const cf_v2_rpwg_name_scenario_t *scenario =
      &cf_v2_rpwg_name_scenarios[program->scenario];
  const char *expected = cf_v2_rpwg_name_expected(program);
  const int unsupported_retained =
      scenario->input_name[0] &&
      !strcmp(header->cupsPageSizeName, scenario->input_name) &&
      scenario->expected_route == CF_V2_RPWG_NAME_FALLBACK;

  if (strcmp(header->cupsPageSizeName, expected) != 0) {
    fprintf(stderr,
            "%s: %s scenario=%u carrier=%u margin=%u input=%s "
            "expected-route=%s observed-route=%s actual=%s expected=%s\n",
            CF_V2_TARGET_NAME, surface, program->scenario, program->carrier,
            program->margin, scenario->input_name,
            cf_v2_rpwg_name_route_name(scenario->expected_route),
            cf_v2_rpwg_name_observed_route(program,
                                           header->cupsPageSizeName),
            header->cupsPageSizeName,
            expected[0] ? expected : "<empty>");
    *failure = unsupported_retained ? "unsupported-name-retained"
                                    : "page-size-name";
    return 0;
  }
  return 1;
}

static int cf_v2_rpwg_name_check_handoff(
    const cf_v2_rpwg_name_program_t *program, const char **failure) {
  if (cf_v2_rpwg_name_handoff_count != 1U) {
    *failure = "handoff-count";
    return 0;
  }
  return cf_v2_rpwg_name_check_name(&cf_v2_rpwg_name_handoff, program,
                                    "handoff", failure);
}

static int cf_v2_rpwg_name_check_output(
    const cf_v2_run_result_t *result,
    const cf_v2_rpwg_name_program_t *program, const char **failure) {
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  uint8_t row[CF_V2_RPWG_NAME_MAX_ROW_BYTES];
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
  if (!cupsRasterReadHeader2(raster, &header)) {
    *failure = "page-count-short";
    goto done;
  }
  if (!cf_v2_rpwg_name_check_name(&header, program, "wire", failure)) {
    goto done;
  }
  if (!header.cupsBytesPerLine ||
      header.cupsBytesPerLine > sizeof(row) || !header.cupsHeight) {
    *failure = "wire-geometry";
    goto done;
  }
  for (unsigned y = 0U; y < header.cupsHeight; y++) {
    if (cupsRasterReadPixels(raster, row, header.cupsBytesPerLine) !=
        header.cupsBytesPerLine) {
      *failure = "short-row";
      goto done;
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
  if (!data || max_size < CF_V2_RPWG_NAME_INPUT_SIZE) {
    return 0U;
  }
  if (size < CF_V2_RPWG_NAME_INPUT_SIZE) {
    memset(data + size, 0, CF_V2_RPWG_NAME_INPUT_SIZE - size);
  }
  memcpy(data, CF_V2_RPWG_NAME_MAGIC, CF_V2_RPWG_NAME_MAGIC_SIZE);
  selector_size = LLVMFuzzerMutate(
      data + CF_V2_RPWG_NAME_MAGIC_SIZE, CF_V2_RPWG_NAME_SELECTOR_SIZE,
      CF_V2_RPWG_NAME_SELECTOR_SIZE);
  if (selector_size < CF_V2_RPWG_NAME_SELECTOR_SIZE) {
    memset(data + CF_V2_RPWG_NAME_MAGIC_SIZE + selector_size, 0,
           CF_V2_RPWG_NAME_SELECTOR_SIZE - selector_size);
  }
  memcpy(data, CF_V2_RPWG_NAME_MAGIC, CF_V2_RPWG_NAME_MAGIC_SIZE);
  return CF_V2_RPWG_NAME_INPUT_SIZE;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cf_v2_control_t control;
  cf_v2_run_result_t result = {0};
  uint8_t *document = NULL;
  size_t document_size = 0U;
  const char *failure = NULL;
  const char *handoff_failure = NULL;
  const char *wire_failure = NULL;
  int executed;
  int handoff_valid = 0;
  int wire_valid = 0;
  int failed = 0;

  if (!data || size != CF_V2_RPWG_NAME_INPUT_SIZE ||
      memcmp(data, CF_V2_RPWG_NAME_MAGIC,
             CF_V2_RPWG_NAME_MAGIC_SIZE) != 0) {
    return 0;
  }
  cf_v2_rpwg_name_decode(data, &cf_v2_rpwg_name_current);
  document =
      cf_v2_rpwg_name_document(&cf_v2_rpwg_name_current, &document_size);
  if (!document) {
    return 0;
  }

  memset(&control, 0, sizeof(control));
  cf_v2_rpwg_name_handoff_count = 0U;
  memset(&cf_v2_rpwg_name_handoff, 0, sizeof(cf_v2_rpwg_name_handoff));
  executed =
      cf_v2_execute_direct(document, document_size, &control, 1, &result);
  if (executed) {
    handoff_valid = cf_v2_rpwg_name_check_handoff(
        &cf_v2_rpwg_name_current, &handoff_failure);
    wire_valid = cf_v2_rpwg_name_check_output(
        &result, &cf_v2_rpwg_name_current, &wire_failure);
  }
  if (!executed || !handoff_valid || !wire_valid) {
    failed = 1;
    failure = handoff_failure ? handoff_failure : wire_failure;
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
