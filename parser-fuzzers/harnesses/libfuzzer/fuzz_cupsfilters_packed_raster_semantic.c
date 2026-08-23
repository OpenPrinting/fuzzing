// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * Structured packed-CUPS-Raster harness for the legacy rastertopclx and
 * rastertoescpx standalone filters.
 *
 * Grammar:
 *   "PKRAST1\n"
 *   byte 0: width/height selector
 *   byte 1: colorspace/color-count/BPC selector
 *   byte 2: order/compression/PPD-profile selector
 *   byte 3: payload-pattern selector
 *   remaining bytes: cyclic payload material
 *
 * Exactly one target macro must be defined:
 *   CUPSFILTERS_PACKED_RASTER_PCLX
 *   CUPSFILTERS_PACKED_RASTER_ESCPX
 *
 * CUPSFILTERS_PACKED_RASTER_FILTER_SOURCE must quote the corresponding
 * upstream filter source. PCLX builds also link filter/pcl-common.c.
 *
 * Define CUPSFILTERS_PACKED_RASTER_CONTINUATION for the continuation role.
 * It excludes only layouts where a byte-per-sample converter would read past
 * the generated packed scanline. It deliberately retains safe low-BPC states.
 *
 * Define CUPSFILTERS_PACKED_RASTER_ESCPX_WEAVE_STATE with the ESC/P target to
 * select the separate ESCPROW1 grammar. It keeps byte-oriented input valid and
 * varies row count/feed plus encoded column/row step so ProcessLine reaches
 * softweave band completion and recycling.
 *
 * Define CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE to select ESCPPAG1. It
 * extends the same valid byte-oriented contract to 1--4 heterogeneous pages,
 * exercising EndPage-to-StartPage cleanup and reinitialization.
 *
 * Define CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT to select RSTRGEN1. Its
 * 32 selector bytes independently describe the resource-bounded Raster image
 * geometry, pixel/storage relations, PPD capabilities, resolution/weave
 * state, and page/job metadata. Every selector value maps to a documented
 * finite domain; no selector encodes a historical crash tuple.
 *
 * CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM selects RSTRJOB1. It keeps the old
 * RSTRGEN1 contract intact while expressing the same job through the shared
 * scalar, length, cardinality and opaque relation vocabulary.
 */

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/colormanager.h>
#include <cupsfilters/filter.h>
#include <ppd/ppd.h>

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
#include "raster_job_relation.h"
#endif

#if defined(CUPSFILTERS_PACKED_RASTER_PCLX) == \
    defined(CUPSFILTERS_PACKED_RASTER_ESCPX)
#error "define exactly one packed Raster target macro"
#endif

#ifndef CUPSFILTERS_PACKED_RASTER_FILTER_SOURCE
#error "CUPSFILTERS_PACKED_RASTER_FILTER_SOURCE must quote the filter source"
#endif

#if defined(CUPSFILTERS_PACKED_RASTER_ESCPX_WEAVE_STATE) || \
    defined(CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE) || \
    defined(CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM) || \
    defined(CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT)
#define CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
#endif

#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
#ifndef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
#error "RSTRJOB1 requires CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT"
#endif
#define PACKED_RASTER_MAGIC CF_V2_RASTER_JOB_MAGIC
#define PACKED_RASTER_SELECTOR_BYTES CF_V2_RASTER_JOB_HEADER_SIZE
#elif defined(CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT)
#define PACKED_RASTER_MAGIC "RSTRGEN1"
#define PACKED_RASTER_SELECTOR_BYTES 32U
#elif defined(CUPSFILTERS_PACKED_RASTER_PCLX_RELATION_PROGRAM)
#ifndef CUPSFILTERS_PACKED_RASTER_PCLX
#error "the RSTRPCL1 relation program requires CUPSFILTERS_PACKED_RASTER_PCLX"
#endif
#ifndef CF_V2_PCLX_RELATION_LANE
#error "CF_V2_PCLX_RELATION_LANE must select one relation boundary"
#endif
#define PACKED_RASTER_MAGIC "RSTRPCL1"
#define PACKED_RASTER_SELECTOR_BYTES 8U
#elif defined(CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM)
#ifndef CUPSFILTERS_PACKED_RASTER_ESCPX
#error "the RSTRESC1 relation program requires CUPSFILTERS_PACKED_RASTER_ESCPX"
#endif
#ifndef CF_V2_ESCPX_RELATION_LANE
#error "CF_V2_ESCPX_RELATION_LANE must select one relation boundary"
#endif
#define PACKED_RASTER_MAGIC "RSTRESC1"
#define PACKED_RASTER_SELECTOR_BYTES 8U
#elif defined(CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE)
#ifndef CUPSFILTERS_PACKED_RASTER_ESCPX
#error "the ESCPPAG1 state requires CUPSFILTERS_PACKED_RASTER_ESCPX"
#endif
#define PACKED_RASTER_MAGIC "ESCPPAG1"
#define PACKED_RASTER_SELECTOR_BYTES 12U
#elif defined(CUPSFILTERS_PACKED_RASTER_ESCPX_WEAVE_STATE)
#ifndef CUPSFILTERS_PACKED_RASTER_ESCPX
#error "the ESCPROW1 state requires CUPSFILTERS_PACKED_RASTER_ESCPX"
#endif
#define PACKED_RASTER_MAGIC "ESCPROW1"
#define PACKED_RASTER_SELECTOR_BYTES 8U
#else
#define PACKED_RASTER_MAGIC "PKRAST1\n"
#define PACKED_RASTER_SELECTOR_BYTES 4U
#endif
#define PACKED_RASTER_MAX_MATERIAL 4096U
#define PACKED_RASTER_MAX_WIDTH 256U
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
#define PACKED_RASTER_MAX_HEIGHT 64U
#define PACKED_RASTER_MAX_PAYLOAD (256U * 1024U)
#elif defined(CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE)
#define PACKED_RASTER_MAX_HEIGHT 64U
#define PACKED_RASTER_MAX_PAYLOAD (64U * 1024U)
#else
#define PACKED_RASTER_MAX_HEIGHT 4U
#define PACKED_RASTER_MAX_PAYLOAD (8U * 1024U)
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
#define PACKED_RASTER_MAX_COLORS 15U
#else
#define PACKED_RASTER_MAX_COLORS 4U
#endif
#define PACKED_RASTER_MAX_BPC 16U
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
#define PACKED_RASTER_MAX_BPL 8192U
#else
#define PACKED_RASTER_MAX_BPL 2048U
#endif
#define PACKED_RASTER_MAX_PHYSICAL_ROWS \
  (PACKED_RASTER_MAX_HEIGHT * PACKED_RASTER_MAX_COLORS)

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/common_interface_defs.h>
#define PACKED_RASTER_HAS_ASAN_REPORT_FD 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) && \
    !defined(PACKED_RASTER_HAS_ASAN_REPORT_FD)
#include <sanitizer/common_interface_defs.h>
#define PACKED_RASTER_HAS_ASAN_REPORT_FD 1
#endif

typedef struct packed_raster_format_s {
  cups_cspace_t color_space;
  unsigned colors;
  unsigned bits_per_color;
} packed_raster_format_t;

typedef struct packed_raster_state_s {
  unsigned width;
  unsigned height;
  cups_cspace_t color_space;
  unsigned colors;
  unsigned bits_per_color;
  unsigned bits_per_pixel;
  unsigned bytes_per_line;
  cups_order_t order;
  unsigned compression;
  unsigned profile;
  unsigned pattern;
  unsigned physical_rows;
#if defined(CUPSFILTERS_PACKED_RASTER_PCLX_RELATION_PROGRAM) || \
    defined(CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM)
  unsigned relation_boundary;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM
  unsigned resolution_x;
  unsigned resolution_y;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
  unsigned resolution_x;
  unsigned resolution_y;
  cups_cspace_t ppd_color_space;
  unsigned ppd_channels;
  unsigned ppd_bits_per_pixel;
  unsigned page_size_count;
  unsigned model_number_mode;
  unsigned page_count;
  unsigned page_width;
  unsigned page_height;
  unsigned cups_media_type;
  unsigned media_name_index;
  unsigned num_copies;
  unsigned duplex;
  unsigned tumble;
  unsigned material_phase;
  unsigned page_pattern_stride;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
  cf_v2_raster_job_relation_t relation;
  const uint8_t *opaque_command;
  size_t opaque_command_size;
  cf_v2_relation_mode_t opaque_command_mode;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
  unsigned row_count;
  unsigned row_feed;
  unsigned row_step;
  unsigned column_step;
#endif
#if defined(CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE) && \
    !defined(CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT)
  unsigned page_count;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  unsigned page_height_seed;
  unsigned page_height_stride;
  unsigned page_state_stride;
  unsigned page_pattern_stride;
#endif
} packed_raster_state_t;

typedef struct packed_saved_env_s {
  const char *name;
  char *value;
} packed_saved_env_t;

#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
static const unsigned packed_raster_widths[] = {
    12U, 24U, 36U, 48U, 96U, 120U, 192U, 240U,
};
static const unsigned packed_raster_heights[] = {
    2U, 4U, 8U, 16U, 32U, 64U,
};
static const unsigned packed_raster_row_counts[] = {2U, 3U, 4U, 8U, 16U};
static const unsigned packed_raster_row_feeds[] = {0U, 1U, 2U, 3U, 5U, 7U, 11U};
static const unsigned packed_raster_weave_steps[] = {1U, 2U, 3U, 4U};
#else
static const unsigned packed_raster_widths[] = {
    1U, 2U, 3U, 7U, 8U, 15U, 31U, 63U, 127U, 128U, 129U, 255U, 256U,
};

static const unsigned packed_raster_heights[] = {1U, 2U, 3U, 4U};
#endif
static const unsigned packed_raster_compressions[] = {0U, 1U, 2U};

#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
/*
 * The generic contract domain is derived from the CUPS Raster header and the
 * two legacy filter APIs.  Values are systematic type/packet boundaries, not
 * tuples copied from historical reproducers.
 */
static const unsigned packed_raster_contract_widths[] = {
    1U, 2U, 3U, 7U, 8U, 9U, 15U, 16U, 17U, 31U, 32U, 33U,
    63U, 64U, 65U, 127U, 128U, 129U, 255U, 256U,
};
static const unsigned packed_raster_contract_heights[] = {
    1U, 2U, 3U, 4U, 7U, 8U, 15U, 16U, 31U, 32U, 63U, 64U,
};
static const cups_cspace_t packed_raster_contract_cspaces[] = {
    CUPS_CSPACE_W, CUPS_CSPACE_RGB, CUPS_CSPACE_K,
    CUPS_CSPACE_CMY, CUPS_CSPACE_CMYK, CUPS_CSPACE_KCMY,
    CUPS_CSPACE_RGBA, CUPS_CSPACE_YMC, CUPS_CSPACE_YMCK,
    CUPS_CSPACE_KCMYcm, CUPS_CSPACE_GMCK, CUPS_CSPACE_GMCS,
    CUPS_CSPACE_WHITE, CUPS_CSPACE_GOLD, CUPS_CSPACE_SILVER,
    CUPS_CSPACE_CIEXYZ, CUPS_CSPACE_CIELab, CUPS_CSPACE_RGBW,
    CUPS_CSPACE_SW, CUPS_CSPACE_SRGB, CUPS_CSPACE_ADOBERGB,
    CUPS_CSPACE_ICC1, CUPS_CSPACE_ICC2, CUPS_CSPACE_ICC3,
    CUPS_CSPACE_ICC4, CUPS_CSPACE_ICC5, CUPS_CSPACE_ICC6,
    CUPS_CSPACE_ICC7, CUPS_CSPACE_ICC8, CUPS_CSPACE_ICC9,
    CUPS_CSPACE_ICCA, CUPS_CSPACE_ICCB, CUPS_CSPACE_ICCC,
    CUPS_CSPACE_ICCD, CUPS_CSPACE_ICCE, CUPS_CSPACE_ICCF,
    CUPS_CSPACE_DEVICE1, CUPS_CSPACE_DEVICE2, CUPS_CSPACE_DEVICE3,
    CUPS_CSPACE_DEVICE4, CUPS_CSPACE_DEVICE5, CUPS_CSPACE_DEVICE6,
    CUPS_CSPACE_DEVICE7, CUPS_CSPACE_DEVICE8, CUPS_CSPACE_DEVICE9,
    CUPS_CSPACE_DEVICEA, CUPS_CSPACE_DEVICEB, CUPS_CSPACE_DEVICEC,
    CUPS_CSPACE_DEVICED, CUPS_CSPACE_DEVICEE, CUPS_CSPACE_DEVICEF,
};
static const unsigned packed_raster_contract_bpc[] = {1U, 2U, 4U, 8U, 16U};
static const unsigned packed_raster_contract_compressions[] = {
    0U, 1U, 2U, 3U, 10U,
};
static const unsigned packed_raster_contract_lengths[] = {
    1U, 2U, 3U, 7U, 8U, 9U, 15U, 16U, 17U, 31U, 32U, 33U,
    63U, 64U, 65U, 127U, 128U, 129U, 255U, 256U, 257U,
    511U, 512U, 513U, 1023U, 1024U, 1025U, 2048U,
};
static const unsigned packed_raster_contract_resolutions[] = {
    0U, 1U, 72U, 150U, 300U, 600U, 1200U, 2400U,
    4800U, 9600U, 65535U, UINT32_MAX,
};
static const unsigned packed_raster_contract_weave[] = {
    0U, 1U, 2U, 3U, 4U, 7U, 8U, 15U, 16U,
    31U, 32U, 63U, 64U, 127U, 128U,
};
static const unsigned packed_raster_contract_ppd_bpp[] = {
    1U, 2U, 4U, 8U, 16U, 24U, 32U, 48U, 64U,
};
static const unsigned packed_raster_contract_page_sizes[] = {
    0U, 1U, 72U, 288U, 420U, 595U, 612U, 792U, 842U,
    65535U, UINT32_MAX,
};
static const unsigned packed_raster_contract_media_types[] = {
    0U, 1U, 2U, 3U, 255U, 65535U, UINT32_MAX,
};
static const char *const packed_raster_contract_media_names[] = {
    "", "PLAIN", "Plain", "Glossy", "Transparency", "Custom",
};
static const unsigned packed_raster_contract_copies[] = {
    0U, 1U, 2U, 3U, 255U, 65535U,
};

static const char *packed_raster_contract_model(cups_cspace_t color_space) {
  switch (color_space) {
    case CUPS_CSPACE_K:
      return "Black";
    case CUPS_CSPACE_W:
      return "Gray";
    case CUPS_CSPACE_RGB:
      return "RGB";
#ifdef CUPSFILTERS_PACKED_RASTER_PCLX
    case CUPS_CSPACE_CMY:
      return "CMY";
#endif
    case CUPS_CSPACE_CMYK:
      return "CMYK";
    default:
      return "RGB";
  }
}
#endif

#define PACKED_FORMAT(space, colors, bpc) {space, colors, bpc}
static const packed_raster_format_t packed_raster_formats[] = {
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
    PACKED_FORMAT(CUPS_CSPACE_K, 1, 8),
    PACKED_FORMAT(CUPS_CSPACE_W, 1, 8),
    PACKED_FORMAT(CUPS_CSPACE_RGB, 3, 8),
    PACKED_FORMAT(CUPS_CSPACE_CMYK, 4, 8),
#else
    PACKED_FORMAT(CUPS_CSPACE_K, 1, 1),
    PACKED_FORMAT(CUPS_CSPACE_K, 1, 2),
    PACKED_FORMAT(CUPS_CSPACE_K, 1, 4),
    PACKED_FORMAT(CUPS_CSPACE_K, 1, 8),
    PACKED_FORMAT(CUPS_CSPACE_K, 1, 16),
    PACKED_FORMAT(CUPS_CSPACE_W, 1, 1),
    PACKED_FORMAT(CUPS_CSPACE_W, 1, 2),
    PACKED_FORMAT(CUPS_CSPACE_W, 1, 4),
    PACKED_FORMAT(CUPS_CSPACE_W, 1, 8),
    PACKED_FORMAT(CUPS_CSPACE_W, 1, 16),
    PACKED_FORMAT(CUPS_CSPACE_RGB, 3, 1),
    PACKED_FORMAT(CUPS_CSPACE_RGB, 3, 2),
    PACKED_FORMAT(CUPS_CSPACE_RGB, 3, 4),
    PACKED_FORMAT(CUPS_CSPACE_RGB, 3, 8),
    PACKED_FORMAT(CUPS_CSPACE_RGB, 3, 16),
    PACKED_FORMAT(CUPS_CSPACE_CMYK, 4, 1),
    PACKED_FORMAT(CUPS_CSPACE_CMYK, 4, 2),
    PACKED_FORMAT(CUPS_CSPACE_CMYK, 4, 4),
    PACKED_FORMAT(CUPS_CSPACE_CMYK, 4, 8),
    PACKED_FORMAT(CUPS_CSPACE_CMYK, 4, 16),
#endif
};
#undef PACKED_FORMAT

#ifdef CUPSFILTERS_PACKED_RASTER_PCLX
#define PACKED_RASTER_FILTER_NAME "rastertopclx"
#define PACKED_RASTER_FILTER_MIME "application/vnd.cups-raster"
static const unsigned packed_raster_profile_channels[] = {1U, 3U, 4U, 3U};
static const char *const packed_raster_profile_models[] = {
    "Gray", "RGB", "CMYK", "RGB",
};
static const unsigned packed_raster_profile_cspaces[] = {
    CUPS_CSPACE_K, CUPS_CSPACE_RGB, CUPS_CSPACE_CMYK, CUPS_CSPACE_RGB,
};
static const unsigned packed_raster_profile_bpps[] = {8U, 24U, 32U, 24U};
#else
#define PACKED_RASTER_FILTER_NAME "rastertoescpx"
#define PACKED_RASTER_FILTER_MIME "application/vnd.cups-raster"
static const unsigned packed_raster_profile_channels[] = {1U, 3U, 4U, 6U};
static const char *const packed_raster_profile_models[] = {
    "Gray", "RGB", "CMYK", "CMYK",
};
static const unsigned packed_raster_profile_cspaces[] = {
    CUPS_CSPACE_K, CUPS_CSPACE_RGB, CUPS_CSPACE_CMYK, CUPS_CSPACE_CMYK,
};
static const unsigned packed_raster_profile_bpps[] = {8U, 24U, 32U, 32U};
#endif

static ppd_file_t *packed_raster_opened_ppd;

static ppd_file_t *packed_raster_ppd_open_file(const char *path) {
  ppd_file_t *ppd = ppdOpenFile(path);

  packed_raster_opened_ppd = ppd;
  return ppd;
}

#define ppdOpenFile packed_raster_ppd_open_file
#define main packed_raster_filter_main
#include CUPSFILTERS_PACKED_RASTER_FILTER_SOURCE
#undef main
#undef ppdOpenFile

static int packed_raster_capture_env(packed_saved_env_t *saved) {
  const char *value = getenv(saved->name);

  saved->value = value ? strdup(value) : NULL;
  return !value || saved->value != NULL;
}

static void packed_raster_restore_env(packed_saved_env_t *saved) {
  if (saved->value) {
    (void)setenv(saved->name, saved->value, 1);
  } else {
    (void)unsetenv(saved->name);
  }
  free(saved->value);
  saved->value = NULL;
}

#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
static size_t packed_raster_contract_adjust(size_t derived, unsigned mode,
                                            unsigned independent) {
  switch (mode % 5U) {
    case 0U:
      return derived;
    case 1U:
      return derived > 1U ? derived - 1U : 1U;
    case 2U:
      return derived + 1U;
    case 3U:
      return packed_raster_contract_lengths[
          independent % (sizeof(packed_raster_contract_lengths) /
                         sizeof(packed_raster_contract_lengths[0]))];
    default:
      return (derived + 7U) / 8U;
  }
}

static int packed_raster_decode_contract(
    const uint8_t selector[PACKED_RASTER_SELECTOR_BYTES],
    packed_raster_state_t *state) {
  size_t plane_bytes;
  size_t derived_bpp;
  size_t derived_bpl;
  size_t expected_rows;
  size_t physical_rows;

  memset(state, 0, sizeof(*state));
  state->width = packed_raster_contract_widths[
      selector[0] % (sizeof(packed_raster_contract_widths) /
                     sizeof(packed_raster_contract_widths[0]))];
  state->height = packed_raster_contract_heights[
      selector[1] % (sizeof(packed_raster_contract_heights) /
                     sizeof(packed_raster_contract_heights[0]))];
  state->color_space = packed_raster_contract_cspaces[
      selector[2] % (sizeof(packed_raster_contract_cspaces) /
                     sizeof(packed_raster_contract_cspaces[0]))];
  state->colors = 1U + selector[3] % PACKED_RASTER_MAX_COLORS;
  state->bits_per_color = packed_raster_contract_bpc[
      selector[4] % (sizeof(packed_raster_contract_bpc) /
                     sizeof(packed_raster_contract_bpc[0]))];
  state->order = (cups_order_t)(selector[5] % 3U);
  state->compression = packed_raster_contract_compressions[
      selector[6] % (sizeof(packed_raster_contract_compressions) /
                     sizeof(packed_raster_contract_compressions[0]))];

  derived_bpp = state->order == CUPS_ORDER_CHUNKED
                    ? (size_t)state->bits_per_color * state->colors
                    : state->bits_per_color;
  switch (selector[7] % 4U) {
    case 0U:
      state->bits_per_pixel = (unsigned)derived_bpp;
      break;
    case 1U:
      state->bits_per_pixel = (unsigned)(derived_bpp > 1U
                                             ? derived_bpp - 1U : 1U);
      break;
    case 2U:
      state->bits_per_pixel = (unsigned)(derived_bpp + 1U);
      break;
    default:
      state->bits_per_pixel = packed_raster_contract_ppd_bpp[
          selector[9] % (sizeof(packed_raster_contract_ppd_bpp) /
                         sizeof(packed_raster_contract_ppd_bpp[0]))];
      break;
  }

  plane_bytes = ((size_t)state->width * state->bits_per_color + 7U) / 8U;
  if (state->order == CUPS_ORDER_CHUNKED) {
    derived_bpl = ((size_t)state->width * state->bits_per_pixel + 7U) / 8U;
    expected_rows = state->height;
  } else if (state->order == CUPS_ORDER_BANDED) {
    derived_bpl = plane_bytes * state->colors;
    expected_rows = state->height;
  } else {
    derived_bpl = plane_bytes;
    expected_rows = (size_t)state->height * state->colors;
  }
  derived_bpl = packed_raster_contract_adjust(
      derived_bpl, selector[8], selector[9]);

  switch (selector[10] % 4U) {
    case 0U:
      physical_rows = expected_rows;
      break;
    case 1U:
      physical_rows = state->height;
      break;
    case 2U:
      physical_rows = expected_rows > 1U ? expected_rows - 1U : 1U;
      break;
    default:
      physical_rows = expected_rows + 1U;
      break;
  }

  state->bytes_per_line = (unsigned)derived_bpl;
  state->physical_rows = (unsigned)physical_rows;
  state->profile = 0U;
  state->pattern = selector[22] & 0x07U;
  state->material_phase = selector[23];
  state->ppd_color_space = packed_raster_contract_cspaces[
      selector[11] % (sizeof(packed_raster_contract_cspaces) /
                      sizeof(packed_raster_contract_cspaces[0]))];
  state->ppd_channels = 1U + selector[12] % PACKED_RASTER_MAX_COLORS;
  state->ppd_bits_per_pixel = packed_raster_contract_ppd_bpp[
      selector[13] % (sizeof(packed_raster_contract_ppd_bpp) /
                      sizeof(packed_raster_contract_ppd_bpp[0]))];
  state->model_number_mode = selector[14] % 4U;
  state->resolution_x = packed_raster_contract_resolutions[
      selector[15] % (sizeof(packed_raster_contract_resolutions) /
                      sizeof(packed_raster_contract_resolutions[0]))];
  state->resolution_y = packed_raster_contract_resolutions[
      selector[16] % (sizeof(packed_raster_contract_resolutions) /
                      sizeof(packed_raster_contract_resolutions[0]))];
  state->row_count = packed_raster_contract_weave[
      selector[17] % (sizeof(packed_raster_contract_weave) /
                      sizeof(packed_raster_contract_weave[0]))];
  state->row_feed = packed_raster_contract_weave[
      selector[18] % (sizeof(packed_raster_contract_weave) /
                      sizeof(packed_raster_contract_weave[0]))];
  state->row_step = packed_raster_contract_weave[
      selector[19] % (sizeof(packed_raster_contract_weave) /
                      sizeof(packed_raster_contract_weave[0]))];
  state->column_step = packed_raster_contract_weave[
      selector[20] % (sizeof(packed_raster_contract_weave) /
                      sizeof(packed_raster_contract_weave[0]))];
  state->page_size_count = 1U + selector[21] % 2U;
  state->page_count = 1U + selector[24] % 4U;
  state->page_width = packed_raster_contract_page_sizes[
      selector[25] % (sizeof(packed_raster_contract_page_sizes) /
                      sizeof(packed_raster_contract_page_sizes[0]))];
  state->page_height = packed_raster_contract_page_sizes[
      selector[26] % (sizeof(packed_raster_contract_page_sizes) /
                      sizeof(packed_raster_contract_page_sizes[0]))];
  state->cups_media_type = packed_raster_contract_media_types[
      selector[27] % (sizeof(packed_raster_contract_media_types) /
                      sizeof(packed_raster_contract_media_types[0]))];
  state->media_name_index =
      selector[28] % (sizeof(packed_raster_contract_media_names) /
                      sizeof(packed_raster_contract_media_names[0]));
  state->num_copies = packed_raster_contract_copies[
      selector[29] % (sizeof(packed_raster_contract_copies) /
                      sizeof(packed_raster_contract_copies[0]))];
  state->duplex = selector[30] & 1U;
  state->tumble = (selector[30] >> 1U) & 1U;
  state->page_pattern_stride = selector[31] & 0x07U;

  if (!state->bytes_per_line ||
      state->bytes_per_line > PACKED_RASTER_MAX_BPL ||
      !state->physical_rows ||
      state->physical_rows > PACKED_RASTER_MAX_PHYSICAL_ROWS ||
      state->bytes_per_line >
          PACKED_RASTER_MAX_PAYLOAD / state->physical_rows) {
    return 0;
  }
  return 1;
}
#endif

#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
static cf_v2_relation_stats_t packed_raster_job_stats;

static int packed_raster_decode_job(const uint8_t *data, size_t size,
                                    packed_raster_state_t *state) {
  cf_v2_raster_job_relation_t relation;
  size_t bytes_per_line;
  size_t physical_rows;

  if (!cf_v2_raster_job_parse(data, size, &relation)) {
    return 0;
  }
  memset(state, 0, sizeof(*state));
  bytes_per_line = cf_v2_length_relation_value(&relation.bytes_per_line);
  physical_rows = cf_v2_raster_job_physical_rows(&relation);
  if (!bytes_per_line || bytes_per_line > PACKED_RASTER_MAX_BPL ||
      physical_rows > PACKED_RASTER_MAX_PHYSICAL_ROWS ||
      (physical_rows &&
       bytes_per_line > PACKED_RASTER_MAX_PAYLOAD / physical_rows)) {
    return 0;
  }

  state->width = relation.width;
  state->height = relation.height;
  state->color_space = relation.color_space;
  state->colors = (unsigned)cf_v2_scalar_relation_value(&relation.colors);
  state->bits_per_color = relation.bits_per_color;
  state->bits_per_pixel =
      (unsigned)cf_v2_scalar_relation_value(&relation.bits_per_pixel);
  state->bytes_per_line = (unsigned)bytes_per_line;
  state->order = relation.color_order;
  state->compression = relation.compression;
  state->physical_rows = (unsigned)physical_rows;
  state->profile = 0U;
  state->pattern = relation.pattern;
  state->resolution_x =
      (unsigned)cf_v2_scalar_relation_value(&relation.resolution_x);
  state->resolution_y =
      (unsigned)cf_v2_scalar_relation_value(&relation.resolution_y);
  state->ppd_color_space =
      (cups_cspace_t)cf_v2_scalar_relation_value(&relation.ppd_color_space);
  state->ppd_channels =
      (unsigned)cf_v2_scalar_relation_value(&relation.ppd_channels);
  state->ppd_bits_per_pixel =
      (unsigned)cf_v2_scalar_relation_value(&relation.ppd_bits_per_pixel);
  state->row_count =
      (unsigned)cf_v2_scalar_relation_value(&relation.row_count);
  state->row_feed =
      (unsigned)cf_v2_scalar_relation_value(&relation.row_feed);
  state->row_step =
      (unsigned)cf_v2_scalar_relation_value(&relation.row_step);
  state->column_step =
      (unsigned)cf_v2_scalar_relation_value(&relation.column_step);
  state->page_size_count =
      (unsigned)cf_v2_cardinality_value(&relation.page_size_count);
  state->page_count =
      (unsigned)cf_v2_cardinality_value(&relation.page_count);
  state->page_width =
      (unsigned)cf_v2_scalar_relation_value(&relation.page_width);
  state->page_height =
      (unsigned)cf_v2_scalar_relation_value(&relation.page_height);
  state->cups_media_type = 0U;
  state->media_name_index = 2U;
  state->num_copies =
      (unsigned)cf_v2_cardinality_value(&relation.copies);
  state->duplex = relation.duplex;
  state->tumble = relation.tumble;
  state->model_number_mode = relation.model_mode;
  state->material_phase = relation.material_phase;
  state->page_pattern_stride = 1U;
  state->opaque_command = relation.opaque.data;
  state->opaque_command_size =
      cf_v2_length_relation_value(&relation.opaque_length);
  if (state->opaque_command_size > relation.opaque.size) {
    state->opaque_command_size = relation.opaque.size;
  }
  state->opaque_command_mode = relation.opaque_mode;
  state->relation = relation;
  return 1;
}

#if defined(CF_V2_RASTER_JOB_DEEP) || \
    defined(CF_V2_RASTER_JOB_LAYOUT_BOUNDARY) || \
    defined(CF_V2_RASTER_JOB_FORMAT_STORAGE) || \
    defined(CF_V2_RASTER_JOB_PROFILE_CARDINALITY) || \
    defined(CF_V2_RASTER_JOB_STORAGE_CHANNELS)
static unsigned packed_raster_job_consumer_channels(cups_cspace_t color_space) {
  switch (color_space) {
    case CUPS_CSPACE_W:
    case CUPS_CSPACE_K:
      return 1U;
    case CUPS_CSPACE_CMYK:
      return 4U;
    default:
      return 3U;
  }
}
#endif

#ifdef CF_V2_RASTER_JOB_CODEC_ROW
static int packed_raster_job_codec_row_reject(
    const packed_raster_state_t *state) {
  uint64_t tuple_bytes = (uint64_t)state->width * 3U;

  /* Compression 3 has an independent first-crash root in this source branch. */
  return state->compression == 3U ||
         state->color_space != CUPS_CSPACE_RGB ||
         state->bits_per_color != 8U ||
         state->order != CUPS_ORDER_CHUNKED ||
         state->colors != 3U || state->bits_per_pixel != 24U ||
         state->relation.colors.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bytes_per_line.base != tuple_bytes ||
         state->height < 2U || state->physical_rows != state->height ||
         state->relation.physical_rows_mode != CF_V2_RELATION_DERIVED ||
         state->ppd_color_space != CUPS_CSPACE_RGB ||
         state->relation.ppd_color_space.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_channels != 3U ||
         state->relation.ppd_channels.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_bits_per_pixel != 24U ||
         state->relation.ppd_bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->resolution_x != 300U || state->resolution_y != 300U ||
         state->relation.resolution_x.mode != CF_V2_RELATION_DERIVED ||
         state->relation.resolution_y.mode != CF_V2_RELATION_DERIVED ||
         state->row_count != 1U || state->row_feed != 1U ||
         state->row_step != 1U || state->column_step != 1U ||
         state->relation.row_count.mode != CF_V2_RELATION_DERIVED ||
         state->relation.row_feed.mode != CF_V2_RELATION_DERIVED ||
         state->relation.row_step.mode != CF_V2_RELATION_DERIVED ||
         state->relation.column_step.mode != CF_V2_RELATION_DERIVED ||
         state->page_size_count != 2U || state->page_count != 1U ||
         state->page_width != 612U || state->page_height != 792U ||
         state->relation.page_width.mode != CF_V2_RELATION_DERIVED ||
         state->relation.page_height.mode != CF_V2_RELATION_DERIVED ||
         state->num_copies != 1U || state->duplex || state->tumble ||
         state->model_number_mode != 2U ||
         state->opaque_command_mode != CF_V2_RELATION_DERIVED;
}
#endif

#ifdef CF_V2_RASTER_JOB_PCLX_ENDJOB_OPAQUE
static int packed_raster_job_pclx_endjob_opaque_reject(
    const packed_raster_state_t *state) {
  return state->color_space != CUPS_CSPACE_K ||
         state->bits_per_color != 8U ||
         state->order != CUPS_ORDER_CHUNKED ||
         state->colors != 1U || state->bits_per_pixel != 8U ||
         state->bytes_per_line != state->width ||
         state->relation.colors.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bytes_per_line.mode != CF_V2_RELATION_DERIVED ||
         state->physical_rows != state->height ||
         state->relation.physical_rows_mode != CF_V2_RELATION_DERIVED ||
         state->ppd_color_space != CUPS_CSPACE_K ||
         state->relation.ppd_color_space.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_channels != 1U ||
         state->relation.ppd_channels.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_bits_per_pixel != 8U ||
         state->relation.ppd_bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->compression != 0U ||
         state->resolution_x != 300U || state->resolution_y != 300U ||
         state->relation.resolution_x.mode != CF_V2_RELATION_DERIVED ||
         state->relation.resolution_y.mode != CF_V2_RELATION_DERIVED ||
         state->row_count != 1U || state->row_feed != 1U ||
         state->row_step != 1U || state->column_step != 1U ||
         state->relation.row_count.mode != CF_V2_RELATION_DERIVED ||
         state->relation.row_feed.mode != CF_V2_RELATION_DERIVED ||
         state->relation.row_step.mode != CF_V2_RELATION_DERIVED ||
         state->relation.column_step.mode != CF_V2_RELATION_DERIVED ||
         state->page_size_count != 2U || state->page_count != 1U ||
         state->page_width != 612U || state->page_height != 792U ||
         state->relation.page_width.mode != CF_V2_RELATION_DERIVED ||
         state->relation.page_height.mode != CF_V2_RELATION_DERIVED ||
         state->num_copies != 1U || state->duplex || state->tumble ||
         state->model_number_mode != 0U ||
         state->opaque_command_mode != CF_V2_RELATION_EXPLICIT ||
         !state->opaque_command_size || state->opaque_command_size > 64U;
}
#endif

#if defined(CF_V2_RASTER_JOB_ESCPX_PAGE_SETUP) || \
    defined(CF_V2_RASTER_JOB_ESCPX_SOFTWEAVE_LAYOUT)
static int packed_raster_job_escpx_common_reject(
    const packed_raster_state_t *state) {
  return state->color_space != CUPS_CSPACE_K ||
         state->bits_per_color != 8U ||
         state->order != CUPS_ORDER_CHUNKED ||
         state->colors != 1U || state->bits_per_pixel != 8U ||
         state->bytes_per_line != state->width ||
         state->relation.colors.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bytes_per_line.mode != CF_V2_RELATION_DERIVED ||
         state->physical_rows != state->height ||
         state->relation.physical_rows_mode != CF_V2_RELATION_DERIVED ||
         state->ppd_color_space != CUPS_CSPACE_K ||
         state->relation.ppd_color_space.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_channels != 1U ||
         state->relation.ppd_channels.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_bits_per_pixel != 8U ||
         state->relation.ppd_bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->compression != 0U ||
         state->page_count != 1U ||
         state->page_width != 612U || state->page_height != 792U ||
         state->relation.page_width.mode != CF_V2_RELATION_DERIVED ||
         state->relation.page_height.mode != CF_V2_RELATION_DERIVED ||
         state->num_copies != 1U || state->duplex || state->tumble ||
         state->model_number_mode != 0U ||
         state->opaque_command_mode != CF_V2_RELATION_DERIVED;
}
#endif

#ifdef CF_V2_RASTER_JOB_ESCPX_PAGE_SETUP
static int packed_raster_job_escpx_page_setup_reject(
    const packed_raster_state_t *state) {
  return packed_raster_job_escpx_common_reject(state) ||
         state->row_count != 1U || state->row_feed != 1U ||
         state->row_step != 1U || state->column_step != 1U ||
         state->relation.row_count.mode != CF_V2_RELATION_DERIVED ||
         state->relation.row_feed.mode != CF_V2_RELATION_DERIVED ||
         state->relation.row_step.mode != CF_V2_RELATION_DERIVED ||
         state->relation.column_step.mode != CF_V2_RELATION_DERIVED;
}
#endif

#ifdef CF_V2_RASTER_JOB_ESCPX_SOFTWEAVE_LAYOUT
static int packed_raster_job_escpx_softweave_layout_reject(
    const packed_raster_state_t *state) {
  uint64_t weave_product =
      (uint64_t)state->row_step * state->column_step;

  return packed_raster_job_escpx_common_reject(state) ||
         state->resolution_x != 300U || state->resolution_y != 300U ||
         state->relation.resolution_x.mode != CF_V2_RELATION_DERIVED ||
         state->relation.resolution_y.mode != CF_V2_RELATION_DERIVED ||
         state->page_size_count != 2U ||
         state->row_count <= 1U || state->row_count > 32U ||
         state->row_feed == 0U || state->row_feed > 128U ||
         state->row_step == 0U || state->row_step >= 100U ||
         state->column_step == 0U || state->column_step > 128U ||
         state->column_step > state->width || weave_product > 256U;
}
#endif

#ifdef CF_V2_RASTER_JOB_ESCPX_HORIZONTAL_RESOLUTION
static int packed_raster_job_escpx_horizontal_resolution_reject(
    const packed_raster_state_t *state) {
  return state->resolution_x == 0U || state->resolution_y == 0U ||
         state->page_size_count != 2U;
}
#endif

#ifdef CF_V2_RASTER_JOB_ESCPX_VERTICAL_RESOLUTION
static int packed_raster_job_escpx_vertical_resolution_reject(
    const packed_raster_state_t *state) {
  return state->resolution_x != 300U ||
         state->relation.resolution_x.mode != CF_V2_RELATION_DERIVED ||
         state->page_size_count != 2U;
}
#endif

#ifdef CF_V2_RASTER_JOB_ESCPX_PAGE_CARDINALITY
static int packed_raster_job_escpx_page_cardinality_reject(
    const packed_raster_state_t *state) {
  return state->resolution_x != 300U || state->resolution_y != 300U ||
         state->relation.resolution_x.mode != CF_V2_RELATION_DERIVED ||
         state->relation.resolution_y.mode != CF_V2_RELATION_DERIVED;
}
#endif

#if defined(CF_V2_RASTER_JOB_FORMAT_STORAGE) || \
    defined(CF_V2_RASTER_JOB_PROFILE_CARDINALITY) || \
    defined(CF_V2_RASTER_JOB_STORAGE_CHANNELS)
static int packed_raster_job_control_reject(
    const packed_raster_state_t *state) {
  return !state->physical_rows || state->order != CUPS_ORDER_CHUNKED ||
         state->physical_rows != state->height ||
         state->relation.physical_rows_mode != CF_V2_RELATION_DERIVED ||
         state->compression != 0U ||
         state->resolution_x != 300U || state->resolution_y != 300U ||
         state->row_count != 1U || state->row_feed != 1U ||
         state->row_step != 1U || state->column_step != 1U ||
         state->page_size_count != 2U || state->page_count != 1U ||
         state->page_width != 612U || state->page_height != 792U ||
         state->num_copies != 1U || state->model_number_mode != 0U ||
         state->opaque_command_mode != CF_V2_RELATION_DERIVED;
}
#endif

#ifdef CF_V2_RASTER_JOB_STORAGE_CHANNELS
static int packed_raster_job_storage_channels_reject(
    const packed_raster_state_t *state) {
  unsigned format_colors = cf_v2_raster_job_channels(state->color_space);
  unsigned consumer_colors =
      packed_raster_job_consumer_channels(state->color_space);
  uint64_t expected_line_bytes =
      (uint64_t)state->width * state->colors;

  return packed_raster_job_control_reject(state) ||
         consumer_colors != format_colors ||
         state->bits_per_color != 8U ||
         state->bits_per_pixel != state->colors * 8U ||
         state->bytes_per_line != expected_line_bytes ||
         state->relation.bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bytes_per_line.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_color_space != state->color_space ||
         state->relation.ppd_color_space.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_channels != state->colors ||
         state->ppd_channels > 6U ||
         state->relation.ppd_channels.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_bits_per_pixel != state->bits_per_pixel ||
         state->relation.ppd_bits_per_pixel.mode != CF_V2_RELATION_DERIVED;
}
#endif

#ifdef CF_V2_RASTER_JOB_FORMAT_STORAGE
static int packed_raster_job_format_storage_reject(
    const packed_raster_state_t *state) {
  return packed_raster_job_control_reject(state) ||
         state->ppd_channels > 6U;
}
#endif

#ifdef CF_V2_RASTER_JOB_PROFILE_CARDINALITY
static int packed_raster_job_profile_cardinality_reject(
    const packed_raster_state_t *state) {
  unsigned format_colors = cf_v2_raster_job_channels(state->color_space);
  unsigned consumer_colors =
      packed_raster_job_consumer_channels(state->color_space);
  uint64_t expected_line_bytes =
      (uint64_t)state->width * format_colors;

  return packed_raster_job_control_reject(state) ||
         consumer_colors != format_colors ||
         state->bits_per_color != 8U ||
         state->colors != format_colors ||
         state->bits_per_pixel != format_colors * 8U ||
         state->bytes_per_line != expected_line_bytes ||
         state->relation.colors.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bytes_per_line.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_color_space != state->color_space ||
         state->relation.ppd_color_space.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_bits_per_pixel != state->bits_per_pixel ||
         state->relation.ppd_bits_per_pixel.mode != CF_V2_RELATION_DERIVED;
}
#endif

#ifdef CF_V2_RASTER_JOB_DEEP
static int packed_raster_job_deep_reject(
    const packed_raster_state_t *state) {
  unsigned format_colors = cf_v2_raster_job_channels(state->color_space);
  unsigned consumer_colors =
      packed_raster_job_consumer_channels(state->color_space);
  uint64_t format_line_bytes = (uint64_t)state->width * format_colors;
  uint64_t consumer_line_bytes = (uint64_t)state->width * consumer_colors;
  uint64_t weave_product = (uint64_t)state->row_step * state->column_step;

  return !state->physical_rows || !state->page_count ||
         state->resolution_x == 0U || state->resolution_y == 0U ||
         state->resolution_x > 9600U || state->resolution_y > 9600U ||
         state->bits_per_color != 8U ||
         state->order != CUPS_ORDER_CHUNKED ||
         state->colors != format_colors ||
         state->bits_per_pixel != format_colors * 8U ||
         state->bytes_per_line != format_line_bytes ||
         state->bytes_per_line < consumer_line_bytes ||
         state->physical_rows != state->height ||
         state->ppd_channels > 6U || state->page_size_count < 2U ||
         weave_product > 128U ||
         state->opaque_command_mode == CF_V2_RELATION_EXPLICIT
#ifdef CUPSFILTERS_PACKED_RASTER_PCLX
         || state->compression != 0U || state->page_count != 1U
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX
         || state->row_step == 0U || state->column_step == 0U
#endif
         ;
}
#endif

#ifdef CF_V2_RASTER_JOB_LAYOUT_BOUNDARY
static int packed_raster_job_layout_reject(
    const packed_raster_state_t *state) {
  unsigned format_colors = cf_v2_raster_job_channels(state->color_space);
  unsigned consumer_colors =
      packed_raster_job_consumer_channels(state->color_space);
  uint64_t expected_bpp =
      state->order == CUPS_ORDER_CHUNKED ? format_colors * 8U : 8U;
  uint64_t expected_bpl =
      state->order == CUPS_ORDER_CHUNKED ?
          (uint64_t)state->width * format_colors :
          (state->order == CUPS_ORDER_BANDED ?
               (uint64_t)state->width * format_colors : state->width);
  uint64_t expected_rows =
      state->order == CUPS_ORDER_PLANAR ?
          (uint64_t)state->height * format_colors : state->height;

  return (state->color_space != CUPS_CSPACE_W &&
          state->color_space != CUPS_CSPACE_K &&
          state->color_space != CUPS_CSPACE_RGB &&
          state->color_space != CUPS_CSPACE_CMYK) ||
         state->colors != format_colors ||
         consumer_colors != format_colors ||
         state->bits_per_color != 8U ||
         state->bits_per_pixel != expected_bpp ||
         state->bytes_per_line != expected_bpl ||
         state->physical_rows != expected_rows ||
         state->relation.colors.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->relation.bytes_per_line.mode != CF_V2_RELATION_DERIVED ||
         state->relation.physical_rows_mode != CF_V2_RELATION_DERIVED ||
         state->relation.ppd_color_space.mode != CF_V2_RELATION_DERIVED ||
         state->relation.ppd_channels.mode != CF_V2_RELATION_DERIVED ||
         state->relation.ppd_bits_per_pixel.mode != CF_V2_RELATION_DERIVED ||
         state->ppd_color_space != state->color_space ||
         state->ppd_channels != format_colors ||
         state->ppd_bits_per_pixel != expected_bpp ||
         state->compression != 0U ||
         state->resolution_x != 300U || state->resolution_y != 300U ||
         state->row_count != 1U || state->row_feed != 1U ||
         state->row_step != 1U || state->column_step != 1U ||
         state->page_size_count != 2U || state->page_count != 1U ||
         state->page_width != 612U || state->page_height != 792U ||
         state->num_copies != 1U ||
         state->opaque_command_mode != CF_V2_RELATION_DERIVED;
}
#endif
#endif

static int packed_raster_decode(const uint8_t *selector,
                                packed_raster_state_t *state) {
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
  return packed_raster_decode_contract(selector, state);
#else
  const packed_raster_format_t *format;
  size_t plane_bytes;
  size_t bytes_per_line;

  format = &packed_raster_formats[
      selector[1] %
      (sizeof(packed_raster_formats) / sizeof(packed_raster_formats[0]))];
  state->width =
      packed_raster_widths[
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
          selector[0] %
#else
          (selector[0] & 0x0fU) %
#endif
          (sizeof(packed_raster_widths) / sizeof(packed_raster_widths[0]))];
  state->height =
      packed_raster_heights[
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
          selector[7] %
#else
          (selector[0] >> 4U) %
#endif
          (sizeof(packed_raster_heights) / sizeof(packed_raster_heights[0]))];
  state->color_space = format->color_space;
  state->colors = format->colors;
  state->bits_per_color = format->bits_per_color;
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
  state->order = CUPS_ORDER_CHUNKED;
#else
  state->order = (cups_order_t)((selector[2] & 0x03U) % 3U);
#endif
  state->compression =
      packed_raster_compressions[
          ((selector[2] >> 2U) & 0x07U) %
          (sizeof(packed_raster_compressions) /
           sizeof(packed_raster_compressions[0]))];
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
  switch (state->color_space) {
    case CUPS_CSPACE_RGB:
      state->profile = 1U;
      break;
    case CUPS_CSPACE_CMYK:
      state->profile = (selector[2] & 0x80U) ? 3U : 2U;
      break;
    default:
      state->profile = 0U;
      break;
  }
  state->row_count = packed_raster_row_counts[selector[4] %
      (sizeof(packed_raster_row_counts) /
       sizeof(packed_raster_row_counts[0]))];
  state->row_feed = packed_raster_row_feeds[selector[5] %
      (sizeof(packed_raster_row_feeds) /
       sizeof(packed_raster_row_feeds[0]))];
  state->row_step = packed_raster_weave_steps[(selector[6] & 0x0fU) %
      (sizeof(packed_raster_weave_steps) /
       sizeof(packed_raster_weave_steps[0]))];
  state->column_step = packed_raster_weave_steps[(selector[6] >> 4U) %
      (sizeof(packed_raster_weave_steps) /
       sizeof(packed_raster_weave_steps[0]))];
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  state->page_count = 1U + selector[8] % 4U;
  state->page_height_seed = selector[7];
  state->page_height_stride = 1U + selector[9] % 5U;
  state->page_state_stride = 1U + selector[10] % 7U;
  state->page_pattern_stride = 1U + selector[11] % 7U;
#endif
#else
  state->profile =
      (selector[2] >> 5U) %
      (sizeof(packed_raster_profile_channels) /
       sizeof(packed_raster_profile_channels[0]));
#endif
  state->pattern = selector[3] & 0x07U;

#ifdef CUPSFILTERS_PACKED_RASTER_PCLX_RELATION_PROGRAM
  state->relation_boundary = selector[4] % 3U;
  if (state->relation_boundary == 2U) {
#if CF_V2_PCLX_RELATION_LANE == 1 || CF_V2_PCLX_RELATION_LANE == 2
    state->width = 129U;
    state->height = 2U;
    state->color_space = CUPS_CSPACE_RGB;
    state->colors = 1U;
    state->bits_per_color = 4U;
    state->order = CUPS_ORDER_CHUNKED;
    state->compression = CF_V2_PCLX_RELATION_LANE == 2 ? 10U : 0U;
    state->profile = CF_V2_PCLX_RELATION_LANE == 2 ? 3U : 1U;
#elif CF_V2_PCLX_RELATION_LANE == 3 || CF_V2_PCLX_RELATION_LANE == 4
    state->width = 24U;
    state->height = 1U;
    state->color_space = CUPS_CSPACE_K;
    state->colors = 1U;
    state->bits_per_color = 8U;
    state->order = CUPS_ORDER_CHUNKED;
    state->compression = 0U;
    state->profile = 0U;
#else
#error "unsupported CF_V2_PCLX_RELATION_LANE"
#endif

  } else if (state->relation_boundary == 1U) {
    state->width = 24U;
    state->height = 2U;
    state->color_space = CUPS_CSPACE_RGB;
    state->colors = 3U;
    state->bits_per_color = 8U;
    state->order = CUPS_ORDER_CHUNKED;
    state->compression = 0U;
    state->profile = 1U;
  } else {
    state->width = 24U;
    state->height = 2U;
    state->color_space = CUPS_CSPACE_K;
    state->colors = 1U;
    state->bits_per_color = 8U;
    state->order = CUPS_ORDER_CHUNKED;
    state->compression = 0U;
    state->profile = 0U;
  }
#endif

#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM
  state->relation_boundary = selector[4] % 3U;
  state->width = 24U;
  state->height = 2U;
  state->color_space = CUPS_CSPACE_K;
  state->colors = 1U;
  state->bits_per_color = 8U;
  state->order = CUPS_ORDER_CHUNKED;
  state->compression = 0U;
  state->profile = 0U;
  state->row_count = 1U;
  state->row_feed = 1U;
  state->row_step = 1U;
  state->column_step = 1U;
  state->resolution_x = 300U;
  state->resolution_y = 300U;
  if (state->relation_boundary == 2U) {
#if CF_V2_ESCPX_RELATION_LANE == 1
    state->resolution_x = UINT32_MAX;
#elif CF_V2_ESCPX_RELATION_LANE == 2
    state->resolution_y = 0U;
#elif CF_V2_ESCPX_RELATION_LANE == 3
    state->height = 1U;
    state->row_count = 2U;
    state->row_feed = 1U;
    state->row_step = 43U;
    state->column_step = 3U;
#elif CF_V2_ESCPX_RELATION_LANE != 4
#error "unsupported CF_V2_ESCPX_RELATION_LANE"
#endif
  }
#endif

  plane_bytes =
      ((size_t)state->width * state->bits_per_color + 7U) / 8U;
  if (state->order == CUPS_ORDER_CHUNKED) {
    state->bits_per_pixel = state->bits_per_color * state->colors;
    bytes_per_line =
        ((size_t)state->width * state->bits_per_pixel + 7U) / 8U;
    state->physical_rows = state->height;
  } else if (state->order == CUPS_ORDER_BANDED) {
    state->bits_per_pixel = state->bits_per_color;
    bytes_per_line = plane_bytes * state->colors;
    state->physical_rows = state->height;
  } else {
    state->bits_per_pixel = state->bits_per_color;
    bytes_per_line = plane_bytes;
    state->physical_rows = state->height * state->colors;
  }

  if (!state->width || state->width > PACKED_RASTER_MAX_WIDTH ||
      !state->height || state->height > PACKED_RASTER_MAX_HEIGHT ||
      !state->colors || state->colors > PACKED_RASTER_MAX_COLORS ||
      !state->bits_per_color ||
      state->bits_per_color > PACKED_RASTER_MAX_BPC ||
      !bytes_per_line || bytes_per_line > PACKED_RASTER_MAX_BPL ||
      !state->physical_rows ||
      state->physical_rows > PACKED_RASTER_MAX_PHYSICAL_ROWS ||
      bytes_per_line > PACKED_RASTER_MAX_PAYLOAD / state->physical_rows) {
    return 0;
  }
  state->bytes_per_line = (unsigned)bytes_per_line;
  return 1;
#endif
}

#ifdef CUPSFILTERS_PACKED_RASTER_CONTINUATION
static int packed_raster_has_unsafe_byte_converter_layout(
    const packed_raster_state_t *state) {
  size_t byte_converter_demand =
      (size_t)state->width * state->colors;

  /*
   * Both legacy filters pass the scanline to byte-per-sample CMYK helpers.
   * Keep finding mode unfiltered, but let the persistent continuation enter
   * only layouts whose physical row can satisfy that read contract.
   */
  return state->bytes_per_line < byte_converter_demand;
}
#endif

static uint8_t packed_raster_material(const uint8_t *material,
                                      size_t material_size, unsigned pattern,
                                      unsigned physical_row, size_t offset) {
  uint8_t value;

  if (material_size) {
    value = material[((size_t)physical_row * 257U + offset) % material_size];
  } else {
    value =
        (uint8_t)(1U + ((physical_row * 67U + offset * 131U + pattern * 29U) %
                        254U));
  }

  switch (pattern) {
    case 0:
      return value;
    case 1:
      return 0x00U;
    case 2:
      return 0xffU;
    case 3:
      return (offset + physical_row) & 1U ? 0xaaU : 0x55U;
    case 4:
      return ((offset / 127U) + physical_row) & 1U ? value : 0x33U;
    case 5:
      return (uint8_t)(value ^ (uint8_t)(physical_row * 0x31U));
    case 6:
      return (uint8_t)((offset + physical_row * 17U) & 0xffU);
    default:
      return (uint8_t)(value | 1U);
  }
}

static int packed_raster_write_document(const char *path,
                                        const packed_raster_state_t *state,
                                        const uint8_t *material,
                                        size_t material_size) {
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  uint8_t *row = NULL;
  int fd = -1;
  int ok = 0;
  unsigned page;
  unsigned page_count = 1U;

  fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (fd < 0) {
    return 0;
  }
  raster = cupsRasterOpen(fd, CUPS_RASTER_WRITE);
  if (!raster) {
    close(fd);
    return 0;
  }
  row = (uint8_t *)malloc(state->bytes_per_line);
  if (!row) {
    goto done;
  }

#if defined(CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE) || \
    defined(CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT)
  page_count = state->page_count;
#endif
  for (page = 0U; page < page_count; page++) {
    packed_raster_state_t page_state = *state;
    unsigned physical_row;

#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
    page_state.height = packed_raster_heights[
        (state->page_height_seed + page * state->page_height_stride) %
        (sizeof(packed_raster_heights) / sizeof(packed_raster_heights[0]))];
    page_state.physical_rows = page_state.height;
    page_state.row_count = packed_raster_row_counts[
        (state->row_count + page * state->page_state_stride) %
        (sizeof(packed_raster_row_counts) /
         sizeof(packed_raster_row_counts[0]))];
    page_state.row_feed = packed_raster_row_feeds[
        (state->row_feed + page * state->page_state_stride) %
        (sizeof(packed_raster_row_feeds) /
         sizeof(packed_raster_row_feeds[0]))];
    page_state.row_step = packed_raster_weave_steps[
        (state->row_step + page * state->page_state_stride) %
        (sizeof(packed_raster_weave_steps) /
         sizeof(packed_raster_weave_steps[0]))];
    page_state.column_step = packed_raster_weave_steps[
        (state->column_step + page * (state->page_state_stride + 1U)) %
        (sizeof(packed_raster_weave_steps) /
         sizeof(packed_raster_weave_steps[0]))];
    page_state.pattern =
        (state->pattern + page * state->page_pattern_stride) & 0x07U;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
    page_state.pattern =
        (state->pattern + page * state->page_pattern_stride) & 0x07U;
#endif

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
    snprintf(header.MediaType, sizeof(header.MediaType), "%s",
             packed_raster_contract_media_names[page_state.media_name_index]);
    if (page_state.page_width == 595U && page_state.page_height == 842U) {
      memcpy(header.cupsPageSizeName, "A4", sizeof("A4"));
    } else if (page_state.page_width == 612U &&
               page_state.page_height == 792U) {
      memcpy(header.cupsPageSizeName, "Letter", sizeof("Letter"));
    } else {
      memcpy(header.cupsPageSizeName, "Custom", sizeof("Custom"));
    }
#else
    memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
    memcpy(header.cupsPageSizeName, "Letter", sizeof("Letter"));
#endif
#if defined(CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM) || \
    defined(CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT)
    header.HWResolution[0] = page_state.resolution_x;
    header.HWResolution[1] = page_state.resolution_y;
#else
    header.HWResolution[0] = 300U;
    header.HWResolution[1] = 300U;
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
    header.PageSize[0] = page_state.page_width;
    header.PageSize[1] = page_state.page_height;
    header.cupsPageSize[0] = (float)page_state.page_width;
    header.cupsPageSize[1] = (float)page_state.page_height;
    header.ImagingBoundingBox[2] = page_state.page_width;
    header.ImagingBoundingBox[3] = page_state.page_height;
    header.cupsImagingBBox[2] = (float)page_state.page_width;
    header.cupsImagingBBox[3] = (float)page_state.page_height;
    header.cupsMediaType = page_state.cups_media_type;
    header.Duplex = page_state.duplex;
    header.Tumble = page_state.tumble;
    header.NumCopies = page_state.num_copies;
#else
    header.PageSize[0] = 612U;
    header.PageSize[1] = 792U;
    header.cupsPageSize[0] = 612.0f;
    header.cupsPageSize[1] = 792.0f;
    header.ImagingBoundingBox[2] = 612U;
    header.ImagingBoundingBox[3] = 792U;
    header.cupsImagingBBox[2] = 612.0f;
    header.cupsImagingBBox[3] = 792.0f;
#endif
    header.cupsWidth = page_state.width;
    header.cupsHeight = page_state.height;
    header.cupsBitsPerColor = page_state.bits_per_color;
    header.cupsBitsPerPixel = page_state.bits_per_pixel;
    header.cupsBytesPerLine = page_state.bytes_per_line;
    header.cupsColorOrder = page_state.order;
    header.cupsColorSpace = page_state.color_space;
    header.cupsCompression = page_state.compression;
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
    header.cupsRowCount = page_state.row_count;
    header.cupsRowFeed = page_state.row_feed;
    header.cupsRowStep =
        page_state.column_step * 100U + page_state.row_step;
#else
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
#endif
    header.cupsNumColors = page_state.colors;
#ifndef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
    header.NumCopies = 1U;
#endif

    if (!cupsRasterWriteHeader2(raster, &header)) {
      goto done;
    }
    for (physical_row = 0; physical_row < page_state.physical_rows;
         physical_row++) {
      size_t offset;

      for (offset = 0; offset < page_state.bytes_per_line; offset++) {
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
        unsigned material_row =
            physical_row + page * PACKED_RASTER_MAX_PHYSICAL_ROWS +
            page_state.material_phase;
#else
        unsigned material_row =
            physical_row + page * PACKED_RASTER_MAX_PHYSICAL_ROWS;
#endif
        row[offset] = packed_raster_material(
            material, material_size, page_state.pattern,
            material_row, offset);
      }
      if (cupsRasterWritePixels(raster, row, page_state.bytes_per_line) !=
          page_state.bytes_per_line) {
        goto done;
      }
    }
  }
  ok = 1;

done:
  free(row);
  if (raster) {
    cupsRasterClose(raster);
  }
  /* cupsRasterClose releases the raster stream, but does not own its fd. */
  if (fd >= 0) {
    close(fd);
  }
  return ok;
}

static int packed_raster_write_ppd(const char *path,
                                   const packed_raster_state_t *state) {
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
  unsigned channels = state->ppd_channels;
  const char *model = packed_raster_contract_model(state->ppd_color_space);
  const unsigned color_space = (unsigned)state->ppd_color_space;
  const unsigned bits_per_pixel = state->ppd_bits_per_pixel;
#else
  const unsigned profile = state->profile;
  unsigned channels = packed_raster_profile_channels[profile];
  const char *model = packed_raster_profile_models[profile];
  const unsigned color_space = packed_raster_profile_cspaces[profile];
  const unsigned bits_per_pixel = packed_raster_profile_bpps[profile];
#endif
  unsigned model_number = 0U;
  const char *relation_attribute = "";
  const char *letter_page_size =
      "*PageSize Letter/Letter: \"<</PageSize[612 792]/ImagingBBox null>>"
      "setpagedevice\"\n";
  const char *a4_page_size =
      "*PageSize A4/A4: \"<</PageSize[595 842]/ImagingBBox null>>"
      "setpagedevice\"\n";
  const char *legal_page_size =
      "*PageSize Legal/Legal: \"<</PageSize[612 1008]/ImagingBBox null>>"
      "setpagedevice\"\n";
  const char *executive_page_size =
      "*PageSize Executive/Executive: "
      "\"<</PageSize[522 756]/ImagingBBox null>>setpagedevice\"\n";
  const char *letter_imageable =
      "*ImageableArea Letter/Letter: \"18 36 594 756\"\n";
  const char *a4_imageable = "*ImageableArea A4/A4: \"12 12 583 830\"\n";
  const char *legal_imageable =
      "*ImageableArea Legal/Legal: \"18 36 594 972\"\n";
  const char *executive_imageable =
      "*ImageableArea Executive/Executive: \"18 36 504 720\"\n";
  const char *letter_dimension =
      "*PaperDimension Letter/Letter: \"612 792\"\n";
  const char *a4_dimension = "*PaperDimension A4/A4: \"595 842\"\n";
  const char *legal_dimension =
      "*PaperDimension Legal/Legal: \"612 1008\"\n";
  const char *executive_dimension =
      "*PaperDimension Executive/Executive: \"522 756\"\n";
  FILE *file;
  int result;

#ifdef CUPSFILTERS_PACKED_RASTER_PCLX
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
  if (state->model_number_mode & 1U) {
    model_number |= PCL_RASTER_CID;
  }
  if (state->model_number_mode & 2U) {
    model_number |= PCL_RASTER_RGB24;
  }
#else
  if (profile == 3U) {
    model_number = PCL_RASTER_CID | PCL_RASTER_RGB24;
  }
#endif
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
  if (state->page_size_count < 1U) {
    letter_page_size = "";
    letter_imageable = "";
    letter_dimension = "";
  }
  if (state->page_size_count < 2U) {
    a4_page_size = "";
    a4_imageable = "";
    a4_dimension = "";
  }
  if (state->page_size_count < 3U) {
    legal_page_size = "";
    legal_imageable = "";
    legal_dimension = "";
  }
  if (state->page_size_count < 4U) {
    executive_page_size = "";
    executive_imageable = "";
    executive_dimension = "";
  }
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM
  if (state->relation_boundary == 2U && CF_V2_ESCPX_RELATION_LANE == 4) {
    a4_page_size = "";
    a4_imageable = "";
    a4_dimension = "";
    legal_page_size = "";
    legal_imageable = "";
    legal_dimension = "";
    executive_page_size = "";
    executive_imageable = "";
    executive_dimension = "";
  }
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_PCLX_RELATION_PROGRAM
  if (state->relation_boundary == 2U && CF_V2_PCLX_RELATION_LANE == 3) {
    channels = 7U;
  } else if (state->relation_boundary == 2U &&
             CF_V2_PCLX_RELATION_LANE == 4) {
    relation_attribute = "*cupsPCL EndJob: \"%n\"\n";
  }
#endif

  file = fopen(path, "w");
  if (!file) {
    return 0;
  }
  result = fprintf(
      file,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"1.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"Packed Raster semantic %s\"\n"
      "*ShortNickName: \"Packed Raster semantic %s\"\n"
      "*NickName: \"Packed Raster semantic %s\"\n"
      "*PCFileName: \"PACKRAST.PPD\"\n"
      "*Product: \"(Packed Raster semantic)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 1.0\n"
      "*cupsModelNumber: %u\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 %s\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Letter\n"
      "%s%s%s%s"
      "*CloseUI: *PageSize\n"
      "*DefaultImageableArea: Letter\n"
      "%s%s%s%s"
      "*DefaultPaperDimension: Letter\n"
      "%s%s%s%s"
      "*OpenUI *ColorModel/Color: PickOne\n"
      "*DefaultColorModel: %s\n"
      "*ColorModel %s/%s: "
      "\"<</cupsColorSpace %u/cupsColorOrder 0/cupsBitsPerColor 8/"
      "cupsBitsPerPixel %u>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *MediaType/Media Type: PickOne\n"
      "*DefaultMediaType: Plain\n"
      "*MediaType Plain/Plain: \"<</MediaType(PLAIN)>>setpagedevice\"\n"
      "*CloseUI: *MediaType\n"
      "*OpenUI *Resolution/Resolution: PickOne\n"
      "*DefaultResolution: 300dpi\n"
      "*Resolution 300dpi/300 dpi: "
      "\"<</HWResolution[300 300]>>setpagedevice\"\n"
      "*Resolution 600dpi/600 dpi: "
      "\"<</HWResolution[600 600]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n"
      "*cupsInkChannels: \"%u\"\n"
      "*cupsAllGamma: \"1.0 1.0\"\n"
      "*cupsAllXY: \"0 0\"\n"
      "*cupsAllXY: \"1 1\"\n"
      "%s",
      PACKED_RASTER_FILTER_NAME, PACKED_RASTER_FILTER_NAME,
      PACKED_RASTER_FILTER_NAME, model_number, PACKED_RASTER_FILTER_NAME,
      letter_page_size, a4_page_size, legal_page_size, executive_page_size,
      letter_imageable, a4_imageable, legal_imageable, executive_imageable,
      letter_dimension, a4_dimension, legal_dimension, executive_dimension,
      model, model, model, color_space, bits_per_pixel, channels,
      relation_attribute);

#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
  if (result >= 0 &&
      state->opaque_command_mode == CF_V2_RELATION_EXPLICIT) {
    if (fputs("*cupsPCL EndJob: \"", file) == EOF ||
        fwrite(state->opaque_command, 1U, state->opaque_command_size, file) !=
            state->opaque_command_size ||
        fputs("\"\n", file) == EOF) {
      result = -1;
    }
  }
#endif

  if (fclose(file) != 0) {
    return 0;
  }
  return result >= 0;
}

static void packed_raster_reset_filter_globals(void) {
  RGB = NULL;
  CMYK = NULL;
  PixelBuffer = NULL;
  CMYKBuffer = NULL;
  InputBuffer = NULL;
  CompBuffer = NULL;
  memset(OutputBuffers, 0, sizeof(OutputBuffers));
  memset(DotBuffers, 0, sizeof(DotBuffers));
  memset(DitherLuts, 0, sizeof(DitherLuts));
  memset(DitherStates, 0, sizeof(DitherStates));
  PrinterPlanes = 0;
  Canceled = 0;

#ifdef CUPSFILTERS_PACKED_RASTER_PCLX
  SeedBuffer = NULL;
  memset(DotBits, 0, sizeof(DotBits));
  memset(DotBufferSizes, 0, sizeof(DotBufferSizes));
  SeedInvalid = 0;
  DotBufferSize = 0;
  OutputFeed = 0;
  Page = 0;
#else
  memset(DotBands, 0, sizeof(DotBands));
  DotAvailList = NULL;
  DotUsedList = NULL;
  DotBufferSize = 0;
  DotRowMax = 0;
  DotRowStep = 0;
  DotRowFeed = 0;
  DotRowCount = 0;
  DotRowCurrent = 0;
  OutputFeed = 0;
#endif
}

#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
static int packed_raster_verify_page_trace(FILE *trace,
                                           unsigned expected_pages) {
  char line[256];
  unsigned page_records = 0U;

  if (fflush(trace) != 0 || fseek(trace, 0L, SEEK_SET) != 0) {
    return 1;
  }
  while (fgets(line, sizeof(line), trace)) {
    if (strncmp(line, "PAGE: ", 6U) == 0) {
      page_records++;
    }
  }
  if (ferror(trace)) {
    return 1;
  }
  return page_records == expected_pages;
}
#endif

static int packed_raster_run_filter(const char *ppd_path,
                                    const char *raster_path,
                                    const packed_raster_state_t *state) {
  char options[256];
#ifdef CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
  const char *option_model =
      packed_raster_contract_model(state->ppd_color_space);
#else
  const char *option_model = packed_raster_profile_models[state->profile];
#endif
  char *argv[] = {
      (char *)PACKED_RASTER_FILTER_NAME,
      (char *)"1",
      (char *)"libfuzzer",
      (char *)"packed-raster-semantic",
      (char *)"1",
      options,
      (char *)raster_path,
      NULL,
  };
  packed_saved_env_t saved_env[] = {
      {"PPD", NULL},
      {"PRINTER", NULL},
      {"CONTENT_TYPE", NULL},
  };
  struct sigaction saved_sigterm;
  int have_saved_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  int saved_stdout = -1;
  int saved_stderr = -1;
  int devnull = -1;
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  FILE *page_trace = NULL;
  int page_oracle_failed = 0;
#endif
  size_t saved_count = 0;
  int status = 1;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=%s MediaType=Plain "
           "Resolution=300dpi emit-jcl=false",
           option_model);

  for (; saved_count < sizeof(saved_env) / sizeof(saved_env[0]);
       saved_count++) {
    if (!packed_raster_capture_env(&saved_env[saved_count])) {
      goto done;
    }
  }
  if (setenv("PPD", ppd_path, 1) != 0 ||
      setenv("PRINTER", "packed-raster-semantic", 1) != 0 ||
      setenv("CONTENT_TYPE", PACKED_RASTER_FILTER_MIME, 1) != 0) {
    goto done;
  }

  fflush(stdout);
  fflush(stderr);
  saved_stdout = dup(STDOUT_FILENO);
  saved_stderr = dup(STDERR_FILENO);
  devnull = open("/dev/null", O_WRONLY);
  if (saved_stdout < 0 || saved_stderr < 0 || devnull < 0) {
    goto done;
  }
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  page_trace = tmpfile();
  if (!page_trace) {
    goto done;
  }
#endif
#ifdef PACKED_RASTER_HAS_ASAN_REPORT_FD
  __sanitizer_set_report_fd((void *)(intptr_t)saved_stderr);
#endif
  if (dup2(devnull, STDOUT_FILENO) < 0 ||
      dup2(
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
          fileno(page_trace),
#else
          devnull,
#endif
          STDERR_FILENO) < 0) {
    goto done;
  }

  srand(0x5041434bU);
  packed_raster_opened_ppd = NULL;
  status = packed_raster_filter_main(7, argv);
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  if (status == 0) {
    (void)fflush(stderr);
    page_oracle_failed =
        !packed_raster_verify_page_trace(page_trace, state->page_count);
  }
#endif

done:
  if (packed_raster_opened_ppd) {
    ppdClose(packed_raster_opened_ppd);
    packed_raster_opened_ppd = NULL;
  }
  packed_raster_reset_filter_globals();
  if (saved_stderr >= 0) {
    fflush(stderr);
    (void)dup2(saved_stderr, STDERR_FILENO);
#ifdef PACKED_RASTER_HAS_ASAN_REPORT_FD
    __sanitizer_set_report_fd((void *)(intptr_t)STDERR_FILENO);
#endif
  }
  if (saved_stdout >= 0) {
    fflush(stdout);
    (void)dup2(saved_stdout, STDOUT_FILENO);
  }
  clearerr(stdout);
  clearerr(stderr);
  if (devnull >= 0) {
    close(devnull);
  }
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  if (page_trace) {
    fclose(page_trace);
  }
#endif
  if (saved_stderr >= 0) {
    close(saved_stderr);
  }
  if (saved_stdout >= 0) {
    close(saved_stdout);
  }
  if (have_saved_sigterm) {
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  }
  while (saved_count > 0) {
    packed_raster_restore_env(&saved_env[--saved_count]);
  }
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
  if (page_oracle_failed) {
    __builtin_trap();
  }
#endif
  return status;
}

static void packed_raster_remove_temp_files(const char *directory,
                                            const char *ppd_path,
                                            const char *raster_path) {
  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const size_t magic_size = sizeof(PACKED_RASTER_MAGIC) - 1U;
  char directory[] = "/tmp/packed-raster-semantic-XXXXXX";
  char ppd_path[sizeof(directory) + 24U];
  char raster_path[sizeof(directory) + 24U];
  packed_raster_state_t state;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;

  if (!data || size < magic_size + PACKED_RASTER_SELECTOR_BYTES ||
      size > magic_size + PACKED_RASTER_SELECTOR_BYTES +
                 PACKED_RASTER_MAX_MATERIAL ||
      memcmp(data, PACKED_RASTER_MAGIC, magic_size) != 0) {
    return 0;
  }

  selector = data + magic_size;
  material = selector + PACKED_RASTER_SELECTOR_BYTES;
  material_size =
      size - magic_size - PACKED_RASTER_SELECTOR_BYTES;
#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
  if (!packed_raster_decode_job(data, size, &state)) {
    return 0;
  }
#ifdef CF_V2_RASTER_JOB_DEEP
  if (packed_raster_job_deep_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_LAYOUT_BOUNDARY
  if (packed_raster_job_layout_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_FORMAT_STORAGE
  if (packed_raster_job_format_storage_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_PROFILE_CARDINALITY
  if (packed_raster_job_profile_cardinality_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_STORAGE_CHANNELS
  if (packed_raster_job_storage_channels_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_CODEC_ROW
  if (packed_raster_job_codec_row_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_PCLX_ENDJOB_OPAQUE
  if (packed_raster_job_pclx_endjob_opaque_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_ESCPX_PAGE_SETUP
  if (packed_raster_job_escpx_page_setup_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_ESCPX_HORIZONTAL_RESOLUTION
  if (packed_raster_job_escpx_horizontal_resolution_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_ESCPX_VERTICAL_RESOLUTION
  if (packed_raster_job_escpx_vertical_resolution_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_ESCPX_PAGE_CARDINALITY
  if (packed_raster_job_escpx_page_cardinality_reject(&state)) {
    return 0;
  }
#endif
#ifdef CF_V2_RASTER_JOB_ESCPX_SOFTWEAVE_LAYOUT
  if (packed_raster_job_escpx_softweave_layout_reject(&state)) {
    return 0;
  }
#endif
  cf_v2_relation_stats_register(&packed_raster_job_stats, CF_V2_TARGET_NAME);
  cf_v2_raster_job_record(&packed_raster_job_stats, &state.relation);
#else
  if (!packed_raster_decode(selector, &state)) {
    return 0;
  }
#endif

#ifdef CUPSFILTERS_PACKED_RASTER_CONTINUATION
  if (packed_raster_has_unsafe_byte_converter_layout(&state)) {
    return 0;
  }
#endif

  if (getenv("PACKED_RASTER_TRACE")) {
    fprintf(stderr,
            "%s mode=%s width=%u height=%u cspace=%u colors=%u bpc=%u "
            "bpp=%u bpl=%u order=%u compression=%u profile=%u rows=%u"
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
            " row_count=%u row_feed=%u row_step=%u column_step=%u"
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
            " pages=%u page_height_stride=%u page_state_stride=%u"
#endif
            "\n",
            PACKED_RASTER_FILTER_NAME,
#ifdef CUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
            "raster-job",
#elif defined(CUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT)
            "contract",
#elif defined(CUPSFILTERS_PACKED_RASTER_CONTINUATION)
            "continuation",
#else
            "finding",
#endif
            state.width, state.height, (unsigned)state.color_space,
            state.colors, state.bits_per_color, state.bits_per_pixel,
            state.bytes_per_line, (unsigned)state.order, state.compression,
            state.profile, state.physical_rows
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_DEEP_STATE
            , state.row_count, state.row_feed, state.row_step,
            state.column_step
#endif
#ifdef CUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE
            , state.page_count, state.page_height_stride,
            state.page_state_stride
#endif
            );
  }

  if (!mkdtemp(directory)) {
    return 0;
  }
  snprintf(ppd_path, sizeof(ppd_path), "%s/printer.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);

  if (packed_raster_write_ppd(ppd_path, &state) &&
      packed_raster_write_document(raster_path, &state, material,
                                   material_size)) {
    (void)packed_raster_run_filter(ppd_path, raster_path, &state);
  }

  packed_raster_remove_temp_files(directory, ppd_path, raster_path);
  return 0;
}
