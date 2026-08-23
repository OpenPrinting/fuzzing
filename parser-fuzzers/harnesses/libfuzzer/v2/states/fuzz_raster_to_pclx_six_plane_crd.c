// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * PCLX6PG1: six-plane CRD and page-lifecycle state for rastertopclx.
 *
 * Input:
 *   bytes 0..7   "PCLX6PG1"
 *   bytes 8..15  width, height, page-count, profile, writer, duplex,
 *                row-schedule, and material-pattern selectors
 *   remaining    1..256 bytes of cyclic CMYK material
 *
 * Every selector value maps to a bounded state.  The full build generates a
 * valid six-channel PPD and one to four complete chunked CMYK8 CUPS Raster
 * pages, invokes the current rastertopclx and pcl-common sources directly,
 * and validates the captured PCL without consulting filter globals.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CF_V2_PCLX6_MAGIC "PCLX6PG1"
#define CF_V2_PCLX6_MAGIC_SIZE 8U
#define CF_V2_PCLX6_SELECTOR_SIZE 8U
#define CF_V2_PCLX6_HEADER_SIZE \
  (CF_V2_PCLX6_MAGIC_SIZE + CF_V2_PCLX6_SELECTOR_SIZE)
#define CF_V2_PCLX6_MIN_MATERIAL 1U
#define CF_V2_PCLX6_MAX_MATERIAL 256U
#define CF_V2_PCLX6_MAX_PAGES 4U
#define CF_V2_PCLX6_MAX_CAPTURE (64U * 1024U)
#define CF_V2_PCLX6_PLANES 6U
#define CF_V2_PCLX6_CRD_SIZE 38U

#define CF_V2_PCLX6_END_COLOR 1U
#define CF_V2_PCLX6_PJL 2U

typedef struct cf_v2_pclx6_state_s
{
  unsigned int width_index;
  unsigned int height_index;
  unsigned int page_count;
  unsigned int profile;
  unsigned int writer_flags;
  unsigned int duplex;
  unsigned int row_schedule;
  unsigned int pattern;
} cf_v2_pclx6_state_t;

static const unsigned int cf_v2_pclx6_widths[] = {
  1U, 7U, 8U, 9U, 15U, 16U, 31U, 32U, 63U
};
static const unsigned int cf_v2_pclx6_heights[] = {1U, 2U, 3U, 4U, 8U};

static void
cf_v2_pclx6_decode(const uint8_t selector[CF_V2_PCLX6_SELECTOR_SIZE],
                   cf_v2_pclx6_state_t *state)
{
  state->width_index = selector[0] %
      (sizeof(cf_v2_pclx6_widths) / sizeof(cf_v2_pclx6_widths[0]));
  state->height_index = selector[1] %
      (sizeof(cf_v2_pclx6_heights) / sizeof(cf_v2_pclx6_heights[0]));
  state->page_count = 1U + selector[2] % CF_V2_PCLX6_MAX_PAGES;
  state->profile = selector[3] % 4U;
  state->writer_flags = selector[4] % 4U;
  state->duplex = selector[5] % 3U;
  state->row_schedule = selector[6] % 8U;
  state->pattern = selector[7] % 8U;
}

static unsigned int
cf_v2_pclx6_page_width(const cf_v2_pclx6_state_t *state, unsigned int page)
{
  const size_t count = sizeof(cf_v2_pclx6_widths) /
                       sizeof(cf_v2_pclx6_widths[0]);

  return cf_v2_pclx6_widths[(state->width_index + page) % count];
}

static unsigned int
cf_v2_pclx6_page_height(const cf_v2_pclx6_state_t *state, unsigned int page)
{
  const size_t count = sizeof(cf_v2_pclx6_heights) /
                       sizeof(cf_v2_pclx6_heights[0]);

  return cf_v2_pclx6_heights[(state->height_index + page) % count];
}

static int
cf_v2_pclx6_row_is_dirty(const cf_v2_pclx6_state_t *state,
                         unsigned int page, unsigned int row,
                         unsigned int height)
{
  switch (state->row_schedule)
  {
    case 0U : return 1;
    case 1U : return row + 1U == height;
    case 2U : return row == 0U;
    case 3U : return (row & 1U) != 0U || row + 1U == height;
    case 4U : return (row & 1U) == 0U;
    case 5U : return row == height / 2U;
    case 6U : return row == 0U || row + 1U == height;
    default :
        return (row + page + state->pattern) % 3U != 0U ||
               row + 1U == height;
  }
}

static size_t
cf_v2_pclx6_find(const uint8_t *data, size_t size, size_t start,
                 const uint8_t *needle, size_t needle_size)
{
  size_t position;

  if (!needle_size || start > size || needle_size > size - start)
    return SIZE_MAX;
  for (position = start; position <= size - needle_size; position ++)
    if (memcmp(data + position, needle, needle_size) == 0)
      return position;
  return SIZE_MAX;
}

static size_t
cf_v2_pclx6_count_span(const uint8_t *data, size_t begin, size_t end,
                       const uint8_t *needle, size_t needle_size)
{
  size_t count = 0U;
  size_t position = begin;

  if (begin > end || !needle_size)
    return 0U;
  while (position <= end && needle_size <= end - position)
  {
    size_t found = cf_v2_pclx6_find(data, end, position, needle, needle_size);

    if (found == SIZE_MAX)
      break;
    count ++;
    position = found + needle_size;
  }
  return count;
}

static int
cf_v2_pclx6_parse_transfer(const uint8_t *capture, size_t capture_size,
                           size_t *position, size_t row_bytes,
                           uint8_t expected_terminator, size_t *encoded_size)
{
  size_t cursor = *position;
  size_t length = 0U;
  int have_digit = 0;

  if (cursor + 4U > capture_size || capture[cursor] != 0x1bU ||
      capture[cursor + 1U] != '*' || capture[cursor + 2U] != 'b')
    return 0;
  cursor += 3U;
  while (cursor < capture_size && capture[cursor] >= '0' &&
         capture[cursor] <= '9')
  {
    size_t digit = (size_t)(capture[cursor] - '0');

    if (length > (CF_V2_PCLX6_MAX_CAPTURE - digit) / 10U)
      return 0;
    length = length * 10U + digit;
    have_digit = 1;
    cursor ++;
  }
  if (!have_digit || cursor >= capture_size ||
      capture[cursor] != expected_terminator ||
      (length != 0U && length != row_bytes) ||
      length > capture_size - cursor - 1U)
    return 0;
  cursor ++;
  *encoded_size = length;
  *position = cursor + length;
  return 1;
}

static int
cf_v2_pclx6_validate_output(const uint8_t *capture, size_t capture_size,
                            const cf_v2_pclx6_state_t *state)
{
  static const uint8_t crd_marker[] = {0x1bU, '*', 'g', '3', '8', 'W'};
  static const uint8_t reset[] = {0x1bU, 'E'};
  static const uint8_t duplex_reload[] = {0x1bU, '&', 'l', '-', '2', 'H'};
  static const uint8_t duplex_back[] = {0x1bU, '&', 'a', '2', 'G'};
  static const uint8_t pjl_job[] = {'@', 'P', 'J', 'L', ' ', 'J', 'O', 'B'};
  static const uint8_t pjl_language[] = {
    '@', 'P', 'J', 'L', ' ', 'E', 'N', 'T', 'E', 'R', ' ',
    'L', 'A', 'N', 'G', 'U', 'A', 'G', 'E', '=', 'P', 'C', 'L'
  };
  static const uint8_t uel[] = {
    0x1bU, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L',
    '\r', '\n'
  };
  static const uint8_t tail_plain[] = {0x1bU, 'E'};
  static const uint8_t tail_pjl[] = {
    0x1bU, 'E',
    0x1bU, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L',
    '\r', '\n',
    '@', 'P', 'J', 'L', ' ', 'E', 'O', 'J', '\r', '\n',
    0x1bU, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L',
    '\r', '\n'
  };
  size_t position = 0U;
  unsigned int page;

  if (!capture || !capture_size || capture_size > CF_V2_PCLX6_MAX_CAPTURE)
    return 0;

  for (page = 0U; page < state->page_count; page ++)
  {
    unsigned int width = cf_v2_pclx6_page_width(state, page);
    unsigned int height = cf_v2_pclx6_page_height(state, page);
    size_t setup_begin = position;
    size_t crd_position = cf_v2_pclx6_find(
        capture, capture_size, position, crd_marker, sizeof(crd_marker));
    size_t descriptor_position;
    size_t geometry_position;
    size_t row_bytes = (width + 7U) / 8U;
    unsigned int plane;
    unsigned int row;
    unsigned int pending_blank = 0U;
    char geometry[64];
    int geometry_size;

    if (crd_position == SIZE_MAX)
      return 0;
    if (page == 0U)
    {
      if (cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                 reset, sizeof(reset)) != 1U)
        return 0;
      if (state->writer_flags & CF_V2_PCLX6_PJL)
      {
        if (cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                   uel, sizeof(uel)) != 1U ||
            cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                   pjl_job, sizeof(pjl_job)) != 1U ||
            cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                   pjl_language, sizeof(pjl_language)) != 1U)
          return 0;
      }
      else if (cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                      uel, sizeof(uel)) != 0U ||
               cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                      pjl_job, sizeof(pjl_job)) != 0U ||
               cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                      pjl_language,
                                      sizeof(pjl_language)) != 0U)
        return 0;
    }
    else if (cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                    reset, sizeof(reset)) != 0U ||
             cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                    uel, sizeof(uel)) != 0U)
      return 0;

    if (state->duplex)
    {
      size_t expected_back = ((page + 1U) & 1U) ? 0U : 1U;

      if (cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                 duplex_reload, sizeof(duplex_reload)) != 1U ||
          cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                 duplex_back, sizeof(duplex_back)) !=
              expected_back)
        return 0;
    }
    else if (cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                    duplex_reload,
                                    sizeof(duplex_reload)) != 0U ||
             cf_v2_pclx6_count_span(capture, setup_begin, crd_position,
                                    duplex_back, sizeof(duplex_back)) != 0U)
      return 0;

    descriptor_position = crd_position + sizeof(crd_marker);
    if (CF_V2_PCLX6_CRD_SIZE > capture_size - descriptor_position ||
        capture[descriptor_position] != 2U ||
        capture[descriptor_position + 1U] != CF_V2_PCLX6_PLANES)
      return 0;
    for (plane = 0U; plane < CF_V2_PCLX6_PLANES; plane ++)
    {
      const size_t offset = descriptor_position + 2U + 6U * plane;

      if (capture[offset] != 1U || capture[offset + 1U] != 44U ||
          capture[offset + 2U] != 1U || capture[offset + 3U] != 44U ||
          capture[offset + 4U] != 0U || capture[offset + 5U] != 2U)
        return 0;
    }

    geometry_size = snprintf(geometry, sizeof(geometry),
                             "\033*r%uS\033*r%uT\033*r1A", width, height);
    if (geometry_size <= 0 || (size_t)geometry_size >= sizeof(geometry))
      return 0;
    geometry_position = cf_v2_pclx6_find(
        capture, capture_size,
        descriptor_position + CF_V2_PCLX6_CRD_SIZE,
        (const uint8_t *)geometry, (size_t)geometry_size);
    if (geometry_position == SIZE_MAX)
      return 0;
    position = geometry_position + (size_t)geometry_size;

    for (row = 0U; row < height; row ++)
    {
      if (!cf_v2_pclx6_row_is_dirty(state, page, row, height))
      {
        pending_blank ++;
        continue;
      }

      while (pending_blank > 0U)
      {
        size_t encoded_size;

        if (!cf_v2_pclx6_parse_transfer(capture, capture_size, &position,
                                        row_bytes, 'W', &encoded_size) ||
            encoded_size != 0U)
          return 0;
        pending_blank --;
      }

      {
        int have_nonblank_plane = 0;

        for (plane = 0U; plane < CF_V2_PCLX6_PLANES; plane ++)
        {
          size_t encoded_size;
          uint8_t terminator =
              plane + 1U == CF_V2_PCLX6_PLANES ? 'W' : 'V';

          if (!cf_v2_pclx6_parse_transfer(capture, capture_size, &position,
                                          row_bytes, terminator,
                                          &encoded_size))
            return 0;
          if (encoded_size)
            have_nonblank_plane = 1;
        }
        if (!have_nonblank_plane)
          return 0;
      }
    }

    if (state->writer_flags & CF_V2_PCLX6_END_COLOR)
    {
      static const uint8_t end_color[] = {0x1bU, '*', 'r', 'C'};

      if (sizeof(end_color) > capture_size - position ||
          memcmp(capture + position, end_color, sizeof(end_color)) != 0)
        return 0;
      position += sizeof(end_color);
    }
    else
    {
      static const uint8_t end_mono[] = {0x1bU, '*', 'r', '0', 'B'};

      if (sizeof(end_mono) > capture_size - position ||
          memcmp(capture + position, end_mono, sizeof(end_mono)) != 0)
        return 0;
      position += sizeof(end_mono);
    }

    if (!state->duplex || ((page + 1U) & 1U) == 0U)
    {
      if (position >= capture_size || capture[position] != '\f')
        return 0;
      position ++;
    }
    else if (position < capture_size && capture[position] == '\f')
      return 0;
  }

  if (cf_v2_pclx6_find(capture, capture_size, position,
                       crd_marker, sizeof(crd_marker)) != SIZE_MAX)
    return 0;
  if (state->writer_flags & CF_V2_PCLX6_PJL)
    return sizeof(tail_pjl) == capture_size - position &&
           memcmp(capture + position, tail_pjl, sizeof(tail_pjl)) == 0;
  return sizeof(tail_plain) == capture_size - position &&
         memcmp(capture + position, tail_plain, sizeof(tail_plain)) == 0;
}

int
cf_v2_pclx6_validate_capture_for_test(
    const uint8_t *capture, size_t capture_size,
    const uint8_t *selector, size_t selector_size)
{
  cf_v2_pclx6_state_t state;

  if (!selector || selector_size != CF_V2_PCLX6_SELECTOR_SIZE)
    return 0;
  cf_v2_pclx6_decode(selector, &state);
  return cf_v2_pclx6_validate_output(capture, capture_size, &state);
}

#ifndef CF_V2_PCLX6_ORACLE_ONLY

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/colormanager.h>
#include <cupsfilters/driver.h>
#include <cupsfilters/filter.h>
#include <fcntl.h>
#include <ppd/ppd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef CF_V2_RASTERTOPCLX_SOURCE
#error "CF_V2_RASTERTOPCLX_SOURCE must quote filter/rastertopclx.c"
#endif
#ifndef CF_V2_PCL_COMMON_SOURCE
#error "CF_V2_PCL_COMMON_SOURCE must quote filter/pcl-common.c"
#endif

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

typedef struct cf_v2_pclx6_profile_s
{
  const char *cyan_ltdk;
  const char *magenta_ltdk;
} cf_v2_pclx6_profile_t;

static const cf_v2_pclx6_profile_t cf_v2_pclx6_profiles[] = {
  {"0.00 1.00", "0.00 1.00"},
  {"0.20 0.80", "0.30 0.70"},
  {"0.35 0.65", "0.15 0.85"},
  {"0.45 0.55", "0.40 0.60"}
};

static uint8_t cf_v2_pclx6_capture[CF_V2_PCLX6_MAX_CAPTURE];
static size_t cf_v2_pclx6_capture_size;
static ppd_file_t *cf_v2_pclx6_filter_ppd;
static unsigned int cf_v2_pclx6_page_log_count;
static int cf_v2_pclx6_page_logs[CF_V2_PCLX6_MAX_PAGES];
static char cf_v2_pclx6_ppd_env[
    sizeof("PPD=/tmp/pclx6pg1-XXXXXX/input.ppd")];
static char cf_v2_pclx6_printer_env[] = "PRINTER=pclx6pg1";
static char cf_v2_pclx6_content_type_env[] =
    "CONTENT_TYPE=application/vnd.cups-raster";
static int cf_v2_pclx6_environment_installed;

static void
cf_v2_pclx6_require(int condition)
{
  if (!condition)
    __builtin_trap();
}

static size_t
cf_v2_pclx6_capture_bytes(const void *data, size_t size)
{
  cf_v2_pclx6_require(size <=
                      CF_V2_PCLX6_MAX_CAPTURE - cf_v2_pclx6_capture_size);
  memcpy(cf_v2_pclx6_capture + cf_v2_pclx6_capture_size, data, size);
  cf_v2_pclx6_capture_size += size;
  return size;
}

static int
cf_v2_pclx6_capture_putchar(int value)
{
  const uint8_t byte = (uint8_t)value;

  (void)cf_v2_pclx6_capture_bytes(&byte, 1U);
  return byte;
}

static int
cf_v2_pclx6_capture_printf(const char *format, ...)
{
  char buffer[512];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  cf_v2_pclx6_require(result >= 0 && (size_t)result < sizeof(buffer));
  (void)cf_v2_pclx6_capture_bytes(buffer, (size_t)result);
  return result;
}

static int
cf_v2_pclx6_capture_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;

  va_start(arguments, format);
  if (stream == stdout)
  {
    char buffer[512];
    int result = vsnprintf(buffer, sizeof(buffer), format, arguments);

    va_end(arguments);
    cf_v2_pclx6_require(result >= 0 && (size_t)result < sizeof(buffer));
    (void)cf_v2_pclx6_capture_bytes(buffer, (size_t)result);
    return result;
  }
  if (strcmp(format, "PAGE: %d %d\n") == 0)
  {
    int page = va_arg(arguments, int);
    int copies = va_arg(arguments, int);

    if (cf_v2_pclx6_page_log_count < CF_V2_PCLX6_MAX_PAGES && copies == 1)
      cf_v2_pclx6_page_logs[cf_v2_pclx6_page_log_count ++] = page;
  }
  va_end(arguments);
  return 0;
}

static int
cf_v2_pclx6_capture_fputs(const char *text, FILE *stream)
{
  if (stream == stdout)
  {
    size_t size = strlen(text);

    (void)cf_v2_pclx6_capture_bytes(text, size);
    return 0;
  }
  return 0;
}

static void
cf_v2_pclx6_quiet_log(void *data, cf_loglevel_t level,
                      const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static ppd_file_t *
cf_v2_pclx6_ppd_open(const char *path)
{
  cf_v2_pclx6_filter_ppd = ppdOpenFile(path);
  return cf_v2_pclx6_filter_ppd;
}

static cf_cm_calibration_t
cf_v2_pclx6_calibration_mode(cf_filter_data_t *data)
{
  (void)data;
  return CF_CM_CALIBRATION_DISABLED;
}

static int
cf_v2_pclx6_color_management_disabled(cf_filter_data_t *data)
{
  (void)data;
  return 0;
}

static void
cf_v2_pclx6_ignore_setbuf(FILE *stream, char *buffer)
{
  (void)stream;
  (void)buffer;
}

#undef cfWritePrintData
#define cfWritePrintData(data, size) \
  cf_v2_pclx6_capture_bytes((data), (size_t)(size))
#define putchar cf_v2_pclx6_capture_putchar
#define printf cf_v2_pclx6_capture_printf
#define fprintf cf_v2_pclx6_capture_fprintf
#define fputs cf_v2_pclx6_capture_fputs
#define cfCUPSLogFunc cf_v2_pclx6_quiet_log
#define ppdOpenFile cf_v2_pclx6_ppd_open
#define cfCmGetCupsColorCalibrateMode cf_v2_pclx6_calibration_mode
#define cfCmIsPrinterCmDisabled cf_v2_pclx6_color_management_disabled
#define setbuf cf_v2_pclx6_ignore_setbuf
#define main cf_v2_pclx6_rastertopclx_main
#include CF_V2_RASTERTOPCLX_SOURCE
#undef main
#include CF_V2_PCL_COMMON_SOURCE
#undef setbuf
#undef cfCmIsPrinterCmDisabled
#undef cfCmGetCupsColorCalibrateMode
#undef ppdOpenFile
#undef cfCUPSLogFunc
#undef fputs
#undef fprintf
#undef printf
#undef putchar
#undef cfWritePrintData

static int
cf_v2_pclx6_write_ppd(const char *path, const cf_v2_pclx6_state_t *state)
{
  const cf_v2_pclx6_profile_t *profile =
      &cf_v2_pclx6_profiles[state->profile];
  unsigned int model_number = PCL_RASTER_CRD;
  FILE *file;
  int result;

  if (state->writer_flags & CF_V2_PCLX6_END_COLOR)
    model_number |= PCL_RASTER_END_COLOR;
  if (state->writer_flags & CF_V2_PCLX6_PJL)
    model_number |= PCL_PJL;

  file = fopen(path, "w");
  if (!file)
    return 0;
  result = fprintf(
      file,
      "*PPD-Adobe: \"4.3\"\n"
      "*FormatVersion: \"4.3\"\n"
      "*FileVersion: \"1.0\"\n"
      "*LanguageVersion: English\n"
      "*LanguageEncoding: ISOLatin1\n"
      "*Manufacturer: \"OpenPrinting\"\n"
      "*ModelName: \"PCLX6PG1 six-plane CRD\"\n"
      "*ShortNickName: \"PCLX6PG1\"\n"
      "*NickName: \"PCLX6PG1 six-plane CRD lifecycle\"\n"
      "*PCFileName: \"PCLX6PG.PPD\"\n"
      "*Product: \"(PCLX6PG1)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 1.0\n"
      "*cupsModelNumber: %u\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 rastertopclx\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Letter\n"
      "*PageSize Letter/Letter: "
      "\"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*OpenUI *PageRegion/Page Region: PickOne\n"
      "*DefaultPageRegion: Letter\n"
      "*PageRegion Letter/Letter: "
      "\"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageRegion\n"
      "*DefaultImageableArea: Letter\n"
      "*ImageableArea Letter/Letter: \"18 36 594 756\"\n"
      "*DefaultPaperDimension: Letter\n"
      "*PaperDimension Letter/Letter: \"612 792\"\n"
      "*OpenUI *ColorModel/Color Model: PickOne\n"
      "*DefaultColorModel: CMYK\n"
      "*ColorModel CMYK/CMYK: "
      "\"<</cupsColorSpace 6/cupsColorOrder 0/cupsBitsPerColor 8/"
      "cupsBitsPerPixel 32>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *MediaType/Media Type: PickOne\n"
      "*DefaultMediaType: Plain\n"
      "*MediaType Plain/Plain: \"<</MediaType(PLAIN)>>setpagedevice\"\n"
      "*CloseUI: *MediaType\n"
      "*OpenUI *Resolution/Resolution: PickOne\n"
      "*DefaultResolution: 300dpi\n"
      "*Resolution 300dpi/300 dpi: "
      "\"<</HWResolution[300 300]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n"
      "*cupsInkChannels CMYK.PLAIN.300dpi: \"6\"\n"
      "*cupsAllGamma CMYK.PLAIN.300dpi: \"1.0 1.0\"\n"
      "*cupsAllXY CMYK.PLAIN.300dpi: \"0 0\"\n"
      "*cupsAllXY CMYK.PLAIN.300dpi: \"1 1\"\n"
      "*cupsCyanLtDk CMYK.PLAIN.300dpi: \"%s\"\n"
      "*cupsMagentaLtDk CMYK.PLAIN.300dpi: \"%s\"\n"
      "*cupsAllDither CMYK.PLAIN.300dpi: \"1.0\"\n",
      model_number, profile->cyan_ltdk, profile->magenta_ltdk);
  if (fclose(file) != 0)
    return 0;
  return result >= 0;
}

static int
cf_v2_pclx6_verify_ppd(const char *path, const cf_v2_pclx6_state_t *state)
{
  ppd_file_t *ppd = ppdOpenFile(path);
  ppd_attr_t *attribute;
  unsigned int expected_model = PCL_RASTER_CRD;
  int ok = 0;

  if (!ppd)
    return 0;
  if (state->writer_flags & CF_V2_PCLX6_END_COLOR)
    expected_model |= PCL_RASTER_END_COLOR;
  if (state->writer_flags & CF_V2_PCLX6_PJL)
    expected_model |= PCL_PJL;
  attribute = ppdFindAttr(ppd, "cupsInkChannels", "CMYK.PLAIN.300dpi");
  if (!attribute || !attribute->value || strcmp(attribute->value, "6") != 0 ||
      (unsigned int)ppd->model_number != expected_model)
    goto done;
  attribute = ppdFindAttr(ppd, "cupsAllDither", "CMYK.PLAIN.300dpi");
  if (!attribute || !attribute->value || strcmp(attribute->value, "1.0") != 0 ||
      ppdFindAttr(ppd, "cupsPCL", "EndJob") != NULL)
    goto done;
  ok = 1;

done:
  ppdClose(ppd);
  return ok;
}

static uint8_t
cf_v2_pclx6_material(const uint8_t *material, size_t material_size,
                     unsigned int page, unsigned int row,
                     unsigned int pixel, unsigned int channel)
{
  size_t offset = (size_t)page * 1031U + (size_t)row * 257U +
                  (size_t)pixel * 17U + channel * 5U;

  return material[offset % material_size];
}

static void
cf_v2_pclx6_fill_row(uint8_t *line, unsigned int width,
                     const cf_v2_pclx6_state_t *state,
                     const uint8_t *material, size_t material_size,
                     unsigned int page, unsigned int row)
{
  unsigned int pixel;

  memset(line, 0, width * 4U);
  for (pixel = 0U; pixel < width; pixel ++)
  {
    unsigned int channel;
    uint8_t base = (uint8_t)(0xc0U |
        (cf_v2_pclx6_material(material, material_size, page, row, pixel, 0U) &
         0x3fU));

    switch (state->pattern)
    {
      case 0U :
          for (channel = 0U; channel < 4U; channel ++)
            line[4U * pixel + channel] = base;
          break;
      case 1U :
          channel = (page + row) % 4U;
          line[4U * pixel + channel] = base;
          break;
      case 2U :
          for (channel = 0U; channel < 4U; channel ++)
            line[4U * pixel + channel] =
                ((pixel + channel) & 1U) ? 0xffU : 0U;
          break;
      case 3U :
          for (channel = 0U; channel < 4U; channel ++)
            line[4U * pixel + channel] =
                (uint8_t)((pixel * 255U) / (width > 1U ? width - 1U : 1U));
          break;
      case 4U :
          channel = pixel % 4U;
          line[4U * pixel + channel] = 0xffU;
          break;
      case 5U :
          memset(line + 4U * pixel, 0xff, 4U);
          break;
      case 6U :
          for (channel = 0U; channel < 4U; channel ++)
            line[4U * pixel + channel] =
                (pixel & 1U) ? (uint8_t)(0x80U + channel * 0x20U) : 0U;
          break;
      default :
          for (channel = 0U; channel < 4U; channel ++)
            line[4U * pixel + channel] = (uint8_t)(
                cf_v2_pclx6_material(material, material_size, page, row,
                                     pixel, channel) |
                1U);
          break;
    }
  }

  /* Every scheduled data row is visibly nonblank and has a deterministic K
   * endpoint, so the structural oracle can require one non-empty plane. */
  line[3] = 0xffU;
}

static int
cf_v2_pclx6_write_raster(const char *path,
                         const cf_v2_pclx6_state_t *state,
                         const uint8_t *material, size_t material_size)
{
  cups_raster_t *raster = NULL;
  uint8_t *line = NULL;
  int descriptor = -1;
  int ok = 0;
  unsigned int page;

  descriptor = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (descriptor < 0)
    return 0;
  raster = cupsRasterOpen(descriptor, CUPS_RASTER_WRITE);
  if (!raster)
    goto done;
  line = (uint8_t *)malloc(cf_v2_pclx6_widths[
      sizeof(cf_v2_pclx6_widths) / sizeof(cf_v2_pclx6_widths[0]) - 1U] * 4U);
  if (!line)
    goto done;

  for (page = 0U; page < state->page_count; page ++)
  {
    cups_page_header2_t header;
    unsigned int width = cf_v2_pclx6_page_width(state, page);
    unsigned int height = cf_v2_pclx6_page_height(state, page);
    unsigned int row;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
    memcpy(header.cupsPageSizeName, "Letter", sizeof("Letter"));
    header.HWResolution[0] = 300U;
    header.HWResolution[1] = 300U;
    header.PageSize[0] = 612U;
    header.PageSize[1] = 792U;
    header.cupsPageSize[0] = 612.0f;
    header.cupsPageSize[1] = 792.0f;
    header.ImagingBoundingBox[2] = 612U;
    header.ImagingBoundingBox[3] = 792U;
    header.cupsImagingBBox[2] = 612.0f;
    header.cupsImagingBBox[3] = 792.0f;
    header.cupsWidth = width;
    header.cupsHeight = height;
    header.cupsBitsPerColor = 8U;
    header.cupsBitsPerPixel = 32U;
    header.cupsBytesPerLine = width * 4U;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = CUPS_CSPACE_CMYK;
    header.cupsCompression = 0U;
    header.cupsRowCount = 1U;
    header.cupsRowFeed = 1U;
    header.cupsRowStep = 1U;
    header.cupsNumColors = 4U;
    header.NumCopies = 1U;
    header.Duplex = state->duplex != 0U;
    header.Tumble = state->duplex == 2U;

    if (!cupsRasterWriteHeader2(raster, &header))
      goto done;
    for (row = 0U; row < height; row ++)
    {
      if (cf_v2_pclx6_row_is_dirty(state, page, row, height))
        cf_v2_pclx6_fill_row(line, width, state, material, material_size,
                             page, row);
      else
        memset(line, 0, width * 4U);
      if (cupsRasterWritePixels(raster, line, width * 4U) != width * 4U)
        goto done;
    }
  }
  ok = 1;

done:
  free(line);
  if (raster)
    cupsRasterClose(raster);
  if (descriptor >= 0)
    close(descriptor);
  return ok;
}

static int
cf_v2_pclx6_install_environment(const char *ppd_path)
{
  int length = snprintf(cf_v2_pclx6_ppd_env,
                        sizeof(cf_v2_pclx6_ppd_env), "PPD=%s", ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_pclx6_ppd_env))
    return 0;
  if (cf_v2_pclx6_environment_installed)
    return 1;
  if (putenv(cf_v2_pclx6_ppd_env) != 0 ||
      putenv(cf_v2_pclx6_printer_env) != 0 ||
      putenv(cf_v2_pclx6_content_type_env) != 0)
    return 0;
  cf_v2_pclx6_environment_installed = 1;
  return 1;
}

static void
cf_v2_pclx6_reset_filter_globals(void)
{
  RGB = NULL;
  CMYK = NULL;
  PixelBuffer = NULL;
  CMYKBuffer = NULL;
  InputBuffer = NULL;
  CompBuffer = NULL;
  SeedBuffer = NULL;
  memset(OutputBuffers, 0, sizeof(OutputBuffers));
  memset(DotBuffers, 0, sizeof(DotBuffers));
  memset(DitherLuts, 0, sizeof(DitherLuts));
  memset(DitherStates, 0, sizeof(DitherStates));
  memset(DotBits, 0, sizeof(DotBits));
  memset(DotBufferSizes, 0, sizeof(DotBufferSizes));
  BlankValue = 0U;
  PrinterPlanes = 0;
  SeedInvalid = 0;
  DotBufferSize = 0;
  OutputFeed = 0;
  Page = 0;
  Canceled = 0;
  OutputMode = OUTPUT_DITHERED;
  logfunc = NULL;
  ld = NULL;
}

static int
cf_v2_pclx6_run_filter(const char *ppd_path, const char *raster_path,
                       const cf_v2_pclx6_state_t *state)
{
  char options[192];
  char *arguments[] = {
    (char *)"rastertopclx", (char *)"1", (char *)"libfuzzer",
    (char *)"PCLX6PG1", (char *)"1", options, (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  int have_saved_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  unsigned int page;
  int status;
  int ok = 0;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=CMYK MediaType=Plain "
           "Resolution=300dpi emit-jcl=false");
  if (!cf_v2_pclx6_install_environment(ppd_path))
    goto done;

  cf_v2_pclx6_capture_size = 0U;
  cf_v2_pclx6_filter_ppd = NULL;
  cf_v2_pclx6_page_log_count = 0U;
  memset(cf_v2_pclx6_page_logs, 0, sizeof(cf_v2_pclx6_page_logs));
  status = cf_v2_pclx6_rastertopclx_main(7, arguments);
  cf_v2_pclx6_require(status == 0 && cf_v2_pclx6_filter_ppd != NULL &&
                      cf_v2_pclx6_page_log_count == state->page_count);
  for (page = 0U; page < state->page_count; page ++)
    cf_v2_pclx6_require(cf_v2_pclx6_page_logs[page] == (int)page + 1);
  cf_v2_pclx6_require(cf_v2_pclx6_validate_output(
      cf_v2_pclx6_capture, cf_v2_pclx6_capture_size, state));
  ok = 1;

done:
  if (cf_v2_pclx6_filter_ppd)
  {
    ppdClose(cf_v2_pclx6_filter_ppd);
    cf_v2_pclx6_filter_ppd = NULL;
  }
  cf_v2_pclx6_reset_filter_globals();
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return ok;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t minimum =
      CF_V2_PCLX6_HEADER_SIZE + CF_V2_PCLX6_MIN_MATERIAL;
  const size_t maximum =
      CF_V2_PCLX6_HEADER_SIZE + CF_V2_PCLX6_MAX_MATERIAL;
  const size_t limit = max_size < maximum ? max_size : maximum;
  size_t material_size;

  if (!data || limit < minimum)
    return 0U;
  if (size > limit)
    size = limit;
  if (size < minimum)
  {
    memset(data + size, 0, minimum - size);
    size = minimum;
  }
  memcpy(data, CF_V2_PCLX6_MAGIC, CF_V2_PCLX6_MAGIC_SIZE);

  if ((seed & 3U) != 0U)
  {
    size_t slot = CF_V2_PCLX6_MAGIC_SIZE +
                  ((seed >> 2U) % CF_V2_PCLX6_SELECTOR_SIZE);
    uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      data[slot] ^= delta;
    else
      data[slot] += delta;
    return size;
  }

  material_size = LLVMFuzzerMutate(data + CF_V2_PCLX6_HEADER_SIZE,
                                   size - CF_V2_PCLX6_HEADER_SIZE,
                                   limit - CF_V2_PCLX6_HEADER_SIZE);
  if (material_size < CF_V2_PCLX6_MIN_MATERIAL)
  {
    data[CF_V2_PCLX6_HEADER_SIZE] = (uint8_t)seed;
    material_size = CF_V2_PCLX6_MIN_MATERIAL;
  }
  if (material_size > CF_V2_PCLX6_MAX_MATERIAL)
    material_size = CF_V2_PCLX6_MAX_MATERIAL;
  memcpy(data, CF_V2_PCLX6_MAGIC, CF_V2_PCLX6_MAGIC_SIZE);
  return CF_V2_PCLX6_HEADER_SIZE + material_size;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/pclx6pg1-XXXXXX";
  char ppd_path[sizeof(directory) + 16U];
  char raster_path[sizeof(directory) + 16U];
  cf_v2_pclx6_state_t state;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;

  if (!data || size < CF_V2_PCLX6_HEADER_SIZE +
                          CF_V2_PCLX6_MIN_MATERIAL ||
      size > CF_V2_PCLX6_HEADER_SIZE + CF_V2_PCLX6_MAX_MATERIAL ||
      memcmp(data, CF_V2_PCLX6_MAGIC, CF_V2_PCLX6_MAGIC_SIZE) != 0)
    return 0;
  selector = data + CF_V2_PCLX6_MAGIC_SIZE;
  material = data + CF_V2_PCLX6_HEADER_SIZE;
  material_size = size - CF_V2_PCLX6_HEADER_SIZE;
  cf_v2_pclx6_decode(selector, &state);
  if (!mkdtemp(directory))
    return 0;

  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_pclx6_write_ppd(ppd_path, &state) &&
      cf_v2_pclx6_verify_ppd(ppd_path, &state) &&
      cf_v2_pclx6_write_raster(raster_path, &state, material, material_size))
    (void)cf_v2_pclx6_run_filter(ppd_path, raster_path, &state);

  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
  return 0;
}

#endif /* !CF_V2_PCLX6_ORACLE_ONLY */
