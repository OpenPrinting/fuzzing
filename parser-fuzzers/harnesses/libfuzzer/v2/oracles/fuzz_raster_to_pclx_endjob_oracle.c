// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * PCLXEND1: Raster-to-PCLx Shutdown/EndJob output oracle.
 *
 * Input (exactly 15 bytes):
 *   bytes 0..7   "PCLXEND1"
 *   byte 8       EndJob: missing, fixed literal, or one safe page-count slot
 *   byte 9       one to four pages
 *   byte 10      simplex, long-edge duplex, or short-edge duplex
 *   byte 11      normal raster end or PCL_RASTER_END_COLOR
 *   byte 12      PJL disabled or enabled
 *   byte 13      compression mode 0, 1, or 2
 *   byte 14      one of eight finite row materials
 *
 * The full target generates a PPD and complete CUPS Raster job, invokes the
 * unmodified legacy rastertopclx main, and captures all PCL/PJL output.  The
 * mature PCLXRAW1 oracle owns the page setup, row codecs, page termination,
 * and duplex framing.  This target additionally owns the Shutdown lookup and
 * the exact EndJob/reset/PJL suffix.  No PPD bytes are accepted from input.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CF_V2_PCLXEND_MAGIC "PCLXEND1"
#define CF_V2_PCLXEND_MAGIC_SIZE 8U
#define CF_V2_PCLXEND_SELECTOR_SIZE 7U
#define CF_V2_PCLXEND_INPUT_SIZE \
  (CF_V2_PCLXEND_MAGIC_SIZE + CF_V2_PCLXEND_SELECTOR_SIZE)
#define CF_V2_PCLXEND_MAX_PAGES 4U
#define CF_V2_PCLXEND_WIDTH 16U
#define CF_V2_PCLXEND_HEIGHT 3U
#define CF_V2_PCLXEND_MAX_CAPTURE (128U * 1024U)

#define CF_V2_PCLXEND_END_COLOR 1U
#define CF_V2_PCLXEND_PJL 2U

/* Pull in only the independent PCL page/row parser, never its filter runner. */
#define CF_V2_PCLXRAW_ORACLE_ONLY
#include "../states/fuzz_raster_to_pclx_raw_plane_writer.c"
#undef CF_V2_PCLXRAW_ORACLE_ONLY

typedef enum cf_v2_pclxend_endjob_e
{
  CF_V2_PCLXEND_ENDJOB_MISSING = 0,
  CF_V2_PCLXEND_ENDJOB_LITERAL,
  CF_V2_PCLXEND_ENDJOB_PAGE_COUNT,
  CF_V2_PCLXEND_ENDJOB_COUNT
} cf_v2_pclxend_endjob_t;

typedef struct cf_v2_pclxend_state_s
{
  unsigned int endjob;
  unsigned int page_count;
  unsigned int duplex;
  unsigned int end_color;
  unsigned int pjl;
  unsigned int compression;
  unsigned int material;
} cf_v2_pclxend_state_t;

static const uint8_t cf_v2_pclxend_material[] = {
  0x00U, 0x11U, 0x55U, 0x80U, 0xaaU, 0xeeU, 0xffU
};

static const uint8_t cf_v2_pclxend_uel[] = {
  0x1bU, '%', '-', '1', '2', '3', '4', '5', 'X', '@', 'P', 'J', 'L',
  '\r', '\n'
};
static const uint8_t cf_v2_pclxend_pjl_eoj[] = {
  '@', 'P', 'J', 'L', ' ', 'E', 'O', 'J', '\r', '\n'
};

static void
cf_v2_pclxend_decode(
    const uint8_t selector[CF_V2_PCLXEND_SELECTOR_SIZE],
    cf_v2_pclxend_state_t *state)
{
  state->endjob = selector[0] % CF_V2_PCLXEND_ENDJOB_COUNT;
  state->page_count = 1U + selector[1] % CF_V2_PCLXEND_MAX_PAGES;
  state->duplex = selector[2] % 3U;
  state->end_color = selector[3] % 2U;
  state->pjl = selector[4] % 2U;
  state->compression = selector[5] % 3U;
  state->material = selector[6] % 8U;
}

static void
cf_v2_pclxend_raw_state(const cf_v2_pclxend_state_t *state,
                        cf_v2_pclxraw_state_t *raw)
{
  memset(raw, 0, sizeof(*raw));
  raw->base_profile = CF_V2_PCLXRAW_K1;
  raw->profile_stride_index = 0U;
  raw->width_index = 5U;       /* PCLXRAW1 width table: 16 pixels. */
  raw->height_index = 2U;      /* PCLXRAW1 height table: 3 rows. */
  raw->page_count = state->page_count;
  raw->writer_tuple = 0U;
  raw->compression = state->compression;
  raw->row_schedule = 0U;
  raw->pattern = state->material;
  raw->writer_flags =
      (state->end_color ? CF_V2_PCLXRAW_END_COLOR : 0U) |
      (state->pjl ? CF_V2_PCLXRAW_PJL : 0U);
  raw->duplex = state->duplex;
  raw->resolution_index = 1U; /* 300 dpi. */
}

static size_t
cf_v2_pclxend_append(uint8_t *output, size_t capacity, size_t position,
                     const void *data, size_t size)
{
  if (!output || !data || position > capacity || size > capacity - position)
    return SIZE_MAX;
  memcpy(output + position, data, size);
  return position + size;
}

static size_t
cf_v2_pclxend_build_tail(uint8_t *output, size_t capacity,
                         const cf_v2_pclxend_state_t *state,
                         size_t *endjob_size)
{
  static const uint8_t reset[] = {0x1bU, 'E'};
  static const uint8_t literal[] = {0x1bU, '&', 'l', '0', 'H'};
  uint8_t page_command[32];
  size_t position = 0U;

  if (!output || !state || !endjob_size)
    return SIZE_MAX;
  switch (state->endjob)
  {
    case CF_V2_PCLXEND_ENDJOB_MISSING :
        position = cf_v2_pclxend_append(
            output, capacity, position, reset, sizeof(reset));
        break;
    case CF_V2_PCLXEND_ENDJOB_LITERAL :
        position = cf_v2_pclxend_append(
            output, capacity, position, literal, sizeof(literal));
        break;
    case CF_V2_PCLXEND_ENDJOB_PAGE_COUNT :
    {
      int length = snprintf((char *)page_command, sizeof(page_command),
                            "\033&l%uX", state->page_count);

      if (length <= 0 || (size_t)length >= sizeof(page_command))
        return SIZE_MAX;
      position = cf_v2_pclxend_append(
          output, capacity, position, page_command, (size_t)length);
        break;
    }
    default :
        return SIZE_MAX;
  }
  if (position == SIZE_MAX)
    return SIZE_MAX;
  *endjob_size = position;

  if (state->pjl)
  {
    position = cf_v2_pclxend_append(
        output, capacity, position, cf_v2_pclxend_uel,
        sizeof(cf_v2_pclxend_uel));
    if (position != SIZE_MAX)
      position = cf_v2_pclxend_append(
          output, capacity, position, cf_v2_pclxend_pjl_eoj,
          sizeof(cf_v2_pclxend_pjl_eoj));
    if (position != SIZE_MAX)
      position = cf_v2_pclxend_append(
          output, capacity, position, cf_v2_pclxend_uel,
          sizeof(cf_v2_pclxend_uel));
  }
  return position;
}

static size_t
cf_v2_pclxend_replace_title(uint8_t *data, size_t size)
{
  static const uint8_t actual[] = "PCLXEND1";
  static const uint8_t normalized[] = "PCLXRAW1";
  size_t count = 0U;
  size_t position;

  for (position = 0U; position + sizeof(actual) - 1U <= size; position ++)
    if (memcmp(data + position, actual, sizeof(actual) - 1U) == 0)
    {
      memcpy(data + position, normalized, sizeof(normalized) - 1U);
      count ++;
      position += sizeof(actual) - 2U;
    }
  return count;
}

static int
cf_v2_pclxend_validate_output(const uint8_t *capture, size_t capture_size,
                              const cf_v2_pclxend_state_t *state)
{
  static const uint8_t reset[] = {0x1bU, 'E'};
  uint8_t expected_tail[96];
  uint8_t normalized[CF_V2_PCLXEND_MAX_CAPTURE];
  cf_v2_pclxraw_state_t raw;
  size_t endjob_size;
  size_t tail_size;
  size_t prefix_size;
  size_t normalized_size;
  size_t title_count;

  if (!capture || !state || !capture_size ||
      capture_size > sizeof(normalized))
    return 0;
  tail_size = cf_v2_pclxend_build_tail(
      expected_tail, sizeof(expected_tail), state, &endjob_size);
  if (tail_size == SIZE_MAX || tail_size > capture_size)
    return 0;
  prefix_size = capture_size - tail_size;

  /* Exact suffix equality proves ordering and rejects any trailing garbage. */
  if (memcmp(capture + prefix_size, expected_tail, tail_size) != 0 ||
      memchr(capture + prefix_size, '%', endjob_size) != NULL)
    return 0;

  memcpy(normalized, capture, prefix_size);
  memcpy(normalized + prefix_size, reset, sizeof(reset));
  normalized_size = prefix_size + sizeof(reset);
  if (state->pjl)
  {
    size_t pjl_size = tail_size - endjob_size;

    if (pjl_size > sizeof(normalized) - normalized_size)
      return 0;
    memcpy(normalized + normalized_size,
           expected_tail + endjob_size, pjl_size);
    normalized_size += pjl_size;
  }

  /* PCLXRAW1's parser expects its own harmless synthetic job title. */
  title_count = cf_v2_pclxend_replace_title(normalized, normalized_size);
  if (title_count != (state->pjl ? 2U : 0U))
    return 0;

  cf_v2_pclxend_raw_state(state, &raw);
  return cf_v2_pclxraw_width(&raw) == CF_V2_PCLXEND_WIDTH &&
         cf_v2_pclxraw_height(&raw) == CF_V2_PCLXEND_HEIGHT &&
         cf_v2_pclxraw_validate_output(
             normalized, normalized_size, &raw,
             cf_v2_pclxend_material, sizeof(cf_v2_pclxend_material));
}

int
cf_v2_pclxend_validate_capture_for_test(
    const uint8_t *capture, size_t capture_size,
    const uint8_t *selector, size_t selector_size)
{
  cf_v2_pclxend_state_t state;

  if (!selector || selector_size != CF_V2_PCLXEND_SELECTOR_SIZE)
    return 0;
  cf_v2_pclxend_decode(selector, &state);
  return cf_v2_pclxend_validate_output(capture, capture_size, &state);
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                        unsigned int seed)
{
  static const uint8_t cardinalities[CF_V2_PCLXEND_SELECTOR_SIZE] = {
    3U, 4U, 3U, 2U, 2U, 3U, 8U
  };
  size_t index;
  size_t slot;
  uint8_t delta;

  if (!data || max_size < CF_V2_PCLXEND_INPUT_SIZE)
    return 0U;
  if (size < CF_V2_PCLXEND_INPUT_SIZE)
    memset(data + size, 0, CF_V2_PCLXEND_INPUT_SIZE - size);
  memcpy(data, CF_V2_PCLXEND_MAGIC, CF_V2_PCLXEND_MAGIC_SIZE);
  for (index = 0U; index < CF_V2_PCLXEND_SELECTOR_SIZE; index ++)
    data[CF_V2_PCLXEND_MAGIC_SIZE + index] %= cardinalities[index];

  slot = (size_t)seed % CF_V2_PCLXEND_SELECTOR_SIZE;
  delta = (uint8_t)(1U +
      ((seed / CF_V2_PCLXEND_SELECTOR_SIZE) %
       (cardinalities[slot] - 1U)));
  data[CF_V2_PCLXEND_MAGIC_SIZE + slot] = (uint8_t)(
      (data[CF_V2_PCLXEND_MAGIC_SIZE + slot] + delta) %
      cardinalities[slot]);
  return CF_V2_PCLXEND_INPUT_SIZE;
}

#ifndef CF_V2_PCLXEND_ORACLE_ONLY

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

static uint8_t cf_v2_pclxend_capture[CF_V2_PCLXEND_MAX_CAPTURE];
static size_t cf_v2_pclxend_capture_size;
static ppd_file_t *cf_v2_pclxend_filter_ppd;
static unsigned int cf_v2_pclxend_page_log_count;
static int cf_v2_pclxend_page_logs[CF_V2_PCLXEND_MAX_PAGES];
static unsigned int cf_v2_pclxend_lookup_count;
static unsigned int cf_v2_pclxend_template_printf_count;
static unsigned int cf_v2_pclxend_expected_endjob;
static char cf_v2_pclxend_ppd_env[512];
static char cf_v2_pclxend_printer_env[] = "PRINTER=pclxend1";
static char cf_v2_pclxend_content_type_env[] =
    "CONTENT_TYPE=application/vnd.cups-raster";
static int cf_v2_pclxend_environment_installed;

static void
cf_v2_pclxend_require(int condition)
{
  if (!condition)
    __builtin_trap();
}

static size_t
cf_v2_pclxend_capture_bytes(const void *data, size_t size)
{
  cf_v2_pclxend_require(
      size <= sizeof(cf_v2_pclxend_capture) - cf_v2_pclxend_capture_size);
  memcpy(cf_v2_pclxend_capture + cf_v2_pclxend_capture_size, data, size);
  cf_v2_pclxend_capture_size += size;
  return size;
}

static int
cf_v2_pclxend_capture_putchar(int value)
{
  uint8_t byte = (uint8_t)value;

  (void)cf_v2_pclxend_capture_bytes(&byte, 1U);
  return byte;
}

static int
cf_v2_pclxend_capture_printf(const char *format, ...)
{
  char buffer[1024];
  va_list arguments;
  int result;

  if ((cf_v2_pclxend_expected_endjob == CF_V2_PCLXEND_ENDJOB_LITERAL &&
       strcmp(format, "&l0H") == 0) ||
      (cf_v2_pclxend_expected_endjob ==
           CF_V2_PCLXEND_ENDJOB_PAGE_COUNT &&
       strcmp(format, "&l%dX") == 0))
    cf_v2_pclxend_template_printf_count ++;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  cf_v2_pclxend_require(result >= 0 && (size_t)result < sizeof(buffer));
  (void)cf_v2_pclxend_capture_bytes(buffer, (size_t)result);
  return result;
}

static int
cf_v2_pclxend_capture_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;

  va_start(arguments, format);
  if (stream == stdout)
  {
    char buffer[1024];
    int result = vsnprintf(buffer, sizeof(buffer), format, arguments);

    va_end(arguments);
    cf_v2_pclxend_require(result >= 0 && (size_t)result < sizeof(buffer));
    (void)cf_v2_pclxend_capture_bytes(buffer, (size_t)result);
    return result;
  }
  if (strcmp(format, "PAGE: %d %d\n") == 0)
  {
    int page = va_arg(arguments, int);
    int copies = va_arg(arguments, int);

    if (cf_v2_pclxend_page_log_count < CF_V2_PCLXEND_MAX_PAGES &&
        copies == 1)
      cf_v2_pclxend_page_logs[cf_v2_pclxend_page_log_count ++] = page;
  }
  va_end(arguments);
  return 0;
}

static int
cf_v2_pclxend_capture_fputs(const char *text, FILE *stream)
{
  if (stream == stdout)
  {
    (void)cf_v2_pclxend_capture_bytes(text, strlen(text));
    return 0;
  }
  return 0;
}

static void
cf_v2_pclxend_quiet_log(void *data, cf_loglevel_t level,
                        const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static ppd_file_t *
cf_v2_pclxend_ppd_open(const char *path)
{
  cf_v2_pclxend_filter_ppd = ppdOpenFile(path);
  return cf_v2_pclxend_filter_ppd;
}

static ppd_attr_t *
cf_v2_pclxend_ppd_find_attr(ppd_file_t *ppd, const char *name,
                            const char *spec)
{
  if (name && spec && strcmp(name, "cupsPCL") == 0 &&
      strcmp(spec, "EndJob") == 0)
    cf_v2_pclxend_lookup_count ++;
  return ppdFindAttr(ppd, name, spec);
}

static cf_cm_calibration_t
cf_v2_pclxend_calibration_mode(cf_filter_data_t *data)
{
  (void)data;
  return CF_CM_CALIBRATION_DISABLED;
}

static int
cf_v2_pclxend_color_management_disabled(cf_filter_data_t *data)
{
  (void)data;
  return 0;
}

static void
cf_v2_pclxend_ignore_setbuf(FILE *stream, char *buffer)
{
  (void)stream;
  (void)buffer;
}

#undef cfWritePrintData
#define cfWritePrintData(data, size) \
  cf_v2_pclxend_capture_bytes((data), (size_t)(size))
#define putchar cf_v2_pclxend_capture_putchar
#define printf cf_v2_pclxend_capture_printf
#define fprintf cf_v2_pclxend_capture_fprintf
#define fputs cf_v2_pclxend_capture_fputs
#define cfCUPSLogFunc cf_v2_pclxend_quiet_log
#define ppdOpenFile cf_v2_pclxend_ppd_open
#define ppdFindAttr cf_v2_pclxend_ppd_find_attr
#define cfCmGetCupsColorCalibrateMode cf_v2_pclxend_calibration_mode
#define cfCmIsPrinterCmDisabled cf_v2_pclxend_color_management_disabled
#define setbuf cf_v2_pclxend_ignore_setbuf
#define main cf_v2_pclxend_rastertopclx_main
#include CF_V2_RASTERTOPCLX_SOURCE
#undef main
#include CF_V2_PCL_COMMON_SOURCE
#undef setbuf
#undef cfCmIsPrinterCmDisabled
#undef cfCmGetCupsColorCalibrateMode
#undef ppdFindAttr
#undef ppdOpenFile
#undef cfCUPSLogFunc
#undef fputs
#undef fprintf
#undef printf
#undef putchar
#undef cfWritePrintData

static unsigned int
cf_v2_pclxend_model_number(const cf_v2_pclxend_state_t *state)
{
  unsigned int model = PCL_RASTER_SIMPLE | PCL_RASTER_RGB24;

  if (state->end_color)
    model |= PCL_RASTER_END_COLOR;
  if (state->pjl)
    model |= PCL_PJL;
  return model;
}

static int
cf_v2_pclxend_write_ppd(const char *path,
                        const cf_v2_pclxend_state_t *state)
{
  FILE *file = fopen(path, "w");
  int result;

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
      "*ModelName: \"PCLXEND1 shutdown oracle\"\n"
      "*ShortNickName: \"PCLXEND1\"\n"
      "*NickName: \"PCLXEND1 shutdown lifecycle\"\n"
      "*PCFileName: \"PCLXEND.PPD\"\n"
      "*Product: \"(PCLXEND1)\"\n"
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
      "*DefaultColorModel: RGB\n"
      "*ColorModel RGB/RGB: "
      "\"<</cupsColorSpace 1/cupsColorOrder 0/cupsBitsPerColor 8/"
      "cupsBitsPerPixel 24>>setpagedevice\"\n"
      "*CloseUI: *ColorModel\n"
      "*OpenUI *MediaType/Media Type: PickOne\n"
      "*DefaultMediaType: Plain\n"
      "*MediaType Plain/Plain: \"<</MediaType(PLAIN)>>setpagedevice\"\n"
      "*CloseUI: *MediaType\n"
      "*OpenUI *Resolution/Resolution: PickOne\n"
      "*DefaultResolution: 300dpi\n"
      "*Resolution 300dpi/300 dpi: "
      "\"<</HWResolution[300 300]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n",
      cf_v2_pclxend_model_number(state));
  if (result >= 0 && state->endjob == CF_V2_PCLXEND_ENDJOB_LITERAL)
    result = fputs("*cupsPCL EndJob: \"&l0H\"\n", file);
  else if (result >= 0 &&
           state->endjob == CF_V2_PCLXEND_ENDJOB_PAGE_COUNT)
    result = fputs("*cupsPCL EndJob: \"&l%dX\"\n", file);
  if (fclose(file) != 0)
    return 0;
  return result >= 0;
}

static int
cf_v2_pclxend_verify_ppd(const char *path,
                         const cf_v2_pclxend_state_t *state)
{
  ppd_file_t *ppd = ppdOpenFile(path);
  ppd_attr_t *attr;
  int ok = 0;

  if (!ppd)
    return 0;
  attr = ppdFindAttr(ppd, "cupsPCL", "EndJob");
  if ((unsigned int)ppd->model_number ==
          cf_v2_pclxend_model_number(state))
  {
    if (state->endjob == CF_V2_PCLXEND_ENDJOB_MISSING)
      ok = attr == NULL;
    else if (attr && state->endjob == CF_V2_PCLXEND_ENDJOB_LITERAL)
      ok = strcmp(attr->value, "&l0H") == 0;
    else if (attr)
      ok = strcmp(attr->value, "&l%dX") == 0;
  }
  ppdClose(ppd);
  return ok;
}

static void
cf_v2_pclxend_fill_header(cups_page_header2_t *header,
                          const cf_v2_pclxend_state_t *state)
{
  memset(header, 0, sizeof(*header));
  memcpy(header->MediaClass, "PwgRaster", sizeof("PwgRaster"));
  memcpy(header->MediaType, "PLAIN", sizeof("PLAIN"));
  memcpy(header->cupsPageSizeName, "Letter", sizeof("Letter"));
  header->HWResolution[0] = 300U;
  header->HWResolution[1] = 300U;
  header->PageSize[0] = 612U;
  header->PageSize[1] = 792U;
  header->cupsPageSize[0] = 612.0f;
  header->cupsPageSize[1] = 792.0f;
  header->ImagingBoundingBox[2] = 612U;
  header->ImagingBoundingBox[3] = 792U;
  header->cupsImagingBBox[2] = 612.0f;
  header->cupsImagingBBox[3] = 792.0f;
  header->cupsWidth = CF_V2_PCLXEND_WIDTH;
  header->cupsHeight = CF_V2_PCLXEND_HEIGHT;
  header->cupsBitsPerColor = 1U;
  header->cupsBitsPerPixel = 1U;
  header->cupsBytesPerLine = (CF_V2_PCLXEND_WIDTH + 7U) / 8U;
  header->cupsColorOrder = CUPS_ORDER_BANDED;
  header->cupsColorSpace = CUPS_CSPACE_K;
  header->cupsNumColors = 1U;
  header->cupsCompression = state->compression;
  header->cupsRowCount = 1U;
  header->cupsRowFeed = 1U;
  header->cupsRowStep = 1U;
  header->NumCopies = 1U;
  header->Duplex = state->duplex != 0U;
  header->Tumble = state->duplex == 2U;
}

static int
cf_v2_pclxend_write_raster(const char *path,
                           const cf_v2_pclxend_state_t *state)
{
  cf_v2_pclxraw_state_t raw;
  cups_raster_t *raster = NULL;
  uint8_t line[(CF_V2_PCLXEND_WIDTH + 7U) / 8U];
  int descriptor = -1;
  int ok = 0;
  unsigned int page;

  cf_v2_pclxend_raw_state(state, &raw);
  descriptor = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (descriptor < 0)
    return 0;
  raster = cupsRasterOpen(descriptor, CUPS_RASTER_WRITE);
  if (!raster)
    goto done;

  for (page = 0U; page < state->page_count; page ++)
  {
    cups_page_header2_t header;
    unsigned int row;

    cf_v2_pclxend_fill_header(&header, state);
    if (!cupsRasterWriteHeader2(raster, &header))
      goto done;
    for (row = 0U; row < CF_V2_PCLXEND_HEIGHT; row ++)
    {
      cf_v2_pclxraw_build_row(
          line, sizeof(line), &raw, cf_v2_pclxend_material,
          sizeof(cf_v2_pclxend_material), page, row,
          CF_V2_PCLXRAW_K1, CF_V2_PCLXEND_WIDTH, 1);
      if (cupsRasterWritePixels(raster, line, sizeof(line)) != sizeof(line))
        goto done;
    }
  }
  ok = 1;

done:
  if (raster)
    cupsRasterClose(raster);
  if (descriptor >= 0)
    close(descriptor);
  return ok;
}

static int
cf_v2_pclxend_install_environment(const char *ppd_path)
{
  int length = snprintf(cf_v2_pclxend_ppd_env,
                        sizeof(cf_v2_pclxend_ppd_env), "PPD=%s", ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_pclxend_ppd_env))
    return 0;
  if (cf_v2_pclxend_environment_installed)
    return 1;
  if (putenv(cf_v2_pclxend_ppd_env) != 0 ||
      putenv(cf_v2_pclxend_printer_env) != 0 ||
      putenv(cf_v2_pclxend_content_type_env) != 0)
    return 0;
  cf_v2_pclxend_environment_installed = 1;
  return 1;
}

static void
cf_v2_pclxend_reset_filter_globals(void)
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
  OutputMode = OUTPUT_BITMAP;
  logfunc = NULL;
  ld = NULL;
}

static int
cf_v2_pclxend_run_filter(const char *ppd_path, const char *raster_path,
                         const cf_v2_pclxend_state_t *state)
{
  char options[192];
  char *arguments[] = {
    (char *)"rastertopclx", (char *)"1", (char *)"libfuzzer",
    (char *)"PCLXEND1", (char *)"1", options, (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  int have_saved_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  unsigned int page;
  int status;
  int ok = 0;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=RGB MediaType=Plain "
           "Resolution=300dpi emit-jcl=false");
  if (!cf_v2_pclxend_install_environment(ppd_path))
    goto done;

  cf_v2_pclxend_capture_size = 0U;
  cf_v2_pclxend_filter_ppd = NULL;
  cf_v2_pclxend_page_log_count = 0U;
  cf_v2_pclxend_lookup_count = 0U;
  cf_v2_pclxend_template_printf_count = 0U;
  cf_v2_pclxend_expected_endjob = state->endjob;
  memset(cf_v2_pclxend_page_logs, 0, sizeof(cf_v2_pclxend_page_logs));
  status = cf_v2_pclxend_rastertopclx_main(7, arguments);
  cf_v2_pclxend_require(status == 0 && cf_v2_pclxend_filter_ppd != NULL);
  cf_v2_pclxend_require(cf_v2_pclxend_lookup_count == 1U);
  cf_v2_pclxend_require(
      cf_v2_pclxend_template_printf_count ==
      (state->endjob == CF_V2_PCLXEND_ENDJOB_MISSING ? 0U : 1U));
  cf_v2_pclxend_require(
      cf_v2_pclxend_page_log_count == state->page_count);
  for (page = 0U; page < state->page_count; page ++)
    cf_v2_pclxend_require(
        cf_v2_pclxend_page_logs[page] == (int)page + 1);
  cf_v2_pclxend_require(cf_v2_pclxend_validate_output(
      cf_v2_pclxend_capture, cf_v2_pclxend_capture_size, state));
  ok = 1;

done:
  if (cf_v2_pclxend_filter_ppd)
  {
    ppdClose(cf_v2_pclxend_filter_ppd);
    cf_v2_pclxend_filter_ppd = NULL;
  }
  cf_v2_pclxend_reset_filter_globals();
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return ok;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/pclxend1-XXXXXX";
  char ppd_path[sizeof(directory) + 16U];
  char raster_path[sizeof(directory) + 16U];
  cf_v2_pclxend_state_t state;
  const uint8_t *selector;

  if (!data || size != CF_V2_PCLXEND_INPUT_SIZE ||
      memcmp(data, CF_V2_PCLXEND_MAGIC,
             CF_V2_PCLXEND_MAGIC_SIZE) != 0)
    return 0;
  selector = data + CF_V2_PCLXEND_MAGIC_SIZE;
  cf_v2_pclxend_decode(selector, &state);
  if (!mkdtemp(directory))
    return 0;

  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_pclxend_write_ppd(ppd_path, &state) &&
      cf_v2_pclxend_verify_ppd(ppd_path, &state) &&
      cf_v2_pclxend_write_raster(raster_path, &state))
    (void)cf_v2_pclxend_run_filter(ppd_path, raster_path, &state);

  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
  return 0;
}

#endif /* !CF_V2_PCLXEND_ORACLE_ONLY */
