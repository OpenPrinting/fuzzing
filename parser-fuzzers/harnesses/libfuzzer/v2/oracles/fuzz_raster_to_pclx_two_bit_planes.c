// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * PCLX2BP1: valid two-bit dither planes through the real rastertopclx main.
 *
 * Input:
 *   bytes 0..7    "PCLX2BP1"
 *   bytes 8..19   channel profile, width, height, pages, compression,
 *                 row schedule, pixel pattern, LUT curve, writer flags,
 *                 duplex, resolution, and LUT-source selectors
 *   remaining     1..256 bytes of cyclic pixel material
 *
 * The boundary build keeps the production destination passed to both
 * cfPackHorizontalBit calls.  It initializes the otherwise unwritten second
 * half to the complement of the independently packed second plane, then
 * reports the known disclosure when that value reaches PCL output.
 *
 * CF_V2_PCLX2_SAFE_CONTINUATION changes only the destination of the second
 * real packing call to the matching second half.  This explicit research
 * continuation does not replace or suppress the paired boundary target.
 */

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/colormanager.h>
#include <cupsfilters/driver.h>
#include <cupsfilters/filter.h>
#include <fcntl.h>
#include <ppd/ppd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CF_V2_RASTERTOPCLX_SOURCE
#error "CF_V2_RASTERTOPCLX_SOURCE must quote filter/rastertopclx.c"
#endif
#ifndef CF_V2_PCL_COMMON_SOURCE
#error "CF_V2_PCL_COMMON_SOURCE must quote filter/pcl-common.c"
#endif

#define CF_V2_PCLX2_MAGIC "PCLX2BP1"
#define CF_V2_PCLX2_MAGIC_SIZE 8U
#define CF_V2_PCLX2_SELECTOR_SIZE 12U
#define CF_V2_PCLX2_HEADER_SIZE \
  (CF_V2_PCLX2_MAGIC_SIZE + CF_V2_PCLX2_SELECTOR_SIZE)
#define CF_V2_PCLX2_MIN_MATERIAL 1U
#define CF_V2_PCLX2_MAX_MATERIAL 256U
#define CF_V2_PCLX2_MAX_PAGES 3U
#define CF_V2_PCLX2_MAX_WIDTH 128U
#define CF_V2_PCLX2_MAX_HEIGHT 16U
#define CF_V2_PCLX2_MAX_PLANES 6U
#define CF_V2_PCLX2_MAX_PACKED ((CF_V2_PCLX2_MAX_WIDTH + 7U) / 8U)
#define CF_V2_PCLX2_MAX_RECORDS \
  (CF_V2_PCLX2_MAX_PAGES * CF_V2_PCLX2_MAX_HEIGHT * \
   CF_V2_PCLX2_MAX_PLANES * 2U)
#define CF_V2_PCLX2_MAX_CAPTURE (256U * 1024U)
#define CF_V2_PCLX2_MAX_TRANSFERS \
  (CF_V2_PCLX2_MAX_RECORDS + \
   CF_V2_PCLX2_MAX_PAGES * CF_V2_PCLX2_MAX_HEIGHT)

#define CF_V2_PCLX2_END_COLOR 1U
#define CF_V2_PCLX2_PJL 2U

typedef struct cf_v2_pclx2_state_s
{
  unsigned int profile;
  unsigned int width_index;
  unsigned int height_index;
  unsigned int page_count;
  unsigned int compression;
  unsigned int row_schedule;
  unsigned int pattern;
  unsigned int curve;
  unsigned int writer_flags;
  unsigned int duplex;
  unsigned int resolution_index;
  unsigned int lut_source;
} cf_v2_pclx2_state_t;

typedef struct cf_v2_pclx2_pack_record_s
{
  uint8_t expected[CF_V2_PCLX2_MAX_PACKED];
  size_t size;
  unsigned int page;
  unsigned int bit;
} cf_v2_pclx2_pack_record_t;

typedef struct cf_v2_pclx2_transfer_s
{
  const uint8_t *payload;
  size_t payload_size;
  uint8_t terminator;
} cf_v2_pclx2_transfer_t;

static const unsigned int cf_v2_pclx2_planes[] = {1U, 3U, 4U, 6U};
static const unsigned int cf_v2_pclx2_widths[] = {
  1U, 7U, 8U, 9U, 15U, 16U, 17U, 31U,
  32U, 33U, 63U, 64U, 65U, 127U, 128U
};
static const unsigned int cf_v2_pclx2_heights[] = {
  1U, 2U, 3U, 4U, 8U, 16U
};
static const unsigned int cf_v2_pclx2_resolutions[] = {150U, 300U, 600U};

static uint8_t cf_v2_pclx2_capture[CF_V2_PCLX2_MAX_CAPTURE];
static size_t cf_v2_pclx2_capture_size;
static cf_v2_pclx2_pack_record_t
    cf_v2_pclx2_records[CF_V2_PCLX2_MAX_RECORDS];
static size_t cf_v2_pclx2_record_count;
static unsigned int cf_v2_pclx2_current_page;
static unsigned char *cf_v2_pclx2_pair_destination;
static size_t cf_v2_pclx2_pair_size;
static unsigned int cf_v2_pclx2_pack_mismatches;
static ppd_file_t *cf_v2_pclx2_filter_ppd;
static char cf_v2_pclx2_ppd_env[
    sizeof("PPD=/tmp/pclx2bp1-XXXXXX/input.ppd")];
static char cf_v2_pclx2_printer_env[] = "PRINTER=pclx2bp1";
static char cf_v2_pclx2_content_type_env[] =
    "CONTENT_TYPE=application/vnd.cups-raster";
static int cf_v2_pclx2_environment_installed;

static void
cf_v2_pclx2_require(int condition)
{
  if (!condition)
    __builtin_trap();
}

static void
cf_v2_pclx2_decode(const uint8_t selector[CF_V2_PCLX2_SELECTOR_SIZE],
                   cf_v2_pclx2_state_t *state)
{
  state->profile = selector[0] % 4U;
  state->width_index = selector[1] %
      (sizeof(cf_v2_pclx2_widths) / sizeof(cf_v2_pclx2_widths[0]));
  state->height_index = selector[2] %
      (sizeof(cf_v2_pclx2_heights) / sizeof(cf_v2_pclx2_heights[0]));
  state->page_count = 1U + selector[3] % CF_V2_PCLX2_MAX_PAGES;
  state->compression = selector[4] % 3U;
  state->row_schedule = selector[5] % 6U;
  state->pattern = selector[6] % 8U;
  state->curve = selector[7] % 4U;
  state->writer_flags = selector[8] % 4U;
  state->duplex = selector[9] % 3U;
  state->resolution_index = selector[10] %
      (sizeof(cf_v2_pclx2_resolutions) /
       sizeof(cf_v2_pclx2_resolutions[0]));
  state->lut_source = selector[11] % 2U;
}

static unsigned int
cf_v2_pclx2_width(const cf_v2_pclx2_state_t *state)
{
  return cf_v2_pclx2_widths[state->width_index];
}

static unsigned int
cf_v2_pclx2_height(const cf_v2_pclx2_state_t *state)
{
  return cf_v2_pclx2_heights[state->height_index];
}

static unsigned int
cf_v2_pclx2_resolution(const cf_v2_pclx2_state_t *state)
{
  return cf_v2_pclx2_resolutions[state->resolution_index];
}

static unsigned int
cf_v2_pclx2_plane_count(const cf_v2_pclx2_state_t *state)
{
  return cf_v2_pclx2_planes[state->profile];
}

static int
cf_v2_pclx2_row_is_data(const cf_v2_pclx2_state_t *state,
                        unsigned int page, unsigned int row,
                        unsigned int height)
{
  switch (state->row_schedule)
  {
    case 0U : return 1;
    case 1U : return row == 0U || row + 1U == height;
    case 2U : return (row & 1U) == 0U;
    case 3U : return row == height / 2U;
    case 4U : return row >= height / 2U;
    default :
        return row < (height + 1U) / 2U ||
               (row + page + state->pattern) % 5U == 0U;
  }
}

static void
cf_v2_pclx2_pack_expected(const unsigned char *pixels, uint8_t *output,
                          int width, uint8_t clear_to, uint8_t bit)
{
  int pixel;

  memset(output, clear_to, ((size_t)width + 7U) / 8U);
  for (pixel = 0; pixel < width; pixel ++)
    if (pixels[pixel] & bit)
      output[(unsigned int)pixel / 8U] ^=
          (uint8_t)(0x80U >> ((unsigned int)pixel & 7U));
}

static void
cf_v2_pclx2_pack(const unsigned char *pixels, unsigned char *output,
                 int width, unsigned char clear_to, unsigned char bit)
{
  cf_v2_pclx2_pack_record_t *record;
  unsigned char *real_output = output;
  size_t packed_size;
#ifndef CF_V2_PCLX2_SAFE_CONTINUATION
  size_t index;
#endif

  cf_v2_pclx2_require(width > 0 && width <= (int)CF_V2_PCLX2_MAX_WIDTH);
  packed_size = ((size_t)width + 7U) / 8U;
  cf_v2_pclx2_require(cf_v2_pclx2_record_count <
                      CF_V2_PCLX2_MAX_RECORDS);
  record = &cf_v2_pclx2_records[cf_v2_pclx2_record_count ++];
  record->size = packed_size;
  record->page = cf_v2_pclx2_current_page;
  record->bit = bit;
  cf_v2_pclx2_pack_expected(pixels, record->expected, width, clear_to, bit);

  if ((cf_v2_pclx2_record_count & 1U) != 0U)
  {
    if (bit != 1U)
      cf_v2_pclx2_pack_mismatches ++;
    cf_v2_pclx2_pair_destination = output;
    cf_v2_pclx2_pair_size = packed_size;
  }
  else
  {
    if (bit != 2U || output != cf_v2_pclx2_pair_destination ||
        packed_size != cf_v2_pclx2_pair_size)
      cf_v2_pclx2_pack_mismatches ++;
#ifdef CF_V2_PCLX2_SAFE_CONTINUATION
    real_output = output + packed_size;
#else
    for (index = 0U; index < packed_size; index ++)
      output[packed_size + index] = (uint8_t)~record->expected[index];
#endif
  }

  cfPackHorizontalBit(pixels, real_output, width, clear_to, bit);
}

static size_t
cf_v2_pclx2_capture_bytes(const void *data, size_t size)
{
  cf_v2_pclx2_require(size <=
      CF_V2_PCLX2_MAX_CAPTURE - cf_v2_pclx2_capture_size);
  memcpy(cf_v2_pclx2_capture + cf_v2_pclx2_capture_size, data, size);
  cf_v2_pclx2_capture_size += size;
  return size;
}

static int
cf_v2_pclx2_capture_putchar(int value)
{
  uint8_t byte = (uint8_t)value;

  (void)cf_v2_pclx2_capture_bytes(&byte, 1U);
  return byte;
}

static int
cf_v2_pclx2_capture_printf(const char *format, ...)
{
  char buffer[512];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  cf_v2_pclx2_require(result >= 0 && (size_t)result < sizeof(buffer));
  (void)cf_v2_pclx2_capture_bytes(buffer, (size_t)result);
  return result;
}

static int
cf_v2_pclx2_capture_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;

  va_start(arguments, format);
  if (stream == stdout)
  {
    char buffer[512];
    int result = vsnprintf(buffer, sizeof(buffer), format, arguments);

    va_end(arguments);
    cf_v2_pclx2_require(result >= 0 && (size_t)result < sizeof(buffer));
    (void)cf_v2_pclx2_capture_bytes(buffer, (size_t)result);
    return result;
  }
  if (strcmp(format, "PAGE: %d %d\n") == 0)
  {
    int page = va_arg(arguments, int);
    int copies = va_arg(arguments, int);

    if (page > 0 && page <= (int)CF_V2_PCLX2_MAX_PAGES && copies == 1)
      cf_v2_pclx2_current_page = (unsigned int)page - 1U;
  }
  va_end(arguments);
  return 0;
}

static int
cf_v2_pclx2_capture_fputs(const char *text, FILE *stream)
{
  if (stream == stdout)
    (void)cf_v2_pclx2_capture_bytes(text, strlen(text));
  return 0;
}

static void
cf_v2_pclx2_quiet_log(void *data, cf_loglevel_t level,
                      const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static ppd_file_t *
cf_v2_pclx2_ppd_open(const char *path)
{
  cf_v2_pclx2_filter_ppd = ppdOpenFile(path);
  return cf_v2_pclx2_filter_ppd;
}

static cf_cm_calibration_t
cf_v2_pclx2_calibration_mode(cf_filter_data_t *data)
{
  (void)data;
  return CF_CM_CALIBRATION_DISABLED;
}

static int
cf_v2_pclx2_color_management_disabled(cf_filter_data_t *data)
{
  (void)data;
  return 0;
}

static void
cf_v2_pclx2_ignore_setbuf(FILE *stream, char *buffer)
{
  (void)stream;
  (void)buffer;
}

#undef cfWritePrintData
#define cfWritePrintData(data, size) \
  cf_v2_pclx2_capture_bytes((data), (size_t)(size))
#define cfPackHorizontalBit cf_v2_pclx2_pack
#define putchar cf_v2_pclx2_capture_putchar
#define printf cf_v2_pclx2_capture_printf
#define fprintf cf_v2_pclx2_capture_fprintf
#define fputs cf_v2_pclx2_capture_fputs
#define cfCUPSLogFunc cf_v2_pclx2_quiet_log
#define ppdOpenFile cf_v2_pclx2_ppd_open
#define cfCmGetCupsColorCalibrateMode cf_v2_pclx2_calibration_mode
#define cfCmIsPrinterCmDisabled cf_v2_pclx2_color_management_disabled
#define setbuf cf_v2_pclx2_ignore_setbuf
#define main cf_v2_pclx2_rastertopclx_main
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
#undef cfPackHorizontalBit
#undef cfWritePrintData

static const char *
cf_v2_pclx2_color_model(const cf_v2_pclx2_state_t *state)
{
  static const char *const names[] = {"Black", "CMY", "CMYK", "CMYK"};

  return names[state->profile];
}

static unsigned int
cf_v2_pclx2_source_channels(const cf_v2_pclx2_state_t *state)
{
  static const unsigned int channels[] = {1U, 3U, 4U, 4U};

  return channels[state->profile];
}

static unsigned int
cf_v2_pclx2_color_space(const cf_v2_pclx2_state_t *state)
{
  static const unsigned int spaces[] = {
    CUPS_CSPACE_K, CUPS_CSPACE_CMY, CUPS_CSPACE_CMYK, CUPS_CSPACE_CMYK
  };

  return spaces[state->profile];
}

static int
cf_v2_pclx2_write_ppd(const char *path, const cf_v2_pclx2_state_t *state)
{
  static const char *const curves[] = {
    "0.20 0.55 1.00", "0.10 0.80 1.00",
    "0.35 0.65 1.00", "0.45 0.75 1.00"
  };
  const char *model = cf_v2_pclx2_color_model(state);
  const char *curve = curves[state->curve];
  unsigned int model_number = PCL_RASTER_CRD;
  unsigned int source_channels = cf_v2_pclx2_source_channels(state);
  unsigned int resolution = cf_v2_pclx2_resolution(state);
  FILE *file;
  int result;

  if (state->writer_flags & CF_V2_PCLX2_END_COLOR)
    model_number |= PCL_RASTER_END_COLOR;
  if (state->writer_flags & CF_V2_PCLX2_PJL)
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
      "*ModelName: \"PCLX2BP1 two-bit planes\"\n"
      "*ShortNickName: \"PCLX2BP1\"\n"
      "*NickName: \"PCLX2BP1 semantic block\"\n"
      "*PCFileName: \"PCLX2BP.PPD\"\n"
      "*Product: \"(PCLX2BP1)\"\n"
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
      "*DefaultImageableArea: Letter\n"
      "*ImageableArea Letter: \"18 36 594 756\"\n"
      "*DefaultPaperDimension: Letter\n"
      "*PaperDimension Letter: \"612 792\"\n"
      "*OpenUI *ColorModel/Color Model: PickOne\n"
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
      "*DefaultResolution: %udpi\n"
      "*Resolution %udpi/%u dpi: "
      "\"<</HWResolution[%u %u]>>setpagedevice\"\n"
      "*CloseUI: *Resolution\n"
      "*cupsAllDither %s.PLAIN.%udpi: \"%s\"\n",
      model_number, model, model, model, cf_v2_pclx2_color_space(state),
      source_channels * 8U, resolution, resolution, resolution, resolution,
      resolution, model, resolution, curve);
  if (result >= 0 && state->lut_source)
  {
    static const char *const inks[] = {
      "Black", "Cyan", "Magenta", "Yellow", "LightCyan", "LightMagenta"
    };
    unsigned int ink;

    for (ink = 0U; ink < cf_v2_pclx2_plane_count(state); ink ++)
      if (fprintf(file, "*cups%sDither %s.PLAIN.%udpi: \"%s\"\n",
                  inks[ink], model, resolution, curve) < 0)
        result = -1;
  }
  if (result >= 0 && state->profile == 3U)
    result = fprintf(
        file,
        "*cupsInkChannels CMYK.PLAIN.%udpi: \"6\"\n"
        "*cupsAllGamma CMYK.PLAIN.%udpi: \"1.0 1.0\"\n"
        "*cupsAllXY CMYK.PLAIN.%udpi: \"0 0\"\n"
        "*cupsAllXY CMYK.PLAIN.%udpi: \"1 1\"\n"
        "*cupsCyanLtDk CMYK.PLAIN.%udpi: \"0.30 0.70\"\n"
        "*cupsMagentaLtDk CMYK.PLAIN.%udpi: \"0.25 0.75\"\n",
        resolution, resolution, resolution, resolution, resolution,
        resolution);
  if (fclose(file) != 0)
    return 0;
  return result >= 0;
}

static uint8_t
cf_v2_pclx2_material(const uint8_t *material, size_t material_size,
                     unsigned int page, unsigned int row,
                     unsigned int pixel, unsigned int channel)
{
  size_t offset = (size_t)page * 1031U + (size_t)row * 257U +
                  (size_t)pixel * 17U + (size_t)channel * 5U;

  return material[offset % material_size];
}

static void
cf_v2_pclx2_fill_row(uint8_t *line, const cf_v2_pclx2_state_t *state,
                     const uint8_t *material, size_t material_size,
                     unsigned int page, unsigned int row, int data_row)
{
  unsigned int width = cf_v2_pclx2_width(state);
  unsigned int channels = cf_v2_pclx2_source_channels(state);
  unsigned int pixel;

  memset(line, 0, (size_t)width * channels);
  if (!data_row)
    return;
  for (pixel = 0U; pixel < width; pixel ++)
  {
    unsigned int channel;

    for (channel = 0U; channel < channels; channel ++)
    {
      uint8_t value = cf_v2_pclx2_material(
          material, material_size, page, row, pixel, channel);

      switch (state->pattern)
      {
        case 0U : value = 0xffU; break;
        case 1U : value = (pixel & 1U) ? 0xffU : 0x40U; break;
        case 2U : value = (channel == (pixel + row) % channels) ? 0xffU : 0U;
                  break;
        case 3U : value = (uint8_t)((pixel * 255U) /
                              (width > 1U ? width - 1U : 1U)); break;
        case 4U : value = (uint8_t)(0x20U + channel * 0x31U); break;
        case 5U : value = (uint8_t)((pixel * 37U + row * 19U +
                                     channel * 53U) & 0xffU); break;
        case 6U : value = (pixel + row + channel) & 1U ? 0xaaU : 0x55U;
                  break;
        default : value |= 1U; break;
      }
      line[(size_t)pixel * channels + channel] = value;
    }
  }
  line[channels - 1U] = 0xffU;
}

static int
cf_v2_pclx2_write_raster(const char *path,
                         const cf_v2_pclx2_state_t *state,
                         const uint8_t *material, size_t material_size)
{
  uint8_t line[CF_V2_PCLX2_MAX_WIDTH * 4U];
  cups_raster_t *raster = NULL;
  int descriptor = -1;
  int ok = 0;
  unsigned int page;

  descriptor = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (descriptor < 0)
    return 0;
  raster = cupsRasterOpen(descriptor, CUPS_RASTER_WRITE);
  if (!raster)
    goto done;
  for (page = 0U; page < state->page_count; page ++)
  {
    cups_page_header2_t header;
    unsigned int channels = cf_v2_pclx2_source_channels(state);
    unsigned int width = cf_v2_pclx2_width(state);
    unsigned int height = cf_v2_pclx2_height(state);
    unsigned int row;

    memset(&header, 0, sizeof(header));
    memcpy(header.MediaClass, "PwgRaster", sizeof("PwgRaster"));
    memcpy(header.MediaType, "PLAIN", sizeof("PLAIN"));
    memcpy(header.cupsPageSizeName, "Letter", sizeof("Letter"));
    header.HWResolution[0] = cf_v2_pclx2_resolution(state);
    header.HWResolution[1] = cf_v2_pclx2_resolution(state);
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
    header.cupsBitsPerPixel = channels * 8U;
    header.cupsBytesPerLine = width * channels;
    header.cupsColorOrder = CUPS_ORDER_CHUNKED;
    header.cupsColorSpace = cf_v2_pclx2_color_space(state);
    header.cupsCompression = state->compression;
    header.cupsNumColors = channels;
    header.NumCopies = 1U;
    header.Duplex = state->duplex != 0U;
    header.Tumble = state->duplex == 2U;
    if (!cupsRasterWriteHeader2(raster, &header))
      goto done;
    for (row = 0U; row < height; row ++)
    {
      cf_v2_pclx2_fill_row(
          line, state, material, material_size, page, row,
          cf_v2_pclx2_row_is_data(state, page, row, height));
      if (cupsRasterWritePixels(raster, line, header.cupsBytesPerLine) !=
          header.cupsBytesPerLine)
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
cf_v2_pclx2_parse_transfers(cf_v2_pclx2_transfer_t *transfers,
                            size_t *transfer_count)
{
  size_t position = 0U;
  size_t count = 0U;

  while (position + 5U <= cf_v2_pclx2_capture_size)
  {
    size_t cursor;
    size_t length = 0U;
    int have_digit = 0;

    if (cf_v2_pclx2_capture[position] != 0x1bU ||
        cf_v2_pclx2_capture[position + 1U] != '*' ||
        cf_v2_pclx2_capture[position + 2U] != 'b')
    {
      position ++;
      continue;
    }
    cursor = position + 3U;
    while (cursor < cf_v2_pclx2_capture_size &&
           cf_v2_pclx2_capture[cursor] >= '0' &&
           cf_v2_pclx2_capture[cursor] <= '9')
    {
      size_t digit = (size_t)(cf_v2_pclx2_capture[cursor] - '0');

      if (length > (CF_V2_PCLX2_MAX_CAPTURE - digit) / 10U)
        return 0;
      length = length * 10U + digit;
      have_digit = 1;
      cursor ++;
    }
    if (!have_digit || cursor >= cf_v2_pclx2_capture_size ||
        (cf_v2_pclx2_capture[cursor] != 'V' &&
         cf_v2_pclx2_capture[cursor] != 'W'))
    {
      position ++;
      continue;
    }
    if (count >= CF_V2_PCLX2_MAX_TRANSFERS ||
        length > cf_v2_pclx2_capture_size - cursor - 1U)
      return 0;
    transfers[count].terminator = cf_v2_pclx2_capture[cursor];
    transfers[count].payload = cf_v2_pclx2_capture + cursor + 1U;
    transfers[count].payload_size = length;
    count ++;
    position = cursor + 1U + length;
  }
  *transfer_count = count;
  return 1;
}

static int
cf_v2_pclx2_decode_transfer(const cf_v2_pclx2_transfer_t *transfer,
                            unsigned int compression, uint8_t *decoded,
                            size_t decoded_size)
{
  size_t input = 0U;
  size_t output = 0U;

  if (compression == 0U)
  {
    if (transfer->payload_size == 0U)
      memset(decoded, 0, decoded_size);
    else if (transfer->payload_size == decoded_size)
      memcpy(decoded, transfer->payload, decoded_size);
    else
      return 0;
    return 1;
  }
  while (input < transfer->payload_size)
  {
    uint8_t control = transfer->payload[input ++];
    size_t count;

    if (compression == 1U)
    {
      count = (size_t)control + 1U;
      if (input >= transfer->payload_size || count > decoded_size - output)
        return 0;
      memset(decoded + output, transfer->payload[input ++], count);
      output += count;
    }
    else if (compression == 2U && control <= 127U)
    {
      count = (size_t)control + 1U;
      if (count > transfer->payload_size - input ||
          count > decoded_size - output)
        return 0;
      memcpy(decoded + output, transfer->payload + input, count);
      input += count;
      output += count;
    }
    else if (compression == 2U && control >= 129U)
    {
      count = 257U - (size_t)control;
      if (input >= transfer->payload_size || count > decoded_size - output)
        return 0;
      memset(decoded + output, transfer->payload[input ++], count);
      output += count;
    }
    else
      return 0;
  }
  return output == decoded_size;
}

static size_t
cf_v2_pclx2_find(const uint8_t *needle, size_t needle_size, size_t start)
{
  size_t position;

  if (!needle_size || start > cf_v2_pclx2_capture_size ||
      needle_size > cf_v2_pclx2_capture_size - start)
    return SIZE_MAX;
  for (position = start;
       position <= cf_v2_pclx2_capture_size - needle_size; position ++)
    if (memcmp(cf_v2_pclx2_capture + position, needle, needle_size) == 0)
      return position;
  return SIZE_MAX;
}

static int
cf_v2_pclx2_validate_crd(const cf_v2_pclx2_state_t *state)
{
  char command[16];
  unsigned int planes = cf_v2_pclx2_plane_count(state);
  unsigned int resolution = cf_v2_pclx2_resolution(state);
  size_t position = 0U;
  unsigned int page;
  int command_size = snprintf(command, sizeof(command), "\033*g%uW",
                              planes * 6U + 2U);

  if (command_size <= 0 || (size_t)command_size >= sizeof(command))
    return 0;
  for (page = 0U; page < state->page_count; page ++)
  {
    unsigned int plane;
    size_t descriptor;

    position = cf_v2_pclx2_find((const uint8_t *)command,
                                (size_t)command_size, position);
    if (position == SIZE_MAX)
      return 0;
    descriptor = position + (size_t)command_size;
    if (2U + planes * 6U > cf_v2_pclx2_capture_size - descriptor ||
        cf_v2_pclx2_capture[descriptor] != 2U ||
        cf_v2_pclx2_capture[descriptor + 1U] != planes)
      return 0;
    for (plane = 0U; plane < planes; plane ++)
    {
      size_t offset = descriptor + 2U + plane * 6U;

      if (cf_v2_pclx2_capture[offset] != (uint8_t)(resolution >> 8U) ||
          cf_v2_pclx2_capture[offset + 1U] != (uint8_t)resolution ||
          cf_v2_pclx2_capture[offset + 2U] !=
              (uint8_t)(resolution >> 8U) ||
          cf_v2_pclx2_capture[offset + 3U] != (uint8_t)resolution ||
          cf_v2_pclx2_capture[offset + 4U] != 0U ||
          cf_v2_pclx2_capture[offset + 5U] != 4U)
        return 0;
    }
    position = descriptor + 2U + planes * 6U;
  }
  return cf_v2_pclx2_find((const uint8_t *)command,
                          (size_t)command_size, position) == SIZE_MAX;
}

static int
cf_v2_pclx2_validate_output(const cf_v2_pclx2_state_t *state,
                            int *disclosure_seen)
{
  cf_v2_pclx2_transfer_t transfers[CF_V2_PCLX2_MAX_TRANSFERS];
  size_t transfer_count = 0U;
  size_t transfer_index = 0U;
  size_t record_index = 0U;
  unsigned int planes = cf_v2_pclx2_plane_count(state);
  unsigned int height = cf_v2_pclx2_height(state);
  unsigned int page;

  *disclosure_seen = 0;
  if (!cf_v2_pclx2_validate_crd(state) ||
      !cf_v2_pclx2_parse_transfers(transfers, &transfer_count))
    return 0;
  for (page = 0U; page < state->page_count; page ++)
  {
    unsigned int pending_blank = 0U;
    unsigned int row;

    for (row = 0U; row < height; row ++)
    {
      unsigned int call;

      if (!cf_v2_pclx2_row_is_data(state, page, row, height))
      {
        pending_blank ++;
        continue;
      }
      while (pending_blank > 0U)
      {
        if (transfer_index >= transfer_count ||
            transfers[transfer_index].terminator != 'W' ||
            transfers[transfer_index].payload_size != 0U)
          return 0;
        transfer_index ++;
        pending_blank --;
      }
      for (call = 0U; call < planes * 2U; call ++)
      {
        const cf_v2_pclx2_pack_record_t *record;
        uint8_t decoded[CF_V2_PCLX2_MAX_PACKED];
        uint8_t terminator = call + 1U == planes * 2U ? 'W' : 'V';
        size_t index;
        int exact = 1;
#ifndef CF_V2_PCLX2_SAFE_CONTINUATION
        int complement = 1;
#endif

        if (record_index >= cf_v2_pclx2_record_count ||
            transfer_index >= transfer_count)
          return 0;
        record = &cf_v2_pclx2_records[record_index ++];
        if (record->page != page ||
            record->bit != ((call & 1U) ? 2U : 1U) ||
            transfers[transfer_index].terminator != terminator ||
            !cf_v2_pclx2_decode_transfer(
                &transfers[transfer_index], state->compression, decoded,
                record->size))
          return 0;
        for (index = 0U; index < record->size; index ++)
        {
          if (decoded[index] != record->expected[index])
            exact = 0;
#ifndef CF_V2_PCLX2_SAFE_CONTINUATION
          if (decoded[index] != (uint8_t)~record->expected[index])
            complement = 0;
#endif
        }
#ifdef CF_V2_PCLX2_SAFE_CONTINUATION
        if (!exact)
          return 0;
#else
        if ((call & 1U) == 0U)
        {
          if (!exact)
            return 0;
        }
        else
        {
          if (!complement)
            return 0;
          *disclosure_seen = 1;
        }
#endif
        transfer_index ++;
      }
    }
  }
  return record_index == cf_v2_pclx2_record_count &&
         transfer_index == transfer_count;
}

static int
cf_v2_pclx2_install_environment(const char *ppd_path)
{
  int length = snprintf(cf_v2_pclx2_ppd_env,
                        sizeof(cf_v2_pclx2_ppd_env), "PPD=%s", ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_pclx2_ppd_env))
    return 0;
  if (cf_v2_pclx2_environment_installed)
    return 1;
  if (putenv(cf_v2_pclx2_ppd_env) != 0 ||
      putenv(cf_v2_pclx2_printer_env) != 0 ||
      putenv(cf_v2_pclx2_content_type_env) != 0)
    return 0;
  cf_v2_pclx2_environment_installed = 1;
  return 1;
}

static void
cf_v2_pclx2_reset_filter_globals(void)
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
cf_v2_pclx2_run_filter(const char *ppd_path, const char *raster_path,
                       const cf_v2_pclx2_state_t *state)
{
  char options[192];
  char *arguments[] = {
    (char *)"rastertopclx", (char *)"1", (char *)"libfuzzer",
    (char *)"PCLX2BP1", (char *)"1", options, (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  int have_saved_sigterm = sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  int disclosure_seen = 0;
  int status;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=%s MediaType=Plain "
           "Resolution=%udpi emit-jcl=false",
           cf_v2_pclx2_color_model(state), cf_v2_pclx2_resolution(state));
  if (!cf_v2_pclx2_install_environment(ppd_path))
    return 0;
  cf_v2_pclx2_capture_size = 0U;
  cf_v2_pclx2_record_count = 0U;
  cf_v2_pclx2_current_page = 0U;
  cf_v2_pclx2_pair_destination = NULL;
  cf_v2_pclx2_pair_size = 0U;
  cf_v2_pclx2_pack_mismatches = 0U;
  cf_v2_pclx2_filter_ppd = NULL;
  status = cf_v2_pclx2_rastertopclx_main(7, arguments);
  cf_v2_pclx2_require(status == 0 && cf_v2_pclx2_filter_ppd != NULL &&
                      cf_v2_pclx2_pack_mismatches == 0U &&
                      (cf_v2_pclx2_record_count & 1U) == 0U &&
                      cf_v2_pclx2_validate_output(state, &disclosure_seen));
#ifndef CF_V2_PCLX2_SAFE_CONTINUATION
  if (disclosure_seen)
    __builtin_trap();
#else
  cf_v2_pclx2_require(!disclosure_seen);
#endif
  if (cf_v2_pclx2_filter_ppd)
  {
    ppdClose(cf_v2_pclx2_filter_ppd);
    cf_v2_pclx2_filter_ppd = NULL;
  }
  cf_v2_pclx2_reset_filter_globals();
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/pclx2bp1-XXXXXX";
  char ppd_path[sizeof(directory) + sizeof("/input.ppd")];
  char raster_path[sizeof(directory) + sizeof("/input.ras")];
  uint8_t selector[CF_V2_PCLX2_SELECTOR_SIZE] = {0};
  static const uint8_t fallback_material = 0x5aU;
  const uint8_t *material = &fallback_material;
  size_t material_size = 1U;
  cf_v2_pclx2_state_t state;

  if (!data || size < CF_V2_PCLX2_MAGIC_SIZE ||
      size > CF_V2_PCLX2_HEADER_SIZE + CF_V2_PCLX2_MAX_MATERIAL ||
      memcmp(data, CF_V2_PCLX2_MAGIC, CF_V2_PCLX2_MAGIC_SIZE) != 0)
    return 0;
  if (size > CF_V2_PCLX2_MAGIC_SIZE)
  {
    size_t selector_size = size - CF_V2_PCLX2_MAGIC_SIZE;

    if (selector_size > sizeof(selector))
      selector_size = sizeof(selector);
    memcpy(selector, data + CF_V2_PCLX2_MAGIC_SIZE, selector_size);
  }
  if (size > CF_V2_PCLX2_HEADER_SIZE)
  {
    material = data + CF_V2_PCLX2_HEADER_SIZE;
    material_size = size - CF_V2_PCLX2_HEADER_SIZE;
  }
  cf_v2_pclx2_decode(selector, &state);
  if (!mkdtemp(directory))
    return 0;
  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_pclx2_write_ppd(ppd_path, &state) &&
      cf_v2_pclx2_write_raster(
          raster_path, &state, material, material_size))
    (void)cf_v2_pclx2_run_filter(ppd_path, raster_path, &state);
  if (cf_v2_pclx2_filter_ppd)
  {
    ppdClose(cf_v2_pclx2_filter_ppd);
    cf_v2_pclx2_filter_ppd = NULL;
  }
  cf_v2_pclx2_reset_filter_globals();
  unlink(raster_path);
  unlink(ppd_path);
  rmdir(directory);
  return 0;
}
