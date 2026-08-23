// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

/*
 * ESCPLUT1 state target: a coherent PPD + CUPS Raster continuation for the
 * rastertoescpx PPD-LUT-to-bit-plane route.
 * Target: fuzz_v2_cupsfilters_state_raster_to_escpx_ppd_lut_bitplanes.
 *
 * Input:
 *   bytes 0..7   "ESCPLUT1"
 *   byte  8      width selector
 *   byte  9      LUT cardinality/source selector
 *   byte 10      valid weave-tuple selector
 *   byte 11      ESC . / ESC i selector
 *   byte 12      requested compression selector
 *   byte 13      lifecycle-depth selector
 *   byte 14      raster-material schedule selector
 *   byte 15      material salt
 *   remaining    1..1024 bytes of cyclic raster material
 *
 * A build must define CF_V2_RASTERTOESCPX_SOURCE to the quoted,
 * current-upstream filter/rastertoescpx.c path and use the normal
 * CUPS/libppd/libcupsfilters link closure.
 */

#include <cups/cups.h>
#include <cups/raster.h>
#include <cupsfilters/driver.h>
#include <ppd/ppd.h>

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CF_V2_RASTERTOESCPX_SOURCE
#error "CF_V2_RASTERTOESCPX_SOURCE must quote filter/rastertoescpx.c"
#endif

#define CF_V2_MAGIC "ESCPLUT1"
#define CF_V2_MAGIC_SIZE 8U
#define CF_V2_SELECTOR_SIZE 8U
#define CF_V2_HEADER_SIZE (CF_V2_MAGIC_SIZE + CF_V2_SELECTOR_SIZE)
#define CF_V2_MAX_MATERIAL 1024U
#define CF_V2_MAX_CAPTURE (512U * 1024U)
#define CF_V2_MAX_BAND_TRACES 2048U

extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

typedef struct cf_v2_escpx_lut_state_s
{
  unsigned int width;
  unsigned int height;
  unsigned int lut_shape;
  unsigned int use_all_dither;
  unsigned int expected_bitplanes;
  unsigned int use_esci;
  unsigned int compression;
  unsigned int row_count;
  unsigned int row_feed;
  unsigned int row_step;
  unsigned int column_step;
  unsigned int lifecycle;
  unsigned int material_schedule;
  unsigned int material_salt;
  unsigned int bytes_per_line;
} cf_v2_escpx_lut_state_t;

typedef struct cf_v2_escpx_lut_band_trace_s
{
  int x;
  int y;
  int plane;
  int count;
  int feed;
} cf_v2_escpx_lut_band_trace_t;

typedef struct cf_v2_escpx_lut_weave_s
{
  unsigned int row_count;
  unsigned int row_feed;
  unsigned int row_step;
  unsigned int column_step;
} cf_v2_escpx_lut_weave_t;

static unsigned char cf_v2_escpx_lut_capture[CF_V2_MAX_CAPTURE];
static size_t cf_v2_escpx_lut_capture_size;
static cf_v2_escpx_lut_band_trace_t
    cf_v2_escpx_lut_band_traces[CF_V2_MAX_BAND_TRACES];
static size_t cf_v2_escpx_lut_band_trace_count;
static ppd_file_t *cf_v2_escpx_lut_filter_ppd;
static char cf_v2_escpx_lut_ppd_env[
    sizeof("PPD=/tmp/escplut1-XXXXXX/input.ppd")];
static char cf_v2_escpx_lut_printer_env[] = "PRINTER=escplut1";
static char cf_v2_escpx_lut_content_type_env[] =
    "CONTENT_TYPE=application/vnd.cups-raster";
static int cf_v2_escpx_lut_environment_installed;

static void
cf_v2_escpx_lut_require(int condition)
{
  if (!condition)
    __builtin_trap();
}

static size_t
cf_v2_escpx_lut_capture_bytes(const void *data, size_t size)
{
  cf_v2_escpx_lut_require(
      size <= CF_V2_MAX_CAPTURE - cf_v2_escpx_lut_capture_size);
  memcpy(cf_v2_escpx_lut_capture + cf_v2_escpx_lut_capture_size, data, size);
  cf_v2_escpx_lut_capture_size += size;
  return size;
}

static int
cf_v2_escpx_lut_capture_putchar(int value)
{
  const unsigned char byte = (unsigned char)value;

  (void)cf_v2_escpx_lut_capture_bytes(&byte, 1U);
  return byte;
}

static int
cf_v2_escpx_lut_capture_printf(const char *format, ...)
{
  char buffer[128];
  va_list arguments;
  int result;

  va_start(arguments, format);
  result = vsnprintf(buffer, sizeof(buffer), format, arguments);
  va_end(arguments);
  cf_v2_escpx_lut_require(result >= 0 && (size_t)result < sizeof(buffer));
  (void)cf_v2_escpx_lut_capture_bytes(buffer, (size_t)result);
  return result;
}

static int
cf_v2_escpx_lut_trace_fprintf(FILE *stream, const char *format, ...)
{
  va_list arguments;

  (void)stream;
  if (strncmp(format, "DEBUG: Printing band ", 21U) == 0)
  {
    cf_v2_escpx_lut_band_trace_t *trace;

    cf_v2_escpx_lut_require(
        cf_v2_escpx_lut_band_trace_count < CF_V2_MAX_BAND_TRACES);
    trace = &cf_v2_escpx_lut_band_traces[
        cf_v2_escpx_lut_band_trace_count ++];
    va_start(arguments, format);
    (void)va_arg(arguments, void *);
    trace->x = va_arg(arguments, int);
    trace->y = va_arg(arguments, int);
    trace->plane = va_arg(arguments, int);
    trace->count = va_arg(arguments, int);
    trace->feed = va_arg(arguments, int);
    va_end(arguments);
  }
  return 0;
}

static int
cf_v2_escpx_lut_quiet_fputs(const char *text, FILE *stream)
{
  (void)text;
  (void)stream;
  return 0;
}

static void
cf_v2_escpx_lut_quiet_log(void *data, cf_loglevel_t level,
                          const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static ppd_file_t *
cf_v2_escpx_lut_filter_ppd_open(const char *path)
{
  cf_v2_escpx_lut_filter_ppd = ppdOpenFile(path);
  return cf_v2_escpx_lut_filter_ppd;
}

#undef cfWritePrintData
#define cfWritePrintData(data, size) \
    cf_v2_escpx_lut_capture_bytes((data), (size_t)(size))
#define putchar cf_v2_escpx_lut_capture_putchar
#define printf cf_v2_escpx_lut_capture_printf
#define fprintf cf_v2_escpx_lut_trace_fprintf
#define fputs cf_v2_escpx_lut_quiet_fputs
#define cfCUPSLogFunc cf_v2_escpx_lut_quiet_log
#define ppdOpenFile cf_v2_escpx_lut_filter_ppd_open
#define main cf_v2_escpx_lut_rastertoescpx_main
#include CF_V2_RASTERTOESCPX_SOURCE
#undef main
#undef ppdOpenFile
#undef cfCUPSLogFunc
#undef fputs
#undef fprintf
#undef printf
#undef putchar
#undef cfWritePrintData

static const unsigned int cf_v2_escpx_lut_widths[] = {
  16U, 32U, 64U, 128U
};

static const cf_v2_escpx_lut_weave_t cf_v2_escpx_lut_weaves[] = {
  {1U, 1U, 1U, 1U},
  {2U, 1U, 1U, 1U},
  {4U, 0U, 1U, 1U},
  {4U, 1U, 2U, 2U}
};

static const char *const cf_v2_escpx_lut_values[] = {
  "1", "0.5 1", "0.25 0.75 1"
};

static unsigned int
cf_v2_escpx_lut_min(unsigned int left, unsigned int right)
{
  return left < right ? left : right;
}

static unsigned int
cf_v2_escpx_lut_max(unsigned int left, unsigned int right)
{
  return left > right ? left : right;
}

static int
cf_v2_escpx_lut_decode(const uint8_t *selector,
                       cf_v2_escpx_lut_state_t *state)
{
  const unsigned int lut_selector = selector[1] % 6U;
  const cf_v2_escpx_lut_weave_t *weave = &cf_v2_escpx_lut_weaves[
      selector[2] % (sizeof(cf_v2_escpx_lut_weaves) /
                     sizeof(cf_v2_escpx_lut_weaves[0]))];

  memset(state, 0, sizeof(*state));
  state->width = cf_v2_escpx_lut_widths[selector[0] %
      (sizeof(cf_v2_escpx_lut_widths) /
       sizeof(cf_v2_escpx_lut_widths[0]))];
  state->lut_shape = lut_selector % 3U;
  state->use_all_dither = lut_selector / 3U;
  state->expected_bitplanes = state->lut_shape == 0U ? 1U : 2U;
  state->row_count = weave->row_count;
  state->row_feed = weave->row_feed;
  state->row_step = weave->row_step;
  state->column_step = weave->column_step;
  state->use_esci = selector[3] & 1U;
  state->compression = selector[4] % 3U;
  state->lifecycle = selector[5] % 3U;
  state->material_schedule = selector[6] % 8U;
  state->material_salt = selector[7];
  state->bytes_per_line = state->width;

  switch (state->lifecycle)
  {
    case 0U :
        state->height = state->row_count == 1U ? 1U :
            cf_v2_escpx_lut_max(2U, state->row_step);
        break;
    case 1U :
        state->height = cf_v2_escpx_lut_max(
            2U, state->row_count * state->row_step);
        break;
    default :
        state->height = 4U * state->row_count * state->row_step +
                        state->row_step;
        break;
  }
  state->height = cf_v2_escpx_lut_min(state->height, 64U);

  return state->width % state->column_step == 0U &&
         state->row_count >= 1U && state->row_count <= 4U &&
         state->row_step >= 1U && state->row_step <= 2U &&
         state->column_step >= 1U && state->column_step <= 2U &&
         state->row_step * state->column_step <= 4U;
}

static unsigned char
cf_v2_escpx_lut_material(const uint8_t *material, size_t material_size,
                         unsigned int row, unsigned int pixel,
                         unsigned int salt)
{
  const size_t index = ((size_t)row * 131U + pixel + salt) % material_size;

  return (unsigned char)(material[index] ^
      (unsigned char)(row * 29U + pixel * 17U + salt));
}

static void
cf_v2_escpx_lut_fill_row(unsigned char *row,
                         const cf_v2_escpx_lut_state_t *state,
                         const uint8_t *material, size_t material_size,
                         unsigned int row_number)
{
  unsigned int pixel;

  switch (state->material_schedule)
  {
    case 0U :
        memset(row, 0, state->bytes_per_line);
        return;
    case 1U :
        memset(row, 0xff, state->bytes_per_line);
        return;
    case 3U :
        memset(row, (row_number & 1U) ? 0U : 0xffU,
               state->bytes_per_line);
        return;
    case 7U :
        memset(row, row_number == 0U || row_number + 1U == state->height ?
                    0xffU : 0U, state->bytes_per_line);
        return;
    default :
        break;
  }

  for (pixel = 0U; pixel < state->width; pixel ++)
  {
    switch (state->material_schedule)
    {
      case 2U :
          row[pixel] = (pixel & 1U) ? 0U : 0xffU;
          break;
      case 4U :
          row[pixel] = (unsigned char)(
              pixel * 255U / (state->width - 1U));
          break;
      case 5U :
          row[pixel] = (pixel / 8U) % 3U == 0U ? 0xffU :
                       ((pixel / 8U) % 3U == 1U ? 0x80U : 0U);
          break;
      case 6U :
          row[pixel] = (unsigned char)(0x80U |
              (cf_v2_escpx_lut_material(material, material_size, row_number,
                                        pixel, state->material_salt) & 0x7fU));
          break;
      default :
          row[pixel] = 0U;
          break;
    }
  }
}

static int
cf_v2_escpx_lut_write_raster(const char *path,
                             const cf_v2_escpx_lut_state_t *state,
                             const uint8_t *material, size_t material_size)
{
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  unsigned char *row = NULL;
  unsigned int row_number;
  int descriptor = -1;
  int ok = 0;

  descriptor = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
  if (descriptor < 0)
    return 0;
  raster = cupsRasterOpen(descriptor, CUPS_RASTER_WRITE);
  if (!raster)
    goto done;
  row = (unsigned char *)malloc(state->bytes_per_line);
  if (!row)
    goto done;

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
  header.cupsWidth = state->width;
  header.cupsHeight = state->height;
  header.cupsBitsPerColor = 8U;
  header.cupsBitsPerPixel = 8U;
  header.cupsBytesPerLine = state->bytes_per_line;
  header.cupsColorOrder = CUPS_ORDER_CHUNKED;
  header.cupsColorSpace = CUPS_CSPACE_K;
  header.cupsCompression = state->compression;
  header.cupsRowCount = state->row_count;
  header.cupsRowFeed = state->row_feed;
  header.cupsRowStep = state->column_step * 100U + state->row_step;
  header.cupsNumColors = 1U;
  header.NumCopies = 1U;

  if (!cupsRasterWriteHeader2(raster, &header))
    goto done;
  for (row_number = 0U; row_number < state->height; row_number ++)
  {
    cf_v2_escpx_lut_fill_row(row, state, material, material_size, row_number);
    if (cupsRasterWritePixels(raster, row, state->bytes_per_line) !=
        state->bytes_per_line)
      goto done;
  }
  ok = 1;

done:
  free(row);
  if (raster)
    cupsRasterClose(raster);
  if (descriptor >= 0)
    close(descriptor);
  return ok;
}

static int
cf_v2_escpx_lut_write_ppd(const char *path,
                          const cf_v2_escpx_lut_state_t *state)
{
  const unsigned int model_number =
      state->use_esci ? ESCP_RASTER_ESCI : 0U;
  const char *dither_name = state->use_all_dither ?
      "cupsAllDither" : "cupsBlackDither";
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
      "*ModelName: \"ESCPLUT1\"\n"
      "*ShortNickName: \"ESCPLUT1\"\n"
      "*NickName: \"ESCPLUT1 PPD LUT bit planes\"\n"
      "*PCFileName: \"ESCPLUT.PPD\"\n"
      "*Product: \"(ESCPLUT1)\"\n"
      "*PSVersion: \"(3010) 0\"\n"
      "*cupsVersion: 1.0\n"
      "*cupsModelNumber: %u\n"
      "*cupsManualCopies: False\n"
      "*cupsFilter: \"application/vnd.cups-raster 0 rastertoescpx\"\n"
      "*OpenUI *PageSize/Page Size: PickOne\n"
      "*DefaultPageSize: Letter\n"
      "*PageSize Letter/Letter: "
      "\"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
      "*PageSize A4/A4: "
      "\"<</PageSize[595 842]/ImagingBBox null>>setpagedevice\"\n"
      "*CloseUI: *PageSize\n"
      "*DefaultImageableArea: Letter\n"
      "*ImageableArea Letter/Letter: \"18 36 594 756\"\n"
      "*ImageableArea A4/A4: \"12 12 583 830\"\n"
      "*DefaultPaperDimension: Letter\n"
      "*PaperDimension Letter/Letter: \"612 792\"\n"
      "*PaperDimension A4/A4: \"595 842\"\n"
      "*OpenUI *ColorModel/Color: PickOne\n"
      "*DefaultColorModel: Black\n"
      "*ColorModel Black/Black: "
      "\"<</cupsColorSpace 3/cupsColorOrder 0/cupsBitsPerColor 8/"
      "cupsBitsPerPixel 8>>setpagedevice\"\n"
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
      "*cupsInkChannels Black.PLAIN.300dpi: \"1\"\n"
      "*cupsBlackXY Black.PLAIN.300dpi: \"0 0\"\n"
      "*cupsBlackXY Black.PLAIN.300dpi: \"1 1\"\n"
      "*%s Black.PLAIN.300dpi: \"%s\"\n",
      model_number, dither_name,
      cf_v2_escpx_lut_values[state->lut_shape]);
  if (fclose(file) != 0)
    return 0;
  return result >= 0;
}

static int
cf_v2_escpx_lut_verify_ppd(const char *path,
                           const cf_v2_escpx_lut_state_t *state)
{
  static const char spec[] = "Black.PLAIN.300dpi";
  const char *selected_name = state->use_all_dither ?
      "cupsAllDither" : "cupsBlackDither";
  const char *absent_name = state->use_all_dither ?
      "cupsBlackDither" : "cupsAllDither";
  ppd_file_t *ppd = ppdOpenFile(path);
  ppd_attr_t *attribute;
  cf_lut_t *lut = NULL;
  int ok = 0;

  if (!ppd)
    return 0;
  attribute = ppdFindAttr(ppd, "cupsInkChannels", spec);
  if (!attribute || !attribute->value || strcmp(attribute->value, "1") != 0)
    goto done;
  attribute = ppdFindAttr(ppd, selected_name, spec);
  if (!attribute || !attribute->value ||
      strcmp(attribute->value,
             cf_v2_escpx_lut_values[state->lut_shape]) != 0 ||
      ppdFindAttr(ppd, absent_name, spec) != NULL ||
      ppdFindAttr(ppd, "cupsESCPBlack", "300dpi") != NULL ||
      ppdFindAttr(ppd, "cupsESCPOffsets", "300dpi") != NULL ||
      !!(ppd->model_number & ESCP_RASTER_ESCI) != !!state->use_esci ||
      (ppd->model_number & ESCP_STAGGER) != 0)
    goto done;

  lut = ppdLutLoad(ppd, "Black", "PLAIN", "300dpi", "Black", NULL, NULL);
  if (!lut || (unsigned int)lut[4095].pixel !=
                  (state->lut_shape == 0U ? 1U : state->lut_shape + 1U))
    goto done;
  ok = 1;

done:
  cfLutDelete(lut);
  ppdClose(ppd);
  return ok;
}

static int
cf_v2_escpx_lut_install_environment(const char *ppd_path)
{
  int length = snprintf(cf_v2_escpx_lut_ppd_env,
                        sizeof(cf_v2_escpx_lut_ppd_env), "PPD=%s", ppd_path);

  if (length < 0 || (size_t)length >= sizeof(cf_v2_escpx_lut_ppd_env))
    return 0;
  if (cf_v2_escpx_lut_environment_installed)
    return 1;
  if (putenv(cf_v2_escpx_lut_ppd_env) != 0 ||
      putenv(cf_v2_escpx_lut_printer_env) != 0 ||
      putenv(cf_v2_escpx_lut_content_type_env) != 0)
    return 0;
  cf_v2_escpx_lut_environment_installed = 1;
  return 1;
}

static size_t
cf_v2_escpx_lut_decode_packbits(size_t position, size_t expected_size)
{
  size_t decoded = 0U;

  while (decoded < expected_size)
  {
    unsigned int control;
    size_t count;

    cf_v2_escpx_lut_require(position < cf_v2_escpx_lut_capture_size);
    control = cf_v2_escpx_lut_capture[position ++];
    if (control <= 127U)
    {
      count = (size_t)control + 1U;
      cf_v2_escpx_lut_require(
          count <= expected_size - decoded &&
          count <= cf_v2_escpx_lut_capture_size - position);
      position += count;
    }
    else
    {
      cf_v2_escpx_lut_require(
          control >= 129U && position < cf_v2_escpx_lut_capture_size);
      count = 257U - control;
      cf_v2_escpx_lut_require(count <= expected_size - decoded);
      position ++;
    }
    decoded += count;
  }
  cf_v2_escpx_lut_require(decoded == expected_size);
  return position;
}

static size_t
cf_v2_escpx_lut_verify_graphics(
    size_t position, const cf_v2_escpx_lut_state_t *state,
    unsigned int x, unsigned int rows)
{
  size_t cursor = position + 1U;
  const size_t row_bytes =
      (state->width / state->column_step * state->expected_bitplanes + 7U) /
      8U;
  size_t expected_payload;
  unsigned int compression;
  unsigned int encoded_rows;
  unsigned int encoded_row_bytes;
  unsigned int encoded_offset = 0U;

  cf_v2_escpx_lut_require(
      position < cf_v2_escpx_lut_capture_size &&
      cf_v2_escpx_lut_capture[position] == '\r');
  if (x != 0U)
  {
    if (state->expected_bitplanes == 1U)
    {
      static const unsigned char prefix[7] = {
        '\033', '(', '\\', 4, 0, 0xa0, 5
      };

      cf_v2_escpx_lut_require(
          cursor + 9U <= cf_v2_escpx_lut_capture_size &&
          memcmp(cf_v2_escpx_lut_capture + cursor, prefix,
                 sizeof(prefix)) == 0);
      encoded_offset = (unsigned int)cf_v2_escpx_lut_capture[cursor + 7U] |
          (unsigned int)cf_v2_escpx_lut_capture[cursor + 8U] << 8U;
      cursor += 9U;
    }
    else
    {
      cf_v2_escpx_lut_require(
          cursor + 4U <= cf_v2_escpx_lut_capture_size &&
          cf_v2_escpx_lut_capture[cursor] == '\033' &&
          cf_v2_escpx_lut_capture[cursor + 1U] == '\\');
      encoded_offset = (unsigned int)cf_v2_escpx_lut_capture[cursor + 2U] |
          (unsigned int)cf_v2_escpx_lut_capture[cursor + 3U] << 8U;
      cursor += 4U;
    }
  }
  cf_v2_escpx_lut_require(
      encoded_offset == x && x < state->column_step);

  if (state->use_esci)
  {
    cf_v2_escpx_lut_require(
        cursor + 9U <= cf_v2_escpx_lut_capture_size &&
        cf_v2_escpx_lut_capture[cursor] == '\033' &&
        cf_v2_escpx_lut_capture[cursor + 1U] == 'i' &&
        cf_v2_escpx_lut_capture[cursor + 2U] == 0U &&
        cf_v2_escpx_lut_capture[cursor + 4U] ==
            (unsigned char)state->expected_bitplanes);
    compression = cf_v2_escpx_lut_capture[cursor + 3U];
    encoded_row_bytes =
        (unsigned int)cf_v2_escpx_lut_capture[cursor + 5U] |
        (unsigned int)cf_v2_escpx_lut_capture[cursor + 6U] << 8U;
    encoded_rows = (unsigned int)cf_v2_escpx_lut_capture[cursor + 7U] |
        (unsigned int)cf_v2_escpx_lut_capture[cursor + 8U] << 8U;
    cursor += 9U;
  }
  else
  {
    unsigned int encoded_bits;

    cf_v2_escpx_lut_require(
        cursor + 8U <= cf_v2_escpx_lut_capture_size &&
        cf_v2_escpx_lut_capture[cursor] == '\033' &&
        cf_v2_escpx_lut_capture[cursor + 1U] == '.' &&
        cf_v2_escpx_lut_capture[cursor + 3U] ==
            (unsigned char)(12U * state->row_step) &&
        cf_v2_escpx_lut_capture[cursor + 4U] ==
            (unsigned char)(12U * state->column_step));
    compression = cf_v2_escpx_lut_capture[cursor + 2U];
    encoded_rows = cf_v2_escpx_lut_capture[cursor + 5U];
    encoded_bits = (unsigned int)cf_v2_escpx_lut_capture[cursor + 6U] |
        (unsigned int)cf_v2_escpx_lut_capture[cursor + 7U] << 8U;
    cf_v2_escpx_lut_require(encoded_bits % 8U == 0U);
    encoded_row_bytes = encoded_bits / 8U;
    cursor += 8U;
  }

  cf_v2_escpx_lut_require(
      (compression == '0' || compression == '1') &&
      encoded_row_bytes == row_bytes && encoded_rows == rows &&
      rows >= 1U && rows <= state->row_count);
  if (state->row_count > 1U && state->compression == 0U)
    cf_v2_escpx_lut_require(compression == '0');

  expected_payload = row_bytes * rows;
  cf_v2_escpx_lut_require(
      expected_payload > 0U &&
      expected_payload <= ((128U * 2U + 7U) / 8U) * 4U);
  if (compression == '0')
  {
    cf_v2_escpx_lut_require(
        expected_payload <= cf_v2_escpx_lut_capture_size - cursor);
    cursor += expected_payload;
  }
  else
    cursor = cf_v2_escpx_lut_decode_packbits(cursor, expected_payload);
  return cursor;
}

static void
cf_v2_escpx_lut_verify_output(const cf_v2_escpx_lut_state_t *state)
{
  static const unsigned char feed_prefix[5] = {'\033', '(', 'v', 2, 0};
  size_t position = 0U;
  size_t trace_index = 0U;
  unsigned int pending_feed = 0U;
  unsigned int feed_records = 0U;
  unsigned int graphics_records = 0U;

  while (position < cf_v2_escpx_lut_capture_size)
  {
    if (position + 5U <= cf_v2_escpx_lut_capture_size &&
        memcmp(cf_v2_escpx_lut_capture + position, feed_prefix,
               sizeof(feed_prefix)) == 0)
    {
      cf_v2_escpx_lut_require(
          pending_feed == 0U &&
          position + 8U <= cf_v2_escpx_lut_capture_size);
      pending_feed =
          (unsigned int)cf_v2_escpx_lut_capture[position + 5U] |
          (unsigned int)cf_v2_escpx_lut_capture[position + 6U] << 8U;
      cf_v2_escpx_lut_require(
          pending_feed > 0U && pending_feed <= state->height &&
          cf_v2_escpx_lut_capture[position + 7U] == '\r');
      feed_records ++;
      position += 7U;
      continue;
    }
    if (cf_v2_escpx_lut_capture[position] == '\r')
    {
      if (state->row_count == 1U)
      {
        position = cf_v2_escpx_lut_verify_graphics(position, state, 0U, 1U);
      }
      else
      {
        const cf_v2_escpx_lut_band_trace_t *trace;
        const unsigned int expected_feed =
            trace_index < cf_v2_escpx_lut_band_trace_count &&
            cf_v2_escpx_lut_band_traces[trace_index].feed > 0 ?
            (unsigned int)cf_v2_escpx_lut_band_traces[trace_index].feed : 0U;

        cf_v2_escpx_lut_require(
            trace_index < cf_v2_escpx_lut_band_trace_count &&
            pending_feed == expected_feed);
        trace = &cf_v2_escpx_lut_band_traces[trace_index ++];
        cf_v2_escpx_lut_require(
            trace->x >= 0 && (unsigned int)trace->x < state->column_step &&
            trace->plane == 0 && trace->count >= 1 &&
            (unsigned int)trace->count <= state->row_count);
        position = cf_v2_escpx_lut_verify_graphics(
            position, state, (unsigned int)trace->x,
            (unsigned int)trace->count);
      }
      pending_feed = 0U;
      graphics_records ++;
      continue;
    }
    cf_v2_escpx_lut_require(pending_feed == 0U);
    position ++;
  }

  cf_v2_escpx_lut_require(
      pending_feed == 0U &&
      trace_index == cf_v2_escpx_lut_band_trace_count &&
      cf_v2_escpx_lut_capture_size >= 3U &&
      cf_v2_escpx_lut_capture[cf_v2_escpx_lut_capture_size - 3U] == 12U &&
      cf_v2_escpx_lut_capture[cf_v2_escpx_lut_capture_size - 2U] == '\033' &&
      cf_v2_escpx_lut_capture[cf_v2_escpx_lut_capture_size - 1U] == '@');
  if (state->material_schedule != 0U)
    cf_v2_escpx_lut_require(graphics_records > 0U);
  if (state->row_count > 1U && state->material_schedule != 0U &&
      state->lifecycle == 2U)
    cf_v2_escpx_lut_require(feed_records > 0U);
}

static void
cf_v2_escpx_lut_reset_filter_globals(void)
{
  RGB = NULL;
  CMYK = NULL;
  PixelBuffer = NULL;
  CMYKBuffer = NULL;
  InputBuffer = NULL;
  CompBuffer = NULL;
  memset(OutputBuffers, 0, sizeof(OutputBuffers));
  memset(DotBuffers, 0, sizeof(DotBuffers));
  memset(DotBands, 0, sizeof(DotBands));
  memset(DotRowOffset, 0, sizeof(DotRowOffset));
  memset(DitherLuts, 0, sizeof(DitherLuts));
  memset(DitherStates, 0, sizeof(DitherStates));
  DotAvailList = NULL;
  DotUsedList = NULL;
  DotBufferSize = 0;
  DotRowMax = 0;
  DotColStep = 0;
  DotRowStep = 0;
  DotRowFeed = 0;
  DotRowCount = 0;
  DotRowCurrent = 0;
  DotSize = 0;
  PrinterPlanes = 0;
  BitPlanes = 0;
  PrinterTop = 0;
  PrinterLength = 0;
  OutputFeed = 0;
  Canceled = 0;
  logfunc = NULL;
  ld = NULL;
}

static int
cf_v2_escpx_lut_run_filter(const char *ppd_path, const char *raster_path,
                           const cf_v2_escpx_lut_state_t *state)
{
  char options[192];
  char *arguments[] = {
    (char *)"rastertoescpx", (char *)"1", (char *)"libfuzzer",
    (char *)"ESCPLUT1", (char *)"1", options, (char *)raster_path, NULL
  };
  struct sigaction saved_sigterm;
  const int have_saved_sigterm =
      sigaction(SIGTERM, NULL, &saved_sigterm) == 0;
  const unsigned int expected_row_bytes =
      (state->width / state->column_step * state->expected_bitplanes + 7U) /
      8U;
  int status;

  snprintf(options, sizeof(options),
           "PageSize=Letter ColorModel=Black MediaType=Plain "
           "Resolution=300dpi emit-jcl=false");
  if (!cf_v2_escpx_lut_install_environment(ppd_path))
    goto environment_done;

  cf_v2_escpx_lut_capture_size = 0U;
  cf_v2_escpx_lut_band_trace_count = 0U;
  cf_v2_escpx_lut_filter_ppd = NULL;
  srand(0x45534350U);
  status = cf_v2_escpx_lut_rastertoescpx_main(7, arguments);
  cf_v2_escpx_lut_require(
      status == 0 && cf_v2_escpx_lut_filter_ppd != NULL &&
      PrinterPlanes == 1 &&
      BitPlanes == (int)state->expected_bitplanes &&
      DotBufferSize == (int)expected_row_bytes &&
      DotRowCount == (int)state->row_count &&
      DotRowStep == (int)state->row_step &&
      DotColStep == (int)state->column_step &&
      DotRowMax == (int)(state->row_count * state->row_step) &&
      (state->row_feed == 0U ? DotRowFeed >= 1 :
       DotRowFeed == (int)state->row_feed));
  cf_v2_escpx_lut_verify_output(state);

  ppdClose(cf_v2_escpx_lut_filter_ppd);
  cf_v2_escpx_lut_filter_ppd = NULL;
  cf_v2_escpx_lut_reset_filter_globals();
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return 1;

environment_done:
  if (have_saved_sigterm)
    (void)sigaction(SIGTERM, &saved_sigterm, NULL);
  return 0;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size,
                       unsigned int seed)
{
  const size_t minimum = CF_V2_HEADER_SIZE + 1U;
  const size_t maximum = CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL;
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
  memcpy(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE);

  if ((seed & 3U) != 0U)
  {
    const size_t slot = CF_V2_MAGIC_SIZE +
        ((seed >> 2U) % CF_V2_SELECTOR_SIZE);
    const uint8_t delta = (uint8_t)(1U + ((seed >> 10U) & 0xffU));

    if (seed & (1U << 18U))
      data[slot] ^= delta;
    else
      data[slot] += delta;
    return size;
  }

  material_size = LLVMFuzzerMutate(data + CF_V2_HEADER_SIZE,
                                   size - CF_V2_HEADER_SIZE,
                                   limit - CF_V2_HEADER_SIZE);
  if (material_size == 0U)
  {
    data[CF_V2_HEADER_SIZE] = (uint8_t)seed;
    material_size = 1U;
  }
  memcpy(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE);
  return CF_V2_HEADER_SIZE + material_size;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char directory[] = "/tmp/escplut1-XXXXXX";
  char ppd_path[sizeof(directory) + 16U];
  char raster_path[sizeof(directory) + 16U];
  cf_v2_escpx_lut_state_t state;
  const uint8_t *selector;
  const uint8_t *material;
  size_t material_size;

  if (!data || size < CF_V2_HEADER_SIZE + 1U ||
      size > CF_V2_HEADER_SIZE + CF_V2_MAX_MATERIAL ||
      memcmp(data, CF_V2_MAGIC, CF_V2_MAGIC_SIZE) != 0)
    return 0;
  selector = data + CF_V2_MAGIC_SIZE;
  material = data + CF_V2_HEADER_SIZE;
  material_size = size - CF_V2_HEADER_SIZE;
  if (!cf_v2_escpx_lut_decode(selector, &state) || !mkdtemp(directory))
    return 0;

  snprintf(ppd_path, sizeof(ppd_path), "%s/input.ppd", directory);
  snprintf(raster_path, sizeof(raster_path), "%s/input.ras", directory);
  if (cf_v2_escpx_lut_write_ppd(ppd_path, &state) &&
      cf_v2_escpx_lut_verify_ppd(ppd_path, &state) &&
      cf_v2_escpx_lut_write_raster(raster_path, &state, material,
                                   material_size))
    (void)cf_v2_escpx_lut_run_filter(ppd_path, raster_path, &state);

  (void)unlink(raster_path);
  (void)unlink(ppd_path);
  (void)rmdir(directory);
  return 0;
}
