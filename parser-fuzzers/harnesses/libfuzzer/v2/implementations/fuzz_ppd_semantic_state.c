// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_ppd_semantic_test_one_input
#define LIBPPD_SEMANTIC_DEEP_MODE
#define LIBPPD_SEMANTIC_MAX_INPUT (32U * 1024U)
#include "../../fuzz_libppd_semantic.c"
#undef LLVMFuzzerTestOneInput

#define CF_V2_PPD_STATE_MAGIC "PPDSTAT1"
#define CF_V2_PPD_STATE_MAGIC_SIZE 8U
#define CF_V2_PPD_STATE_SELECTORS 16U
#define CF_V2_PPD_STATE_MAX_PAYLOAD 64U
#define CF_V2_PPD_TEXT_SIZE (32U * 1024U)

typedef struct
{
  const char *name;
  unsigned int width;
  unsigned int height;
  unsigned int left;
  unsigned int bottom;
  unsigned int right;
  unsigned int top;
} cf_v2_ppd_media_t;

typedef struct
{
  const char *name;
  unsigned int space;
  unsigned int bits_per_pixel;
} cf_v2_ppd_color_t;

static int
cf_v2_ppd_append(char *buffer, size_t capacity, size_t *used,
                 const char *format, ...)
{
  va_list args;
  int length;

  if (*used >= capacity)
    return 0;

  va_start(args, format);
  length = vsnprintf(buffer + *used, capacity - *used, format, args);
  va_end(args);
  if (length < 0 || (size_t)length >= capacity - *used)
    return 0;

  *used += (size_t)length;
  return 1;
}

static size_t
cf_v2_build_ppd(const uint8_t *selector, const uint8_t *payload,
                size_t payload_size, char *ppd, size_t ppd_size)
{
  static const cf_v2_ppd_media_t media[] = {
    {"Letter", 612U, 792U, 18U, 36U, 594U, 756U},
    {"A4", 595U, 842U, 12U, 12U, 583U, 830U},
    {"Photo4x6", 288U, 432U, 9U, 9U, 279U, 423U},
  };
  static const unsigned int resolutions[] = {150U, 300U, 600U, 1200U};
  static const cf_v2_ppd_color_t colors[] = {
    {"Gray", 18U, 8U},
    {"RGB", 1U, 24U},
    {"CMYK", 6U, 32U},
  };
  static const char *const duplex[] = {
    "None", "DuplexNoTumble", "DuplexTumble",
  };
  static const char *const slots[] = {"Auto", "Cassette", "Manual"};
  static const char *const types[] = {"Plain", "Gloss", "Labels"};
  static const char *const bins[] = {"StandardBin", "FaceUp"};
  static const char *const filters[] = {
    "application/pdf application/vnd.cups-raster 0 pdftoraster",
    "image/png application/vnd.cups-raster 10 imagetoraster",
    "application/vnd.cups-raster application/vnd.hp-pcl 20 rastertopclx",
  };
  const cf_v2_ppd_media_t *default_media =
      media + selector[0] % (sizeof(media) / sizeof(media[0]));
  const unsigned int default_resolution =
      resolutions[selector[1] %
                  (sizeof(resolutions) / sizeof(resolutions[0]))];
  const cf_v2_ppd_color_t *default_color =
      colors + selector[2] % (sizeof(colors) / sizeof(colors[0]));
  const char *default_duplex =
      duplex[selector[3] % (sizeof(duplex) / sizeof(duplex[0]))];
  const char *default_slot =
      slots[selector[4] % (sizeof(slots) / sizeof(slots[0]))];
  const char *default_type =
      types[selector[5] % (sizeof(types) / sizeof(types[0]))];
  const char *default_bin =
      bins[selector[6] % (sizeof(bins) / sizeof(bins[0]))];
  uint64_t state_hash = libppd_hash(selector, CF_V2_PPD_STATE_SELECTORS);
  size_t used = 0;
  size_t index;

  if (payload_size)
    state_hash ^= libppd_hash(payload, payload_size);

  if (!cf_v2_ppd_append(
          ppd, ppd_size, &used,
          "*PPD-Adobe: \"4.3\"\n"
          "*FormatVersion: \"4.3\"\n"
          "*FileVersion: \"2.0\"\n"
          "*LanguageVersion: English\n"
          "*LanguageEncoding: ISOLatin1\n"
          "*Manufacturer: \"OpenPrinting\"\n"
          "*ModelName: \"semantic state printer\"\n"
          "*ShortNickName: \"semantic state\"\n"
          "*NickName: \"semantic state printer %016llx\"\n"
          "*PCFileName: \"PPDSTATE.PPD\"\n"
          "*Product: \"(semantic state printer)\"\n"
          "*PSVersion: \"(3010) 0\"\n"
          "*LanguageLevel: \"3\"\n"
          "*ColorDevice: True\n"
          "*cupsVersion: 2.0\n"
          "*cupsModelNumber: %u\n"
          "*cupsManualCopies: False\n"
          "*cupsFilter2: \"%s\"\n",
          (unsigned long long)state_hash, (unsigned int)(selector[13] % 8U),
          filters[selector[13] % (sizeof(filters) / sizeof(filters[0]))]))
    return 0;

  if (!cf_v2_ppd_append(ppd, ppd_size, &used,
          "*OpenUI *PageSize/Media Size: PickOne\n"
          "*OrderDependency: 10 AnySetup *PageSize\n"
          "*DefaultPageSize: %s\n",
          default_media->name))
    return 0;
  for (index = 0; index < sizeof(media) / sizeof(media[0]); index++)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*PageSize %s/%s: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n",
            media[index].name, media[index].name, media[index].width,
            media[index].height))
      return 0;
  if (!cf_v2_ppd_append(ppd, ppd_size, &used,
                        "*CloseUI: *PageSize\n"
                        "*OpenUI *PageRegion/Media Region: PickOne\n"
                        "*DefaultPageRegion: %s\n",
                        default_media->name))
    return 0;
  for (index = 0; index < sizeof(media) / sizeof(media[0]); index++)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*PageRegion %s/%s: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n",
            media[index].name, media[index].name, media[index].width,
            media[index].height))
      return 0;
  if (!cf_v2_ppd_append(ppd, ppd_size, &used,
                        "*CloseUI: *PageRegion\n"
                        "*DefaultImageableArea: %s\n",
                        default_media->name))
    return 0;
  for (index = 0; index < sizeof(media) / sizeof(media[0]); index++)
    if (!cf_v2_ppd_append(ppd, ppd_size, &used,
            "*ImageableArea %s: \"%u %u %u %u\"\n",
            media[index].name, media[index].left, media[index].bottom,
            media[index].right, media[index].top))
      return 0;
  if (!cf_v2_ppd_append(ppd, ppd_size, &used,
                        "*DefaultPaperDimension: %s\n",
                        default_media->name))
    return 0;
  for (index = 0; index < sizeof(media) / sizeof(media[0]); index++)
    if (!cf_v2_ppd_append(ppd, ppd_size, &used,
            "*PaperDimension %s: \"%u %u\"\n", media[index].name,
            media[index].width, media[index].height))
      return 0;

  if (!cf_v2_ppd_append(ppd, ppd_size, &used,
          "*OpenUI *Resolution/Resolution: PickOne\n"
          "*OrderDependency: 20 AnySetup *Resolution\n"
          "*DefaultResolution: %udpi\n",
          default_resolution))
    return 0;
  for (index = 0;
       index < sizeof(resolutions) / sizeof(resolutions[0]); index++)
    if (!cf_v2_ppd_append(ppd, ppd_size, &used,
            "*Resolution %udpi/%u dpi: \"<</HWResolution[%u %u]>>setpagedevice\"\n",
            resolutions[index], resolutions[index], resolutions[index],
            resolutions[index]))
      return 0;
  if (!cf_v2_ppd_append(ppd, ppd_size, &used,
          "*CloseUI: *Resolution\n"
          "*OpenUI *ColorModel/Color Mode: PickOne\n"
          "*OrderDependency: 30 AnySetup *ColorModel\n"
          "*DefaultColorModel: %s\n",
          default_color->name))
    return 0;
  for (index = 0; index < sizeof(colors) / sizeof(colors[0]); index++)
    if (!cf_v2_ppd_append(ppd, ppd_size, &used,
            "*ColorModel %s/%s: \"<</cupsColorSpace %u/cupsColorOrder 0/cupsBitsPerColor 8/cupsBitsPerPixel %u>>setpagedevice\"\n",
            colors[index].name, colors[index].name, colors[index].space,
            colors[index].bits_per_pixel))
      return 0;

  if (!cf_v2_ppd_append(
          ppd, ppd_size, &used,
          "*CloseUI: *ColorModel\n"
          "*OpenUI *Duplex/Two-Sided Printing: PickOne\n"
          "*OrderDependency: 40 AnySetup *Duplex\n"
          "*DefaultDuplex: %s\n"
          "*Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n"
          "*Duplex DuplexNoTumble/Long Edge: \"<</Duplex true/Tumble false>>setpagedevice\"\n"
          "*Duplex DuplexTumble/Short Edge: \"<</Duplex true/Tumble true>>setpagedevice\"\n"
          "*CloseUI: *Duplex\n"
          "*OpenUI *InputSlot/Media Source: PickOne\n"
          "*DefaultInputSlot: %s\n"
          "*InputSlot Auto/Automatic: \"<</MediaPosition 7>>setpagedevice\"\n"
          "*InputSlot Cassette/Main Tray: \"<</MediaPosition 0>>setpagedevice\"\n"
          "*InputSlot Manual/Manual Feed: \"<</MediaPosition 3>>setpagedevice\"\n"
          "*CloseUI: *InputSlot\n"
          "*OpenUI *MediaType/Media Type: PickOne\n"
          "*DefaultMediaType: %s\n"
          "*MediaType Plain/Plain Paper: \"<</MediaType(Plain)>>setpagedevice\"\n"
          "*MediaType Gloss/Glossy Photo: \"<</MediaType(Gloss)>>setpagedevice\"\n"
          "*MediaType Labels/Labels: \"<</MediaType(Labels)>>setpagedevice\"\n"
          "*CloseUI: *MediaType\n"
          "*OpenUI *OutputBin/Output Bin: PickOne\n"
          "*DefaultOutputBin: %s\n"
          "*OutputBin StandardBin/Standard Bin: \"\"\n"
          "*OutputBin FaceUp/Face Up: \"\"\n"
          "*CloseUI: *OutputBin\n",
          default_duplex, default_slot, default_type, default_bin))
    return 0;

  if (selector[7] & 1U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*UIConstraints: \"*InputSlot Manual *Duplex DuplexNoTumble\"\n"
            "*UIConstraints: \"*Duplex DuplexNoTumble *InputSlot Manual\"\n"))
      return 0;
  if (selector[7] & 2U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*NonUIConstraints: \"*PageSize Photo4x6 *OutputBin FaceUp\"\n"
            "*NonUIConstraints: \"*OutputBin FaceUp *PageSize Photo4x6\"\n"))
      return 0;

  switch (selector[8] % 4U)
  {
    case 1:
      if (!cf_v2_ppd_append(
              ppd, ppd_size, &used,
              "*OpenUI *Tuning/Tuning: PickOne\n"
              "*DefaultTuning: Standard\n"
              "*Tuning Standard/Standard: \"\"\n"
              "*CloseUI: *Tuning\n"
              "*CustomTuning True/Custom: \"pop pop\"\n"
              "*ParamCustomTuning Level/Level: 1 int -100 100\n"
              "*ParamCustomTuning Scalar/Scalar: 2 real -1000 1000\n"))
        return 0;
      break;
    case 2:
      if (!cf_v2_ppd_append(
              ppd, ppd_size, &used,
              "*OpenUI *Tuning/Tuning: PickOne\n"
              "*DefaultTuning: Standard\n"
              "*Tuning Standard/Standard: \"\"\n"
              "*CloseUI: *Tuning\n"
              "*CustomTuning True/Custom: \"pop pop pop pop pop pop pop pop\"\n"
              "*ParamCustomTuning Curve/Curve: 1 curve 0.1 10\n"
              "*ParamCustomTuning Integer/Integer: 2 int -100 100\n"
              "*ParamCustomTuning Inverse/Inverse: 3 invcurve 0.1 10\n"
              "*ParamCustomTuning Passcode/Passcode: 4 passcode 1 16\n"
              "*ParamCustomTuning Password/Password: 5 password 1 32\n"
              "*ParamCustomTuning Measure/Measure: 6 points 0 1000\n"
              "*ParamCustomTuning Scalar/Scalar: 7 real -1000 1000\n"
              "*ParamCustomTuning Text/Text: 8 string 0 80\n"))
        return 0;
      break;
    case 3:
      if (!cf_v2_ppd_append(
              ppd, ppd_size, &used,
              "*VariablePaperSize: True\n"
              "*ParamCustomPageSize Width: 1 points 36 1000\n"
              "*ParamCustomPageSize Height: 2 points 36 1000\n"
              "*ParamCustomPageSize WidthOffset: 3 points 0 0\n"
              "*ParamCustomPageSize HeightOffset: 4 points 0 0\n"
              "*ParamCustomPageSize Orientation: 5 int 0 3\n"
              "*CustomPageSize True: \"pop pop pop pop pop\"\n"))
        return 0;
      break;
    default:
      break;
  }

  if ((selector[9] & 1U) && selector[8] % 4U != 3U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*VariablePaperSize: True\n"
            "*ParamCustomPageSize Width: 1 points 36 1000\n"
            "*ParamCustomPageSize Height: 2 points 36 1000\n"
            "*ParamCustomPageSize WidthOffset: 3 points 0 0\n"
            "*ParamCustomPageSize HeightOffset: 4 points 0 0\n"
            "*ParamCustomPageSize Orientation: 5 int 0 3\n"
            "*CustomPageSize True: \"pop pop pop pop pop\"\n"))
      return 0;

  if (selector[10] & 1U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*JCLBegin: \"<1B>%%-12345X@PJL JOB<0A>\"\n"
            "*JCLToPSInterpreter: \"@PJL ENTER LANGUAGE=POSTSCRIPT<0A>\"\n"
            "*JCLToPDFInterpreter: \"@PJL ENTER LANGUAGE=PDF<0A>\"\n"
            "*JCLEnd: \"<1B>%%-12345X@PJL EOJ<0A><1B>%%-12345X\"\n"
            "*JCLOpenUI *JCLDuplex/JCL Duplex: PickOne\n"
            "*DefaultJCLDuplex: Off\n"
            "*JCLDuplex Off/Off: \"@PJL SET DUPLEX=OFF<0A>\"\n"
            "*JCLDuplex On/On: \"@PJL SET DUPLEX=ON<0A>\"\n"
            "*JCLCloseUI: *JCLDuplex\n"))
      return 0;

  if (selector[11] & 1U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*APPrinterPreset Draft/Draft: \"com.apple.print.preset.quality low *ColorModel Gray *MediaType Plain\"\n"
            "*APPrinterPreset Photo/Photo: \"com.apple.print.preset.quality high *ColorModel RGB *MediaType Gloss\"\n"
            "*cupsIPPFinishings 20/staple-top-left: \"*OutputBin FaceUp\"\n"
            "*cupsIPPFinishings 3/none: \"*OutputBin StandardBin\"\n"
            "*cupsIPPReason media-empty/Media empty: \"text:Load%%20paper http://localhost/media-empty\"\n"
            "*cupsMarkerName cyan/Cyan toner: \"cyan\"\n"
            "*cupsMandatory: \"job-account-id job-accounting-user-id\"\n"
            "*cupsJobAccountId: True\n"
            "*cupsJobAccountingUserId: True\n"))
      return 0;

  if (selector[12] & 1U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*fr.Translation Main/Options principales: \"\"\n"
            "*fr.PageSize Letter/Lettre: \"\"\n"
            "*fr.PageSize A4/A4: \"\"\n"
            "*fr.cupsMarkerName cyan/Toner cyan: \"cyan\"\n"))
      return 0;

  if (selector[14] & 1U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*OpenUI *Smoothing/Smoothing: PickOne\n"
            "*OrderDependency: 20 DocumentSetup *Smoothing\n"
            "*DefaultSmoothing: None\n"
            "*Smoothing None/No: \"<</PostRenderingEnhance false>>setpagedevice\"\n"
            "*Smoothing Best/Yes: \"<</PostRenderingEnhance true>>setpagedevice\"\n"
            "*CloseUI: *Smoothing\n"
            "*OpenUI *MyPrologue/Prologue: PickOne\n"
            "*OrderDependency: 5 Prolog *MyPrologue\n"
            "*DefaultMyPrologue: Standard\n"
            "*MyPrologue Standard/Standard: \"<</PrologueFlavor (Std)>>setpagedevice\"\n"
            "*CloseUI: *MyPrologue\n"
            "*OpenUI *MyExit/Exit Code: PickOne\n"
            "*OrderDependency: 200 ExitServer *MyExit\n"
            "*DefaultMyExit: ResetExit\n"
            "*MyExit ResetExit/Reset Exit: \"%%%%RESETEXIT%%%%\"\n"
            "*CloseUI: *MyExit\n"))
      return 0;

  if (selector[15] & 1U)
    if (!cf_v2_ppd_append(
            ppd, ppd_size, &used,
            "*OpenGroup: InstallableOptions/Installed Options\n"
            "*OpenUI *OptionDuplexer/Duplex Unit: Boolean\n"
            "*DefaultOptionDuplexer: True\n"
            "*OptionDuplexer False/Not Installed: \"\"\n"
            "*OptionDuplexer True/Installed: \"\"\n"
            "*CloseUI: *OptionDuplexer\n"
            "*CloseGroup: InstallableOptions\n"
            "*UIConstraints: \"*OptionDuplexer False *Duplex DuplexNoTumble\"\n"
            "*UIConstraints: \"*Duplex DuplexNoTumble *OptionDuplexer False\"\n"))
      return 0;

  if (!cf_v2_ppd_append(
          ppd, ppd_size, &used,
          "*cupsInkChannels Gray.Plain.300dpi: \"1\"\n"
          "*cupsInkChannels RGB.Plain.300dpi: \"3\"\n"
          "*cupsInkChannels CMYK.Gloss.600dpi: \"4\"\n"
          "*%% State selector checksum: %016llx\n"
          "*%% EOF\n",
          (unsigned long long)state_hash))
    return 0;

  return used;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char ppd[CF_V2_PPD_TEXT_SIZE];
  const size_t fixed_size =
      CF_V2_PPD_STATE_MAGIC_SIZE + CF_V2_PPD_STATE_SELECTORS;
  size_t ppd_length;

  if (!data || size < fixed_size ||
      size > fixed_size + CF_V2_PPD_STATE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_PPD_STATE_MAGIC, CF_V2_PPD_STATE_MAGIC_SIZE))
    return 0;

  ppd_length = cf_v2_build_ppd(
      data + CF_V2_PPD_STATE_MAGIC_SIZE, data + fixed_size,
      size - fixed_size, ppd, sizeof(ppd));
  if (!ppd_length)
    return 0;

  return cf_v2_ppd_semantic_test_one_input((const uint8_t *)ppd, ppd_length);
}
