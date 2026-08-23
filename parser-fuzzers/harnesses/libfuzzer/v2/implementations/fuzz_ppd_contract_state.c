// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_ppd_contract_semantic_test_one_input
#define LIBPPD_SEMANTIC_DEEP_MODE
#define LIBPPD_SEMANTIC_MAX_INPUT (64U * 1024U)
#include "../../fuzz_libppd_semantic.c"
#undef LLVMFuzzerTestOneInput

#include "../include/runtime.h"

#include <cups/cups.h>
#include <cupsfilters/filter.h>
#include <ppd/ppd-filter.h>

#include <stdarg.h>

#define CF_V2_PPD_CONTRACT_MAGIC "PPDGEN01"
#define CF_V2_PPD_CONTRACT_MAGIC_SIZE 8U
#define CF_V2_PPD_CONTRACT_FIELDS 32U
#define CF_V2_PPD_CONTRACT_MAX_MATERIAL 256U
#define CF_V2_PPD_CONTRACT_TEXT_SIZE (64U * 1024U)

typedef struct cf_v2_ppd_contract_media_s {
  const char *name;
  unsigned width;
  unsigned height;
  unsigned left;
  unsigned bottom;
  unsigned right;
  unsigned top;
} cf_v2_ppd_contract_media_t;

static const cf_v2_ppd_contract_media_t cf_v2_ppd_contract_media[] = {
  {"Letter", 612U, 792U, 18U, 36U, 594U, 756U},
  {"A4", 595U, 842U, 12U, 12U, 583U, 830U},
  {"Photo4x6", 288U, 432U, 9U, 9U, 279U, 423U},
};

static const unsigned cf_v2_ppd_contract_resolutions[] = {
  150U, 300U, 600U, 1200U,
};

static int
cf_v2_ppd_contract_append(char *buffer, size_t capacity, size_t *used,
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
cf_v2_ppd_contract_relation_count(size_t base, unsigned relation,
                                  size_t maximum)
{
  switch (relation % 4U) {
    case 0U:
      return base;
    case 1U:
      return 0U;
    case 2U:
      return base ? base - 1U : 0U;
    default:
      return maximum;
  }
}

static const char *
cf_v2_ppd_contract_default_name(size_t base, unsigned relation)
{
  switch (relation % 4U) {
    case 0U:
      return cf_v2_ppd_contract_media[base % 3U].name;
    case 1U:
      return "MissingMedia";
    case 2U:
      return cf_v2_ppd_contract_media[(base + 1U) % 3U].name;
    default:
      return "Custom.100x200";
  }
}

static const char *
cf_v2_ppd_contract_choice_default(unsigned relation, size_t count)
{
  if (relation % 4U == 1U || !count)
    return "MissingChoice";
  if (relation % 4U == 2U)
    return "Choice1";
  if (relation % 4U == 3U)
    return "Custom";
  return "Choice0";
}

static const char *
cf_v2_ppd_contract_custom_type(unsigned selector)
{
  static const char *const types[] = {
    "points", "int", "real", "curve", "invcurve", "passcode",
    "password", "string",
  };

  return types[selector % (sizeof(types) / sizeof(types[0]))];
}

static const char *
cf_v2_ppd_contract_custom_value(unsigned value_class,
                                const char *type)
{
  if (!strcmp(type, "passcode") || !strcmp(type, "password") ||
      !strcmp(type, "string"))
    return value_class % 5U == 4U
               ? "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
               : "A";
  switch (value_class % 5U) {
    case 0U:
      return "0";
    case 1U:
      return "1";
    case 2U:
      return "1000";
    case 3U:
      return "-1000";
    default:
      return "1e38";
  }
}

static int
cf_v2_ppd_contract_append_media_choices(char *ppd, size_t capacity,
                                        size_t *used, const char *keyword,
                                        size_t count)
{
  size_t index;

  for (index = 0U; index < count; index ++) {
    const cf_v2_ppd_contract_media_t *media =
        cf_v2_ppd_contract_media + index % 3U;

    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*%s %s/%s: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n",
            keyword, media->name, media->name, media->width, media->height))
      return 0;
  }
  return 1;
}

static int
cf_v2_ppd_contract_append_page_geometry(char *ppd, size_t capacity,
                                        size_t *used,
                                        const uint8_t *field)
{
  const size_t page_count = field[1] % 4U;
  const size_t region_count =
      cf_v2_ppd_contract_relation_count(page_count, field[2], 3U);
  const size_t imageable_count =
      cf_v2_ppd_contract_relation_count(page_count, field[3], 3U);
  const size_t dimension_count =
      cf_v2_ppd_contract_relation_count(page_count, field[4], 3U);
  const char *default_name =
      cf_v2_ppd_contract_default_name(field[0] % 3U, field[5]);
  size_t index;

  if (!cf_v2_ppd_contract_append(
          ppd, capacity, used,
          "*OpenUI *PageSize/Media Size: PickOne\n"
          "*OrderDependency: 10 AnySetup *PageSize\n"
          "*DefaultPageSize: %s\n",
          default_name) ||
      !cf_v2_ppd_contract_append_media_choices(
          ppd, capacity, used, "PageSize", page_count) ||
      !cf_v2_ppd_contract_append(
          ppd, capacity, used,
          "*CloseUI: *PageSize\n"
          "*OpenUI *PageRegion/Media Region: PickOne\n"
          "*DefaultPageRegion: %s\n",
          default_name) ||
      !cf_v2_ppd_contract_append_media_choices(
          ppd, capacity, used, "PageRegion", region_count) ||
      !cf_v2_ppd_contract_append(
          ppd, capacity, used,
          "*CloseUI: *PageRegion\n"
          "*DefaultImageableArea: %s\n",
          default_name))
    return 0;

  for (index = 0U; index < imageable_count; index ++) {
    const cf_v2_ppd_contract_media_t *media =
        cf_v2_ppd_contract_media + index % 3U;

    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used, "*ImageableArea %s: \"%u %u %u %u\"\n",
            media->name, media->left, media->bottom,
            media->right, media->top))
      return 0;
  }
  if (!cf_v2_ppd_contract_append(
          ppd, capacity, used, "*DefaultPaperDimension: %s\n",
          default_name))
    return 0;
  for (index = 0U; index < dimension_count; index ++) {
    const cf_v2_ppd_contract_media_t *media =
        cf_v2_ppd_contract_media + index % 3U;

    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used, "*PaperDimension %s: \"%u %u\"\n",
            media->name, media->width, media->height))
      return 0;
  }
  return 1;
}

static int
cf_v2_ppd_contract_append_core_options(char *ppd, size_t capacity,
                                       size_t *used,
                                       const uint8_t *field)
{
  static const char *const colors[] = {"Gray", "RGB", "CMYK"};
  static const unsigned color_spaces[] = {18U, 1U, 6U};
  static const unsigned color_bpp[] = {8U, 24U, 32U};
  static const char *const duplex[] = {
    "None", "DuplexNoTumble", "DuplexTumble", "MissingDuplex",
  };
  static const char *const slots[] = {
    "Auto", "Cassette", "Manual", "MissingSlot",
  };
  static const char *const media_types[] = {
    "Plain", "Gloss", "Labels", "MissingType",
  };
  static const char *const bins[] = {
    "StandardBin", "FaceUp", "MissingBin",
  };
  const size_t resolution_count = field[7] % 5U;
  const size_t color_count = field[10] % 4U;
  const char *resolution_default;
  const char *color_default;
  size_t index;

  if (field[8] % 4U == 1U || !resolution_count)
    resolution_default = "9999dpi";
  else if (field[8] % 4U == 2U)
    resolution_default = "300x600dpi";
  else if (field[8] % 4U == 3U)
    resolution_default = "0dpi";
  else {
    static char resolution_name[32];
    snprintf(resolution_name, sizeof(resolution_name), "%udpi",
             cf_v2_ppd_contract_resolutions[field[6] % 4U]);
    resolution_default = resolution_name;
  }

  if (!cf_v2_ppd_contract_append(
          ppd, capacity, used,
          "*OpenUI *Resolution/Resolution: PickOne\n"
          "*OrderDependency: 20 AnySetup *Resolution\n"
          "*DefaultResolution: %s\n",
          resolution_default))
    return 0;
  for (index = 0U; index < resolution_count; index ++) {
    const unsigned resolution = cf_v2_ppd_contract_resolutions[index % 4U];

    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*Resolution %udpi/%u dpi: \"<</HWResolution[%u %u]>>setpagedevice\"\n",
            resolution, resolution, resolution, resolution))
      return 0;
  }

  if (field[11] % 4U == 1U || !color_count)
    color_default = "MissingColor";
  else if (field[11] % 4U == 2U)
    color_default = colors[(field[9] + 1U) % 3U];
  else if (field[11] % 4U == 3U)
    color_default = "CustomColor";
  else
    color_default = colors[field[9] % 3U];

  if (!cf_v2_ppd_contract_append(
          ppd, capacity, used,
          "*CloseUI: *Resolution\n"
          "*OpenUI *ColorModel/Color Mode: PickOne\n"
          "*OrderDependency: 30 AnySetup *ColorModel\n"
          "*DefaultColorModel: %s\n",
          color_default))
    return 0;
  for (index = 0U; index < color_count; index ++) {
    const size_t color = index % 3U;

    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*ColorModel %s/%s: \"<</cupsColorSpace %u/cupsBitsPerColor 8/cupsBitsPerPixel %u>>setpagedevice\"\n",
            colors[color], colors[color], color_spaces[color],
            color_bpp[color]))
      return 0;
  }

  return cf_v2_ppd_contract_append(
      ppd, capacity, used,
      "*CloseUI: *ColorModel\n"
      "*OpenUI *Duplex/Two-Sided Printing: PickOne\n"
      "*DefaultDuplex: %s\n"
      "*Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n"
      "*Duplex DuplexNoTumble/Long Edge: \"<</Duplex true/Tumble false>>setpagedevice\"\n"
      "*Duplex DuplexTumble/Short Edge: \"<</Duplex true/Tumble true>>setpagedevice\"\n"
      "*CloseUI: *Duplex\n"
      "*OpenUI *InputSlot/Media Source: PickOne\n"
      "*DefaultInputSlot: %s\n"
      "*InputSlot Auto/Automatic: \"\"\n"
      "*InputSlot Cassette/Main Tray: \"\"\n"
      "*InputSlot Manual/Manual Feed: \"\"\n"
      "*CloseUI: *InputSlot\n"
      "*OpenUI *MediaType/Media Type: PickOne\n"
      "*DefaultMediaType: %s\n"
      "*MediaType Plain/Plain: \"\"\n"
      "*MediaType Gloss/Gloss: \"\"\n"
      "*MediaType Labels/Labels: \"\"\n"
      "*CloseUI: *MediaType\n"
      "*OpenUI *OutputBin/Output Bin: PickOne\n"
      "*DefaultOutputBin: %s\n"
      "*OutputBin StandardBin/Standard Bin: \"\"\n"
      "*OutputBin FaceUp/Face Up: \"\"\n"
      "*CloseUI: *OutputBin\n",
      duplex[field[12] % 4U], slots[field[13] % 4U],
      media_types[field[14] % 4U], bins[field[15] % 3U]);
}

static int
cf_v2_ppd_contract_append_option_graph(char *ppd, size_t capacity,
                                       size_t *used,
                                       const uint8_t *field,
                                       char *option_value,
                                       size_t option_capacity)
{
  static const char *const option_types[] = {
    "PickOne", "Boolean", "PickMany",
  };
  static const size_t choice_counts[] = {0U, 1U, 2U, 4U, 8U};
  static const size_t parameter_counts[] = {0U, 1U, 2U, 4U, 8U, 16U, 32U};
  const size_t choice_count = choice_counts[field[18] % 5U];
  const size_t parameter_count = parameter_counts[field[21] % 7U];
  const unsigned custom_family = field[20] % 6U;
  size_t index;
  size_t option_used = 0U;

  if (!cf_v2_ppd_contract_append(
          ppd, capacity, used,
          "*OpenUI *ContractOption/Contract Option: %s\n"
          "*DefaultContractOption: %s\n",
          option_types[field[17] % 3U],
          cf_v2_ppd_contract_choice_default(field[19], choice_count)))
    return 0;
  for (index = 0U; index < choice_count; index ++)
    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*ContractOption Choice%u/Choice %u: \"\"\n",
            (unsigned)index, (unsigned)index))
      return 0;
  if (!cf_v2_ppd_contract_append(ppd, capacity, used,
                                 "*CloseUI: *ContractOption\n"))
    return 0;

  switch (field[16] % 5U) {
    case 1U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*UIConstraints: \"*InputSlot Manual *Duplex DuplexNoTumble\"\n"))
        return 0;
      break;
    case 2U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*UIConstraints: \"*InputSlot Manual *Duplex DuplexNoTumble\"\n"
              "*UIConstraints: \"*Duplex DuplexNoTumble *InputSlot Manual\"\n"))
        return 0;
      break;
    case 3U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*NonUIConstraints: \"*PageSize Photo4x6 *OutputBin FaceUp\"\n"))
        return 0;
      break;
    case 4U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*UIConstraints: \"*MissingOption MissingChoice *ContractOption Choice0\"\n"))
        return 0;
      break;
    default:
      break;
  }

  option_value[0] = '\0';
  if (custom_family == 1U || custom_family == 2U ||
      custom_family == 3U || custom_family == 5U) {
    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*CustomContractOption True/Custom: \"pop pop\"\n"))
      return 0;
    if (!cf_v2_ppd_contract_append(option_value, option_capacity,
                                   &option_used, "{"))
      return 0;
    for (index = 0U; index < parameter_count; index ++) {
      const char *type = custom_family == 3U
                             ? cf_v2_ppd_contract_custom_type(
                                   (unsigned)(field[22] + index))
                             : (custom_family == 1U ? "int" : "real");
      const char *value =
          cf_v2_ppd_contract_custom_value(field[23], type);

      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*ParamCustomContractOption P%u/P%u: %u %s -1000 1000\n",
              (unsigned)(index + 1U), (unsigned)(index + 1U),
              (unsigned)(index + 1U), type) ||
          !cf_v2_ppd_contract_append(
              option_value, option_capacity, &option_used, "%sP%u=%s",
              index ? " " : " ", (unsigned)(index + 1U), value))
        return 0;
    }
    if (!cf_v2_ppd_contract_append(option_value, option_capacity,
                                   &option_used, " }"))
      return 0;
  }

  if (custom_family == 4U || custom_family == 5U) {
    static const char *const names[] = {
      "Width", "Height", "WidthOffset", "HeightOffset", "Orientation",
    };

    if (!cf_v2_ppd_contract_append(ppd, capacity, used,
                                   "*VariablePaperSize: True\n"))
      return 0;
    for (index = 0U; index < parameter_count; index ++) {
      const char *type = cf_v2_ppd_contract_custom_type(field[22]);

      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*ParamCustomPageSize %s%u: %u %s 0 1000\n",
              names[index % 5U], (unsigned)(index / 5U),
              (unsigned)(index + 1U), type))
        return 0;
    }
    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*CustomPageSize True: \"pop pop pop pop pop\"\n"))
      return 0;
  }
  return 1;
}

static int
cf_v2_ppd_contract_append_metadata(char *ppd, size_t capacity,
                                   size_t *used, const uint8_t *field,
                                   const uint8_t *material,
                                   size_t material_size)
{
  static const size_t preset_counts[] = {0U, 1U, 2U, 4U, 8U, 16U};
  static const size_t item_counts[] = {
    0U, 1U, 2U, 7U, 8U, 15U, 16U, 31U, 32U,
  };
  static const size_t filter_counts[] = {0U, 1U, 2U, 4U, 8U};
  const size_t preset_count = preset_counts[field[25] % 6U];
  const size_t item_count = item_counts[field[26] % 9U];
  const size_t filter_count = filter_counts[field[27] % 5U];
  size_t index;

  switch (field[24] % 5U) {
    case 1U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*JCLBegin: \"<1B>%%-12345X@PJL JOB<0A>\"\n"))
        return 0;
      break;
    case 2U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*JCLEnd: \"<1B>%%-12345X@PJL EOJ<0A>\"\n"))
        return 0;
      break;
    case 3U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*JCLBegin: \"<1B>%%-12345X@PJL JOB<0A>\"\n"
              "*JCLToPSInterpreter: \"@PJL ENTER LANGUAGE=POSTSCRIPT<0A>\"\n"
              "*JCLEnd: \"<1B>%%-12345X@PJL EOJ<0A>\"\n"))
        return 0;
      break;
    case 4U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*JCLOpenUI *JCLMode/JCL Mode: PickOne\n"
              "*DefaultJCLMode: Off\n"
              "*JCLMode Off/Off: \"@PJL SET MODE=OFF<0A>\"\n"
              "*JCLMode On/On: \"@PJL SET MODE=ON<0A>\"\n"
              "*JCLCloseUI: *JCLMode\n"))
        return 0;
      break;
    default:
      break;
  }

  for (index = 0U; index < preset_count; index ++)
    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*APPrinterPreset Preset%u/Preset %u: \"com.apple.print.preset.quality %s *ColorModel %s\"\n",
            (unsigned)index, (unsigned)index,
            index & 1U ? "high" : "low", index & 1U ? "RGB" : "Gray"))
      return 0;

  if (item_count) {
    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*cupsPwgRasterDocumentTypeSupported: \""))
      return 0;
    for (index = 0U; index < item_count; index ++)
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used, "%stype%u",
              index ? "," : "", (unsigned)index))
        return 0;
    if (!cf_v2_ppd_contract_append(ppd, capacity, used, "\"\n"))
      return 0;
  }

  for (index = 0U; index < filter_count; index ++) {
    const unsigned syntax = field[28] % 7U;
    char long_program[160];
    const char *value;

    memset(long_program, 'a' + (int)(index % 26U),
           sizeof(long_program) - 1U);
    long_program[sizeof(long_program) - 1U] = '\0';
    switch (syntax) {
      case 0U:
        value = "application/vnd.cups-raster 0 rastertopclx";
        break;
      case 1U:
        value = "application/pdf 10 pdftopdf";
        break;
      case 2U:
        value = "";
        break;
      case 3U:
        value = "rastertopclx";
        break;
      case 4U:
        value = "0 rastertopclx";
        break;
      case 5U:
        value = "x 1 y";
        break;
      default:
        value = long_program;
        break;
    }
    if (!cf_v2_ppd_contract_append(ppd, capacity, used,
                                   "*cupsFilter: \"%s\"\n", value))
      return 0;
  }

  if (field[29] % 4U) {
    static const char *const languages[] = {"fr", "de", "ja"};
    const char *language = languages[(field[29] - 1U) % 3U];

    if (!cf_v2_ppd_contract_append(
            ppd, capacity, used,
            "*%s.Translation Main/Localized options: \"\"\n"
            "*%s.PageSize Letter/Localized Letter: \"\"\n"
            "*%s.cupsMarkerName black/Localized Black: \"black\"\n",
            language, language, language))
      return 0;
  }

  switch (field[30] % 5U) {
    case 1U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*OpenUI *Smoothing/Smoothing: PickOne\n"
              "*OrderDependency: 20 DocumentSetup *Smoothing\n"
              "*DefaultSmoothing: None\n"
              "*Smoothing None/None: \"\"\n"
              "*Smoothing Best/Best: \"\"\n"
              "*CloseUI: *Smoothing\n"))
        return 0;
      break;
    case 2U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*OpenGroup: InstallableOptions/Installed Options\n"
              "*OpenUI *OptionDuplexer/Duplex Unit: Boolean\n"
              "*DefaultOptionDuplexer: True\n"
              "*OptionDuplexer False/Not Installed: \"\"\n"
              "*OptionDuplexer True/Installed: \"\"\n"
              "*CloseUI: *OptionDuplexer\n"
              "*CloseGroup: InstallableOptions\n"))
        return 0;
      break;
    case 3U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*OpenUI *ExitCode/Exit Code: PickOne\n"
              "*OrderDependency: 200 ExitServer *ExitCode\n"
              "*DefaultExitCode: Reset\n"
              "*ExitCode Reset/Reset: \"%%%%RESET%%%%\"\n"
              "*CloseUI: *ExitCode\n"))
        return 0;
      break;
    case 4U:
      if (!cf_v2_ppd_contract_append(
              ppd, capacity, used,
              "*OpenGroup: ContractGroup/Contract Group\n"
              "*CloseGroup: DifferentGroup\n"))
        return 0;
      break;
    default:
      break;
  }

  return cf_v2_ppd_contract_append(
      ppd, capacity, used,
      "*%% contract-material=%zu phase=%u hash=%016llx\n"
      "*%% EOF\n",
      material_size, field[31] % 8U,
      (unsigned long long)libppd_hash(material, material_size));
}

static size_t
cf_v2_ppd_contract_build(const uint8_t *field, const uint8_t *material,
                         size_t material_size, char *ppd, size_t capacity,
                         char *option_value, size_t option_capacity)
{
  const int foomatic = field[29] % 4U == 3U;
  size_t used = 0U;

  if (!cf_v2_ppd_contract_append(
          ppd, capacity, &used,
          "*PPD-Adobe: \"4.3\"\n"
          "*FormatVersion: \"4.3\"\n"
          "*FileVersion: \"3.0\"\n"
          "*LanguageVersion: English\n"
          "*LanguageEncoding: ISOLatin1\n"
          "*Manufacturer: \"OpenPrinting\"\n"
          "*ModelName: \"Generic PPD contract printer\"\n"
          "*ShortNickName: \"Generic PPD contract\"\n"
          "*NickName: \"Generic PPD contract%s printer\"\n"
          "*PCFileName: \"PPDGEN.PPD\"\n"
          "*Product: \"(Generic PPD contract printer)\"\n"
          "*PSVersion: \"(3010) 0\"\n"
          "*LanguageLevel: \"3\"\n"
          "*ColorDevice: True\n"
          "*cupsVersion: 2.0\n",
          foomatic ? " Foomatic" : "") ||
      !cf_v2_ppd_contract_append_page_geometry(
          ppd, capacity, &used, field) ||
      !cf_v2_ppd_contract_append_core_options(
          ppd, capacity, &used, field) ||
      !cf_v2_ppd_contract_append_option_graph(
          ppd, capacity, &used, field, option_value, option_capacity) ||
      !cf_v2_ppd_contract_append_metadata(
          ppd, capacity, &used, field, material, material_size))
    return 0U;
  return used;
}

static void
cf_v2_ppd_contract_log(void *data, cf_loglevel_t level,
                       const char *message, ...)
{
  (void)data;
  (void)level;
  (void)message;
}

static void
cf_v2_ppd_contract_loader(const char *ppd, size_t ppd_size,
                          const uint8_t *field, const char *option_value)
{
  char path[] = "/tmp/cupsfilters-v2-ppd-contract.XXXXXX";
  cf_filter_data_t filter_data;
  int fd;

  memset(&filter_data, 0, sizeof(filter_data));
  filter_data.printer = (char *)"oss-fuzz-v2";
  filter_data.job_id = 1;
  filter_data.job_user = (char *)"fuzzer";
  filter_data.job_title = (char *)"generic-ppd-contract";
  filter_data.copies = 1;
  filter_data.content_type = (char *)"application/pdf";
  filter_data.final_content_type = (char *)"application/vnd.cups-raster";
  filter_data.back_pipe[0] = filter_data.back_pipe[1] = -1;
  filter_data.side_pipe[0] = filter_data.side_pipe[1] = -1;
  filter_data.logfunc = cf_v2_ppd_contract_log;

  if (option_value[0])
    filter_data.num_options = cupsAddOption(
        "ContractOption", option_value, filter_data.num_options,
        &filter_data.options);
  if (field[20] % 6U == 4U || field[20] % 6U == 5U)
    filter_data.num_options = cupsAddOption(
        "PageSize", "Custom.100x200", filter_data.num_options,
        &filter_data.options);

  fd = mkstemp(path);
  if (fd >= 0) {
    if (!libppd_write_all(fd, (const uint8_t *)ppd, ppd_size) &&
        close(fd) == 0) {
      fd = -1;
      (void)ppdFilterLoadPPDFile(&filter_data, path);
    }
  }
  if (fd >= 0)
    close(fd);
  if (cfFilterDataGetExt(&filter_data, PPD_FILTER_DATA_EXT))
    ppdFilterFreePPDFile(&filter_data);
  cupsFreeOptions(filter_data.num_options, filter_data.options);
  unlink(path);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t fixed_size =
      CF_V2_PPD_CONTRACT_MAGIC_SIZE + CF_V2_PPD_CONTRACT_FIELDS;
  char ppd[CF_V2_PPD_CONTRACT_TEXT_SIZE];
  char option_value[4096];
  const uint8_t *field;
  const uint8_t *material;
  size_t material_size;
  size_t ppd_size;

  if (!data || size < fixed_size + 1U ||
      size > fixed_size + CF_V2_PPD_CONTRACT_MAX_MATERIAL ||
      memcmp(data, CF_V2_PPD_CONTRACT_MAGIC,
             CF_V2_PPD_CONTRACT_MAGIC_SIZE))
    return 0;

  field = data + CF_V2_PPD_CONTRACT_MAGIC_SIZE;
  material = data + fixed_size;
  material_size = size - fixed_size;
  ppd_size = cf_v2_ppd_contract_build(
      field, material, material_size, ppd, sizeof(ppd),
      option_value, sizeof(option_value));
  if (!ppd_size)
    return 0;

  cf_v2_init_runtime();
  cf_v2_ppd_contract_loader(ppd, ppd_size, field, option_value);
  return cf_v2_ppd_contract_semantic_test_one_input(
      (const uint8_t *)ppd, ppd_size);
}
