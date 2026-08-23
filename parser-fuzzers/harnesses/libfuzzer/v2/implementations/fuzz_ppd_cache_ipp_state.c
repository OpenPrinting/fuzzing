// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_ppd_cache_unused_entry
#define LIBPPD_SEMANTIC_DEEP_MODE
#define LIBPPD_SEMANTIC_MAX_INPUT (32U * 1024U)
#include "../../fuzz_libppd_semantic.c"
#undef LLVMFuzzerTestOneInput

#define CF_V2_PPD_CACHE_MAGIC "PPDCACH1"
#define CF_V2_PPD_CACHE_MAGIC_SIZE 8U
#define CF_V2_PPD_CACHE_SELECTORS 16U
#define CF_V2_PPD_CACHE_MAX_PAYLOAD 64U
#define CF_V2_PPD_CACHE_TEXT_SIZE (32U * 1024U)

typedef struct
{
  const char *ppd;
  const char *pwg;
  unsigned int width;
  unsigned int height;
  unsigned int left;
  unsigned int bottom;
  unsigned int right;
  unsigned int top;
} cf_v2_ppd_cache_media_t;

static const cf_v2_ppd_cache_media_t cf_v2_ppd_cache_media[] = {
  {"Letter", "na_letter_8.5x11in", 612U, 792U, 18U, 18U, 594U, 774U},
  {"A4", "iso_a4_210x297mm", 595U, 842U, 18U, 18U, 577U, 824U},
  {"Photo4x6", "na_index-4x6_4x6in", 288U, 432U, 9U, 9U, 279U, 423U},
  {"A4.Borderless", "iso_a4_210x297mm", 595U, 842U, 0U, 0U, 595U, 842U},
};

static int
cf_v2_ppd_cache_append(char *buffer, size_t capacity, size_t *used,
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
cf_v2_build_ppd_cache_state(const uint8_t *selector, const uint8_t *payload,
                            size_t payload_size, char *ppd, size_t ppd_size)
{
  static const char *const sources[] = {
    "Cassette", "Upper", "Manual", "PhotoTray",
  };
  static const char *const types[] = {
    "Plain", "Gloss", "Labels", "Cardstock",
  };
  static const char *const bins[] = {
    "StandardBin", "FaceUp", "Rear",
  };
  static const char *const sides[] = {
    "None", "DuplexNoTumble", "DuplexTumble",
  };
  static const char *const colors[] = {"Gray", "RGB"};
  static const char *const qualities[] = {"Draft", "Normal", "High"};
  const cf_v2_ppd_cache_media_t *default_media =
      cf_v2_ppd_cache_media + selector[0] % 4U;
  uint64_t hash = libppd_hash(selector, CF_V2_PPD_CACHE_SELECTORS);
  size_t index;
  size_t used = 0;

  if (payload_size)
    hash ^= libppd_hash(payload, payload_size);

  if (!cf_v2_ppd_cache_append(
          ppd, ppd_size, &used,
          "*PPD-Adobe: \"4.3\"\n"
          "*FormatVersion: \"4.3\"\n"
          "*FileVersion: \"2.0\"\n"
          "*LanguageVersion: English\n"
          "*LanguageEncoding: ISOLatin1\n"
          "*PCFileName: \"PPCACHE.PPD\"\n"
          "*Manufacturer: \"OpenPrinting\"\n"
          "*Product: \"(PPD cache state printer)\"\n"
          "*ModelName: \"PPD Cache State Printer\"\n"
          "*ShortNickName: \"PPD Cache State\"\n"
          "*NickName: \"PPD Cache State Printer %016llx\"\n"
          "*PSVersion: \"(3010.000) 0\"\n"
          "*LanguageLevel: \"3\"\n"
          "*ColorDevice: %s\n"
          "*DefaultColorSpace: %s\n"
          "*FileSystem: False\n"
          "*Throughput: \"%u\"\n"
          "*LandscapeOrientation: Plus90\n"
          "*TTRasterizer: Type42\n"
          "*1284DeviceID: \"MFG:OpenPrinting;MDL:CacheState;CMD:POSTSCRIPT,PDF;\"\n"
          "*cupsVersion: 2.0\n"
          "*cupsModelNumber: %u\n"
          "*cupsManualCopies: False\n"
          "*cupsMaxCopies: %u\n",
          (unsigned long long)hash, (selector[7] & 1U) ? "True" : "False",
          (selector[7] & 1U) ? "RGB" : "Gray",
          10U + (unsigned int)(selector[15] % 51U),
          (unsigned int)(selector[15] % 16U),
          1U + (unsigned int)(selector[13] % 200U)))
    return 0;

  if (selector[15] & 1U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*cupsFilter2: \"application/pdf application/vnd.cups-raster 10 pdftoraster\"\n"
            "*cupsFilter2: \"image/png application/vnd.cups-raster 20 imagetoraster\"\n"))
      return 0;
  }

  if (!cf_v2_ppd_cache_append(
          ppd, ppd_size, &used,
          "*OpenUI *PageSize/Media Size: PickOne\n"
          "*OrderDependency: 10 AnySetup *PageSize\n"
          "*DefaultPageSize: %s\n",
          default_media->ppd))
    return 0;
  for (index = 0; index < 4U; index++)
  {
    const cf_v2_ppd_cache_media_t *media = cf_v2_ppd_cache_media + index;
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*PageSize %s/%s: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n",
            media->ppd, media->ppd, media->width, media->height))
      return 0;
  }
  if (!cf_v2_ppd_cache_append(ppd, ppd_size, &used,
                              "*CloseUI: *PageSize\n"
                              "*OpenUI *PageRegion/Media Region: PickOne\n"
                              "*OrderDependency: 10 AnySetup *PageRegion\n"
                              "*DefaultPageRegion: %s\n",
                              default_media->ppd))
    return 0;
  for (index = 0; index < 4U; index++)
  {
    const cf_v2_ppd_cache_media_t *media = cf_v2_ppd_cache_media + index;
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*PageRegion %s/%s: \"<</PageSize[%u %u]/ImagingBBox null>>setpagedevice\"\n",
            media->ppd, media->ppd, media->width, media->height))
      return 0;
  }
  if (!cf_v2_ppd_cache_append(ppd, ppd_size, &used,
                              "*CloseUI: *PageRegion\n"
                              "*DefaultImageableArea: %s\n",
                              default_media->ppd))
    return 0;
  for (index = 0; index < 4U; index++)
  {
    const cf_v2_ppd_cache_media_t *media = cf_v2_ppd_cache_media + index;
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*ImageableArea %s: \"%u %u %u %u\"\n",
            media->ppd, media->left, media->bottom, media->right, media->top))
      return 0;
  }
  if (!cf_v2_ppd_cache_append(ppd, ppd_size, &used,
                              "*DefaultPaperDimension: %s\n",
                              default_media->ppd))
    return 0;
  for (index = 0; index < 4U; index++)
  {
    const cf_v2_ppd_cache_media_t *media = cf_v2_ppd_cache_media + index;
    if (!cf_v2_ppd_cache_append(ppd, ppd_size, &used,
                                "*PaperDimension %s: \"%u %u\"\n",
                                media->ppd, media->width, media->height))
      return 0;
  }

  if (selector[12] & 1U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*VariablePaperSize: True\n"
            "*ParamCustomPageSize Width: 1 points 72 1000\n"
            "*ParamCustomPageSize Height: 2 points 72 1400\n"
            "*ParamCustomPageSize WidthOffset: 3 points 0 0\n"
            "*ParamCustomPageSize HeightOffset: 4 points 0 0\n"
            "*ParamCustomPageSize Orientation: 5 int 0 3\n"
            "*HWMargins: 9 12 9 12\n"
            "*CustomPageSize True: \"pop pop pop pop pop\"\n"))
      return 0;
  }

  if (!cf_v2_ppd_cache_append(
          ppd, ppd_size, &used,
          "*OpenUI *InputSlot/Media Source: PickOne\n"
          "*OrderDependency: 20 AnySetup *InputSlot\n"
          "*DefaultInputSlot: %s\n"
          "*InputSlot Cassette/Main Tray: \"\"\n"
          "*InputSlot Upper/Upper Tray: \"\"\n"
          "*InputSlot Manual/Manual Feed: \"\"\n"
          "*InputSlot PhotoTray/Photo Tray: \"\"\n"
          "*CloseUI: *InputSlot\n"
          "*OpenUI *MediaType/Media Type: PickOne\n"
          "*OrderDependency: 30 AnySetup *MediaType\n"
          "*DefaultMediaType: %s\n"
          "*MediaType Plain/Plain Paper: \"\"\n"
          "*MediaType Gloss/Glossy Photo: \"\"\n"
          "*MediaType Labels/Labels: \"\"\n"
          "*MediaType Cardstock/Card Stock: \"\"\n"
          "*CloseUI: *MediaType\n"
          "*OpenUI *OutputBin/Output Bin: PickOne\n"
          "*OrderDependency: 40 AnySetup *OutputBin\n"
          "*DefaultOutputBin: %s\n"
          "*OutputBin StandardBin/Standard Bin: \"\"\n"
          "*OutputBin FaceUp/Face Up: \"\"\n"
          "*OutputBin Rear/Rear Bin: \"\"\n"
          "*CloseUI: *OutputBin\n"
          "*OpenUI *Duplex/Two-Sided Printing: PickOne\n"
          "*OrderDependency: 50 AnySetup *Duplex\n"
          "*DefaultDuplex: %s\n"
          "*Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n"
          "*Duplex DuplexNoTumble/Long Edge: \"<</Duplex true/Tumble false>>setpagedevice\"\n"
          "*Duplex DuplexTumble/Short Edge: \"<</Duplex true/Tumble true>>setpagedevice\"\n"
          "*CloseUI: *Duplex\n",
          sources[selector[2] % 4U], types[selector[3] % 4U],
          bins[selector[4] % 3U], sides[selector[5] % 3U]))
    return 0;

  if (!cf_v2_ppd_cache_append(
          ppd, ppd_size, &used,
          "*OpenUI *Resolution/Resolution: PickOne\n"
          "*OrderDependency: 60 AnySetup *Resolution\n"
          "*DefaultResolution: %udpi\n"
          "*Resolution 300dpi/Draft: \"<</HWResolution[300 300]>>setpagedevice\"\n"
          "*Resolution 600dpi/Normal: \"<</HWResolution[600 600]>>setpagedevice\"\n"
          "*Resolution 1200dpi/High: \"<</HWResolution[1200 1200]>>setpagedevice\"\n"
          "*CloseUI: *Resolution\n"
          "*OpenUI *ColorModel/Color Mode: PickOne\n"
          "*OrderDependency: 70 AnySetup *ColorModel\n"
          "*DefaultColorModel: %s\n"
          "*ColorModel Gray/Monochrome: \"<</cupsColorSpace 18/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice\"\n"
          "*ColorModel RGB/Color: \"<</cupsColorSpace 1/cupsBitsPerColor 8/cupsBitsPerPixel 24>>setpagedevice\"\n"
          "*CloseUI: *ColorModel\n"
          "*OpenUI *cupsPrintQuality/Print Quality: PickOne\n"
          "*DefaultcupsPrintQuality: %s\n"
          "*cupsPrintQuality Draft/Draft: \"\"\n"
          "*cupsPrintQuality Normal/Normal: \"\"\n"
          "*cupsPrintQuality High/High: \"\"\n"
          "*CloseUI: *cupsPrintQuality\n",
          (selector[6] % 3U == 0U) ? 300U :
              ((selector[6] % 3U == 1U) ? 600U : 1200U),
          colors[selector[7] % 2U], qualities[selector[6] % 3U]))
    return 0;

  if (selector[9] & 1U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*APPrinterPreset MonoDraft/Mono Draft: \"com.apple.print.preset.quality low com.apple.print.preset.output-mode monochrome *ColorModel Gray *Resolution 300dpi *cupsPrintQuality Draft\"\n"
            "*APPrinterPreset MonoNormal/Mono Normal: \"com.apple.print.preset.quality normal com.apple.print.preset.output-mode monochrome *ColorModel Gray *Resolution 600dpi *cupsPrintQuality Normal\"\n"
            "*APPrinterPreset MonoHigh/Mono High: \"com.apple.print.preset.quality high com.apple.print.preset.output-mode monochrome *ColorModel Gray *Resolution 1200dpi *cupsPrintQuality High\"\n"
            "*APPrinterPreset ColorDraft/Color Draft: \"com.apple.print.preset.quality low com.apple.print.preset.output-mode color *ColorModel RGB *Resolution 300dpi *cupsPrintQuality Draft\"\n"
            "*APPrinterPreset ColorNormal/Color Normal: \"com.apple.print.preset.quality normal com.apple.print.preset.output-mode color *ColorModel RGB *Resolution 600dpi *cupsPrintQuality Normal\"\n"
            "*APPrinterPreset ColorHigh/Color High: \"com.apple.print.preset.quality high com.apple.print.preset.output-mode color *ColorModel RGB *Resolution 1200dpi *cupsPrintQuality High\"\n"))
      return 0;
  }

  if (selector[8] % 4U == 0U || selector[8] % 4U == 2U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*OpenUI *StapleLocation/Staple: PickOne\n"
            "*DefaultStapleLocation: None\n"
            "*StapleLocation None/None: \"\"\n"
            "*StapleLocation SinglePortrait/Top Left: \"\"\n"
            "*StapleLocation UpperRight/Top Right: \"\"\n"
            "*CloseUI: *StapleLocation\n"
            "*OpenUI *RIPunch/Punch: PickOne\n"
            "*DefaultRIPunch: None\n"
            "*RIPunch None/None: \"\"\n"
            "*RIPunch Left2/Two Left: \"\"\n"
            "*RIPunch Right3/Three Right: \"\"\n"
            "*CloseUI: *RIPunch\n"
            "*OpenUI *BindEdge/Bind: PickOne\n"
            "*DefaultBindEdge: None\n"
            "*BindEdge None/None: \"\"\n"
            "*BindEdge Left/Left: \"\"\n"
            "*BindEdge Right/Right: \"\"\n"
            "*BindEdge Top/Top: \"\"\n"
            "*BindEdge Bottom/Bottom: \"\"\n"
            "*CloseUI: *BindEdge\n"
            "*OpenUI *FoldType/Fold: PickOne\n"
            "*DefaultFoldType: None\n"
            "*FoldType None/None: \"\"\n"
            "*FoldType ZFold/Z Fold: \"\"\n"
            "*FoldType Saddle/Half Fold: \"\"\n"
            "*FoldType Letter/Letter Fold: \"\"\n"
            "*CloseUI: *FoldType\n"))
      return 0;
  }
  else if (selector[8] % 4U != 3U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*cupsIPPFinishings %d/staple-top-left: \"*OutputBin FaceUp\"\n"
            "*cupsIPPFinishings %d/punch-dual-left: \"*OutputBin Rear\"\n"
            "*cupsIPPFinishings %d/bind-left: \"*Duplex DuplexNoTumble\"\n"
            "*cupsIPPFinishings %d/fold-z: \"*Duplex DuplexTumble\"\n",
            IPP_FINISHINGS_STAPLE_TOP_LEFT,
            IPP_FINISHINGS_PUNCH_DUAL_LEFT, IPP_FINISHINGS_BIND_LEFT,
            IPP_FINISHINGS_FOLD_Z))
      return 0;
  }

  if (selector[8] & 2U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*OpenUI *cupsFinishingTemplate/Finishing Template: PickOne\n"
            "*DefaultcupsFinishingTemplate: none\n"
            "*cupsFinishingTemplate none/None: \"\"\n"
            "*cupsFinishingTemplate staple-top-left/Staple Top Left: \"\"\n"
            "*cupsFinishingTemplate fold-z/Z Fold: \"\"\n"
            "*CloseUI: *cupsFinishingTemplate\n"))
      return 0;
  }

  if (selector[14] & 1U)
  {
    if (!cf_v2_ppd_cache_append(
            ppd, ppd_size, &used,
            "*cupsChargeInfoURI: \"https://localhost/charge\"\n"
            "*cupsJobAccountId: True\n"
            "*cupsJobAccountingUserId: True\n"
            "*cupsJobPassword: \"none sha256\"\n"
            "*cupsMandatory: \"job-account-id job-accounting-user-id\"\n"))
      return 0;
  }

  if (!cf_v2_ppd_cache_append(ppd, ppd_size, &used,
                              "*%% Cache selector checksum: %016llx\n"
                              "*%% EOF\n",
                              (unsigned long long)hash))
    return 0;

  return used;
}

static ppd_file_t *
cf_v2_open_generated_ppd(const uint8_t *data, size_t size)
{
  char path[PATH_MAX];
  ppd_file_t *ppd;
  int fd = libppd_make_temp_ppd(path, sizeof(path));

  if (fd < 0)
    return NULL;
  if (libppd_write_all(fd, data, size) != 0)
  {
    close(fd);
    unlink(path);
    return NULL;
  }
  if (close(fd) != 0)
  {
    unlink(path);
    return NULL;
  }
  ppd = ppdOpenFile(path);
  unlink(path);
  return ppd;
}

static void
cf_v2_mark_generated_ppd(ppd_file_t *ppd, const uint8_t *selector)
{
  static const char *const page_sizes[] = {
    "Letter", "A4", "Photo4x6", "A4.Borderless",
  };
  static const char *const sources[] = {
    "Cassette", "Upper", "Manual", "PhotoTray",
  };
  static const char *const media_types[] = {
    "Plain", "Gloss", "Labels", "Cardstock",
  };

  ppdMarkDefaults(ppd);
  if (selector[10] & 1U)
    (void)ppdMarkOption(ppd, "PageSize", page_sizes[selector[0] % 4U]);
  if (selector[10] & 2U)
    (void)ppdMarkOption(ppd, "InputSlot", sources[selector[2] % 4U]);
  if (selector[10] & 4U)
    (void)ppdMarkOption(ppd, "MediaType", media_types[selector[3] % 4U]);
  if (selector[10] & 8U)
    (void)ppdMarkOption(ppd, "Duplex",
                        (selector[5] % 3U == 0U) ? "None" :
                        ((selector[5] % 3U == 1U) ? "DuplexNoTumble" :
                                                   "DuplexTumble"));
}

static void
cf_v2_ppd_cache_roundtrip(ppd_file_t *ppd, ppd_cache_t *cache,
                          ipp_t *attrs, uint64_t hash, int include_attrs)
{
  char path[PATH_MAX];
  ppd_cache_t *loaded = NULL;
  ipp_t *loaded_attrs = NULL;
  int fd;

  if (!cache)
    return;

  fd = libppd_make_temp_ppd(path, sizeof(path));
  if (fd < 0)
    return;
  close(fd);
  unlink(path);

  if (ppdCacheWriteFile(cache, path, include_attrs ? attrs : NULL))
  {
    loaded = ppdCacheCreateWithFile(path, &loaded_attrs);
    libppd_exercise_media_cache(ppd, loaded, hash ^ UINT64_C(0x9e3779b97f4a7c15));
  }
  ippDelete(loaded_attrs);
  ppdCacheDestroy(loaded);
  unlink(path);
}

static void
cf_v2_release_request_collections(ipp_t *request)
{
  ipp_attribute_t *media_attr =
      ippFindAttribute(request, "media-col", IPP_TAG_BEGIN_COLLECTION);
  ipp_t *media_col = media_attr ? ippGetCollection(media_attr, 0) : NULL;
  ipp_attribute_t *size_attr =
      media_col ? ippFindAttribute(media_col, "media-size",
                                   IPP_TAG_BEGIN_COLLECTION)
                : NULL;
  ipp_t *media_size = size_attr ? ippGetCollection(size_attr, 0) : NULL;

  ippDelete(media_size);
  ippDelete(media_col);
}

static void
cf_v2_delete_attribute(ipp_t *attrs, const char *name)
{
  ipp_attribute_t *attr = ippFindAttribute(attrs, name, IPP_TAG_ZERO);

  if (attr)
    ippDeleteAttribute(attrs, attr);
}

static void
cf_v2_ppd_cache_ipp_bridge(ppd_file_t *ppd, ipp_t *printer_attrs,
                           const uint8_t *selector)
{
  static const char *const source_pwg[] = {
    "main", "top", "manual", "photo",
  };
  static const char *const type_pwg[] = {
    "stationery", "photographic-glossy", "labels", "cardstock",
  };
  static const char *const bin_pwg[] = {
    "standard-bin", "face-up", "rear",
  };
  static const char *const side_pwg[] = {
    "one-sided", "two-sided-long-edge", "two-sided-short-edge",
  };
  static const int finishings[] = {
    IPP_FINISHINGS_NONE, IPP_FINISHINGS_STAPLE_TOP_LEFT,
    IPP_FINISHINGS_PUNCH_DUAL_LEFT, IPP_FINISHINGS_BIND_LEFT,
    IPP_FINISHINGS_FOLD_Z,
  };
  static const char *const media_numeric[] = {
    "{media-size={x-dimension=21590 y-dimension=27940}}",
    "{media-size={x-dimension=21000 y-dimension=29700}}",
    "{media-size={x-dimension=10160 y-dimension=15240}}",
    "{media-size={x-dimension=20980 y-dimension=29680}}",
  };
  const cf_v2_ppd_cache_media_t *media =
      cf_v2_ppd_cache_media + selector[0] % 4U;
  const char *source = source_pwg[selector[2] % 4U];
  const char *type = type_pwg[selector[3] % 4U];
  char media_col[512];
  cups_option_t *options = NULL;
  ipp_t *job_attrs = ippNew();
  ipp_t *request = ippNewRequest(IPP_OP_PRINT_JOB);
  ipp_t *support_attrs = ippNew();
  ipp_attribute_t *media_supported;
  ipp_attribute_t *handling_supported;
  ipp_attribute_t *color_supported;
  int num_options;

  if (!job_attrs || !request || !support_attrs || !printer_attrs || !ppd)
    goto cleanup;

  switch ((selector[1] >> 3) % 3U)
  {
    case 1U:
      cf_v2_delete_attribute(printer_attrs, "media-default");
      break;
    case 2U:
      cf_v2_delete_attribute(printer_attrs, "media-default");
      cf_v2_delete_attribute(printer_attrs, "media-col-default");
      break;
    default:
      break;
  }

  switch (selector[1] % 8U)
  {
    case 0:
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media", NULL,
                   media->pwg);
      break;
    case 1:
      snprintf(media_col, sizeof(media_col),
               "{media-size-name=%s media-source=%s media-type=%s}",
               media->pwg, source, type);
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-col", NULL,
                   media_col);
      break;
    case 2:
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-col", NULL,
                   media_numeric[selector[0] % 4U]);
      break;
    case 3:
      break;
    case 4:
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-col", NULL,
                   "{media-size={x-dimension=12700 y-dimension=20320} "
                   "media-source=manual media-type=cardstock}");
      break;
    case 5:
      snprintf(media_col, sizeof(media_col),
               "{media-source=%s media-type=%s}", source, type);
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media-col", NULL,
                   media_col);
      break;
    case 6:
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "media", NULL,
                   media->ppd);
      break;
    default:
      ippAddString(printer_attrs, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
                   "media-default", NULL, media->pwg);
      break;
  }

  if (!(selector[15] & 2U))
    ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "output-bin", NULL,
                 bin_pwg[selector[4] % 3U]);
  if (!(selector[15] & 4U))
    ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "sides", NULL,
                 side_pwg[selector[5] % 3U]);
  if (!(selector[15] & 8U))
  {
    ippAddInteger(job_attrs, IPP_TAG_JOB, IPP_TAG_ENUM, "print-quality",
                  (int)IPP_QUALITY_DRAFT + (int)(selector[6] % 3U));
    ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "print-color-mode",
                 NULL, (selector[7] & 1U) ? "color" : "monochrome");
  }
  if (!(selector[8] & 32U))
  {
    if (selector[8] & 64U)
    {
      char values[64];

      snprintf(values, sizeof(values), "%d,%d,%d",
               finishings[selector[8] % 5U],
               finishings[(selector[8] + 1U) % 5U],
               finishings[(selector[8] + 3U) % 5U]);
      ippAddString(job_attrs, IPP_TAG_JOB, IPP_TAG_KEYWORD, "finishings",
                   NULL, values);
    }
    else if (selector[8] & 16U)
    {
      int values[3] = {
        finishings[selector[8] % 5U],
        finishings[(selector[8] + 1U) % 5U],
        finishings[(selector[8] + 3U) % 5U],
      };
      ippAddIntegers(job_attrs, IPP_TAG_JOB, IPP_TAG_ENUM, "finishings", 3,
                     values);
    }
    else
      ippAddInteger(job_attrs, IPP_TAG_JOB, IPP_TAG_ENUM, "finishings",
                    finishings[selector[8] % 5U]);
  }

  num_options = ppdGetOptions(&options, printer_attrs, job_attrs, ppd);
  num_options = cupsAddOption("collate", (selector[13] & 1U) ? "true" : "false",
                              num_options, &options);
  num_options = cupsAddOption("number-up",
                              (selector[13] & 2U) ? "4" : "1",
                              num_options, &options);
  num_options = cupsAddOption("job-pages",
                              (selector[13] & 4U) ? "7" : "1",
                              num_options, &options);
  if (selector[14] & 1U)
  {
    num_options = cupsAddOption("job-account-id", "cache-account",
                                num_options, &options);
    num_options = cupsAddOption("job-accounting-user-id", "cache-user",
                                num_options, &options);
    num_options = cupsAddOption("job-password", "1234", num_options, &options);
    num_options = cupsAddOption("job-password-encryption", "none",
                                num_options, &options);
  }

  media_supported = ippFindAttribute(printer_attrs, "media-col-supported",
                                     IPP_TAG_ZERO);
  if (!media_supported)
  {
    static const char *const values[] = {
      "media-left-margin", "media-bottom-margin", "media-right-margin",
      "media-top-margin", "media-source", "media-type",
    };
    media_supported = ippAddStrings(support_attrs, IPP_TAG_PRINTER,
                                    IPP_TAG_KEYWORD, "media-col-supported", 6,
                                    NULL, values);
  }
  handling_supported = ippFindAttribute(
      printer_attrs, "multiple-document-handling-supported", IPP_TAG_ZERO);
  if (!handling_supported)
  {
    static const char *const values[] = {
      "separate-documents-uncollated-copies",
      "separate-documents-collated-copies",
    };
    handling_supported = ippAddStrings(
        support_attrs, IPP_TAG_PRINTER, IPP_TAG_KEYWORD,
        "multiple-document-handling-supported", 2, NULL, values);
  }
  color_supported = ippFindAttribute(printer_attrs,
                                     "print-color-mode-supported",
                                     IPP_TAG_ZERO);
  if (!color_supported)
  {
    static const char *const values[] = {"auto", "color", "monochrome"};
    color_supported = ippAddStrings(support_attrs, IPP_TAG_PRINTER,
                                    IPP_TAG_KEYWORD,
                                    "print-color-mode-supported", 3, NULL,
                                    values);
  }

  if (media_supported && handling_supported && color_supported && ppd->cache)
  {
    (void)ppdConvertOptions(
        request, ppd, ppd->cache, media_supported, handling_supported,
        color_supported, "cache-user",
        (selector[13] & 8U) ? "application/pdf" : "application/postscript",
        1 + (int)(selector[13] % 4U), num_options, options);
    cf_v2_release_request_collections(request);
  }

  cupsFreeOptions(num_options, options);
  options = NULL;

cleanup:
  cupsFreeOptions(0, options);
  ippDelete(support_attrs);
  ippDelete(request);
  ippDelete(job_attrs);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char ppd_text[CF_V2_PPD_CACHE_TEXT_SIZE];
  const size_t fixed_size =
      CF_V2_PPD_CACHE_MAGIC_SIZE + CF_V2_PPD_CACHE_SELECTORS;
  const uint8_t *selector;
  ppd_file_t *ppd;
  ppd_cache_t *cache = NULL;
  ipp_t *printer_attrs = NULL;
  uint64_t hash;
  size_t ppd_size;

  if (!data || size < fixed_size ||
      size > fixed_size + CF_V2_PPD_CACHE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_PPD_CACHE_MAGIC, CF_V2_PPD_CACHE_MAGIC_SIZE))
    return 0;

  selector = data + CF_V2_PPD_CACHE_MAGIC_SIZE;
  ppd_size = cf_v2_build_ppd_cache_state(
      selector, data + fixed_size, size - fixed_size,
      ppd_text, sizeof(ppd_text));
  if (!ppd_size)
    return 0;

  ppd = cf_v2_open_generated_ppd((const uint8_t *)ppd_text, ppd_size);
  if (!ppd || !libppd_within_work_budget(ppd))
  {
    ppdClose(ppd);
    return 0;
  }

  hash = libppd_hash(data, size);
  cf_v2_mark_generated_ppd(ppd, selector);

  if (selector[15] & 64U)
  {
    ipp_t *minimal_attrs = ippNew();
    if (minimal_attrs)
    {
      cf_v2_ppd_cache_ipp_bridge(ppd, minimal_attrs, selector);
      ippDelete(minimal_attrs);
    }
    cache = ppd->cache;
  }
  else if (selector[15] & 128U)
  {
    printer_attrs = ppdLoadAttributes(ppd);
    cache = ppd->cache;
  }
  else
    cache = ppdCacheCreateWithPPD(ppd);

  libppd_exercise_media_cache(ppd, cache, hash);

  if (!printer_attrs)
    printer_attrs = ppdLoadAttributes(ppd);
  cf_v2_ppd_cache_roundtrip(ppd, cache, printer_attrs, hash,
                            (selector[11] & 1U) != 0);
  cf_v2_ppd_cache_ipp_bridge(ppd, printer_attrs, selector);

  ippDelete(printer_attrs);
  if (cache != ppd->cache)
    ppdCacheDestroy(cache);
  ppdClose(ppd);
  return 0;
}
