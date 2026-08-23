// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_PROFILES_H
#define CUPSFILTERS_FUZZ_PROFILES_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* These profiles are intentionally small and fixed.  Input bytes exercise the
 * document parser; the hash selects a valid printer configuration. */
static const char *const cupsfilters_fuzz_options[] = {
    "PageSize=A4 ColorModel=Gray Resolution=300dpi",
    "PageSize=Letter ColorModel=RGB Resolution=600dpi Duplex=None",
    "PageSize=A4 ColorModel=CMYK MediaType=Plain",
    "PageSize=A4 ColorModel=Gray Resolution=300dpi",
};

static const char *const cupsfilters_fuzz_image_options[] = {
    "PageSize=A4 ColorModel=Gray Resolution=300dpi",
    "PageSize=Letter ColorModel=RGB Resolution=600dpi orientation-requested=4 position=top-left fit-to-page gamma=1800 brightness=150 saturation=140 hue=15 mirror=true",
    "PageSize=A4 ColorModel=CMYK Resolution=300dpi print-scaling=fill position=bottom-right natural-scaling=85",
    "PageSize=Letter ColorModel=RGB Resolution=300dpi crop-to-fit=true landscape=true mirror=true",
    "PageSize=A4 ColorModel=Gray Resolution=600dpi ppi=150 scaling=75"
};

static inline size_t cupsfilters_fuzz_profile_index(const uint8_t *data,
                                                    size_t size) {
  uint32_t hash = 2166136261u;
  size_t i;
  for (i = 0; i < size; i++) {
    hash ^= data[i];
    hash *= 16777619u;
  }
  return hash % (sizeof(cupsfilters_fuzz_options) /
                 sizeof(cupsfilters_fuzz_options[0]));
}

static inline int cupsfilters_fuzz_write_ppd(FILE *file, size_t profile,
                                             const char *filter_name) {
  static const int model_numbers[] = {0, 2, 0x1130, 0x40};
  static const char *const page_sizes[] = {"A4", "Letter", "A4", "A4"};
  static const char *const page_dimensions[] = {
      "595 842", "612 792", "595 842", "595 842"};
  static const char *const imageable_areas[] = {
      "12 12 583 830", "18 36 594 756", "12 12 583 830",
      "12 12 583 830"};
  static const char *const resolutions[] = {
      "300dpi", "600dpi", "300dpi", "300dpi"};
  static const char *const color_models[] = {"Gray", "RGB", "CMYK", "Gray"};

  return fprintf(
             file,
             "*PPD-Adobe: \"4.3\"\n"
             "*FormatVersion: \"4.3\"\n"
             "*FileVersion: \"1.0\"\n"
             "*LanguageVersion: English\n"
             "*LanguageEncoding: ISOLatin1\n"
             "*Manufacturer: \"OpenPrinting\"\n"
             "*ModelName: \"cups-filters fuzz profile\"\n"
             "*ShortNickName: \"cups-filters fuzz\"\n"
             "*NickName: \"cups-filters fuzz profile\"\n"
             "*PCFileName: \"FUZZ.PPD\"\n"
             "*Product: \"(cups-filters fuzz profile)\"\n"
             "*PSVersion: \"(3010) 0\"\n"
             "*cupsVersion: 1.0\n"
             "*cupsModelNumber: %d\n"
             "*cupsManualCopies: False\n"
             "*cupsFilter: \"application/octet-stream 0 %s\"\n"
             "*OpenUI *PageSize: PickOne\n"
             "*DefaultPageSize: %s\n"
             "*PageSize A4/A4: \"<</PageSize[595 842]/ImagingBBox null>>setpagedevice\"\n"
             "*PageSize Letter/Letter: \"<</PageSize[612 792]/ImagingBBox null>>setpagedevice\"\n"
             "*CloseUI: *PageSize\n"
             "*DefaultImageableArea: %s\n"
             "*ImageableArea A4: \"12 12 583 830\"\n"
             "*ImageableArea Letter: \"18 36 594 756\"\n"
             "*DefaultPaperDimension: %s\n"
             "*PaperDimension A4: \"595 842\"\n"
             "*PaperDimension Letter: \"612 792\"\n"
             "*OpenUI *ColorModel: PickOne\n"
             "*DefaultColorModel: %s\n"
             "*ColorModel Gray/Gray: \"<</cupsColorSpace 18/cupsBitsPerColor 8/cupsBitsPerPixel 8>>setpagedevice\"\n"
             "*ColorModel RGB/RGB: \"<</cupsColorSpace 1/cupsBitsPerColor 8/cupsBitsPerPixel 24>>setpagedevice\"\n"
             "*ColorModel CMYK/CMYK: \"<</cupsColorSpace 6/cupsBitsPerColor 8/cupsBitsPerPixel 32>>setpagedevice\"\n"
             "*CloseUI: *ColorModel\n"
             "*OpenUI *Resolution: PickOne\n"
             "*DefaultResolution: %s\n"
             "*Resolution 300dpi/300 dpi: \"<</HWResolution[300 300]>>setpagedevice\"\n"
             "*Resolution 600dpi/600 dpi: \"<</HWResolution[600 600]>>setpagedevice\"\n"
             "*CloseUI: *Resolution\n",
             model_numbers[profile], filter_name, page_sizes[profile],
             imageable_areas[profile], page_dimensions[profile],
             color_models[profile], resolutions[profile]) < 0
             ? -1
             : 0;
}

#endif
