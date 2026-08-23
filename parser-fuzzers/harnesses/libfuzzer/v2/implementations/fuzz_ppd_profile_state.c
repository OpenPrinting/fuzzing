// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#define LLVMFuzzerTestOneInput cf_v2_ppd_profile_test_one_input
#define LIBPPD_PROFILES_DEEP_MODE
#define LIBPPD_PROFILES_MAX_INPUT (32U * 1024U)
#include "../../fuzz_libppd_profiles.c"
#undef LLVMFuzzerTestOneInput

#define CF_V2_PPD_PROFILE_MAGIC "PPDPROF1"
#define CF_V2_PPD_PROFILE_MAGIC_SIZE 8U
#define CF_V2_PPD_PROFILE_SELECTORS 16U
#define CF_V2_PPD_PROFILE_MAX_PAYLOAD 64U
#define CF_V2_PPD_PROFILE_TEXT_SIZE (32U * 1024U)

static int
cf_v2_profile_append(char *buffer, size_t capacity, size_t *used,
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

static int
cf_v2_profile_attribute(char *buffer, size_t capacity, size_t *used,
                        const char *name, const char *spec,
                        const char *value)
{
  if (spec[0])
    return cf_v2_profile_append(buffer, capacity, used,
                                "*%s %s: \"%s\"\n", name, spec, value);
  return cf_v2_profile_append(buffer, capacity, used,
                              "*%s: \"%s\"\n", name, value);
}

static int
cf_v2_profile_curve(char *buffer, size_t capacity, size_t *used,
                    const char *name, const char *spec,
                    unsigned points, unsigned shape)
{
  char value[64];
  unsigned index;

  for (index = 0; index < points; index ++)
  {
    const double x = points > 1U ? (double)index / (double)(points - 1U) : 0.0;
    double y;

    switch (shape % 4U)
    {
      case 1:
        y = x * x;
        break;
      case 2:
        y = 0.25 * x + 0.75 * x * x;
        break;
      case 3:
        y = index + 1U == points ? 1.0 : 0.8 * x;
        break;
      default:
        y = x;
        break;
    }
    if (snprintf(value, sizeof(value), "%.6f %.6f", x, y) < 0 ||
        !cf_v2_profile_attribute(buffer, capacity, used, name, spec, value))
      return 0;
  }
  return 1;
}

static int
cf_v2_profile_gamma(char *buffer, size_t capacity, size_t *used,
                    const char *name, const char *spec,
                    unsigned gamma_selector, unsigned density_selector)
{
  char value[64];
  const double gamma = 1.0 + (double)(gamma_selector % 24U) / 10.0;
  const double density = 0.4 + (double)(density_selector % 7U) / 10.0;

  if (snprintf(value, sizeof(value), "%.2f %.2f", gamma,
               density > 1.0 ? 1.0 : density) < 0)
    return 0;
  return cf_v2_profile_attribute(buffer, capacity, used, name, spec, value);
}

static int
cf_v2_profile_dither(char *buffer, size_t capacity, size_t *used,
                     const char *name, const char *spec, unsigned selector)
{
  static const char *const values[] = {
    "1", "0.25 1", "0.25 0.75 1", "0.1 0.4 0.8 1", "4 0.25 1",
  };

  return cf_v2_profile_attribute(
      buffer, capacity, used, name, spec,
      values[selector % (sizeof(values) / sizeof(values[0]))]);
}

static int
cf_v2_profile_rgb(char *buffer, size_t capacity, size_t *used,
                  const char *spec,
                  const uint8_t selector[CF_V2_PPD_PROFILE_SELECTORS])
{
  char value[160];
  const unsigned cube_size = 2U + selector[14] % 3U;
  const unsigned channels = 1U + selector[10] % 4U;
  const unsigned samples = cube_size * cube_size * cube_size;
  unsigned sample;

  if (snprintf(value, sizeof(value), "%u %u %u", cube_size, channels,
               samples) < 0 ||
      !cf_v2_profile_attribute(buffer, capacity, used, "cupsRGBProfile",
                               spec, value))
    return 0;
  for (sample = 0; sample < samples; sample ++)
  {
    const unsigned r = sample / (cube_size * cube_size);
    const unsigned g = (sample / cube_size) % cube_size;
    const unsigned b = sample % cube_size;
    const unsigned denominator = 3U * (cube_size - 1U);
    size_t value_used;
    unsigned channel;

    value_used = (size_t)snprintf(value, sizeof(value), "%.4f %.4f %.4f",
                                  (double)r / (double)(cube_size - 1U),
                                  (double)g / (double)(cube_size - 1U),
                                  (double)b / (double)(cube_size - 1U));
    if (value_used >= sizeof(value))
      return 0;
    for (channel = 0; channel < channels; channel ++)
    {
      const unsigned output_value =
          (r * (channel + 1U) + g * (channel + 2U) +
           b * (selector[11] % 5U + 1U)) % (denominator + 1U);
      const int length = snprintf(
          value + value_used, sizeof(value) - value_used, " %.4f",
          (double)output_value / (double)denominator);
      if (length < 0 || (size_t)length >= sizeof(value) - value_used)
        return 0;
      value_used += (size_t)length;
    }
    if (!cf_v2_profile_attribute(buffer, capacity, used, "cupsRGBSample",
                                 spec, value))
      return 0;
  }
  return 1;
}

static int
cf_v2_profile_curve_choice(
    char *buffer, size_t capacity, size_t *used, const char *base_name,
    const char *spec, unsigned mode, unsigned points, unsigned shape,
    unsigned gamma_selector, unsigned density_selector)
{
  char name[64];
  const char *suffix = mode == 0U ? "XY" : "Gamma";

  if (snprintf(name, sizeof(name), "cups%s%s", base_name, suffix) < 0)
    return 0;
  if (mode == 0U)
    return cf_v2_profile_curve(buffer, capacity, used, name, spec, points,
                               shape);
  return cf_v2_profile_gamma(buffer, capacity, used, name, spec,
                             gamma_selector, density_selector);
}

static int
cf_v2_profile_ltdk(char *buffer, size_t capacity, size_t *used,
                   const char *name, const char *spec, unsigned selector)
{
  char value[64];
  const double light = (double)(selector % 4U) / 10.0;
  const double dark = 0.6 + (double)(selector % 4U) / 10.0;

  if (snprintf(value, sizeof(value), "%.2f %.2f", light, dark) < 0)
    return 0;
  return cf_v2_profile_attribute(buffer, capacity, used, name, spec, value);
}

static size_t
cf_v2_build_profile_ppd(const uint8_t selector[CF_V2_PPD_PROFILE_SELECTORS],
                        const uint8_t *payload, size_t payload_size,
                        char *ppd, size_t ppd_size)
{
  static const unsigned channels[] = {1U, 2U, 3U, 4U, 6U, 7U};
  static const char *const specs[] = {
    "Black.Plain.300dpi", "Gray.Plain.600dpi",
    "CMYK.Plain.300dpi", "CMYK.Plain.300x600dpi",
  };
  static const char *const rgb_specs[] = {
    "RGB.Glossy.600dpi", "RGB.600dpi", "RGB", "Glossy.600dpi",
    "Glossy", "600dpi", "",
  };
  static const char *const direct_curves[] = {
    "Black", "Cyan", "Magenta", "Yellow",
    "LightBlack", "LightCyan", "LightMagenta",
  };
  const unsigned curve_mode = selector[12] % 6U;
  const unsigned point_count = 2U + selector[4] % 15U;
  const unsigned dither_mode = (selector[9] >> 2U) % 3U;
  char value[128];
  size_t used = 0;
  size_t index;

  if (!cf_v2_profile_append(
          ppd, ppd_size, &used,
          "*PPD-Adobe: \"4.3\"\n"
          "*FormatVersion: \"4.3\"\n"
          "*FileVersion: \"2.0\"\n"
          "*LanguageVersion: English\n"
          "*LanguageEncoding: ISOLatin1\n"
          "*Manufacturer: \"OpenPrinting\"\n"
          "*ModelName: \"bounded profile state\"\n"
          "*ShortNickName: \"bounded profile\"\n"
          "*NickName: \"bounded profile %u\"\n"
          "*PCFileName: \"PROFILE.PPD\"\n"
          "*Product: \"(bounded profile)\"\n"
          "*PSVersion: \"(3010) 0\"\n"
          "*cupsVersion: 2.0\n",
          selector[15]))
    return 0;

  for (index = 0; index < sizeof(specs) / sizeof(specs[0]); index ++)
    if (!cf_v2_profile_append(ppd, ppd_size, &used,
                              "*cupsInkChannels %s: \"%u\"\n",
                              specs[index],
                              channels[(selector[index] + index) %
                                       (sizeof(channels) / sizeof(channels[0]))]))
      return 0;

  if (curve_mode <= 1U)
  {
    if (!cf_v2_profile_curve_choice(
            ppd, ppd_size, &used, "Black", specs[0], curve_mode,
            point_count, selector[5], selector[5], selector[6]) ||
        !cf_v2_profile_curve_choice(
            ppd, ppd_size, &used, "Black", specs[1], curve_mode,
            point_count, selector[5] + 1U, selector[5] + 1U,
            selector[6] + 1U) ||
        !cf_v2_profile_curve_choice(
            ppd, ppd_size, &used, "LightBlack", specs[1], curve_mode,
            point_count, selector[5] + 2U, selector[5] + 2U,
            selector[6] + 2U))
      return 0;

    for (index = 2; index < sizeof(specs) / sizeof(specs[0]); index ++)
    {
      size_t curve;

      for (curve = 0;
           curve < sizeof(direct_curves) / sizeof(direct_curves[0]);
           curve ++)
        if (!cf_v2_profile_curve_choice(
                ppd, ppd_size, &used, direct_curves[curve], specs[index],
                curve_mode, point_count, selector[5] + (unsigned)curve,
                selector[5] + (unsigned)curve,
                selector[6] + (unsigned)curve))
          return 0;
    }
  }
  else if (curve_mode <= 3U)
  {
    for (index = 0; index < sizeof(specs) / sizeof(specs[0]); index ++)
      if (!cf_v2_profile_curve_choice(
              ppd, ppd_size, &used, "All", specs[index], curve_mode - 2U,
              point_count, selector[5] + (unsigned)index,
              selector[5] + (unsigned)index,
              selector[6] + (unsigned)index))
        return 0;
  }
  else if (curve_mode == 4U)
  {
    if (!cf_v2_profile_ltdk(ppd, ppd_size, &used, "cupsBlackLtDk",
                            specs[0], selector[8]) ||
        !cf_v2_profile_ltdk(ppd, ppd_size, &used, "cupsBlackLtDk",
                            specs[1], selector[8] + 1U))
      return 0;
    for (index = 2; index < sizeof(specs) / sizeof(specs[0]); index ++)
      if (!cf_v2_profile_ltdk(ppd, ppd_size, &used, "cupsBlackLtDk",
                              specs[index], selector[8] + (unsigned)index) ||
          !cf_v2_profile_ltdk(ppd, ppd_size, &used, "cupsCyanLtDk",
                              specs[index], selector[8] + (unsigned)index + 1U) ||
          !cf_v2_profile_ltdk(ppd, ppd_size, &used, "cupsMagentaLtDk",
                              specs[index], selector[8] + (unsigned)index + 2U))
        return 0;
  }

  if (snprintf(value, sizeof(value), "%.2f",
               0.25 + (double)(selector[6] % 28U) / 10.0) < 0 ||
      !cf_v2_profile_attribute(ppd, ppd_size, &used, "cupsInkLimit",
                               specs[2], value) ||
      snprintf(value, sizeof(value), "%.2f %.2f",
               (double)(selector[7] % 5U) / 10.0,
               0.5 + (double)(selector[7] % 6U) / 10.0) < 0 ||
      !cf_v2_profile_attribute(ppd, ppd_size, &used,
                               "cupsBlackGeneration", specs[2], value) ||
      !cf_v2_profile_rgb(ppd, ppd_size, &used,
                         rgb_specs[selector[13] %
                                   (sizeof(rgb_specs) / sizeof(rgb_specs[0]))],
                         selector))
    return 0;

  if (dither_mode == 0U)
  {
    static const char *const dither_names[] = {
      "cupsBlackDither", "cupsLightBlackDither", "cupsCyanDither",
      "cupsMagentaDither", "cupsYellowDither",
    };
    static const char *const dither_specs[] = {
      "Black.Plain.300dpi", "Gray.Plain.600dpi", "RGB.Glossy.600dpi",
      "CMYK.Plain.300dpi", "CMYK.Plain.300x600dpi",
    };

    for (index = 0;
         index < sizeof(dither_names) / sizeof(dither_names[0]); index ++)
      if (!cf_v2_profile_dither(ppd, ppd_size, &used, dither_names[index],
                                dither_specs[index],
                                selector[9] + (unsigned)index))
        return 0;
  }
  else if (dither_mode == 1U)
  {
    static const char *const dither_specs[] = {
      "Black.Plain.300dpi", "Gray.Plain.600dpi", "RGB.Glossy.600dpi",
      "CMYK.Plain.300dpi", "CMYK.Plain.300x600dpi",
    };

    for (index = 0;
         index < sizeof(dither_specs) / sizeof(dither_specs[0]); index ++)
      if (!cf_v2_profile_dither(ppd, ppd_size, &used, "cupsAllDither",
                                dither_specs[index],
                                selector[9] + (unsigned)index))
        return 0;
  }

  if (!cf_v2_profile_append(ppd, ppd_size, &used, "*% profile-material"))
    return 0;
  for (index = 0; index < payload_size; index ++)
    if (!cf_v2_profile_append(ppd, ppd_size, &used, " %02x", payload[index]))
      return 0;
  if (!cf_v2_profile_append(ppd, ppd_size, &used, "\n"))
    return 0;
  return used;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char ppd[CF_V2_PPD_PROFILE_TEXT_SIZE];
  const uint8_t *selector;
  const uint8_t *payload;
  size_t payload_size;
  size_t ppd_size;

  if (!data ||
      size < CF_V2_PPD_PROFILE_MAGIC_SIZE + CF_V2_PPD_PROFILE_SELECTORS ||
      size > CF_V2_PPD_PROFILE_MAGIC_SIZE + CF_V2_PPD_PROFILE_SELECTORS +
                 CF_V2_PPD_PROFILE_MAX_PAYLOAD ||
      memcmp(data, CF_V2_PPD_PROFILE_MAGIC,
             CF_V2_PPD_PROFILE_MAGIC_SIZE) != 0)
    return 0;

  selector = data + CF_V2_PPD_PROFILE_MAGIC_SIZE;
  payload = selector + CF_V2_PPD_PROFILE_SELECTORS;
  payload_size = size - CF_V2_PPD_PROFILE_MAGIC_SIZE -
                 CF_V2_PPD_PROFILE_SELECTORS;
  ppd_size = cf_v2_build_profile_ppd(selector, payload, payload_size,
                                     ppd, sizeof(ppd));
  if (ppd_size)
    (void)cf_v2_ppd_profile_test_one_input((const uint8_t *)ppd, ppd_size);
  return 0;
}
