// SPDX-License-Identifier: Apache-2.0
#include "image_pdf_state.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

typedef struct cf_v3_image_pdf_topology_s {
  unsigned x;
  unsigned y;
} cf_v3_image_pdf_topology_t;

static const cf_v3_image_pdf_topology_t cf_v3_image_pdf_topologies[] = {
    {1U, 1U}, {2U, 1U}, {1U, 2U}, {2U, 2U},
    {3U, 1U}, {1U, 3U}, {2U, 3U}, {3U, 2U},
};

static uint32_t cf_v3_image_pdf_u32le(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

void cf_v3_image_pdf_decode_state(const uint8_t *selector,
                                  cf_v3_image_pdf_state_t *state) {
  static const unsigned ppis[] = {8U, 18U, 36U, 72U, 150U, 300U, 600U, 200U};
  static const unsigned auto_ppi[][2] = {
      {80U, 80U}, {80U, 160U}, {160U, 80U}, {150U, 300U}, {300U, 150U},
  };
  static const unsigned saturations[] = {0U, 50U, 100U, 150U, 200U};
  static const int hues[] = {-90, -45, 0, 45, 90};
  const cf_v3_image_pdf_topology_t *topology;

  memset(state, 0, sizeof(*state));
  state->profile = (cf_v3_image_pdf_profile_t)(selector[0] % 4U);
  state->faithful = (selector[1] & 0x80U) != 0U;
  state->mirror = (selector[1] & 1U) != 0U;
  state->format_selector = selector[2] & ~CF_V3_IMAGE_PDF_RAW_PNG_FLAG;
  state->source_selector = selector[3];
  state->geometry_selector = selector[4];
  state->codec_selector = selector[5];
  topology = &cf_v3_image_pdf_topologies[
      selector[6] % (sizeof(cf_v3_image_pdf_topologies) /
                     sizeof(cf_v3_image_pdf_topologies[0]))];
  state->topology_x = topology->x;
  state->topology_y = topology->y;
  state->natural_scaling = cf_v3_image_pdf_u32le(selector + 8U);
  state->page_size = selector[12] & 1U;
  state->orientation = selector[13] % 5U;
  state->position = selector[14] % 9U;
  state->copies = 1U + selector[15] % 4U;
  state->collate = (selector[16] & 1U) != 0U;
  state->duplex = (selector[16] & 6U) != 0U;
  state->reverse = (selector[16] & 8U) != 0U;
  state->even_duplex = (selector[16] & 16U) != 0U;
  state->hardware_copies_policy = (selector[16] >> 5U) % 3U;
  state->hardware_collate_policy = selector[17] % 3U;
  state->color_selector = selector[18] % 3U;
  state->ppd_profile = selector[19] % 4U;
  state->pattern = selector[20] % 8U;
  state->phase = selector[21];
  state->stride = 1U + 2U * (selector[22] % 32U);
  state->gamma = 500U + 5U * (selector[23] % 301U);
  state->brightness = 50U + selector[24] % 151U;
  state->saturation =
      saturations[selector[25] %
                  (sizeof(saturations) / sizeof(saturations[0]))];
  state->hue = hues[selector[26] % (sizeof(hues) / sizeof(hues[0]))];
  memcpy(state->codec_controls, selector + 27U,
         sizeof(state->codec_controls) - 1U);
  state->codec_controls[5] = selector[7];

  state->xppi = state->yppi = ppis[selector[7] %
                                      (sizeof(ppis) / sizeof(ppis[0]))];
  if (state->profile == CF_V3_IMAGE_PDF_SEQUENCE) {
    state->xppi = state->yppi = 8U;
    state->page_size = 1U;
    state->orientation = 0U;
    state->position = 0U;
    state->explicit_width = 64U * state->topology_x;
    state->explicit_height = 80U * state->topology_y;
  } else if (state->profile == CF_V3_IMAGE_PDF_AUTO_FIT) {
    const unsigned *resolution =
        auto_ppi[selector[7] % (sizeof(auto_ppi) / sizeof(auto_ppi[0]))];

    state->xppi = resolution[0];
    state->yppi = resolution[1];
    state->copies = 1U;
    state->collate = false;
    state->duplex = false;
    state->reverse = false;
    state->even_duplex = false;
    state->hardware_copies_policy = 1U;
    state->hardware_collate_policy = 1U;
  } else if (state->profile == CF_V3_IMAGE_PDF_CARDINALITY) {
    state->orientation = 0U;
    state->position = 0U;
    state->copies = 1U;
    state->collate = false;
    state->duplex = false;
    state->reverse = false;
    state->even_duplex = false;
    state->hardware_copies_policy = 1U;
    state->hardware_collate_policy = 1U;
    if (!state->natural_scaling) {
      state->natural_scaling = 1U;
    }
    if (!state->faithful) {
      state->natural_scaling = 1U + state->natural_scaling % 20000U;
    }
  } else {
    state->copies = 1U;
    state->collate = false;
    state->duplex = false;
    state->reverse = false;
    state->even_duplex = false;
    state->hardware_copies_policy = 1U;
    state->hardware_collate_policy = 1U;
  }
  state->requested_collate = state->collate;
  state->requested_even_duplex = state->even_duplex;
}

static bool cf_v3_image_pdf_append(cf_v3_image_pdf_oracle_t *oracle,
                                   int page) {
  if (oracle->page_count >= CF_V3_IMAGE_PDF_ORACLE_MAX_PAGES) {
    return false;
  }
  oracle->pages[oracle->page_count++] = page;
  return true;
}

static bool cf_v3_image_pdf_sequence_model(cf_v3_image_pdf_state_t *state,
                                           cf_v3_image_pdf_oracle_t *oracle) {
  unsigned device_copies = 1U;
  bool device_collate = false;
  unsigned tile_count = state->topology_x * state->topology_y;

  state->software_copies = state->copies;
  if (state->software_copies == 1U) {
    state->collate = false;
  }
  if (!state->duplex) {
    state->even_duplex = false;
  }
  state->known_collate_boundary =
      state->copies > 1U && state->requested_collate &&
      state->hardware_copies_policy == 1U;
  if (!state->faithful && state->known_collate_boundary) {
    state->hardware_copies_policy = 2U;
    state->known_collate_boundary = false;
  }

  /* Omitted hardware policies default to true for the PDF destination. */
  if (state->hardware_copies_policy != 1U) {
    device_copies = state->software_copies;
    state->software_copies = 1U;
  }
  if (device_copies > 1U && state->collate) {
    device_collate = state->hardware_collate_policy != 1U;
  }
  if (device_copies > 1U && state->collate && !device_collate) {
    state->software_copies = device_copies;
    device_copies = 1U;
  }
  if (state->software_copies > 1U && device_copies == 1U && state->duplex) {
    state->collate = true;
    device_collate = false;
  }
  if (state->duplex && state->collate && !device_collate) {
    state->even_duplex = true;
  }
  if (state->duplex && state->reverse) {
    state->even_duplex = true;
  }
  if (device_collate) {
    state->collate = false;
  }
  if (tile_count == 1U && (state->collate || device_collate) &&
      !state->even_duplex) {
    state->collate = false;
  }
  if ((tile_count & 1U) == 0U) {
    state->even_duplex = false;
  }
  state->known_even_duplex_boundary =
      state->duplex && (tile_count & 1U) != 0U &&
      state->software_copies > 1U && !state->known_collate_boundary;
  if (!state->faithful && state->known_even_duplex_boundary) {
    state->software_copies = state->copies = 1U;
    state->collate = false;
    state->even_duplex = state->reverse;
    state->requested_even_duplex = state->reverse;
    state->known_even_duplex_boundary = false;
  }

  if (state->collate) {
    for (unsigned copy = 0; copy < state->software_copies; copy++) {
      for (unsigned tile = 0; tile < tile_count; tile++) {
        if (!cf_v3_image_pdf_append(oracle, (int)tile)) {
          return false;
        }
      }
      if (state->even_duplex &&
          (copy + 1U < state->software_copies || state->reverse) &&
          !cf_v3_image_pdf_append(oracle, -1)) {
        return false;
      }
    }
  } else {
    for (unsigned tile = 0; tile < tile_count; tile++) {
      for (unsigned copy = 0; copy < state->software_copies; copy++) {
        if (!cf_v3_image_pdf_append(oracle, (int)tile)) {
          return false;
        }
      }
    }
    if (state->even_duplex && !cf_v3_image_pdf_append(oracle, -1)) {
      return false;
    }
  }
  if (state->reverse && oracle->page_count) {
    for (size_t left = 0, right = oracle->page_count - 1U; left < right;
         left++, right--) {
      int temporary = oracle->pages[left];
      oracle->pages[left] = oracle->pages[right];
      oracle->pages[right] = temporary;
    }
  }
  return oracle->page_count > 0U;
}

static bool cf_v3_image_pdf_cardinality(
    cf_v3_image_pdf_state_t *state, unsigned width, unsigned height,
    unsigned *xpages, unsigned *ypages) {
  /* cfRasterPrepareHeader converts each A4 12-point PPD margin to 423 PWG
   * units before converting the resulting imageable area back to points. */
  const float printable_width =
      state->page_size ? 8.0f : 20154.0f / 2540.0f;
  const float printable_height =
      state->page_size ? 10.0f : 28854.0f / 2540.0f;
  uint32_t scaling = state->natural_scaling;

  for (;;) {
    float xinches = (float)width / (float)state->xppi;
    float yinches = (float)height / (float)state->yppi;
    long double wide_x;
    long double wide_y;

    xinches = xinches * (float)scaling / 100.0f;
    yinches = yinches * (float)scaling / 100.0f;
    /* imagetopdf.c divides two floats before promoting the result for ceil().
     * Repeating the division in long double changes exact page boundaries. */
    wide_x = ceil((double)(xinches / printable_width));
    wide_y = ceil((double)(yinches / printable_height));
    if (!isfinite((double)wide_x) || !isfinite((double)wide_y) || wide_x < 1.0L ||
        wide_y < 1.0L) {
      return false;
    }
    if (wide_x <= UINT32_MAX && wide_y <= UINT32_MAX &&
        (state->faithful ||
         (wide_x * wide_y <= 32.0L && wide_x <= (long double)width &&
          wide_y <= (long double)height))) {
      *xpages = (unsigned)wide_x;
      *ypages = (unsigned)wide_y;
      state->natural_scaling = scaling;
      return true;
    }
    if (state->faithful || scaling <= 1U) {
      return false;
    }
    scaling = (scaling + 1U) / 2U;
  }
}

bool cf_v3_image_pdf_model(cf_v3_image_pdf_state_t *state, unsigned width,
                           unsigned height,
                           cf_v3_image_pdf_oracle_t *oracle) {
  unsigned xpages = 1U;
  unsigned ypages = 1U;

  if (!state || !width || !height || !oracle) {
    return false;
  }
  memset(oracle, 0, sizeof(*oracle));
  oracle->page_width = state->page_size ? 612.0L : 595.275590551L;
  oracle->page_height = state->page_size ? 792.0L : 841.889763780L;

  if (state->profile == CF_V3_IMAGE_PDF_SEQUENCE) {
    xpages = state->topology_x;
    ypages = state->topology_y;
  } else if (state->profile == CF_V3_IMAGE_PDF_CARDINALITY &&
             !cf_v3_image_pdf_cardinality(state, width, height, &xpages,
                                          &ypages)) {
    return false;
  }
  state->topology_x = xpages;
  state->topology_y = ypages;
  oracle->xpages = xpages;
  oracle->ypages = ypages;
  if (state->faithful &&
      ((uint64_t)xpages * ypages > CF_V3_IMAGE_PDF_ORACLE_MAX_PAGES)) {
    /* The faithful filter call is still useful for sanitizer replay, but its
     * intentionally huge output is not captured or parsed. */
    return true;
  }
  return cf_v3_image_pdf_sequence_model(state, oracle);
}

int cf_v3_image_pdf_build_options(const cf_v3_image_pdf_state_t *state,
                                  unsigned components, char *buffer,
                                  size_t buffer_size) {
  static const char *const page_sizes[] = {"A4", "Letter"};
  static const char *const positions[] = {
      "center", "top", "top-left", "top-right", "left",
      "right",  "bottom", "bottom-left", "bottom-right",
  };
  static const char *const policies[] = {NULL, "false", "true"};
  const char *color_model =
      components == 1U ? "Gray" : components == 4U ? "CMYK" : "RGB";
  const char *sides = !state->duplex
                          ? "one-sided"
                          : (state->orientation & 1U)
                                ? "two-sided-short-edge"
                                : "two-sided-long-edge";
  char orientation[48] = "";
  int length;

  if (state->profile != CF_V3_IMAGE_PDF_AUTO_FIT || state->orientation) {
    int orientation_length =
        snprintf(orientation, sizeof(orientation), "orientation-requested=%u ",
                 state->orientation ? 2U + state->orientation : 3U);
    if (orientation_length < 0 ||
        (size_t)orientation_length >= sizeof(orientation)) {
      return -1;
    }
  }

  length = snprintf(
      buffer, buffer_size,
      "PageSize=%s ColorModel=%s Resolution=300dpi sides=%s "
      "%sposition=%s Collate=%s OutputOrder=%s "
      "mirror=%s even-duplex=%s gamma=%u brightness=%u saturation=%u "
      "hue=%d emit-jcl=false",
      page_sizes[state->page_size], color_model, sides,
      orientation, positions[state->position],
      state->requested_collate ? "true" : "false",
      state->reverse ? "Reverse" : "Normal",
      state->mirror ? "true" : "false",
      state->requested_even_duplex ? "true" : "false", state->gamma,
      state->brightness, state->saturation, state->hue);
  if (length < 0 || (size_t)length >= buffer_size) {
    return -1;
  }
  if (state->profile == CF_V3_IMAGE_PDF_SEQUENCE) {
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " ppi=8");
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
    length += extra;
  } else if (state->profile == CF_V3_IMAGE_PDF_CARDINALITY) {
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " ppi=%u natural-scaling=%u", state->xppi,
                         state->natural_scaling);
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
    length += extra;
  } else {
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " print-scaling=fit");
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
    length += extra;
  }
  if (policies[state->hardware_copies_policy]) {
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " hardware-copies=%s",
                         policies[state->hardware_copies_policy]);
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
    length += extra;
  }
  if (policies[state->hardware_collate_policy]) {
    int extra = snprintf(buffer + length, buffer_size - (size_t)length,
                         " hardware-collate=%s",
                         policies[state->hardware_collate_policy]);
    if (extra < 0 || (size_t)extra >= buffer_size - (size_t)length) {
      return -1;
    }
  }
  return 0;
}
