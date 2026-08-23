// SPDX-License-Identifier: Apache-2.0
#include "image_raster_state.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

typedef struct cf_v3_image_raster_geometry_s {
  unsigned width;
  unsigned height;
} cf_v3_image_raster_geometry_t;

typedef struct cf_v3_image_raster_topology_s {
  unsigned x;
  unsigned y;
} cf_v3_image_raster_topology_t;

static const cf_v3_image_raster_geometry_t
    cf_v3_image_raster_natural_geometries[] = {
        {4U, 4U},   {8U, 16U},  {16U, 8U},  {16U, 32U}, {32U, 16U},
        {32U, 64U}, {64U, 32U}, {64U, 128U}, {128U, 64U},
};

static const cf_v3_image_raster_topology_t
    cf_v3_image_raster_topologies[] = {
        {2U, 1U}, {1U, 2U}, {2U, 2U}, {3U, 1U},
        {1U, 3U}, {2U, 3U}, {3U, 2U},
};

static uint32_t cf_v3_image_raster_u32le(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static unsigned cf_v3_image_raster_chunked_bpp(unsigned colors,
                                                unsigned bits) {
  return colors * bits;
}

static void cf_v3_image_raster_select_output(
    unsigned selector, cf_v3_image_raster_output_t *output) {
  static const cups_cspace_t spaces[] = {
      CUPS_CSPACE_SW, CUPS_CSPACE_RGB, CUPS_CSPACE_CMYK,
  };
  static const unsigned colors[] = {1U, 3U, 4U};
  static const unsigned depths[] = {1U, 2U, 4U, 8U, 16U};
  unsigned space_index = selector % 3U;
  unsigned depth_index = (selector / 3U) % 5U;
  unsigned order_index = (selector / 15U) % 3U;

  memset(output, 0, sizeof(*output));
  output->color_space = spaces[space_index];
  output->num_colors = colors[space_index];
  output->bits_per_color = depths[depth_index];
  output->color_order = (cups_order_t)order_index;
  output->bits_per_pixel =
      output->color_order == CUPS_ORDER_CHUNKED
          ? cf_v3_image_raster_chunked_bpp(output->num_colors,
                                           output->bits_per_color)
          : output->bits_per_color;
  if (output->color_space == CUPS_CSPACE_RGB &&
      output->color_order == CUPS_ORDER_CHUNKED &&
      output->bits_per_color == 4U) {
    /* The current CUPS Raster/ImageToRaster writer set does not support this
     * tuple. Keep the selector total by projecting it to the adjacent 8-bit
     * RGB writer profile; header-boundary fuzzing owns rejected tuples. */
    output->bits_per_color = 8U;
    output->bits_per_pixel = 24U;
  }
}

static void cf_v3_image_raster_safe_cardinality(
    cf_v3_image_raster_state_t *state) {
  uint64_t xpages;
  uint64_t ypages;
  unsigned scaling = state->natural_scaling ? state->natural_scaling : 1U;
  uint64_t min_x = ((uint64_t)100U * state->xppi +
                    (uint64_t)state->explicit_width *
                            state->output_resolution_x -
                        1U) /
                   ((uint64_t)state->explicit_width *
                    state->output_resolution_x);
  uint64_t min_y = ((uint64_t)100U * state->yppi +
                    (uint64_t)state->explicit_height *
                            state->output_resolution_y -
                        1U) /
                   ((uint64_t)state->explicit_height *
                    state->output_resolution_y);
  unsigned minimum = (unsigned)(min_x > min_y ? min_x : min_y);

  if (!minimum) {
    minimum = 1U;
  }
  if (scaling < minimum) {
    scaling = minimum;
  }

  for (;;) {
    xpages = ((uint64_t)state->explicit_width * scaling +
              (uint64_t)state->xppi * 100U - 1U) /
             ((uint64_t)state->xppi * 100U);
    ypages = ((uint64_t)state->explicit_height * scaling +
              (uint64_t)state->yppi * 100U - 1U) /
             ((uint64_t)state->yppi * 100U);
    if (!xpages) {
      xpages = 1U;
    }
    if (!ypages) {
      ypages = 1U;
    }
    if (xpages * 2U <= state->explicit_width &&
        ypages * 2U <= state->explicit_height && xpages * ypages <= 32U) {
      state->natural_scaling = scaling;
      return;
    }
    if (scaling <= minimum) {
      state->natural_scaling = minimum;
      return;
    }
    scaling = (scaling + 1U) / 2U;
    if (scaling < minimum) {
      scaling = minimum;
    }
  }
}

void cf_v3_image_raster_decode_state(
    const uint8_t selectors[CF_V3_IMAGE_RASTER_SELECTOR_SIZE],
    cf_v3_image_raster_state_t *state) {
  static const unsigned ppis[] = {8U, 18U, 36U, 64U,
                                  72U, 150U, 300U, 600U};
  static const unsigned natural_scales[] = {100U, 50U, 25U};
  static const unsigned cmy_widths[] = {1U, 2U, 3U, 7U, 8U,
                                        9U, 15U, 16U, 17U};
  static const unsigned cmy_safe_4bit_widths[] = {1U, 4U, 5U, 8U, 9U,
                                                  12U, 13U, 16U, 17U};
  static const unsigned cmy_heights[] = {1U, 2U, 3U, 4U,  7U,
                                         8U, 9U, 15U, 16U, 17U};
  static const int deltas[] = {-1, 0, 1};
  static const unsigned orientations[] = {0U, 1U, 3U, 2U};
  const cf_v3_image_raster_geometry_t *geometry;
  const cf_v3_image_raster_topology_t *topology;
  uint32_t relation_value;

  memset(state, 0, sizeof(*state));
  state->profile =
      (cf_v3_image_raster_profile_t)(selectors[0] %
                                     CF_V3_IMAGE_RASTER_PROFILE_COUNT);
  state->faithful = (selectors[1] & 0x80U) != 0U;
  state->mirror = (selectors[1] & 1U) != 0U;
  state->format_selector = selectors[2] & ~CF_V3_IMAGE_RASTER_RAW_PNG_FLAG;
  state->source_selector = selectors[3];
  state->geometry_selector = selectors[4];
  state->scale_policy = selectors[5] % 12U;
  cf_v3_image_raster_select_output(selectors[6], &state->output);
  state->xppi = state->yppi =
      ppis[selectors[7] % (sizeof(ppis) / sizeof(ppis[0]))];
  state->orientation = orientations[selectors[8] % 4U];
  state->orientation_requested = 3U + selectors[8] % 4U;
  state->position = selectors[9] % 9U;
  topology = &cf_v3_image_raster_topologies[
      selectors[10] % (sizeof(cf_v3_image_raster_topologies) /
                       sizeof(cf_v3_image_raster_topologies[0]))];
  state->topology_x = topology->x;
  state->topology_y = topology->y;
  state->copies = 1U + selectors[11] % 2U;
  state->collate = (selectors[12] & 1U) != 0U;
  state->reverse = (selectors[12] & 2U) != 0U;
  state->duplex = (selectors[12] & 4U) != 0U;
  state->pattern = selectors[13] % 9U;
  state->phase = selectors[14];
  state->material_stride = 1U + 2U * (selectors[15] % 32U);
  state->natural_scaling = cf_v3_image_raster_u32le(selectors + 16U);
  memcpy(state->codec_controls, selectors + 20U,
         sizeof(state->codec_controls));
  state->page_policy = selectors[24] & 1U;
  state->cmy_relation_stage = selectors[25] % 4U;
  state->cmy_threshold_delta = deltas[selectors[26] % 3U];
  state->arithmetic_stride = (selectors[27] & 1U) != 0U;
  relation_value = cf_v3_image_raster_u32le(selectors + 28U);

  state->page_width = 216.0;
  state->page_height = 216.0;
  state->margin_left = state->margin_bottom = 12.0;
  state->margin_right = state->margin_top = 12.0;
  state->output_resolution_x = state->output_resolution_y = state->xppi;

  if (state->profile == CF_V3_IMAGE_RASTER_NATURAL) {
    geometry = &cf_v3_image_raster_natural_geometries[
        selectors[4] % (sizeof(cf_v3_image_raster_natural_geometries) /
                        sizeof(cf_v3_image_raster_natural_geometries[0]))];
    state->format_selector = 0U;
    state->source_selector = selectors[3] & 1U;
    state->explicit_width = geometry->width;
    state->explicit_height = geometry->height;
    state->xppi = state->yppi = 72U;
    state->output_resolution_x = state->output_resolution_y = 72U;
    state->natural_scaling = natural_scales[selectors[5] % 3U];
    state->page_width = state->page_policy ? 288.0 : 216.0;
    state->page_height = 216.0;
    state->margin_left = state->margin_bottom = 18.0;
    state->margin_right = state->margin_top = 18.0;
    state->copies = 1U;
    state->collate = state->reverse = state->duplex = false;
    state->output.color_space = state->source_selector
                                    ? CUPS_CSPACE_RGB
                                    : CUPS_CSPACE_K;
    state->output.color_order = CUPS_ORDER_CHUNKED;
    state->output.num_colors = state->source_selector ? 3U : 1U;
    state->output.bits_per_color = 8U;
    state->output.bits_per_pixel = 8U * state->output.num_colors;
  } else if (state->profile == CF_V3_IMAGE_RASTER_MULTIPAGE) {
    state->format_selector = 0U;
    state->source_selector = selectors[3] & 1U;
    state->explicit_width = 252U * state->topology_x;
    state->explicit_height = 252U * state->topology_y;
    state->xppi = state->yppi = 288U;
    state->output_resolution_x = state->output_resolution_y = 72U;
    state->natural_scaling = 100U;
    state->page_width = state->page_height = 72.0;
    state->margin_left = state->margin_bottom = 0.0;
    state->margin_right = state->margin_top = 0.0;
    state->position = 0U;
    state->mirror = false;
    state->copies = 1U;
    state->collate = state->reverse = state->duplex = false;
    if (!state->faithful) {
      state->orientation &= 1U;
      state->orientation_requested = 3U + state->orientation;
    }
    state->output.color_space = state->source_selector
                                    ? CUPS_CSPACE_RGB
                                    : CUPS_CSPACE_K;
    state->output.color_order = CUPS_ORDER_CHUNKED;
    state->output.num_colors = state->source_selector ? 3U : 1U;
    state->output.bits_per_color = 8U;
    state->output.bits_per_pixel = 8U * state->output.num_colors;
  } else if (state->profile == CF_V3_IMAGE_RASTER_CMY) {
    static const unsigned depths[] = {1U, 2U, 4U};
    unsigned width_index = selectors[4] % 9U;

    state->format_selector = 0U;
    state->source_selector = 1U;
    state->output.bits_per_color = depths[selectors[6] % 3U];
    state->explicit_width = cmy_widths[width_index];
    if (!state->faithful && state->output.bits_per_color == 4U) {
      state->explicit_width = cmy_safe_4bit_widths[width_index];
    }
    state->explicit_height = cmy_heights[selectors[5] % 10U];
    state->xppi = state->yppi = 64U;
    state->output_resolution_x = state->output_resolution_y = 64U;
    state->natural_scaling = 100U;
    state->page_width = state->page_height = 72.0;
    state->margin_left = state->margin_bottom = 4.5;
    state->margin_right = state->margin_top = 4.5;
    state->orientation = 0U;
    state->orientation_requested = 3U;
    state->mirror = false;
    state->copies = 1U;
    state->collate = state->reverse = state->duplex = false;
    state->output.color_space = CUPS_CSPACE_CMY;
    state->output.color_order = CUPS_ORDER_CHUNKED;
    state->output.num_colors = 3U;
    state->output.bits_per_pixel = 3U * state->output.bits_per_color;
    if (!state->faithful) {
      state->cmy_relation_stage = 3U;
    }
  } else if (state->profile == CF_V3_IMAGE_RASTER_ARITHMETIC) {
    state->format_selector = 0U;
    state->source_selector = state->arithmetic_stride ? 1U : 0U;
    state->explicit_width = state->arithmetic_stride ? 9U :
                            1U + selectors[4] % 17U;
    state->explicit_height = state->arithmetic_stride ? 2U :
                             1U + selectors[5] % 17U;
    if (!state->faithful && !state->arithmetic_stride) {
      state->explicit_width = 4U + selectors[4] % 14U;
      state->explicit_height = 4U + selectors[5] % 14U;
    }
    state->xppi = state->yppi = state->arithmetic_stride ? 1U : 8U;
    state->natural_scaling = relation_value ? relation_value : 1U;
    state->page_width =
        state->arithmetic_stride ? (double)(state->explicit_width + 1U) * 72.0
                                 : 72.0;
    state->page_height =
        state->arithmetic_stride ? (double)(state->explicit_height + 1U) * 72.0
                                 : 72.0;
    state->margin_left = state->margin_bottom = 0.0;
    state->margin_right = state->margin_top = 0.0;
    state->orientation = 0U;
    state->orientation_requested = 3U;
    state->position = 0U;
    state->mirror = false;
    state->copies = 1U;
    state->collate = state->reverse = state->duplex = false;
    if (state->arithmetic_stride) {
      uint64_t boundary = UINT_MAX / 48U / state->explicit_width;
      int delta = (int)(relation_value % 131073U) - 65536;
      uint64_t resolution = boundary;

      if (delta < 0 && resolution < (uint64_t)(-delta)) {
        resolution = 1U;
      } else {
        resolution = (uint64_t)((int64_t)resolution + delta);
      }
      if (!resolution) {
        resolution = 1U;
      }
      if (!state->faithful &&
          (resolution > 9600U ||
           resolution * state->explicit_width > 4096U)) {
        unsigned safe_max = 4096U / state->explicit_width;

        if (safe_max < 72U) {
          safe_max = 72U;
        }
        resolution = 72U + relation_value % (safe_max - 71U);
      }
      if (resolution > INT_MAX) {
        resolution = INT_MAX;
      }
      state->output_resolution_x = (unsigned)resolution;
      state->output_resolution_y = 1U;
      state->natural_scaling = 100U;
      state->output.color_space = CUPS_CSPACE_RGB;
      state->output.color_order = CUPS_ORDER_CHUNKED;
      state->output.num_colors = 3U;
      state->output.bits_per_color = 16U;
      state->output.bits_per_pixel = 48U;
    } else {
      state->output_resolution_x = state->output_resolution_y = 72U;
      state->output.color_space = CUPS_CSPACE_K;
      state->output.color_order = CUPS_ORDER_CHUNKED;
      state->output.num_colors = 1U;
      state->output.bits_per_color = state->faithful ? 8U : 4U;
      state->output.bits_per_pixel = state->output.bits_per_color;
      if (!state->faithful) {
        cf_v3_image_raster_safe_cardinality(state);
      }
    }
  }
}

void cf_v3_image_raster_normalize_layout(
    cf_v3_image_raster_state_t *state, unsigned width, unsigned height,
    unsigned source_xppi, unsigned source_yppi) {
  const double capture_budget = 6.0 * 1024.0 * 1024.0;
  double printable_width;
  double printable_height;
  double zoom = 1.0;
  double required_fit_base;
  double required_fit;
  double required_native;
  double required;
  double maximum;
  unsigned page_count = 1U;
  unsigned minimum_resolution;
  unsigned maximum_resolution;
  unsigned resolution;
  unsigned source_xppi_min;
  unsigned source_yppi_min;

  if (!state || state->profile != CF_V3_IMAGE_RASTER_LAYOUT ||
      state->faithful || !width || !height) {
    return;
  }

  printable_width =
      (state->page_width - state->margin_left - state->margin_right) / 72.0;
  printable_height =
      (state->page_height - state->margin_bottom - state->margin_top) / 72.0;
  if (!(printable_width > 0.0) || !(printable_height > 0.0)) {
    return;
  }
  if (width < 2U || height < 2U) {
    /* The production crop/fill path converts sub-pixel crop geometry to int
     * and can manufacture a zero-sized image. Other geometries retain every
     * scale policy, while the one-pixel frontier stays on the valid fit path. */
    state->scale_policy = 2U;
  }
  source_xppi_min = source_xppi ? source_xppi : 1U;
  source_yppi_min = source_yppi ? source_yppi : 1U;
  if (state->scale_policy == 10U) {
    unsigned xpages = (unsigned)ceil(
        ((double)width * 0.5 / source_xppi_min) / printable_width);
    unsigned ypages = (unsigned)ceil(
        ((double)height * 0.5 / source_yppi_min) / printable_height);

    if (!xpages) {
      xpages = 1U;
    }
    if (!ypages) {
      ypages = 1U;
    }
    if (xpages > 4U || ypages > 4U || xpages * ypages > 4U ||
        (xpages * ypages > 1U && state->output.bits_per_color >= 8U)) {
      state->scale_policy = 2U;
    } else {
      page_count = xpages * ypages;
    }
    if (state->orientation & 1U) {
      /* Rotated natural-scaling partitions can land on the open #148
       * image-zoom boundary even with a single page. Other scale policies
       * retain rotated layout coverage; faithful states retain this pair. */
      state->orientation = 0U;
      state->orientation_requested = 3U;
    }
  }
  if (state->scale_policy == 7U) {
    zoom = 0.25;
  } else if (state->scale_policy == 8U || state->scale_policy == 10U) {
    zoom = 0.5;
  }

  /* A fit/percentage route must retain at least one pixel on its short axis.
   * Native-size routes need the same guarantee after source-PPI conversion.
   * Checking both keeps auto policies valid whichever production branch wins. */
  required_fit_base =
      width >= height
          ? (double)width / (printable_width * height)
          : (double)height / (printable_height * width);
  required_fit = required_fit_base / zoom;
  if (!source_xppi) {
    source_xppi = 200U;
  }
  if (!source_yppi) {
    source_yppi = 200U;
  }
  if (source_xppi < 200U) {
    source_xppi = 200U;
  }
  if (source_yppi < 200U) {
    source_yppi = 200U;
  }
  required_native = (double)source_xppi / width;
  if ((double)source_yppi / height > required_native) {
    required_native = (double)source_yppi / height;
  }
  if (state->scale_policy == 5U) {
    required_native = 144.0 / (width < height ? width : height);
  } else if (state->scale_policy == 6U) {
    required_native = 288.0 / (width < height ? width : height);
  } else if (state->scale_policy == 10U) {
    required_native *= 2.0;
  }
  switch (state->scale_policy) {
    case 2U:
    case 3U:
    case 7U:
    case 8U:
    case 9U:
      required = required_fit;
      break;
    case 4U:
    case 5U:
    case 6U:
    case 10U:
    case 11U:
      required = required_native;
      break;
    default:
      required = required_fit > required_native ? required_fit
                                                : required_native;
      break;
  }
  required *= 1.01;

  maximum = sqrt((capture_budget * 8.0) /
                 (printable_width * printable_height *
                  state->output.bits_per_color * state->output.num_colors *
                  state->copies * page_count));
  if (required > maximum) {
    /* Preserve the source/output profile while moving only this conflicting
     * scale relation to a single-page fit state. */
    state->scale_policy = 2U;
    page_count = 1U;
    required = required_fit_base * 1.01;
    maximum = sqrt((capture_budget * 8.0) /
                   (printable_width * printable_height *
                    state->output.bits_per_color * state->output.num_colors *
                    state->copies));
  }
  minimum_resolution = (unsigned)ceil(required);
  maximum_resolution = maximum >= (double)UINT_MAX
                           ? UINT_MAX
                           : (unsigned)floor(maximum);
  if (!minimum_resolution) {
    minimum_resolution = 1U;
  }
  if (!maximum_resolution) {
    maximum_resolution = 1U;
  }

  resolution = state->output_resolution_x > state->output_resolution_y
                   ? state->output_resolution_x
                   : state->output_resolution_y;
  if (resolution < minimum_resolution) {
    resolution = minimum_resolution;
  }
  if (resolution > maximum_resolution) {
    resolution = maximum_resolution;
  }
  state->output_resolution_x = resolution;
  state->output_resolution_y = resolution;
}

size_t cf_v3_image_raster_expected_bpl(
    const cf_v3_image_raster_output_t *output, unsigned width) {
  uint64_t bytes;

  if (!output || !width || !output->bits_per_pixel) {
    return 0U;
  }
  bytes = ((uint64_t)output->bits_per_pixel * width + 7U) / 8U;
  if (output->color_order == CUPS_ORDER_BANDED) {
    bytes *= output->num_colors;
  }
  return bytes <= SIZE_MAX ? (size_t)bytes : 0U;
}

unsigned cf_v3_image_raster_plane_count(
    const cf_v3_image_raster_output_t *output) {
  return output && output->color_order == CUPS_ORDER_PLANAR
             ? output->num_colors
             : 1U;
}

const char *cf_v3_image_raster_position_name(unsigned position) {
  static const char *const names[] = {
      "center", "top", "top-left", "top-right", "left",
      "right",  "bottom", "bottom-left", "bottom-right",
  };

  return names[position % (sizeof(names) / sizeof(names[0]))];
}

int cf_v3_image_raster_build_options(
    const cf_v3_image_raster_state_t *state, char *buffer,
    size_t buffer_size) {
  static const char *const scaling[] = {
      "print-scaling=auto", "print-scaling=auto-fit",
      "print-scaling=fit", "print-scaling=fill",
      "print-scaling=none", "ppi=144", "ppi=288", "scaling=25",
      "scaling=50", "fitplot=true", "natural-scaling=50",
      "crop-to-fit=true",
  };
  char scale[96];
  const char *sides = !state->duplex
                          ? "one-sided"
                          : (state->orientation & 1U)
                                ? "two-sided-short-edge"
                                : "two-sided-long-edge";
  int length;

  if (state->profile == CF_V3_IMAGE_RASTER_ARITHMETIC &&
      state->arithmetic_stride) {
    snprintf(scale, sizeof(scale), "ppi=1 natural-scaling=100");
  } else if (state->profile == CF_V3_IMAGE_RASTER_NATURAL ||
      state->profile == CF_V3_IMAGE_RASTER_MULTIPAGE ||
      state->profile == CF_V3_IMAGE_RASTER_CMY ||
      state->profile == CF_V3_IMAGE_RASTER_ARITHMETIC) {
    snprintf(scale, sizeof(scale), "natural-scaling=%u",
             state->natural_scaling);
  } else {
    snprintf(scale, sizeof(scale), "%s", scaling[state->scale_policy]);
  }
  length = snprintf(
      buffer, buffer_size,
      "PageSize=Fuzz PageRegion=Fuzz ColorModel=Fuzz Resolution=Fuzz "
      "sides=%s orientation-requested=%u position=%s mirror=%s copies=%u "
      "Collate=%s OutputOrder=%s hardware-copies=false "
      "hardware-collate=false emit-jcl=false gamma=1000 brightness=100 "
      "saturation=100 hue=0 %s",
      sides, state->orientation_requested,
      cf_v3_image_raster_position_name(state->position),
      state->mirror ? "true" : "false", state->copies,
      state->collate ? "true" : "false",
      state->reverse ? "Reverse" : "Normal", scale);
  return length < 0 || (size_t)length >= buffer_size ? -1 : 0;
}
