// SPDX-License-Identifier: Apache-2.0
#ifndef CF_V3_IMAGE_PDF_FORMATS_H
#define CF_V3_IMAGE_PDF_FORMATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CF_V3_IMAGE_PDF_MAX_DIMENSION 257U
#define CF_V3_IMAGE_PDF_MAX_ENCODED_SIZE (1024U * 1024U)

typedef enum cf_v3_image_pdf_format_e {
  CF_V3_IMAGE_PDF_FORMAT_PNG = 0,
  CF_V3_IMAGE_PDF_FORMAT_JPEG,
  CF_V3_IMAGE_PDF_FORMAT_TIFF
} cf_v3_image_pdf_format_t;

typedef enum cf_v3_image_pdf_colorspace_e {
  CF_V3_IMAGE_PDF_COLORSPACE_GRAY = 0,
  CF_V3_IMAGE_PDF_COLORSPACE_RGB,
  CF_V3_IMAGE_PDF_COLORSPACE_CMYK
} cf_v3_image_pdf_colorspace_t;

enum {
  CF_V3_IMAGE_PDF_RELATION_NONE = 0U,
  CF_V3_IMAGE_PDF_RELATION_TIFF_RGB2 = 1U << 0,
  CF_V3_IMAGE_PDF_RELATION_TIFF_PACKED_ALPHA = 1U << 1,
  CF_V3_IMAGE_PDF_RELATION_PNG_ALPHA = 1U << 2
};

typedef struct cf_v3_image_pdf_format_request_s {
  uint8_t format_selector;
  uint8_t source_selector;
  uint8_t color_selector;
  uint8_t geometry_selector;
  uint8_t codec_selectors[4];
  uint8_t pattern;
  uint8_t phase;
  uint8_t stride;
  const uint8_t *material;
  size_t material_size;

  /* Zero selects the corresponding dimension from geometry_selector. */
  uint16_t explicit_width;
  uint16_t explicit_height;

  /* Zero selects the sane 72-PPI default. */
  uint16_t xppi;
  uint16_t yppi;

  /* Kept false for deploy corpora; true is for faithful boundary validators. */
  bool allow_known_boundaries;
} cf_v3_image_pdf_format_request_t;

typedef struct cf_v3_image_pdf_format_result_s {
  uint8_t *encoded_bytes;
  size_t encoded_size;
  const char *mime;
  uint16_t width;
  uint16_t height;
  uint16_t xppi;
  uint16_t yppi;

  /* Canonical top-to-bottom bytes expected from the selected cfImage mode. */
  uint8_t *reference_pixels;
  size_t reference_size;
  uint8_t reference_components;
  cf_v3_image_pdf_colorspace_t reference_colorspace;
  cf_v3_image_pdf_format_t format;
  uint32_t relation_flags;
} cf_v3_image_pdf_format_result_t;

/* Returns 0 on success and -1 on allocation or codec failure. */
int cf_v3_image_pdf_format_build(
    const cf_v3_image_pdf_format_request_t *request,
    cf_v3_image_pdf_format_result_t *result);

void cf_v3_image_pdf_format_free(cf_v3_image_pdf_format_result_t *result);

#ifdef __cplusplus
}
#endif

#endif
