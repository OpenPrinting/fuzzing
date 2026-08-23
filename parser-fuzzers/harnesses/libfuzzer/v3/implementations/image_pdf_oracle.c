// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE

#include "image_pdf_oracle.h"

#include <errno.h>
#include <math.h>
#include <pdfio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CF_V3_IMAGE_PDF_STREAM_BUDGET (4U * 1024U * 1024U)
#define CF_V3_IMAGE_PDF_TOKEN_BUDGET 256U

typedef struct cf_v3_image_pdf_error_s {
  bool saw_error;
} cf_v3_image_pdf_error_t;

static bool cf_v3_image_pdf_fail(const char **failure, const char *reason) {
  if (failure && !*failure) {
    *failure = reason;
  }
  return false;
}

static bool cf_v3_image_pdf_error(pdfio_file_t *pdf, const char *message,
                                  void *data) {
  cf_v3_image_pdf_error_t *error = (cf_v3_image_pdf_error_t *)data;

  (void)pdf;
  (void)message;
  if (error) {
    error->saw_error = true;
  }
  return false;
}

static bool cf_v3_image_pdf_name_is(pdfio_dict_t *dict, const char *key,
                                    const char *expected) {
  const char *actual = dict ? pdfioDictGetName(dict, key) : NULL;

  return actual && strcmp(actual, expected) == 0;
}

static bool cf_v3_image_pdf_near(double actual, long double expected,
                                 long double tolerance) {
  return isfinite(actual) && fabsl((long double)actual - expected) <= tolerance;
}

static bool cf_v3_image_pdf_content_has_image(pdfio_obj_t *page,
                                              const char **failure) {
  pdfio_stream_t *stream;
  char token[256];
  bool saw_image = false;
  bool saw_invocation = false;
  size_t count = 0;

  if (pdfioPageGetNumStreams(page) != 1U ||
      !(stream = pdfioPageOpenStream(page, 0U, true))) {
    return cf_v3_image_pdf_fail(failure, "content-stream-open");
  }
  while (pdfioStreamGetToken(stream, token, sizeof(token))) {
    if (++count > CF_V3_IMAGE_PDF_TOKEN_BUDGET) {
      (void)pdfioStreamClose(stream);
      return cf_v3_image_pdf_fail(failure, "content-token-budget");
    }
    if (strcmp(token, "/Im") == 0) {
      saw_image = true;
    } else if (saw_image && strcmp(token, "Do") == 0) {
      saw_invocation = true;
    }
  }
  if (!pdfioStreamClose(stream) || !saw_invocation) {
    return cf_v3_image_pdf_fail(failure, "content-image-invocation");
  }
  return true;
}

static bool cf_v3_image_pdf_expected_tile(
    const cf_v3_image_pdf_oracle_t *expect, unsigned tile, uint8_t *output,
    size_t output_size, unsigned *tile_width, unsigned *tile_height) {
  unsigned xpage;
  unsigned ypage;
  unsigned x0;
  unsigned x1;
  unsigned y0;
  unsigned y1;
  size_t expected_size;
  size_t offset = 0;

  if (!expect || !output || !expect->xpages || !expect->ypages ||
      tile >= expect->xpages * expect->ypages) {
    return false;
  }
  xpage = tile / expect->ypages;
  ypage = tile % expect->ypages;
  x0 = expect->width * xpage / expect->xpages;
  x1 = expect->width * (xpage + 1U) / expect->xpages;
  y0 = expect->height * ypage / expect->ypages;
  y1 = expect->height * (ypage + 1U) / expect->ypages;
  if (x1 <= x0 || y1 <= y0) {
    return false;
  }
  expected_size =
      (size_t)(x1 - x0) * (y1 - y0) * expect->components;
  if (expected_size != output_size) {
    return false;
  }
  for (unsigned y = y0; y < y1; y++) {
    const size_t source =
        ((size_t)y * expect->width + x0) * expect->components;
    const size_t row_size = (size_t)(x1 - x0) * expect->components;

    memcpy(output + offset, expect->pixels + source, row_size);
    offset += row_size;
  }
  *tile_width = x1 - x0;
  *tile_height = y1 - y0;
  return true;
}

static bool cf_v3_image_pdf_validate_image(
    pdfio_obj_t *image_obj, unsigned tile,
    const cf_v3_image_pdf_oracle_t *expect, size_t *decoded_budget,
    const char **failure) {
  pdfio_dict_t *dict = image_obj ? pdfioObjGetDict(image_obj) : NULL;
  const char *subtype = dict ? pdfioDictGetName(dict, "Subtype") : NULL;
  const char *color_space = dict ? pdfioDictGetName(dict, "ColorSpace") : NULL;
  const char *expected_space = expect->components == 1U
                                   ? "DeviceGray"
                                   : expect->components == 3U ? "DeviceRGB"
                                                               : "DeviceCMYK";
  double width_number = dict ? pdfioDictGetNumber(dict, "Width") : 0.0;
  double height_number = dict ? pdfioDictGetNumber(dict, "Height") : 0.0;
  double bits = dict ? pdfioDictGetNumber(dict, "BitsPerComponent") : 0.0;
  unsigned width;
  unsigned height;
  size_t expected_size;
  uint8_t *expected_pixels = NULL;
  uint8_t *actual = NULL;
  size_t actual_size = 0;
  pdfio_stream_t *stream = NULL;
  bool valid = false;

  if (!subtype || strcmp(subtype, "Image") != 0 || !color_space ||
      strcmp(color_space, expected_space) != 0 || !isfinite(width_number) ||
      !isfinite(height_number) || width_number < 1.0 || height_number < 1.0 ||
      width_number > expect->width || height_number > expect->height ||
      floor(width_number) != width_number || floor(height_number) != height_number ||
      bits != 8.0) {
    if (getenv("CF_V3_ORACLE_TRACE")) {
      fprintf(stderr,
              "image-pdf-v3 image-dictionary: tile=%u subtype=%s "
              "colorspace=%s expected-space=%s width=%.0f height=%.0f "
              "source=%ux%u bits=%.0f\n",
              tile, subtype ? subtype : "(null)",
              color_space ? color_space : "(null)", expected_space,
              width_number, height_number, expect->width, expect->height, bits);
    }
    return cf_v3_image_pdf_fail(failure, "image-dictionary");
  }
  width = (unsigned)width_number;
  height = (unsigned)height_number;
  if (width > SIZE_MAX / height ||
      (size_t)width * height > SIZE_MAX / expect->components) {
    return cf_v3_image_pdf_fail(failure, "image-size-overflow");
  }
  expected_size = (size_t)width * height * expect->components;
  if (!expected_size || expected_size > CF_V3_IMAGE_PDF_STREAM_BUDGET ||
      *decoded_budget > CF_V3_IMAGE_PDF_STREAM_BUDGET - expected_size ||
      !(actual = (uint8_t *)malloc(expected_size + 2U)) ||
      !(expected_pixels = (uint8_t *)malloc(expected_size)) ||
      !(stream = pdfioObjOpenStream(image_obj, true))) {
    cf_v3_image_pdf_fail(failure, "image-stream-open");
    goto done;
  }
  {
    unsigned tile_width = 0;
    unsigned tile_height = 0;

    if (!cf_v3_image_pdf_expected_tile(expect, tile, expected_pixels,
                                       expected_size, &tile_width,
                                       &tile_height) ||
        tile_width != width || tile_height != height) {
      cf_v3_image_pdf_fail(failure, "image-tile-geometry");
      goto done;
    }
  }
  while (actual_size < expected_size + 2U) {
    ssize_t count = pdfioStreamRead(stream, actual + actual_size,
                                    expected_size + 2U - actual_size);

    if (count < 0) {
      cf_v3_image_pdf_fail(failure, "image-stream-read");
      goto done;
    }
    if (count == 0) {
      break;
    }
    actual_size += (size_t)count;
  }
  {
    uint8_t extra;
    ssize_t count = pdfioStreamRead(stream, &extra, 1U);

    if (count != 0) {
      cf_v3_image_pdf_fail(
          failure, count < 0 ? "image-stream-read" : "image-stream-overrun");
      goto done;
    }
  }
  if (actual_size == expected_size + 1U &&
      actual[expected_size] == (uint8_t)'\n') {
    actual_size--;
  }
  if (actual_size != expected_size) {
    cf_v3_image_pdf_fail(failure, "image-stream-length");
    goto done;
  }
  if (expect->exact_pixels && memcmp(actual, expected_pixels, expected_size)) {
    if (getenv("CF_V3_ORACLE_TRACE")) {
      size_t mismatch = 0U;

      while (mismatch < expected_size &&
             actual[mismatch] == expected_pixels[mismatch]) {
        mismatch++;
      }
      fprintf(stderr,
              "image-pdf-v3 image-pixel-value: tile=%u offset=%zu "
              "actual=%u expected=%u size=%zu geometry=%ux%u\n",
              tile, mismatch, (unsigned)actual[mismatch],
              (unsigned)expected_pixels[mismatch], expected_size, width,
              height);
    }
    cf_v3_image_pdf_fail(failure, "image-pixel-value");
    goto done;
  }
  *decoded_budget += expected_size;
  valid = true;

done:
  if (stream && !pdfioStreamClose(stream)) {
    cf_v3_image_pdf_fail(failure, "image-stream-close");
    valid = false;
  }
  free(actual);
  free(expected_pixels);
  return valid;
}

static bool cf_v3_image_pdf_validate_file(
    const char *path, const cf_v3_image_pdf_oracle_t *expect,
    const char **failure) {
  cf_v3_image_pdf_error_t error = {false};
  pdfio_file_t *pdf = NULL;
  size_t decoded_budget = 0;
  bool valid = false;

  if (failure) {
    *failure = NULL;
  }
  if (!path || !expect || !expect->pixels || !expect->pixel_size ||
      !expect->width || !expect->height ||
      (expect->components != 1U && expect->components != 3U &&
       expect->components != 4U) ||
      !expect->xpages || !expect->ypages || !expect->page_count ||
      expect->page_count > CF_V3_IMAGE_PDF_ORACLE_MAX_PAGES ||
      expect->width > SIZE_MAX / expect->height ||
      (size_t)expect->width * expect->height >
          SIZE_MAX / expect->components ||
      expect->pixel_size !=
          (size_t)expect->width * expect->height * expect->components) {
    return cf_v3_image_pdf_fail(failure, "oracle-input");
  }
  pdf = pdfioFileOpen(path, NULL, NULL, cf_v3_image_pdf_error, &error);
  if (!pdf || error.saw_error) {
    cf_v3_image_pdf_fail(failure, "pdf-open");
    goto done;
  }
  {
    pdfio_dict_t *catalog = pdfioFileGetCatalog(pdf);
    pdfio_obj_t *pages_obj = catalog ? pdfioDictGetObj(catalog, "Pages") : NULL;
    pdfio_dict_t *pages = pages_obj ? pdfioObjGetDict(pages_obj) : NULL;
    pdfio_array_t *kids = pages ? pdfioDictGetArray(pages, "Kids") : NULL;

    const bool catalog_ok =
        cf_v3_image_pdf_name_is(catalog, "Type", "Catalog");
    const bool pages_ok = cf_v3_image_pdf_name_is(pages, "Type", "Pages");
    const size_t actual_pages = pdfioFileGetNumPages(pdf);
    const size_t actual_kids = kids ? pdfioArrayGetSize(kids) : 0U;
    const double declared_pages = pages ? pdfioDictGetNumber(pages, "Count") : 0.0;

    if (!catalog_ok || !pages_ok || !kids ||
        actual_pages != expect->page_count ||
        actual_kids != expect->page_count ||
        declared_pages != (double)expect->page_count) {
      if (getenv("CF_V3_ORACLE_TRACE")) {
        fprintf(stderr,
                "image-pdf-v3 page-tree: expected=%zu actual=%zu kids=%zu "
                "declared=%.0f catalog=%d pages=%d\n",
                expect->page_count, actual_pages, actual_kids, declared_pages,
                catalog_ok, pages_ok);
      }
      cf_v3_image_pdf_fail(failure, "page-tree");
      goto done;
    }
  }

  for (size_t index = 0; index < expect->page_count; index++) {
    pdfio_obj_t *page = pdfioFileGetPage(pdf, index);
    pdfio_dict_t *dict = page ? pdfioObjGetDict(page) : NULL;
    pdfio_dict_t *resources = dict ? pdfioDictGetDict(dict, "Resources") : NULL;
    pdfio_dict_t *xobjects =
        resources ? pdfioDictGetDict(resources, "XObject") : NULL;
    pdfio_obj_t *image_obj = xobjects ? pdfioDictGetObj(xobjects, "Im") : NULL;
    pdfio_rect_t media = {0};
    int tile = expect->pages[index];

    if (!cf_v3_image_pdf_name_is(dict, "Type", "Page") ||
        !pdfioPageGetRect(page, "MediaBox", &media) ||
        !cf_v3_image_pdf_near(media.x1, 0.0L, 0.01L) ||
        !cf_v3_image_pdf_near(media.y1, 0.0L, 0.01L) ||
        !cf_v3_image_pdf_near(media.x2, expect->page_width, 0.02L) ||
        !cf_v3_image_pdf_near(media.y2, expect->page_height, 0.02L)) {
      if (getenv("CF_V3_ORACLE_TRACE")) {
        fprintf(stderr,
                "image-pdf-v3 page-geometry: page=%zu actual=[%.2f %.2f "
                "%.2f %.2f] expected=[0 0 %.2Lf %.2Lf]\n",
                index, media.x1, media.y1, media.x2, media.y2,
                expect->page_width, expect->page_height);
      }
      cf_v3_image_pdf_fail(failure, "page-geometry");
      goto done;
    }
    if (tile < 0) {
      if (image_obj || pdfioPageGetNumStreams(page) != 0U ||
          pdfioDictGetObj(dict, "Contents")) {
        cf_v3_image_pdf_fail(failure, "blank-page-placement");
        goto done;
      }
      continue;
    }
    if ((unsigned)tile >= expect->xpages * expect->ypages || !image_obj ||
        !cf_v3_image_pdf_content_has_image(page, failure) ||
        !cf_v3_image_pdf_validate_image(image_obj, (unsigned)tile, expect,
                                        &decoded_budget, failure)) {
      goto done;
    }
  }
  valid = !error.saw_error;

done:
  if (pdf && !pdfioFileClose(pdf)) {
    cf_v3_image_pdf_fail(failure, "pdf-close");
    valid = false;
  }
  return valid && !error.saw_error;
}

bool cf_v3_image_pdf_validate(const uint8_t *pdf_bytes, size_t pdf_size,
                              const cf_v3_image_pdf_oracle_t *expect,
                              const char **failure) {
  char path[] = "/tmp/cupsfilters-v3-image-pdf.XXXXXX";
  int fd = -1;
  size_t offset = 0;
  bool valid = false;

  if (!pdf_bytes || !pdf_size || pdf_size > 8U * 1024U * 1024U || !expect) {
    return cf_v3_image_pdf_fail(failure, "captured-output-bounds");
  }
  if ((fd = mkstemp(path)) < 0) {
    return cf_v3_image_pdf_fail(failure, "oracle-tempfile");
  }
  while (offset < pdf_size) {
    ssize_t count = write(fd, pdf_bytes + offset, pdf_size - offset);

    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      cf_v3_image_pdf_fail(failure, "oracle-write");
      goto done;
    }
    offset += (size_t)count;
  }
  if (close(fd) != 0) {
    fd = -1;
    cf_v3_image_pdf_fail(failure, "oracle-close");
    goto done;
  }
  fd = -1;
  valid = cf_v3_image_pdf_validate_file(path, expect, failure);

done:
  if (fd >= 0) {
    (void)close(fd);
  }
  (void)unlink(path);
  return valid;
}
