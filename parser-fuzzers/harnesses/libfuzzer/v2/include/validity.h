// SPDX-License-Identifier: Apache-2.0
#ifndef CUPSFILTERS_FUZZ_V2_VALIDITY_H
#define CUPSFILTERS_FUZZ_V2_VALIDITY_H

#include <cups/raster.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define CF_V2_RASTER_REQUIRE_PDF_COLORSPACE 1U
#define CF_V2_RASTER_REQUIRE_ESCPX_WEAVE 2U
#define CF_V2_RASTER_REQUIRE_COMPRESSION_1 4U
#define CF_V2_RASTER_REQUIRE_COMPRESSION_2 8U
#define CF_V2_RASTER_REQUIRE_COMPRESSION_3 16U
#define CF_V2_RASTER_REQUIRE_COMPRESSION_10 32U
#define CF_V2_RASTER_REJECT_COMPRESSION_3 64U
#define CF_V2_RASTER_REQUIRE_MULTIROW 128U
#define CF_V2_RASTER_REQUIRE_MODE10_RGB 256U

#define CF_V2_PDF_REJECT_INTERACTIVE 1U
#define CF_V2_PDF_REQUIRE_INTERACTIVE 2U

static inline uint32_t cf_v2_be32(const uint8_t *data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) | data[3];
}

static inline uint32_t cf_v2_le32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

/* Exact raw pages keep output-state targets past the trailing-data frontier. */
static inline int cf_v2_validate_simple_raster(const uint8_t *data,
                                               size_t size) {
  static const size_t header_size = 1796U;
  size_t offset = 4U;
  unsigned pages = 0;

  if (!data || size < 4U + header_size || memcmp(data, "3SaR", 4U) != 0) {
    return 0;
  }
  while (offset < size) {
    uint32_t height;
    uint32_t bytes_per_line;
    uint64_t page_bytes;

    if (size - offset < header_size || ++pages > 16U) {
      return 0;
    }
    height = cf_v2_le32(data + offset + 376U);
    bytes_per_line = cf_v2_le32(data + offset + 392U);
    if (!height || !bytes_per_line ||
        cf_v2_le32(data + offset + 404U) != 0U) {
      return 0;
    }
    page_bytes = (uint64_t)height * bytes_per_line;
    if (page_bytes > size - offset - header_size) {
      return 0;
    }
    offset += header_size + (size_t)page_bytes;
  }
  return pages > 0U && offset == size;
}

/* imagetopdf/imagetops carry incomplete ASCII85 groups between rows but only
 * reserve three padding bytes.  State lanes use aligned rows to continue past
 * that known boundary; faithful implementation lanes remain unrestricted. */
static inline int cf_v2_png_width_aligned(const uint8_t *data, size_t size,
                                          uint32_t alignment) {
  static const uint8_t signature[] = {0x89, 0x50, 0x4e, 0x47,
                                      0x0d, 0x0a, 0x1a, 0x0a};

  return data && alignment && size >= 24U &&
         memcmp(data, signature, sizeof(signature)) == 0 &&
         cf_v2_be32(data + 8U) == 13U &&
         memcmp(data + 12U, "IHDR", 4U) == 0 &&
         cf_v2_be32(data + 16U) != 0U &&
         cf_v2_be32(data + 16U) % alignment == 0U;
}

static inline int cf_v2_validate_command_safe(const uint8_t *data,
                                              size_t size) {
  static const uint8_t header[] = "#CUPS-COMMAND";
  size_t line_length = 0;

  if (size <= sizeof(header) - 1U ||
      memcmp(data, header, sizeof(header) - 1U) != 0 ||
      (data[sizeof(header) - 1U] != '\n' &&
       data[sizeof(header) - 1U] != '\r')) {
    return 0;
  }
  for (size_t offset = 0; offset < size; offset++) {
    uint8_t value = data[offset];
    if (!value || (value != '\n' && value != '\r' && value != '\t' &&
                   (value < 0x20U || value > 0x7eU))) {
      return 0;
    }
    if (value == '\n') {
      line_length = 0;
    } else if (++line_length >= 1024U) {
      return 0;
    }
  }
  return 1;
}

static inline int cf_v2_command_has_leading_nul_line(const uint8_t *data,
                                                      size_t size) {
  if (!size) {
    return 0;
  }
  if (!data[0]) {
    return 1;
  }
  for (size_t offset = 1; offset < size; offset++) {
    if (!data[offset] && data[offset - 1U] == '\n') {
      return 1;
    }
  }
  return 0;
}

static inline int cf_v2_pdf_hex(uint8_t value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

static inline int cf_v2_pdf_name_delimiter(uint8_t value) {
  return value <= 0x20U || value == '(' || value == ')' || value == '<' ||
         value == '>' || value == '[' || value == ']' || value == '{' ||
         value == '}' || value == '/' || value == '%';
}

/* Match PDF names while decoding #xx escapes. Object streams are excluded
 * from the non-interactive depth lane so hidden dictionaries cannot recreate
 * the known annotation root behind this lightweight preflight. */
static inline int cf_v2_pdf_has_name(const uint8_t *data, size_t size,
                                     const char *wanted) {
  size_t wanted_size = strlen(wanted);

  for (size_t offset = 0; offset < size; offset++) {
    size_t input = offset + 1U;
    size_t output = 0;
    int matched = 1;
    if (data[offset] != '/') {
      continue;
    }
    while (input < size && !cf_v2_pdf_name_delimiter(data[input])) {
      uint8_t value = data[input++];
      if (value == '#' && input + 1U < size) {
        int high = cf_v2_pdf_hex(data[input]);
        int low = cf_v2_pdf_hex(data[input + 1U]);
        if (high >= 0 && low >= 0) {
          value = (uint8_t)((high << 4) | low);
          input += 2U;
        }
      }
      if (output >= wanted_size || value != (uint8_t)wanted[output]) {
        matched = 0;
        break;
      }
      output++;
    }
    if (matched && output == wanted_size &&
        (input == size || cf_v2_pdf_name_delimiter(data[input]))) {
      return 1;
    }
  }
  return 0;
}

static inline int cf_v2_validate_pdf_policy(const uint8_t *data, size_t size,
                                            unsigned flags) {
  int interactive;

  if (size < 8U || memcmp(data, "%PDF-", 5U) != 0) {
    return 0;
  }
  interactive = cf_v2_pdf_has_name(data, size, "AcroForm") ||
                cf_v2_pdf_has_name(data, size, "Annots") ||
                cf_v2_pdf_has_name(data, size, "Annot") ||
                cf_v2_pdf_has_name(data, size, "NeedAppearances");
  if ((flags & CF_V2_PDF_REQUIRE_INTERACTIVE) && !interactive) {
    return 0;
  }
  if ((flags & CF_V2_PDF_REJECT_INTERACTIVE) &&
      (interactive || cf_v2_pdf_has_name(data, size, "ObjStm"))) {
    return 0;
  }
  return 1;
}

/* Validate a complete, bounded PNG before an integration route consumes it. */
static inline int cf_v2_validate_png(const uint8_t *data, size_t size) {
  static const uint8_t signature[] = {0x89, 0x50, 0x4e, 0x47,
                                      0x0d, 0x0a, 0x1a, 0x0a};
  uint8_t *compressed = NULL;
  uint8_t *decoded = NULL;
  size_t offset = sizeof(signature);
  size_t compressed_size = 0;
  size_t compressed_capacity = 0;
  uint32_t width = 0;
  uint32_t height = 0;
  unsigned channels = 0;
  int saw_header = 0;
  int saw_data = 0;
  int saw_end = 0;
  int valid = 0;

  if (size < sizeof(signature) + 12U ||
      memcmp(data, signature, sizeof(signature)) != 0) {
    return 0;
  }
  while (offset + 12U <= size && !saw_end) {
    uint32_t chunk_size = cf_v2_be32(data + offset);
    const uint8_t *kind = data + offset + 4U;
    const uint8_t *chunk = data + offset + 8U;
    uint32_t expected_crc;
    uint32_t actual_crc;

    if ((size_t)chunk_size > size - offset - 12U) {
      goto done;
    }
    expected_crc = cf_v2_be32(chunk + chunk_size);
    actual_crc = (uint32_t)crc32(crc32(0L, Z_NULL, 0), kind, 4U);
    actual_crc = (uint32_t)crc32(actual_crc, chunk, chunk_size);
    if (actual_crc != expected_crc) {
      goto done;
    }
    if (!saw_header) {
      unsigned color_type;
      if (memcmp(kind, "IHDR", 4U) != 0 || chunk_size != 13U) {
        goto done;
      }
      width = cf_v2_be32(chunk);
      height = cf_v2_be32(chunk + 4U);
      color_type = chunk[9];
      if (!width || !height || width > 4096U || height > 4096U ||
          chunk[8] != 8U ||
          (color_type != 0U && color_type != 2U && color_type != 6U) ||
          chunk[10] != 0U || chunk[11] != 0U || chunk[12] != 0U) {
        goto done;
      }
      channels = color_type == 0U ? 1U : (color_type == 2U ? 3U : 4U);
      saw_header = 1;
    } else if (memcmp(kind, "IDAT", 4U) == 0) {
      size_t needed;
      uint8_t *replacement;
      if (chunk_size > 8U * 1024U * 1024U ||
          compressed_size > 8U * 1024U * 1024U - chunk_size) {
        goto done;
      }
      needed = compressed_size + chunk_size;
      if (needed > compressed_capacity) {
        size_t capacity = compressed_capacity ? compressed_capacity : 1024U;
        while (capacity < needed) {
          capacity *= 2U;
        }
        replacement = (uint8_t *)realloc(compressed, capacity);
        if (!replacement) {
          goto done;
        }
        compressed = replacement;
        compressed_capacity = capacity;
      }
      memcpy(compressed + compressed_size, chunk, chunk_size);
      compressed_size = needed;
      saw_data = 1;
    } else if (memcmp(kind, "IEND", 4U) == 0) {
      if (!saw_data || chunk_size != 0U || offset + 12U != size) {
        goto done;
      }
      saw_end = 1;
    } else {
      goto done;
    }
    offset += 12U + chunk_size;
  }

  if (saw_header && saw_data && saw_end) {
    uint64_t decoded_size =
        (uint64_t)height * (1U + (uint64_t)width * channels);
    uLongf output_size;
    if (!decoded_size || decoded_size > 8U * 1024U * 1024U) {
      goto done;
    }
    decoded = (uint8_t *)malloc((size_t)decoded_size);
    if (!decoded) {
      goto done;
    }
    output_size = (uLongf)decoded_size;
    valid = uncompress(decoded, &output_size, compressed,
                       (uLong)compressed_size) == Z_OK &&
            output_size == decoded_size;
  }

done:
  free(decoded);
  free(compressed);
  return valid;
}

/* The parser itself performs validation; only complete bounded pages proceed. */
static inline int cf_v2_pdf_colorspace(unsigned color_space) {
  switch (color_space) {
    case CUPS_CSPACE_K:
    case CUPS_CSPACE_SW:
    case CUPS_CSPACE_RGB:
    case CUPS_CSPACE_SRGB:
    case CUPS_CSPACE_ADOBERGB:
    case CUPS_CSPACE_CMYK:
    case CUPS_CSPACE_DEVICE1:
    case CUPS_CSPACE_DEVICE2:
    case CUPS_CSPACE_DEVICE3:
    case CUPS_CSPACE_DEVICE4:
    case CUPS_CSPACE_DEVICE5:
    case CUPS_CSPACE_DEVICE6:
    case CUPS_CSPACE_DEVICE7:
    case CUPS_CSPACE_DEVICE8:
    case CUPS_CSPACE_DEVICE9:
    case CUPS_CSPACE_DEVICEA:
    case CUPS_CSPACE_DEVICEB:
    case CUPS_CSPACE_DEVICEC:
    case CUPS_CSPACE_DEVICED:
    case CUPS_CSPACE_DEVICEE:
    case CUPS_CSPACE_DEVICEF:
      return 1;
    default:
      return 0;
  }
}

static inline int cf_v2_validate_raster_fd(int fd, unsigned flags) {
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  uint8_t *row = NULL;
  uint64_t decoded = 0;
  unsigned pages = 0;
  int valid = 0;

  if (lseek(fd, 0, SEEK_SET) < 0) {
    return 0;
  }
  raster = cupsRasterOpen(fd, CUPS_RASTER_READ);
  if (!raster) {
    goto done;
  }
  while (cupsRasterReadHeader2(raster, &header)) {
    uint64_t minimum_bytes;
    uint64_t page_size;
    if (++pages > 16U || !header.cupsWidth || !header.cupsHeight ||
        header.cupsWidth > 4096U || header.cupsHeight > 4096U ||
        !header.cupsBytesPerLine || header.cupsBytesPerLine > 16384U ||
        !header.cupsBitsPerColor || header.cupsBitsPerColor > 16U ||
        !header.cupsBitsPerPixel || header.cupsBitsPerPixel > 64U ||
        !header.cupsNumColors || header.cupsNumColors > 16U ||
        !header.HWResolution[0] || !header.HWResolution[1] ||
        header.HWResolution[0] > 9600U || header.HWResolution[1] > 9600U) {
      goto done;
    }
    minimum_bytes = ((uint64_t)header.cupsWidth * header.cupsBitsPerPixel +
                     7U) /
                    8U;
    if (header.cupsBytesPerLine < minimum_bytes ||
        ((flags & CF_V2_RASTER_REQUIRE_PDF_COLORSPACE) &&
         !cf_v2_pdf_colorspace(header.cupsColorSpace))) {
      goto done;
    }
    if (((flags & CF_V2_RASTER_REQUIRE_COMPRESSION_1) &&
         header.cupsCompression != 1U) ||
        ((flags & CF_V2_RASTER_REQUIRE_COMPRESSION_2) &&
         header.cupsCompression != 2U) ||
        ((flags & CF_V2_RASTER_REQUIRE_COMPRESSION_3) &&
         header.cupsCompression != 3U) ||
        ((flags & CF_V2_RASTER_REQUIRE_COMPRESSION_10) &&
         header.cupsCompression != 10U) ||
        ((flags & CF_V2_RASTER_REJECT_COMPRESSION_3) &&
         header.cupsCompression == 3U) ||
        ((flags & CF_V2_RASTER_REQUIRE_MULTIROW) &&
         header.cupsHeight < 2U) ||
        ((flags & CF_V2_RASTER_REQUIRE_MODE10_RGB) &&
         (header.cupsCompression != 10U ||
          header.cupsBitsPerColor != 8U ||
          header.cupsBitsPerPixel != 24U ||
          header.cupsNumColors != 3U ||
          (header.cupsColorSpace != CUPS_CSPACE_RGB &&
           header.cupsColorSpace != CUPS_CSPACE_SRGB &&
           header.cupsColorSpace != CUPS_CSPACE_ADOBERGB) ||
          header.cupsBytesPerLine != header.cupsWidth * 3U))) {
      goto done;
    }
    if ((flags & CF_V2_RASTER_REQUIRE_ESCPX_WEAVE) &&
        header.cupsRowCount > 1U) {
      unsigned row_step = header.cupsRowStep % 100U;
      unsigned column_step = header.cupsRowStep / 100U;
      uint64_t complexity;

      if (!row_step || !column_step || header.cupsRowCount > 64U ||
          header.cupsRowFeed > 4096U) {
        goto done;
      }
      complexity = (uint64_t)header.cupsRowCount * row_step * column_step;
      if (complexity > 128U) {
        goto done;
      }
    }
    page_size = (uint64_t)header.cupsBytesPerLine * header.cupsHeight;
    if (decoded + page_size > 8U * 1024U * 1024U) {
      goto done;
    }
    row = (uint8_t *)malloc(header.cupsBytesPerLine);
    if (!row) {
      goto done;
    }
    for (unsigned y = 0; y < header.cupsHeight; y++) {
      if (cupsRasterReadPixels(raster, row, header.cupsBytesPerLine) !=
          header.cupsBytesPerLine) {
        goto done;
      }
    }
    free(row);
    row = NULL;
    decoded += page_size;
  }
  valid = pages > 0U;

done:
  free(row);
  if (raster) {
    cupsRasterClose(raster);
  }
  return lseek(fd, 0, SEEK_SET) >= 0 && valid;
}

#endif
