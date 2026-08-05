#define _GNU_SOURCE

#include <cups/raster.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef CUPS_RASTER_READER_MAX_INPUT
#define CUPS_RASTER_READER_MAX_INPUT (4U * 1024U * 1024U)
#endif

#ifndef CUPS_RASTER_READER_MAX_PAGES
#define CUPS_RASTER_READER_MAX_PAGES 64U
#endif

#ifndef CUPS_RASTER_READER_MAX_LINE
#define CUPS_RASTER_READER_MAX_LINE (1U * 1024U * 1024U)
#endif

#ifndef CUPS_RASTER_READER_MAX_DECODED
#define CUPS_RASTER_READER_MAX_DECODED (32U * 1024U * 1024U)
#endif

static int write_all(int fd, const uint8_t *data, size_t size) {
  size_t offset = 0;

  while (offset < size) {
    ssize_t written = write(fd, data + offset, size - offset);

    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return -1;
    }
    offset += (size_t)written;
  }

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char input_name[] = "/tmp/cups-raster-reader.XXXXXX";
  cups_page_header2_t header;
  cups_raster_t *raster = NULL;
  unsigned char *line = NULL;
  uint64_t decoded = 0;
  uint64_t pages = 0;
  unsigned schedule;
  int inputfd = -1;

  if (!data || size == 0 ||
      (uint64_t)size > (uint64_t)CUPS_RASTER_READER_MAX_INPUT) {
    return 0;
  }
#ifdef CUPS_RASTER_READER_OVERREAD_ORACLE
  schedule = 3;
#else
  schedule = data[size - 1] % 3;
#endif

  inputfd = mkstemp(input_name);
  if (inputfd < 0) {
    return 0;
  }
  unlink(input_name);

  if (write_all(inputfd, data, size) < 0 ||
      lseek(inputfd, 0, SEEK_SET) < 0) {
    goto done;
  }

  raster = cupsRasterOpen(inputfd, CUPS_RASTER_READ);
  if (!raster) {
    goto done;
  }

  while (pages < (uint64_t)CUPS_RASTER_READER_MAX_PAGES &&
         cupsRasterReadHeader2(raster, &header)) {
    uint64_t line_bytes = (uint64_t)header.cupsBytesPerLine;
    uint64_t rows = (uint64_t)header.cupsHeight;
    uint64_t page_bytes;
    uint64_t row;

    pages++;

    if (header.cupsColorOrder == CUPS_ORDER_PLANAR) {
      if (header.cupsNumColors != 0 &&
          rows > UINT64_MAX / (uint64_t)header.cupsNumColors) {
        break;
      }
      rows *= (uint64_t)header.cupsNumColors;
    }

    if (line_bytes == 0 ||
        line_bytes > (uint64_t)CUPS_RASTER_READER_MAX_LINE ||
        (rows != 0 && line_bytes > UINT64_MAX / rows)) {
      break;
    }

    page_bytes = line_bytes * rows;
    if (page_bytes > (uint64_t)CUPS_RASTER_READER_MAX_DECODED - decoded) {
      break;
    }

    {
      uint64_t allocation = line_bytes;

      if ((schedule == 2 && rows > 1) || schedule == 3) {
        if (line_bytes > SIZE_MAX / 2) {
          break;
        }
        allocation *= 2;
      }
      line = (unsigned char *)malloc((size_t)allocation);
    }
    if (!line) {
      break;
    }

    for (row = 0; row < rows;) {
      uint64_t batch = schedule == 2 && rows - row > 1 ? 2 : 1;
      uint64_t requested = line_bytes * batch;
      unsigned read_bytes;

      if (schedule == 3 && row + 1 == rows) {
        requested = line_bytes * 2;
        read_bytes =
            cupsRasterReadPixels(raster, line, (unsigned)requested);
        if ((uint64_t)read_bytes > line_bytes) {
          __builtin_trap();
        }
        if ((uint64_t)read_bytes != line_bytes) {
          break;
        }
        requested = line_bytes;
      } else if (schedule == 1 && line_bytes > 1) {
        unsigned first = (header.cupsBytesPerLine + 1) / 2;
        unsigned second = header.cupsBytesPerLine - first;

        read_bytes = cupsRasterReadPixels(raster, line, first);
        if (read_bytes != first) {
          break;
        }
        read_bytes = cupsRasterReadPixels(raster, line + first, second);
        if (read_bytes != second) {
          break;
        }
      } else {
        read_bytes =
            cupsRasterReadPixels(raster, line, (unsigned)requested);
        if ((uint64_t)read_bytes != requested) {
          break;
        }
      }
      decoded += requested;
      row += batch;
    }

    free(line);
    line = NULL;

    if (row != rows) {
      break;
    }
  }

done:
  free(line);
  if (raster) {
    cupsRasterClose(raster);
  }
  if (inputfd >= 0) {
    close(inputfd);
  }
  return 0;
}
