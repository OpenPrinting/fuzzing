/*
   Copyright The libcups Developers.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Fuzzes the raster stream reader/writer in raster-stream.c.
//
// Input layout: byte 0 is a control byte, the rest is a CUPS (v1/v2/v3),
// PWG or Apple raster stream.
//   bits 0-1: pixel read size - 0 whole line, 1 half line, 2 seven bytes,
//             3 two lines.
//   bits 2-4: re-encode decoded pages - 1 CUPS_RASTER_WRITE,
//             2 CUPS_RASTER_WRITE_COMPRESSED, 3 CUPS_RASTER_WRITE_PWG,
//             4 CUPS_RASTER_WRITE_APPLE, anything else none.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cups.h"
#include "raster.h"

#define MAX_INPUT	(1024 * 1024)
#define MAX_PAGES	16
#define MAX_LINE	(1024 * 1024)
#define MAX_DECODED	(8 * 1024 * 1024)

typedef struct fuzz_reader_s
{
  const uint8_t	*data;
  size_t	size;
  size_t	offset;
} fuzz_reader_t;


static ssize_t
read_cb(void *ctx, unsigned char *buffer, size_t length)
{
  fuzz_reader_t	*reader = (fuzz_reader_t *)ctx;
  size_t	bytes = reader->size - reader->offset;

  if (bytes > length)
    bytes = length;

  memcpy(buffer, reader->data + reader->offset, bytes);
  reader->offset += bytes;

  return ((ssize_t)bytes);
}


static ssize_t
write_cb(void *ctx, unsigned char *buffer, size_t length)
{
  (void)ctx;
  (void)buffer;

  return ((ssize_t)length);
}


static size_t
chunk_size(unsigned mode, unsigned bpl)
{
  switch (mode)
  {
    case 1 :
        return (bpl > 1 ? bpl / 2 + 1 : 1);
    case 2 :
        return (bpl < 7 ? bpl : 7);
    case 3 :
        return ((size_t)bpl * 2);
    default :
        return (bpl);
  }
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fuzz_reader_t		reader;
  cups_raster_t		*in, *out = NULL;
  cups_page_header_t	header;
  unsigned		read_mode, write_mode;
  size_t		decoded = 0;
  int			page;

  if (size < 1 || size > MAX_INPUT)
    return (0);

  read_mode  = data[0] & 3;
  write_mode = (data[0] >> 2) & 7;

  reader.data   = data + 1;
  reader.size   = size - 1;
  reader.offset = 0;

  if ((in = cupsRasterOpenIO(read_cb, &reader, CUPS_RASTER_READ)) == NULL)
  {
    (void)cupsRasterGetErrorString();
    return (0);
  }

  if (write_mode >= CUPS_RASTER_WRITE && write_mode <= CUPS_RASTER_WRITE_APPLE)
    out = cupsRasterOpenIO(write_cb, NULL, (cups_raster_mode_t)write_mode);

  for (page = 0; page < MAX_PAGES && decoded < MAX_DECODED && cupsRasterReadHeader(in, &header); page ++)
  {
    unsigned char	*buffer;
    size_t		chunk, remaining;
    uint64_t		rows;

    if (header.cupsBytesPerLine == 0 || header.cupsBytesPerLine > MAX_LINE)
      break;

    rows = header.cupsHeight;
    if (header.cupsColorOrder == CUPS_ORDER_PLANAR)
      rows *= header.cupsNumColors;

    if (rows * header.cupsBytesPerLine > MAX_DECODED - decoded)
      remaining = MAX_DECODED - decoded;
    else
      remaining = (size_t)(rows * header.cupsBytesPerLine);

    chunk = chunk_size(read_mode, header.cupsBytesPerLine);

    if ((buffer = malloc(chunk)) == NULL)
      break;

    if (out && !cupsRasterWriteHeader(out, &header))
    {
      cupsRasterClose(out);
      out = NULL;
    }

    while (remaining > 0)
    {
      unsigned len = (unsigned)(remaining < chunk ? remaining : chunk);

      if (cupsRasterReadPixels(in, buffer, len) != len)
        break;

      if (out && cupsRasterWritePixels(out, buffer, len) != len)
      {
        cupsRasterClose(out);
        out = NULL;
      }

      remaining -= len;
      decoded   += len;
    }

    free(buffer);
  }

  (void)cupsRasterGetErrorString();

  cupsRasterClose(out);
  cupsRasterClose(in);

  return (0);
}
