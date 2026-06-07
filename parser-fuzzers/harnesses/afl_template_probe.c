#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile unsigned sink;

static int has(const uint8_t *data, size_t size, const char *needle) {
  size_t n = strlen(needle);
  if (n == 0 || size < n) {
    return 0;
  }
  for (size_t i = 0; i + n <= size; ++i) {
    if (memcmp(data + i, needle, n) == 0) {
      return 1;
    }
  }
  return 0;
}

static uint32_t le32(const uint8_t *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void probe_pwg_or_cups(const uint8_t *data, size_t size) {
  if (size < 64) {
    return;
  }
  if (memcmp(data, "2SaR", 4) == 0) {
    sink += 1;
  } else if (memcmp(data, "3SaR", 4) == 0) {
    sink += 2;
  } else {
    return;
  }

  for (size_t off = 0; off + 16 <= size && off < 4096; off += 4) {
    uint32_t value = le32(data + off);
    if (value == 0) sink += 3;
    if (value == 1) sink += 5;
    if (value == 5) sink += 7;
    if (value == 72 || value == 300 || value == 600 || value == 720 || value == 1200) sink += 11;
    if (value == 0x7fffffffU || value == 0xffffffffU) sink += 13;
    if (value > 0 && value < 65536 && (value % 3) == 0) sink += 17;
  }

  if (has(data, size, "PageSize")) sink += 19;
  if (has(data, size, "ColorModel")) sink += 23;
  if (has(data, size, "DeviceRGB")) sink += 29;
}

static void probe_text_formats(const uint8_t *data, size_t size) {
  if (has(data, size, "*PPD-Adobe:")) sink += 31;
  if (has(data, size, "*cupsFilter:")) sink += 37;
  if (has(data, size, "*cupsFilter2:")) sink += 41;
  if (has(data, size, "*OpenUI")) sink += 43;
  if (has(data, size, "rastertopclx")) sink += 47;
  if (has(data, size, "pwgtopdf")) sink += 53;
  if (has(data, size, "imagetops")) sink += 59;
  if (has(data, size, "%PDF")) sink += 61;
  if (has(data, size, "%%Pages:")) sink += 67;
  if (has(data, size, "showpage")) sink += 71;
  if (has(data, size, "P1\n") || has(data, size, "P2\n") || has(data, size, "P3\n")) sink += 73;
  if (has(data, size, "P4\n") || has(data, size, "P5\n") || has(data, size, "P6\n")) sink += 79;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return 2;
  }
  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    return 2;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return 2;
  }
  long length = ftell(fp);
  if (length < 0) {
    fclose(fp);
    return 2;
  }
  rewind(fp);
  size_t size = (size_t)length;
  uint8_t *data = (uint8_t *)malloc(size ? size : 1);
  if (!data) {
    fclose(fp);
    return 2;
  }
  size_t read_bytes = fread(data, 1, size, fp);
  fclose(fp);
  if (read_bytes != size) {
    free(data);
    return 2;
  }

  probe_pwg_or_cups(data, size);
  probe_text_formats(data, size);

  if (size >= 4 && memcmp(data, "CRSH", 4) == 0) {
    abort();
  }
  free(data);
  return 0;
}
