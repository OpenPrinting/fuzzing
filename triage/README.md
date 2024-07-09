# Triage Reported Issues

## Build

1. Recompile source code with `-g -O0` parameter
2. Replace `main` function for fuzz harness OR simply use `python infra/helper.py reprocude`

```C
/* Example - Replace LLVMFuzzerTestOneInput with main*/
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

int main(int argc, char *argv[]) {

  if (argc < 2) {
      fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
      return 1;
  }
  const char *filename = argv[1];
  FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }
  fseek(file, 0, SEEK_END);
  size_t Size = ftell(file);
  rewind(file);

  uint8_t *Data = (uint8_t *)malloc(Size * sizeof(uint8_t));
  if (Data == NULL) {
      perror("Failed to allocate memory");
      fclose(file);
      return 1;
  }

  size_t bytesRead = fread(Data, sizeof(uint8_t), Size, file);
  if (bytesRead != Size) {
    perror("Failed to read file");
    free(Data);
    fclose(file);
    return 1;
  }
  fclose(file);
// The following commands...
```

3. Minimize PoC file

## Use GDB for Debugging

To be updated