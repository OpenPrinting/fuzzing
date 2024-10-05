# Triage Reported Issues

## Local Traige

0. Local docker (Better use Ubuntu:20.04 for fitting OSS-Fuzz, Must use privileged docker.)
```bash
docker run --privileged -it --name $PROJECT -v $PROJECT:/src ubuntu:20.04 "/bin/bash"
```

1. Recompile source code with `-g -O0 -fsanitize=address` parameter
```bash
vim configure
export CC=clang
export CXX=clang++
export CFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
export CXXFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
export LDFLAGS="-g -fsanitize=address"
./configure --enable-static --disable-shared
```
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

## Debugging with GDB

```bash
python infra/helper.py shell base-runner-debug
```