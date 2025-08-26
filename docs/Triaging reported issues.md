# Triaging reported issues

## Executing local triage

1. Launch a local Docker container. For matching the OSS-Fuzz setup, use a privileged `ubuntu:20.04`.

  ```bash
  docker run --privileged -it --name $PROJECT -v $PROJECT:/src ubuntu:20.04 "/bin/bash"
  ```

2. Recompile the source code with `-g -O0 -fsanitize=address`.

  ```bash
  vim configure
  export CC=clang
  export CXX=clang++
  export CFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
  export CXXFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
  export LDFLAGS="-g -fsanitize=address"
  ./configure --enable-static --disable-shared
  ```

3. Replace the `main` function for fuzz harness or simply use `python infra/helper.py reproduce`:

  ```c
  /*
   * Example for replacing LLVMFuzzerTestOneInput with main
   */

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

    uint8_t *data = (uint8_t *)malloc(Size * sizeof(uint8_t));
    if (data == NULL) {
        perror("Failed to allocate memory");
        fclose(file);

        return 1;
    }

    size_t read_bytes_count = fread(data, sizeof(uint8_t), Size, file);
    if (read_bytes_count != Size) {
      perror("Failed to read file");
      free(data);
      fclose(file);

      return 1;
    }

    fclose(file);

    // The following instructions
  
  }
  ```

4. Minimize the PoC file.

## Debugging with GDB

```bash
python infra/helper.py shell base-runner-debug
```

## Building without optimizations

```bash
sed -i 's/-O[0-9s]/-O0/g' configure
```
