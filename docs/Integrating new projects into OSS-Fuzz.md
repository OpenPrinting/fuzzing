# Integrating new projects into OSS-Fuzz

## Compiling LibFuzzer.a

```bash
apt install vim git clang
cd $HOME
git clone https://github.com/Dor1s/libfuzzer-workshop.git
./libfuzzer-workshop/libFuzzer/Fuzzer/build.sh
```

You can also use `-fsanitize=fuzzer,address` instead, but this is not recommended due to OSS-Fuzz base-image configurations.

## Testing with local OSS-Fuzz

```bash
python infra/helper.py build_fuzzers --sanitizer $SANITIZER --engine $FUZZING_ENGINE --architecture $ARCHITECTURE $PROJECT_NAME
python infra/helper.py check_build --sanitizer $SANITIZER --engine $FUZZING_ENGINE --architecture $ARCHITECTURE $PROJECT_NAME $TARGET_NAME
```
