# Intigrate New Projects

## Compile LibFuzzer.a

```bash
apt install vim git clang
cd $HOME
git clone https://github.com/Dor1s/libfuzzer-workshop.git
./libfuzzer-workshop/libFuzzer/Fuzzer/build.sh
```

or use `-fsanitize=fuzzer,address` (**Not suggested due to OSS-Fuzz base-image configurations**)

## Test with Local OSS-Fuzz

```bash
python infra/helper.py build_fuzzers --sanitizer $SANITIZER --engine $FUZZING_ENGINE --architecture $ARCHITECTURE $PROJECT_NAME
python infra/helper.py check_build --sanitizer $SANITIZER --engine $FUZZING_ENGINE --architecture $ARCHITECTURE $PROJECT_NAME $TARGET_NAME
```
