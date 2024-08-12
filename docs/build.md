# Intigrate New Projects

## libFuzzer.a
```bash
apt install vim git clang
cd $HOME
git clone https://github.com/Dor1s/libfuzzer-workshop.git
./libfuzzer-workshop/libFuzzer/Fuzzer/build.sh
```

or use `-fsanitize=fuzzer,address`
**Better do not use such setting, as it may not fit with OSS-Fuzz container environment**