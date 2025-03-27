## Fuzzing harness of cups

### Build with OSS-Fuzz

```bash
python infra/helper.py build_fuzzers --sanitizer address --engine libfuzzer --architecture x86_64 cups
```

The `build.sh` used in OSS-Fuzz is hosted in [oss_fuzz_build.sh](./oss_fuzz_build.sh).

### Local build with libFuzzer

_Note: Only tested in Ubuntu 22.04._

```bash
apt-get install zlib1g-dev libavahi-client-dev libsystemd-dev

git clone --depth=1 https://github.com/OpenPrinting/cups.git

cd cups/
git clone https://github.com/OpenPrinting/fuzzing.git
bash fuzzing/cups/build-fuzz.sh

cd fuzzing/cups/

./fuzz_cups    fuzz_cups_seed/    fuzz_cups_seed_corpus/
./fuzz_ipp     fuzz_ipp_seed/     fuzz_ipp_seed_corpus/
./fuzz_raster  fuzz_raster_seed/  fuzz_raster_seed_corpus/
./fuzz_ppd     fuzz_pdd_seed/     fuzz_pdd_seed_corpus/
```

### Local build with AFL++

```bash
# build
CC=afl-clang-lto
CXX=afl-clang-lto++
AFL_USE_ASAN=1
./configure --enable-static --disable-shared --host=x86_64
make -C cups/
make -C fuzzer/

# fuzz
afl-fuzz -i in/ -o out/ ./fuzz_ppd @@
```

### Fuzz corpora

#### fuzz_ppd

From existing test input in cups, specifically cups/test.ppd and cups/test2.ppd

```bash
echo -n -e "Letter\0na-letter\0roll_max_36.1025x3622.0472in\0 4x6\0Foo\0foo=buz option=option Foo=Buz tag=fooz\0datanum1920\0datanum1080\0" > 1
cat cups/test.ppd >> 1

echo -n -e "A4\0Letter\0iso_a4_210x297mm\0 2x8\0Option\0Option=Bar Foo=Buz AL=666 Astra=Aspera\0datanum1337\0datanum4242\0 " > 2
cat cups/test2.ppd >> 2

echo -n -e "A4\0A4\0iso_a4_210x297mm\0 2x8\0Astra\0Per=Aspera Ad=Astra\0datanum2048\0datanum2048\0 " > 3
cat cups/test2.ppd >> 3
```


