## CUPS fuzzing harness

### Set up, build, and run.

#### Note: This only works in Ubuntu.

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
```
