#!/bin/bash
set -euxo pipefail

ROOT="$SRC/cupsfilters-core12"
HARNESS_ROOT="$ROOT/harnesses"
source "$ROOT/targets.sh"

PREFIX="$WORK/cupsfilters-core12-prefix"
FUZZERS="$WORK/cupsfilters-core12-fuzzers"
JOBS="${JOBS:-$(nproc)}"
CUPS_PREFIX="$PREFIX/cups"
PDFIO_PREFIX="$PREFIX/pdfio"
LIBCUPSFILTERS_PREFIX="$PREFIX/libcupsfilters"
LIBPPD_PREFIX="$PREFIX/libppd"

export CFLAGS="${CFLAGS} -O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS="${CXXFLAGS} -O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
case "$CFLAGS" in
  *-fsanitize=fuzzer-no-link*) ;;
  *)
    export CFLAGS="${CFLAGS} -fsanitize=fuzzer-no-link"
    export CXXFLAGS="${CXXFLAGS} -fsanitize=fuzzer-no-link"
    ;;
esac
ORIGINAL_LDFLAGS="${LDFLAGS:-}"
FUZZER_CFLAGS="$CFLAGS"
FUZZER_CXXFLAGS="$CXXFLAGS"
export LDFLAGS="${ORIGINAL_LDFLAGS} ${CFLAGS}"
export CPPFLAGS="${CPPFLAGS:-} -I$CUPS_PREFIX/include -I$PDFIO_PREFIX/include"
mkdir -p "$PREFIX" "$FUZZERS" "$OUT"

build_autotools() {
  local source="$1" prefix="$2"
  shift 2
  cd "$source"
  [[ -x ./configure ]] || ./autogen.sh
  make distclean >/dev/null 2>&1 || true
  ./configure --prefix="$prefix" --enable-static --disable-shared "$@"
  make -j"$JOBS"
  make install
}

cd "$SRC/cups"
make distclean >/dev/null 2>&1 || true
./configure --prefix="$CUPS_PREFIX" --libdir="$CUPS_PREFIX/lib" \
  --enable-static --disable-shared
make -j1 -C cups libcups.a
make install-headers
make -C cups install-libs
mkdir -p "$CUPS_PREFIX/lib/pkgconfig"
install -m 0644 cups.pc "$CUPS_PREFIX/lib/pkgconfig/cups.pc"

export PKG_CONFIG_PATH="$CUPS_PREFIX/lib/pkgconfig"
[[ "$(pkg-config --variable=prefix cups)" == "$CUPS_PREFIX" ]]

cd "$SRC/pdfio"
./configure --prefix="$PDFIO_PREFIX" --enable-static --disable-shared
make -j"$JOBS"
make install

export PKG_CONFIG_PATH="$CUPS_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig"
build_autotools "$SRC/libcupsfilters" "$LIBCUPSFILTERS_PREFIX" \
  --without-jpegxl --disable-exif --disable-poppler --disable-dbus \
  --disable-ghostscript --disable-mutool

export PKG_CONFIG_PATH="$LIBCUPSFILTERS_PREFIX/lib/pkgconfig:$CUPS_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig"
build_autotools "$SRC/libppd" "$LIBPPD_PREFIX" \
  --disable-ghostscript --disable-pdftops --disable-mutool \
  --disable-acroread --with-pdftops=pdftocairo

export PKG_CONFIG_PATH="$LIBPPD_PREFIX/lib/pkgconfig:$LIBCUPSFILTERS_PREFIX/lib/pkgconfig:$CUPS_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig"

cd "$SRC/cups-filters"
[[ -x ./configure ]] || ./autogen.sh
make distclean >/dev/null 2>&1 || true
./configure --enable-individual-cups-filters --disable-universal-cups-filter \
  --disable-foomatic --disable-driverless --disable-ghostscript \
  --disable-mutool --enable-static --disable-shared

export CFLAGS="$FUZZER_CFLAGS"
export CXXFLAGS="$FUZZER_CXXFLAGS"
export LDFLAGS="$ORIGINAL_LDFLAGS"

read -r -a PKG_CFLAGS <<< "$(pkg-config --cflags libcupsfilters libppd pdfio cups)"
read -r -a DEP_LIBS <<< "$(pkg-config --libs --static libcupsfilters pdfio cups)"
read -r -a EXTRA_LIBS <<< "$(pkg-config --libs --static libjpeg libexif libqpdf libtiff-4 libpng fontconfig lcms2)"

FILTERED_DEP_LIBS=()
for library in "${DEP_LIBS[@]}"; do
  [[ "$library" == -lcupsfilters ]] || FILTERED_DEP_LIBS+=("$library")
done

COMMON_CFLAGS=(
  -I"$HARNESS_ROOT"
  -I"$SRC/cups-filters"
  -I"$SRC/cups-filters/filter"
  -I"$SRC/libcupsfilters"
  -I"$SRC/libcupsfilters/cupsfilters"
  -I"$SRC/libppd"
  -I"$LIBPPD_PREFIX/include"
  "${PKG_CFLAGS[@]}"
)
COMMON_LIBS=(
  "$LIBPPD_PREFIX/lib/libppd.a"
  "$LIBCUPSFILTERS_PREFIX/lib/libcupsfilters.a"
  "${FILTERED_DEP_LIBS[@]}"
  "${EXTRA_LIBS[@]}"
  -lstdc++
  -Wl,--allow-multiple-definition
)

if [[ "${SANITIZER:-}" == coverage ]]; then
  LSAN_COVERAGE_STUB="$FUZZERS/lsan_coverage_stubs.o"
  "$CC" $CFLAGS -c "$HARNESS_ROOT/lsan_coverage_stubs.c" \
    -o "$LSAN_COVERAGE_STUB"
  COMMON_LIBS+=("$LSAN_COVERAGE_STUB")
fi

build_harness() {
  local output="$1" source="$2"
  shift 2
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "$@" "$source" \
    "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE -o "$FUZZERS/$output"
}

compact_state_mutator() {
  local prefix_size="$1" selector_size="$2" min_payload="$3"
  printf '%s\n' \
    "-DCF_FUZZ_STATE_PREFIX_SIZE=$prefix_size" \
    "-DCF_FUZZ_STATE_SELECTOR_SIZE=$selector_size" \
    "-DCF_FUZZ_STATE_MIN_PAYLOAD=$min_payload" \
    "$HARNESS_ROOT/compact_state_mutator.c"
}

mapfile -t PWG_SCALE_MUTATOR < <(compact_state_mutator 7 8 0)
mapfile -t RASTER_OUTPUT_MUTATOR < <(compact_state_mutator 8 8 0)
mapfile -t PCLX_CODEC_MUTATOR < <(compact_state_mutator 8 12 1)
mapfile -t TEXT_LAYOUT_MUTATOR < <(compact_state_mutator 8 16 1)

build_harness fuzz_cupsfilters_format_cups_raster \
  "$HARNESS_ROOT/fuzz_cups_raster_reader.c" \
  -DCUPS_RASTER_READER_MAX_INPUT=4194304

build_harness fuzz_cupsfilters_format_image_jpeg_bounded \
  "$HARNESS_ROOT/fuzz_cupsfilters_image_codec.c" \
  -DCUPSFILTERS_IMAGE_CODEC_JPEG -DCUPSFILTERS_IMAGE_CODEC_MAX_INPUT=2097152 \
  -Wl,--wrap=jpeg_std_error

build_harness fuzz_cupsfilters_format_image_png_bounded \
  "$HARNESS_ROOT/fuzz_png_bounded_format.c" \
  -DCUPSFILTERS_IMAGE_CODEC_PNG -DCUPSFILTERS_IMAGE_CODEC_MAX_INPUT=2097152

build_harness fuzz_cupsfilters_format_image_tiff_bounded \
  "$HARNESS_ROOT/fuzz_cupsfilters_image_codec.c" \
  -DCUPSFILTERS_IMAGE_CODEC_TIFF -DCUPSFILTERS_IMAGE_CODEC_MAX_INPUT=2097152 \
  -Wl,--wrap=TIFFFdOpen -Wl,--wrap=TIFFReadScanline

for direction in down up; do
  build_harness "fuzz_cupsfilters_state_pwg_to_raster_scale_$direction" \
    "$HARNESS_ROOT/fuzz_pwg_scale_state.c" \
    "-DCF_FUZZ_PWG_SCALE_${direction^^}" "${PWG_SCALE_MUTATOR[@]}"
done

for dialect in apple pwg; do
  if [[ "$dialect" == apple ]]; then
    output_mime=image/urf
  else
    output_mime=image/pwg-raster
  fi
  build_harness "fuzz_cupsfilters_state_raster_to_$dialect" \
    "$HARNESS_ROOT/fuzz_raster_output_state.c" \
    -DCF_FUZZ_FILTER_FUNCTION=cfFilterRasterToPWG \
    -DCF_FUZZ_TARGET_NAME="\"fuzz_cupsfilters_state_raster_to_$dialect\"" \
    -DCF_FUZZ_INPUT_MIME="\"application/vnd.cups-raster\"" \
    -DCF_FUZZ_OUTPUT_MIME="\"$output_mime\"" \
    "${RASTER_OUTPUT_MUTATOR[@]}"
done

for mode in 3 10; do
  build_harness "fuzz_cupsfilters_raster_to_pclx_mode${mode}_codec" \
    "$HARNESS_ROOT/fuzz_rastertopclx_compress_state.c" \
    -DCF_FUZZ_RASTERTOPCLX_SOURCE="\"$SRC/cups-filters/filter/rastertopclx.c\"" \
    "-DCF_FUZZ_PCLX_MODE${mode}_CODEC" \
    "$SRC/cups-filters/filter/pcl-common.c" \
    "${PCLX_CODEC_MUTATOR[@]}"
done

build_harness fuzz_cupsfilters_state_text_to_text_layout \
  "$HARNESS_ROOT/fuzz_text_to_text_state.c" \
  -DCF_FUZZ_FILTER_FUNCTION=cfFilterTextToText \
  -DCF_FUZZ_TARGET_NAME='"fuzz_cupsfilters_state_text_to_text_layout"' \
  -DCF_FUZZ_INPUT_MIME='"text/plain"' \
  -DCF_FUZZ_OUTPUT_MIME='"text/plain"' \
  -DCF_FUZZ_TEXTTOTEXT_STATE_OPTIONS \
  "${TEXT_LAYOUT_MUTATOR[@]}"

build_harness fuzz_cupsfilters_text_to_text_selection_oracle \
  "$HARNESS_ROOT/fuzz_text_to_text_page_order.c" \
  -DCF_FUZZ_FILTER_FUNCTION=cfFilterTextToText \
  -DCF_FUZZ_TARGET_NAME='"fuzz_cupsfilters_text_to_text_selection_oracle"' \
  -DCF_FUZZ_INPUT_MIME='"text/plain"' \
  -DCF_FUZZ_OUTPUT_MIME='"text/plain"' \
  -DCF_FUZZ_TEXTTOTEXT_STATE_OPTIONS \
  "${TEXT_LAYOUT_MUTATOR[@]}"

for target in "${CF_CORE12_TARGETS[@]}"; do
  [[ -x "$FUZZERS/$target" ]] || {
    echo "core12 build did not produce $target" >&2
    exit 2
  }
done

# helper.py preserves $OUT between builds. Remove this project's prior target
# artifacts so a renamed or removed target cannot survive an incremental build.
find "$OUT" -mindepth 1 -maxdepth 1 -name 'fuzz_*cupsfilters_*' \
  -exec rm -rf -- {} +
rm -f "$OUT"/*.so "$OUT"/*.so.* "$OUT/fonts.conf"
rm -rf "$OUT/cups-data" "$OUT/fonts"
mkdir -p "$OUT/cups-data/data" "$OUT/fonts"
cp -a /usr/share/cups/. "$OUT/cups-data/" 2>/dev/null || true
cp -a "$SRC/libcupsfilters/data/"*.pdf "$OUT/cups-data/data/"
cp -a /usr/share/fonts/truetype/dejavu/. "$OUT/fonts/"
cp "$ROOT/fonts.conf" "$OUT/fonts.conf"

for target in "${CF_CORE12_TARGETS[@]}"; do
  install -m 0755 "$FUZZERS/$target" "$OUT/$target"
  cp "$ROOT/corpus/${target}_seed_corpus.zip" "$OUT/"
  cp "$ROOT/dictionaries/${target}.dict" "$OUT/"
  printf '[libfuzzer]\nmax_len=%s\ntimeout=%s\nrss_limit_mb=%s\ndetect_leaks=%s\n' \
    "$(core12_target_max_len "$target")" \
    "$(core12_target_timeout_sec "$target")" \
    "$(core12_target_rss_limit_mb "$target")" \
    "$(core12_target_detect_leaks "$target")" \
    >"$OUT/${target}.options"
  patchelf --set-rpath '$ORIGIN' "$OUT/$target"
done

is_system_runtime() {
  case "$(basename "$1")" in
    ld-linux*|libanl.so.*|libc.so.*|libdl.so.*|libgcc_s.so.*|libm.so.*|\
    libmemusage.so.*|libnsl.so.*|libnss_*.so.*|libpthread.so.*|\
    libresolv.so.*|librt.so.*|libstdc++.so.*|libthread_db.so.*|libutil.so.*)
      return 0 ;;
    *) return 1 ;;
  esac
}

for target in "${CF_CORE12_TARGETS[@]}"; do
  while read -r library; do
    [[ -z "$library" || "$library" == "$OUT/"* ]] && continue
    is_system_runtime "$library" && continue
    cp -L "$library" "$OUT/"
  done < <(ldd "$OUT/$target" | awk '/=> \/[^ ]+/ { print $3 }')
done

for library in "$OUT"/*.so "$OUT"/*.so.*; do
  [[ -f "$library" ]] || continue
  patchelf --set-rpath '$ORIGIN' "$library"
done

echo "Exported ${#CF_CORE12_TARGETS[@]} cups-filters core targets to $OUT"
