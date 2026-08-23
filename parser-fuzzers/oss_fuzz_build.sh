#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

set -euxo pipefail

ROOT="$SRC/fuzzing/parser-fuzzers"
V3_ROOT="$ROOT/harnesses/libfuzzer/v3"
source "$V3_ROOT/targets.sh"

PREFIX="$WORK/cupsfilters-prefix"
FUZZERS="$WORK/cupsfilters-fuzzers"
JOBS="${JOBS:-$(nproc)}"
CUPS_PREFIX="$PREFIX/cups"
PDFIO_PREFIX="$PREFIX/pdfio"
LIBCUPSFILTERS_PREFIX="$PREFIX/libcupsfilters"
LIBPPD_PREFIX="$PREFIX/libppd"

export CFLAGS="${CFLAGS} -O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS="${CXXFLAGS} -O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
if [[ "${SANITIZER:-}" == "undefined" ]]; then
  # Defined unsigned wrap is pervasive in hash and codec implementations.
  # Keep the remaining checks enabled while suppressing one tracked libppd
  # ASCII85 shift that every ordinary high-bit pixel can reach.
  ubsan_ignorelist="$ROOT/config/ubsan-ignorelist.txt"
  export CFLAGS="${CFLAGS} -fno-sanitize=unsigned-integer-overflow -fsanitize-ignorelist=$ubsan_ignorelist"
  export CXXFLAGS="${CXXFLAGS} -fno-sanitize=unsigned-integer-overflow -fsanitize-ignorelist=$ubsan_ignorelist"
fi
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

target_set="${CUPSFILTERS_V3_TARGET_SET:-deploy}"
case "$target_set" in
  deploy)
    selected_targets=("${CF_V3_DEPLOY_TARGETS[@]}" "${CF_V3_COMPATIBILITY_TARGETS[@]}")
    build_selector=package
    ;;
  target:*)
    requested="${target_set#target:}"
    if ! cf_v3_list_targets package | grep -Fxq "$requested"; then
    echo "target is not in the OSS-Fuzz package: $requested" >&2
      exit 2
    fi
    selected_targets=("$requested")
    build_selector="$requested"
    ;;
  *)
    echo "V3 package supports only deploy or target:<deploy-target>" >&2
    exit 2
    ;;
esac

for target in "${CF_V3_TARGETS[@]}"; do
  external_target="$(cf_v3_target_external_name "$target")"
  rm -f "$OUT/$target" "$OUT/${target}.options" \
    "$OUT/${target}.dict" "$OUT/${target}_seed_corpus.zip" \
    "$OUT/$external_target" "$OUT/${external_target}.options" \
    "$OUT/${external_target}.dict" "$OUT/${external_target}_seed_corpus.zip"
done
rm -f "$OUT"/*.so "$OUT"/*.so.* "$OUT/fonts.conf" \
  "$OUT/source-provenance.tsv"
rm -rf "$OUT"/fuzz_v3_*_libfuzzer_*_out
rm -rf "$OUT/cups-data" "$OUT/fonts"

build_autotools() {
  local source="$1" prefix="$2"
  shift 2
  cd "$source"
  if [[ ! -x ./configure ]]; then
    ./autogen.sh
  fi
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
# CUPS uses the system ar directly.  Introspector emits LLVM bitcode objects,
# which that ar cannot index with its older LLVM plugin; gold then rejects the
# otherwise valid archive.  Rebuild both CUPS archive maps with matching tools.
if [[ "${SANITIZER:-}" == "introspector" ]]; then
  llvm-ranlib "$CUPS_PREFIX/lib/libcups.a" "$CUPS_PREFIX/lib/libcupsimage.a"
fi
mkdir -p "$CUPS_PREFIX/lib/pkgconfig"
install -m 0644 cups.pc "$CUPS_PREFIX/lib/pkgconfig/cups.pc"

export PKG_CONFIG_PATH="$CUPS_PREFIX/lib/pkgconfig"
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
if [[ ! -x ./configure ]]; then
  ./autogen.sh
fi
make distclean >/dev/null 2>&1 || true
./configure --enable-individual-cups-filters --disable-universal-cups-filter \
  --disable-foomatic --disable-driverless --disable-ghostscript \
  --disable-mutool --enable-static --disable-shared

export CFLAGS="$FUZZER_CFLAGS"
export CXXFLAGS="$FUZZER_CXXFLAGS"
export LDFLAGS="$ORIGINAL_LDFLAGS"
export CF_V3_INSTALL_ROOT="$PREFIX"
export CF_V3_SOURCE_ROOT="$SRC"
export CF_V3_STACK_BUILD_ROOT="$SRC"
export CF_V3_OUTPUT_ROOT="$FUZZERS"
bash "$V3_ROOT/build_local.sh" "$build_selector"

mkdir -p "$OUT/cups-data/data" "$OUT/fonts"
cp -a /usr/share/cups/. "$OUT/cups-data/" 2>/dev/null || true
cp -a "$SRC/libcupsfilters/data/"*.pdf "$OUT/cups-data/data/"
cp -a /usr/share/fonts/truetype/dejavu/. "$OUT/fonts/"
cp "$ROOT/config/fonts.conf" "$OUT/fonts.conf"

for target in "${selected_targets[@]}"; do
  external_target="$(cf_v3_target_external_name "$target")"
  [[ -x "$FUZZERS/$target" ]] || {
    echo "missing built V3 target: $target" >&2
    exit 2
  }
  if ldd "$FUZZERS/$target" | grep 'libcups\.so' >/dev/null; then
    echo "$target unexpectedly links a system CUPS shared library" >&2
    exit 2
  fi
  install -m 0755 "$FUZZERS/$target" "$OUT/$external_target"
  cp "$ROOT/corpus/${external_target}_seed_corpus.zip" "$OUT/"
  cp "$ROOT/dictionaries/${external_target}.dict" "$OUT/"
  max_len="$(cf_v3_target_max_len "$target")"
  [[ "$external_target" != fuzz_pdf ]] || max_len=4194304
  printf '[libfuzzer]\nmax_len=%s\ntimeout=%s\nrss_limit_mb=%s\ndetect_leaks=1\n' \
    "$max_len" \
    "$(cf_v3_target_timeout "$target")" \
    "$(cf_v3_target_rss_limit_mb "$target")" \
    >"$OUT/${external_target}.options"
  patchelf --set-rpath '$ORIGIN' "$OUT/$external_target"
done

forbidden_runtime() {
  case "$(basename "$1")" in
    ld-linux*|libanl.so.*|libc.so.*|libdl.so.*|libgcc_s.so.*|libm.so.*|\
    libmemusage.so.*|libnsl.so.*|libnss_*.so.*|libpthread.so.*|\
    libresolv.so.*|librt.so.*|libstdc++.so.*|libthread_db.so.*|libutil.so.*)
      return 0 ;;
    *) return 1 ;;
  esac
}

for target in "${selected_targets[@]}"; do
  external_target="$(cf_v3_target_external_name "$target")"
  while read -r library; do
    [[ -z "$library" || "$library" == "$OUT/"* ]] && continue
    forbidden_runtime "$library" && continue
    cp -L "$library" "$OUT/"
  done < <(ldd "$OUT/$external_target" | awk '/=> \/[^ ]+/ { print $3 }')
done
for library in "$OUT"/*.so "$OUT"/*.so.*; do
  [[ -f "$library" ]] || continue
  patchelf --set-rpath '$ORIGIN' "$library"
done

printf 'component\tcommit\n' >"$OUT/source-provenance.tsv"
for component in cups pdfio libcupsfilters libppd cups-filters; do
  printf '%s\t%s\n' "$component" \
    "$(git -C "$SRC/$component" rev-parse HEAD)" \
    >>"$OUT/source-provenance.tsv"
done

echo "Exported ${#selected_targets[@]} stable OSS-Fuzz targets to $OUT"
