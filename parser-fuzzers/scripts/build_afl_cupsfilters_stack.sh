#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SRC_ROOT="${SMT_AFL_SRC_ROOT:-/data/pre-gsoc}"
BUILD_ROOT="${SMT_AFL_BUILD_ROOT:-$ROOT/work/afl-builds}"
INSTALL_ROOT="${SMT_AFL_INSTALL_ROOT:-$ROOT/work/afl-install}"
SRC_COPY_ROOT="${SMT_AFL_SRC_COPY_ROOT:-$ROOT/work/afl-src}"
LOG_ROOT="${SMT_AFL_BUILD_LOG_ROOT:-$ROOT/work/build-afl-cupsfilters}"
JOBS="${JOBS:-$(nproc)}"

LIBPPD_SRC="${SMT_AFL_LIBPPD_SRC:-$SRC_ROOT/libppd-origin-latest}"
LIBCUPSFILTERS_SRC="${SMT_AFL_LIBCUPSFILTERS_SRC:-$SRC_ROOT/libcupsfilters}"
CUPSFILTERS_SRC="${SMT_AFL_CUPSFILTERS_SRC:-$SRC_ROOT/cups-filters}"

LIBPPD_PREFIX="$INSTALL_ROOT/libppd"
LIBCUPSFILTERS_PREFIX="$INSTALL_ROOT/libcupsfilters"
CUPSFILTERS_PREFIX="$INSTALL_ROOT/cups-filters"
PDFIO_PREFIX="${SMT_AFL_PDFIO_PREFIX:-/data/pre-gsoc/env/pdfio-install}"

COMMON_CFLAGS="-O1 -g -fno-omit-frame-pointer ${CFLAGS:-}"
COMMON_CXXFLAGS="-O1 -g -fno-omit-frame-pointer ${CXXFLAGS:-}"
COMMON_LDFLAGS="-fsanitize=address ${LDFLAGS:-}"

export CC="${CC:-afl-clang-fast}"
export CXX="${CXX:-afl-clang-fast++}"
export AFL_USE_ASAN="${AFL_USE_ASAN:-1}"
export AFL_LLVM_CMPLOG="${AFL_LLVM_CMPLOG:-1}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=0}"

mkdir -p "$BUILD_ROOT" "$INSTALL_ROOT" "$SRC_COPY_ROOT" "$LOG_ROOT"
rm -f "$LOG_ROOT"/*.log

copy_source_tree() {
  local name="$1"
  local src="$2"
  local dest="$SRC_COPY_ROOT/$name"

  rm -rf "$dest"
  mkdir -p "$dest"
  (
    cd "$src"
    tar \
      --exclude=.git \
      --exclude=autom4te.cache \
      --exclude=.libs \
      --exclude='*.o' \
      --exclude='*.lo' \
      --exclude='*.la' \
      --exclude='*.log' \
      --exclude='*.trs' \
      --exclude=config.status \
      --exclude=config.log \
      --exclude=config.cache \
      --exclude=config.h \
      --exclude=stamp-h1 \
      --exclude=Makefile \
      --exclude=libtool \
      -cf - .
  ) | (
    cd "$dest"
    tar --no-same-owner -xf -
  )
  if [[ -f "$dest/charset/pdf.utf-8.heavy" && ! -f "$dest/charset/pdf.utf-8.heavy.in" ]]; then
    cp "$dest/charset/pdf.utf-8.heavy" "$dest/charset/pdf.utf-8.heavy.in"
  fi
  if [[ -f "$dest/charset/pdf.utf-8.simple" && ! -f "$dest/charset/pdf.utf-8.simple.in" ]]; then
    cp "$dest/charset/pdf.utf-8.simple" "$dest/charset/pdf.utf-8.simple.in"
  fi
  echo "$dest"
}

build_autotools() {
  local name="$1"
  local src="$2"
  local build="$3"
  local prefix="$4"
  shift 4

  if [[ ! -x "$src/configure" ]]; then
    echo "missing configure script: $src/configure" >&2
    return 2
  fi

  rm -rf "$build" "$prefix"
  mkdir -p "$build"
  (
    cd "$src"
    find . -type d \
      ! -path './.git*' \
      ! -path './autom4te.cache*' \
      ! -path './.libs*' \
      -exec mkdir -p "$build/{}" \;
  )
  (
    cd "$build"
    echo "[build:$name] configure"
    "$src/configure" \
      --prefix="$prefix" \
      --disable-dependency-tracking \
      "$@" \
      >"$LOG_ROOT/$name.configure.log" 2>&1
    echo "[build:$name] make -j$JOBS"
    make -j"$JOBS" >"$LOG_ROOT/$name.make.log" 2>&1
    echo "[build:$name] make install"
    make install >"$LOG_ROOT/$name.install.log" 2>&1
  )
}

export CFLAGS="$COMMON_CFLAGS"
export CXXFLAGS="$COMMON_CXXFLAGS"
export LDFLAGS="$COMMON_LDFLAGS"

LIBPPD_BUILD_SRC="$(copy_source_tree libppd "$LIBPPD_SRC")"
LIBCUPSFILTERS_BUILD_SRC="$(copy_source_tree libcupsfilters "$LIBCUPSFILTERS_SRC")"
CUPSFILTERS_BUILD_SRC="$(copy_source_tree cups-filters "$CUPSFILTERS_SRC")"

build_autotools \
  libppd \
  "$LIBPPD_BUILD_SRC" \
  "$BUILD_ROOT/libppd" \
  "$LIBPPD_PREFIX" \
  --enable-shared \
  --enable-static

export PKG_CONFIG_PATH="$LIBPPD_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

LIBCUPSFILTERS_STATUS="afl-built"
if build_autotools \
  libcupsfilters \
  "$LIBCUPSFILTERS_BUILD_SRC" \
  "$BUILD_ROOT/libcupsfilters" \
  "$LIBCUPSFILTERS_PREFIX" \
  --enable-shared \
  --enable-static; then
  LIBCUPSFILTERS_INCLUDE_ROOT="$LIBCUPSFILTERS_PREFIX/include"
  LIBCUPSFILTERS_LIB_DIR="$LIBCUPSFILTERS_PREFIX/lib"
  export PKG_CONFIG_PATH="$LIBCUPSFILTERS_PREFIX/lib/pkgconfig:$LIBPPD_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
else
  if [[ -f "$LIBCUPSFILTERS_PREFIX/lib/libcupsfilters.so.2.0.0" ]]; then
    LIBCUPSFILTERS_STATUS="afl-built-partial-install"
    LIBCUPSFILTERS_INCLUDE_ROOT="$LIBCUPSFILTERS_BUILD_SRC"
    LIBCUPSFILTERS_LIB_DIR="$LIBCUPSFILTERS_PREFIX/lib"
    {
      echo "libcupsfilters AFL++ library was installed, but data install failed."
      echo "This is acceptable for fuzzing because the project-local library is present."
      echo "install_log=$LOG_ROOT/libcupsfilters.install.log"
      echo "include_root=$LIBCUPSFILTERS_INCLUDE_ROOT"
      echo "lib_dir=$LIBCUPSFILTERS_LIB_DIR"
    } >"$LOG_ROOT/libcupsfilters.partial-install.log"
    export PKG_CONFIG_PATH="$LIBPPD_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  elif [[ -f "$BUILD_ROOT/libcupsfilters/.libs/libcupsfilters.so.2.0.0" ]]; then
    LIBCUPSFILTERS_STATUS="afl-built-builddir"
    LIBCUPSFILTERS_INCLUDE_ROOT="$LIBCUPSFILTERS_BUILD_SRC"
    LIBCUPSFILTERS_LIB_DIR="$BUILD_ROOT/libcupsfilters/.libs"
    {
      echo "libcupsfilters AFL++ library was built but not installed; using builddir library."
      echo "install_log=$LOG_ROOT/libcupsfilters.install.log"
      echo "include_root=$LIBCUPSFILTERS_INCLUDE_ROOT"
      echo "lib_dir=$LIBCUPSFILTERS_LIB_DIR"
    } >"$LOG_ROOT/libcupsfilters.builddir.log"
    export PKG_CONFIG_PATH="$LIBPPD_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  else
    LIBCUPSFILTERS_STATUS="fallback-local-asan"
    LIBCUPSFILTERS_INCLUDE_ROOT="${SMT_AFL_LIBCUPSFILTERS_INCLUDE:-$LIBCUPSFILTERS_SRC}"
    LIBCUPSFILTERS_LIB_DIR="${SMT_AFL_LIBCUPSFILTERS_LIB:-$LIBCUPSFILTERS_SRC/.libs}"
    if [[ ! -d "$LIBCUPSFILTERS_INCLUDE_ROOT" || ! -d "$LIBCUPSFILTERS_LIB_DIR" ]]; then
      echo "libcupsfilters AFL++ build failed and fallback path is missing" >&2
      echo "include_root=$LIBCUPSFILTERS_INCLUDE_ROOT" >&2
      echo "lib_dir=$LIBCUPSFILTERS_LIB_DIR" >&2
      exit 1
    fi
    {
      echo "libcupsfilters AFL++ build failed; using existing local ASan build for now."
      echo "configure_log=$LOG_ROOT/libcupsfilters.configure.log"
      echo "make_log=$LOG_ROOT/libcupsfilters.make.log"
      echo "install_log=$LOG_ROOT/libcupsfilters.install.log"
      echo "include_root=$LIBCUPSFILTERS_INCLUDE_ROOT"
      echo "lib_dir=$LIBCUPSFILTERS_LIB_DIR"
    } >"$LOG_ROOT/libcupsfilters.fallback.log"
    export PKG_CONFIG_PATH="$LIBPPD_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
  fi
fi

export LIBCUPSFILTERS_CFLAGS="-I$LIBCUPSFILTERS_INCLUDE_ROOT -I$LIBCUPSFILTERS_INCLUDE_ROOT/cupsfilters"
export LIBCUPSFILTERS_LIBS="-L$LIBCUPSFILTERS_LIB_DIR -Wl,-rpath,$LIBCUPSFILTERS_LIB_DIR -lcupsfilters -L$PDFIO_PREFIX/lib -Wl,-rpath,$PDFIO_PREFIX/lib"
export LIBPPD_CFLAGS="-I$LIBPPD_PREFIX/include/ppd -I$LIBPPD_PREFIX/include"
export LIBPPD_LIBS="-L$LIBPPD_PREFIX/lib -Wl,-rpath,$LIBPPD_PREFIX/lib -lppd"
export LDFLAGS="$COMMON_LDFLAGS -Wl,-rpath,$LIBCUPSFILTERS_LIB_DIR -Wl,-rpath,$LIBPPD_PREFIX/lib -Wl,-rpath,$PDFIO_PREFIX/lib"

CUPSFILTERS_INSTALL_STATUS="make-install"
if build_autotools \
  cups-filters \
  "$CUPSFILTERS_BUILD_SRC" \
  "$BUILD_ROOT/cups-filters" \
  "$CUPSFILTERS_PREFIX" \
  --enable-individual-cups-filters \
  --disable-shared \
  --enable-static; then
  CUPSFILTERS_INSTALL_STATUS="make-install"
else
  if [[ ! -x "$BUILD_ROOT/cups-filters/pwgtopdf" ]]; then
    echo "cups-filters build failed before producing pwgtopdf" >&2
    echo "make_log=$LOG_ROOT/cups-filters.make.log" >&2
    echo "install_log=$LOG_ROOT/cups-filters.install.log" >&2
    exit 1
  fi
  CUPSFILTERS_INSTALL_STATUS="manual-copy-after-install-hook-failure"
fi

mkdir -p "$CUPSFILTERS_PREFIX/lib/cups/filter"
find "$BUILD_ROOT/cups-filters" -maxdepth 1 -type f -perm -111 \
  ! -name config.status \
  ! -name libtool \
  -exec cp -a {} "$CUPSFILTERS_PREFIX/lib/cups/filter/" \;

cat >"$INSTALL_ROOT/afl-env.sh" <<EOF
export SMT_AFL_INSTALL_ROOT="$INSTALL_ROOT"
export SMT_AFL_CUPSFILTERS_BIN="$CUPSFILTERS_PREFIX/lib/cups/filter"
export SMT_AFL_CUPSFILTERS_PREFIX="$CUPSFILTERS_PREFIX"
export SMT_AFL_LIBCUPSFILTERS_STATUS="$LIBCUPSFILTERS_STATUS"
export SMT_AFL_LIBCUPSFILTERS_LIB="$LIBCUPSFILTERS_LIB_DIR"
export SMT_AFL_LIBPPD_LIB="$LIBPPD_PREFIX/lib"
export SMT_AFL_PDFIO_LIB="$PDFIO_PREFIX/lib"
export LD_LIBRARY_PATH="$LIBCUPSFILTERS_LIB_DIR:$LIBPPD_PREFIX/lib:$PDFIO_PREFIX/lib:\${LD_LIBRARY_PATH:-}"
export ASAN_OPTIONS="\${ASAN_OPTIONS:-abort_on_error=1:detect_leaks=0:symbolize=0}"
EOF

echo "install_root=$INSTALL_ROOT"
echo "cupsfilters_prefix=$CUPSFILTERS_PREFIX"
echo "filter_bin_dir=$CUPSFILTERS_PREFIX/lib/cups/filter"
echo "cupsfilters_install_status=$CUPSFILTERS_INSTALL_STATUS"
echo "libcupsfilters_status=$LIBCUPSFILTERS_STATUS"
echo "libcupsfilters_lib=$LIBCUPSFILTERS_LIB_DIR"
echo "env_file=$INSTALL_ROOT/afl-env.sh"
echo "logs=$LOG_ROOT"
