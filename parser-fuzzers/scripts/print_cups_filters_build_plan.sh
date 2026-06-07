#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASAN_ROOT="${1:-$ROOT/work/openprinting-asan}"
PREFIX="${2:-$ASAN_ROOT/prefix}"
SRC_ROOT="${3:-$ASAN_ROOT/src}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

cat <<EOF
# Example isolated ASan build plan for local OpenPrinting filters.
# Review package dependencies for your distribution before running.
# This plan never installs into /usr or /usr/local by default.

export ASAN_ROOT="$ASAN_ROOT"
export SMT_FUZZER_ROOT="$ROOT"
export PREFIX="$PREFIX"
export SRC_ROOT="$SRC_ROOT"
export JOBS="$JOBS"

case "\$PREFIX" in
  /|/usr|/usr/*|/usr/local|/usr/local/*|/opt|/opt/*)
    echo "refusing non-isolated install prefix: \$PREFIX" >&2
    exit 2
    ;;
esac

mkdir -p "\$SRC_ROOT" "\$PREFIX"

export CC=clang
export CXX=clang++
export CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
export CXXFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address,undefined"
export PKG_CONFIG_PATH="\$PREFIX/lib/pkgconfig:\$PREFIX/lib64/pkgconfig:\${PKG_CONFIG_PATH:-}"

clone_or_update() {
  repo="\$1"
  url="\$2"
  if [[ -d "\$SRC_ROOT/\$repo/.git" ]]; then
    git -C "\$SRC_ROOT/\$repo" pull --ff-only
  else
    git clone "\$url" "\$SRC_ROOT/\$repo"
  fi
}

clone_or_update libcupsfilters https://github.com/OpenPrinting/libcupsfilters.git
clone_or_update libppd https://github.com/OpenPrinting/libppd.git
clone_or_update cups-filters https://github.com/OpenPrinting/cups-filters.git

cd "\$SRC_ROOT/libcupsfilters"
./autogen.sh
./configure --prefix="\$PREFIX"
make -j"\$JOBS"
make install

cd "\$SRC_ROOT/libppd"
./autogen.sh
./configure --prefix="\$PREFIX"
make -j"\$JOBS"
make install

cd "\$SRC_ROOT/cups-filters"
./autogen.sh
./configure --prefix="\$PREFIX"
make -j"\$JOBS"

cd "\$SMT_FUZZER_ROOT"
export SMT_FUZZER_FILTER_ROOT="\$SRC_ROOT/cups-filters"
export SMT_FUZZER_LD_LIBRARY_PATH="\$SRC_ROOT/libcupsfilters/.libs:\$SRC_ROOT/libppd/.libs:\$PREFIX/lib:\$PREFIX/lib64"
export SMT_FUZZER_ASSUME_ASAN=1
scripts/check_cups_filters_targets.sh "\$SMT_FUZZER_FILTER_ROOT"
scripts/run_asan_cups_filters_campaign.sh "\$ASAN_ROOT" 60 4 5
EOF
