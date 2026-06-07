#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
# Source this before configuring an AFL++ instrumented build.
# Example:
#   source scripts/afl_coverage_env.sh
#   cd /data/pre-gsoc/cups-filters
#   make clean
#   ./configure --disable-shared --enable-static --enable-individual-cups-filters
#   make -j"$(nproc)" pwgtoraster rastertoescpx rastertopclx
export CC="${CC:-afl-clang-fast}"
export CXX="${CXX:-afl-clang-fast++}"
export AFL_USE_ASAN="${AFL_USE_ASAN:-1}"
export AFL_LLVM_CMPLOG="${AFL_LLVM_CMPLOG:-1}"
export CFLAGS="-O1 -g -fno-omit-frame-pointer ${CFLAGS:-}"
export CXXFLAGS="-O1 -g -fno-omit-frame-pointer ${CXXFLAGS:-}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86}"
EOF
