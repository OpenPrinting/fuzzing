#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
# Source this before configuring an out-of-tree coverage build.
# Example:
#   source scripts/llvm_coverage_env.sh
#   cd /data/pre-gsoc/cups-filters
#   make clean
#   ./configure --disable-shared --enable-static --enable-individual-cups-filters
#   make -j"$(nproc)" pwgtoraster rastertoescpx rastertopclx
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address -fprofile-instr-generate -fcoverage-mapping ${CFLAGS:-}"
export CXXFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address -fprofile-instr-generate -fcoverage-mapping ${CXXFLAGS:-}"
export LDFLAGS="-fsanitize=address -fprofile-instr-generate ${LDFLAGS:-}"
export ASAN_OPTIONS="${ASAN_OPTIONS:-abort_on_error=0:detect_leaks=0:symbolize=1:exitcode=86}"
EOF
