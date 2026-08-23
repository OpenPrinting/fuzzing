#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

V3_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$V3_ROOT/../../.." && pwd)"
source "$V3_ROOT/targets.sh"

INSTALL_ROOT="${CF_V3_INSTALL_ROOT:-$ROOT/work/libfuzzer-install}"
SOURCE_ROOT="${CF_V3_SOURCE_ROOT:-$ROOT/work/libfuzzer-src}"
BUILD_ROOT="${CF_V3_STACK_BUILD_ROOT:-$ROOT/work/libfuzzer-builds}"
OUTPUT_ROOT="${CF_V3_OUTPUT_ROOT:-$ROOT/work/libfuzzer-v3/bin}"
TARGET_SET="${1:-all}"

CC="${CC:-clang}"
NM_TOOL="${NM:-nm}"
if [[ "${SANITIZER:-}" == "introspector" ]]; then
  NM_TOOL=llvm-nm
fi
CFLAGS="${CFLAGS:--O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address}"
LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer,address}"

CUPS_PREFIX="$INSTALL_ROOT/cups"
PDFIO_PREFIX="${CF_V3_PDFIO_PREFIX:-$INSTALL_ROOT/pdfio}"
LIBPPD_PREFIX="${CF_V3_LIBPPD_PREFIX:-$INSTALL_ROOT/libppd}"
LIBCUPSFILTERS_PREFIX="${CF_V3_LIBCUPSFILTERS_PREFIX:-$INSTALL_ROOT/libcupsfilters}"
CUPSFILTERS_SOURCE="${CF_V3_CUPSFILTERS_SOURCE:-$SOURCE_ROOT/cups-filters}"
LIBCUPSFILTERS_SOURCE="${CF_V3_LIBCUPSFILTERS_SOURCE:-$SOURCE_ROOT/libcupsfilters}"
LIBPPD_SOURCE="${CF_V3_LIBPPD_SOURCE:-$SOURCE_ROOT/libppd}"
CUPS_SOURCE="${CF_V3_CUPS_SOURCE:-$SOURCE_ROOT/cups}"
CUPS_CONFIG_ROOT="${CF_V3_CUPS_CONFIG_ROOT:-$SOURCE_ROOT/cups}"

export PKG_CONFIG_PATH="$LIBPPD_PREFIX/lib/pkgconfig:$LIBCUPSFILTERS_PREFIX/lib/pkgconfig:$CUPS_PREFIX/lib/pkgconfig:$PDFIO_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

for required in \
  "$LIBPPD_PREFIX/lib/libppd.a" \
  "$LIBCUPSFILTERS_PREFIX/lib/libcupsfilters.a" \
  "$CUPSFILTERS_SOURCE/filter"; do
  if [[ ! -e "$required" ]]; then
    echo "missing build prerequisite: $required" >&2
    echo "build the CUPS, PDFio, libcupsfilters, libppd, and cups-filters stack first" >&2
    exit 2
  fi
done

read -r -a PKG_CFLAGS <<< "$(pkg-config --cflags libcupsfilters libppd pdfio cups)"
read -r -a DEP_LIBS <<< "$(pkg-config --libs --static libcupsfilters pdfio cups)"
read -r -a EXTRA_LIBS <<< "$(pkg-config --libs --static libjpeg libexif libqpdf libtiff-4 libpng fontconfig lcms2)"
read -r -a CUPS_CFLAGS <<< "$(pkg-config --cflags cups)"
read -r -a CUPS_LIBS <<< "$(pkg-config --libs --static cups)"
CUPS_LINK_LIBS=("${CUPS_LIBS[@]}")
if [[ -n "${CF_V3_CUPS_ARCHIVE:-}" ]]; then
  [[ -f "$CF_V3_CUPS_ARCHIVE" ]] || {
    echo "missing CUPS static archive: $CF_V3_CUPS_ARCHIVE" >&2
    exit 2
  }
  CUPS_LINK_LIBS=("$CF_V3_CUPS_ARCHIVE")
  for library in "${CUPS_LIBS[@]}"; do
    [[ "$library" == "-lcups" ]] || CUPS_LINK_LIBS+=("$library")
  done
fi

FILTERED_DEP_LIBS=()
for library in "${DEP_LIBS[@]}"; do
  [[ "$library" == "-lcupsfilters" ]] || FILTERED_DEP_LIBS+=("$library")
done

COMMON_CFLAGS=(
  -I"$V3_ROOT"
  -I"$ROOT/harnesses/libfuzzer/v2/include"
  -I"$BUILD_ROOT/cups-filters"
  -I"$CUPSFILTERS_SOURCE/filter"
  -I"$LIBCUPSFILTERS_SOURCE"
  -I"$LIBCUPSFILTERS_SOURCE/cupsfilters"
  -I"$LIBPPD_SOURCE"
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

# OSS-Fuzz's non-ASan runtimes do not provide LeakSanitizer, while libFuzzer
# and target lifecycle wrappers can still reference its scope hooks. Keep the
# no-op definitions out of ASan builds so real leak detection remains active.
if [[ "${SANITIZER:-address}" != "address" ]]; then
  LSAN_RUNTIME_STUB="$OUTPUT_ROOT/lsan_runtime_stubs.o"
  "$CC" $CFLAGS -c \
    "$ROOT/harnesses/libfuzzer/v2/support/lsan_coverage_stubs.c" \
    -o "$LSAN_RUNTIME_STUB"
  COMMON_LIBS+=("$LSAN_RUNTIME_STUB")
fi

# GNU and LLVM objcopy reject the LTO bitcode produced for Introspector.
# Preserve the same symbol operations at IR level so call graphs stay intact.
if [[ "${SANITIZER:-}" == "introspector" ]]; then
  objcopy() {
    python3 "$V3_ROOT/rename_llvm_symbols.py" "$@"
  }
fi

mapfile -t SELECTED_TARGETS < <(cf_v3_list_targets "$TARGET_SET") || {
  echo "unknown target set: $TARGET_SET" >&2
  exit 2
}
mkdir -p "$OUTPUT_ROOT"

selected() {
  local candidate="$1"
  local target

  for target in "${SELECTED_TARGETS[@]}"; do
    [[ "$candidate" == "$target" ]] && return 0
  done
  return 1
}

namespace_v3_route_object() {
  local prefix="$1" role="$2" object="$3"
  local map="$object.redefine"
  local stem="${prefix}_${role}_"
  local symbol

  : > "$map"
  while read -r symbol; do
    [[ -n "$symbol" ]] || continue
    printf '%s%s %s\n' "$stem" "$symbol" "$symbol" >> "$map"
  done < <("$NM_TOOL" -u "$object" | awk 'NF { print $NF }' | sort -u)
  if "$NM_TOOL" -g --defined-only "$object" | awk 'NF >= 3 { print $3 }' | \
      grep -Fxq LLVMFuzzerTestOneInput; then
    printf '%sLLVMFuzzerTestOneInput %s_entry\n' "$stem" "$prefix" >> "$map"
  fi
  if "$NM_TOOL" -g --defined-only "$object" | awk 'NF >= 3 { print $3 }' | \
      grep -Fxq LLVMFuzzerCustomMutator; then
    printf '%sLLVMFuzzerCustomMutator %s_mutator\n' "$stem" "$prefix" >> "$map"
  fi
  if "$NM_TOOL" -g --defined-only "$object" | awk 'NF >= 3 { print $3 }' | \
      grep -Fxq LLVMFuzzerCustomCrossOver; then
    printf '%sLLVMFuzzerCustomCrossOver %s_crossover\n' "$stem" "$prefix" >> "$map"
  fi
  for symbol in asan.module_ctor asan.module_dtor \
                sancov.module_ctor_8bit_counters; do
    if "$NM_TOOL" -a "$object" | awk 'NF >= 3 { print $3 }' | grep -Fxq "$symbol"; then
      printf '%s%s %s\n' "$stem" "$symbol" "$symbol" >> "$map"
    fi
  done
  if "$NM_TOOL" -g --defined-only "$object" | awk 'NF >= 3 { print $3 }' | \
      grep -Fxq ___asan_globals_registered; then
    printf '%s___asan_globals_registered ___asan_globals_registered\n' \
      "$stem" >> "$map"
  fi
  objcopy --prefix-symbols="$stem" "$object"
  objcopy --redefine-syms="$map" "$object"
  rm -f "$map"
}

banner_target=fuzz_v3_cupsfilters_banner_to_pdf
if selected "$banner_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_banner_to_pdf.c" \
    "$V3_ROOT/implementations/banner_graph_adapter.c" \
    "$V3_ROOT/mutators/banner_route_mutator.c" \
    "${COMMON_LIBS[@]}" -lz \
    -Wl,--wrap=fdopen -Wl,--wrap=fclose \
    -Wl,--wrap=malloc -Wl,--wrap=realloc -Wl,--wrap=free \
    -Wl,--wrap=pdfioFileOpen -Wl,--wrap=pdfioFileClose \
    -Wl,--wrap=pdfioDictCopy \
    -Wl,--wrap=fprintf \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$banner_target"
fi

raw_target=fuzz_v3_cupsfilters_pclm_raw
if selected "$raw_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=cfFilterPCLmToRaster \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pclm_raw"' \
    -DCF_V2_INPUT_MIME='"application/PCLm"' \
    -DCF_V2_OUTPUT_MIME='"application/vnd.cups-raster"' \
    -DCF_V2_OUTPUT_FORMAT=CF_FILTER_OUT_FORMAT_CUPS_RASTER \
    -DCF_V3_JOIN_OPTIONS_CONTINUATION \
    "$V3_ROOT/implementations/fuzz_direct_route.c" \
    "$V3_ROOT/implementations/joined_options_continuation.c" \
    "$V3_ROOT/mutators/raw_control_mutator.c" \
    "${COMMON_LIBS[@]}" \
    -Wl,--wrap=cfJoinJobOptionsAndAttrs -Wl,--wrap=cupsFreeOptions \
    $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$raw_target"
fi

graph_target=fuzz_v3_cupsfilters_pclm_graph
if selected "$graph_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCUPSFILTERS_PCLM_NATIVE_STREAM_LIFECYCLE \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pclm_graph"' \
    "$V3_ROOT/implementations/fuzz_pclm_graph.c" \
    "$V3_ROOT/implementations/pclm_output_adapter.c" \
    "$ROOT/harnesses/libfuzzer/v2/schemas/pclm_graph_relation_schema.c" \
    "$V3_ROOT/mutators/pclm_graph_mutator.c" \
    "${COMMON_LIBS[@]}" -lz \
    -Wl,--wrap=cfJoinJobOptionsAndAttrs -Wl,--wrap=cupsFreeOptions \
    -Wl,--wrap=cfRasterPrepareHeader \
    -Wl,--wrap=pdfioObjOpenStream -Wl,--wrap=pdfioStreamRead \
    $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$graph_target"
fi

build_command_target() {
  local target="$1" source="$2" input_mime="$3" output_mime="$4" framing="$5"
  shift 5

  selected "$target" || return 0
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_LEGACY_SOURCE="\"$source\"" \
    -DCF_V2_TARGET_NAME="\"$target\"" \
    -DCF_V2_INPUT_MIME="\"$input_mime\"" \
    -DCF_V2_OUTPUT_MIME="\"$output_mime\"" \
    -D"$framing" "$@" \
    "$V3_ROOT/implementations/fuzz_command_route.c" \
    "$V3_ROOT/implementations/command_legacy_adapter.c" \
    "$V3_ROOT/implementations/command_oracle_adapter.c" \
    "$V3_ROOT/schemas/command_route_schema.c" \
    "$ROOT/harnesses/libfuzzer/v2/mutators/contract_mutator.c" \
    "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$target"
}

build_command_target fuzz_v3_cupsfilters_command_to_escpx \
  "$CUPSFILTERS_SOURCE/filter/commandtoescpx.c" \
  application/vnd.cups-command application/vnd.epson-escp \
  CUPSFILTERS_COMMAND_FRAMING_ESCPX
build_command_target fuzz_v3_cupsfilters_command_to_pclx \
  "$CUPSFILTERS_SOURCE/filter/commandtopclx.c" \
  application/vnd.cups-command application/vnd.hp-pcl \
  CUPSFILTERS_COMMAND_FRAMING_PCLX -DCF_V2_FORCE_PPD_PROFILE=1

foomatic_target=fuzz_v3_cupsfilters_foomatic_jcl
if selected "$foomatic_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -Dmain=cf_v3_foomatic_main \
    -DCONFIG_PATH='"/tmp/foomatic"' \
    -DSYS_HASH_PATH='"/tmp/foomatic/hashes.d"' \
    -DUSR_HASH_PATH='"/tmp/foomatic-user/hashes.d"' \
    -DCF_V3_FOOMATIC_RENDERER_SOURCE="\"$CUPSFILTERS_SOURCE/filter/foomatic-rip/renderer.c\"" \
    "$V3_ROOT/implementations/fuzz_foomatic_jcl.c" \
    "$V3_ROOT/schemas/foomatic_jcl_schema.c" \
    "$ROOT/harnesses/libfuzzer/v2/mutators/contract_mutator.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/foomaticrip.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/options.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/pdf.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/postscript.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/spooler.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/util.c" \
    "$CUPSFILTERS_SOURCE/filter/foomatic-rip/process.c" \
    "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$foomatic_target"
fi

raster_reader_target=fuzz_v3_cupsfilters_cups_raster_reader
if selected "$raster_reader_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCUPS_RASTER_READER_MAX_INPUT=4194304 \
    "$ROOT/harnesses/libfuzzer/fuzz_cups_raster_reader.c" \
    "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$raster_reader_target"
fi

build_image_decoder() {
  local target="$1" codec="$2"
  shift 2

  selected "$target" || return 0
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -D"CUPSFILTERS_IMAGE_CODEC_$codec" \
    -DCUPSFILTERS_IMAGE_CODEC_MAX_INPUT=2097152 \
    "$ROOT/harnesses/libfuzzer/fuzz_cupsfilters_image_codec.c" \
    "$@" "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$target"
}

build_image_decoder fuzz_v3_cupsfilters_image_jpeg_decoder JPEG \
  -Wl,--wrap=jpeg_std_error
build_image_decoder fuzz_v3_cupsfilters_image_png_decoder PNG
build_image_decoder fuzz_v3_cupsfilters_image_tiff_decoder TIFF \
  -Wl,--wrap=TIFFFdOpen -Wl,--wrap=TIFFReadScanline

image_pdf_target=fuzz_v3_cupsfilters_image_to_pdf
if selected "$image_pdf_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_image_to_pdf.c" \
    "$V3_ROOT/implementations/image_raw_png.c" \
    "$V3_ROOT/implementations/image_pdf_formats.c" \
    "$V3_ROOT/implementations/image_pdf_state.c" \
    "$V3_ROOT/implementations/image_pdf_oracle.c" \
    "${COMMON_LIBS[@]}" -lm \
    -Wl,--wrap=fdopen -Wl,--wrap=fclose \
    -Wl,--wrap=cfImageClose \
    -Wl,--wrap=cfJoinJobOptionsAndAttrs -Wl,--wrap=cupsFreeOptions \
    -Wl,--wrap=TIFFFdOpen \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$image_pdf_target"
fi

image_raster_target=fuzz_v3_cupsfilters_image_to_raster
if selected "$image_raster_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_image_to_raster.c" \
    "$V3_ROOT/implementations/image_raw_png.c" \
    "$V3_ROOT/implementations/image_raster_state.c" \
    "$V3_ROOT/implementations/image_raster_source.c" \
    "$V3_ROOT/implementations/image_raster_oracle.c" \
    "$V3_ROOT/implementations/image_pdf_formats.c" \
    "${COMMON_LIBS[@]}" -lm \
    -Wl,--wrap=fdopen -Wl,--wrap=fclose \
    -Wl,--wrap=cfImageClose \
    -Wl,--wrap=cfJoinJobOptionsAndAttrs -Wl,--wrap=cupsFreeOptions \
    -Wl,--wrap=TIFFFdOpen -Wl,--wrap=cfGenerateSizes \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$image_raster_target"
fi

image_ps_target=fuzz_v3_cupsfilters_image_to_ps
if selected "$image_ps_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_image_to_ps.c" \
    "${COMMON_LIBS[@]}" -lm \
    -Wl,--wrap=fdopen -Wl,--wrap=fclose \
    -Wl,--wrap=cfImageClose \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$image_ps_target"
fi

pdfio_document_target=fuzz_v3_cupsfilters_pdfio_document
if selected "$pdfio_document_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_pdfio_document.c" \
    "$V3_ROOT/implementations/pdfio_structured_adapter.c" \
    "$V3_ROOT/mutators/hybrid_mode_mutator.c" \
    "${COMMON_LIBS[@]}" -lz $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$pdfio_document_target"
fi

pdfio_stream_target=fuzz_v3_cupsfilters_pdfio_stream
if selected "$pdfio_stream_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_pdfio_stream.c" \
    "$V3_ROOT/implementations/pdfio_stream_safe_adapter.c" \
    "$V3_ROOT/implementations/pdfio_stream_faithful_adapter.c" \
    "$V3_ROOT/mutators/continuation_mode_mutator.c" \
    "${COMMON_LIBS[@]}" -lz $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$pdfio_stream_target"
fi

PDF_FILTER_ADAPTER_OBJECT="$BUILD_ROOT/cups-filters-v3-pdf-filter-adapter.o"
LIBCUPSFILTERS_CONFIG_ROOT="$BUILD_ROOT/libcupsfilters"
if [[ ! -f "$LIBCUPSFILTERS_CONFIG_ROOT/config.h" ]]; then
  LIBCUPSFILTERS_CONFIG_ROOT="$LIBCUPSFILTERS_SOURCE"
fi

build_pdf_filter_adapter() {
  "$CC" $CFLAGS -I"$LIBCUPSFILTERS_CONFIG_ROOT" \
    "${COMMON_CFLAGS[@]}" \
    -c "$V3_ROOT/implementations/pdf_filter_adapter.c" \
    -o "$PDF_FILTER_ADAPTER_OBJECT"
}

pdf_raw_target=fuzz_v3_cupsfilters_pdf_to_pdf_raw
if selected "$pdf_raw_target"; then
  pdf_raw_direct_object="$BUILD_ROOT/cups-filters-v3-pdf-raw-direct.o"
  pdf_raw_job_object="$BUILD_ROOT/cups-filters-v3-pdf-raw-job.o"
  pdf_raw_flags=(
    -DCF_V2_FILTER_FUNCTION=cfFilterPDFToPDF
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pdf_to_pdf_raw"'
    -DCF_V2_INPUT_MIME='"application/pdf"'
    -DCF_V2_OUTPUT_MIME='"application/pdf"'
  )

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${pdf_raw_flags[@]}" \
    -DCF_V2_MAX_DOCUMENT=4194304 \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    -o "$pdf_raw_direct_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pdf_raw_direct_legacy \
    "$pdf_raw_direct_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${pdf_raw_flags[@]}" \
    -DCF_V2_JOB_OPTION_MASK=0x8U \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -o "$pdf_raw_job_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pdf_raw_job_legacy \
    "$pdf_raw_job_object"

  build_pdf_filter_adapter
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${pdf_raw_flags[@]}" \
    "$V3_ROOT/implementations/fuzz_pdf_to_pdf_raw.c" \
    "$V3_ROOT/implementations/pdf_raw_route_bridge.c" \
    "$V3_ROOT/implementations/pdf_filter_lifecycle.c" \
    "$V3_ROOT/implementations/text_memfd_runtime.c" \
    "$V3_ROOT/mutators/pdf_raw_route_mutator.c" \
    "$pdf_raw_direct_object" "$pdf_raw_job_object" \
    "$PDF_FILTER_ADAPTER_OBJECT" \
    "${COMMON_LIBS[@]}" \
    -Wl,--wrap=cfFilterOptionsCreate -Wl,--wrap=cfFilterOptionsDelete \
    -Wl,--wrap=fdopen -Wl,--wrap=fclose \
    -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
    -Wl,--wrap=strdup -Wl,--wrap=free \
    -Wl,--wrap=fprintf -Wl,--wrap=fputs \
    -Wl,--wrap=mkstemp -Wl,--wrap=tmpfile -Wl,--wrap=unlink \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$pdf_raw_target"
fi

pdf_graph_target=fuzz_v3_cupsfilters_pdf_to_pdf_graph
if selected "$pdf_graph_target"; then
  pdf_graph_objects=()
  pdf_graph_flags=(
    -DCF_V2_FILTER_FUNCTION=cfFilterPDFToPDF
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pdf_to_pdf_graph"'
    -DCF_V2_INPUT_MIME='"application/pdf"'
    -DCF_V2_OUTPUT_MIME='"application/pdf"'
  )

  build_pdf_graph_object() {
    local name="$1" symbol="$2" source="$3"
    shift 3
    local object="$BUILD_ROOT/cups-filters-v3-pdf-graph-$name.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${pdf_graph_flags[@]}" \
      "$@" -c "$source" -o "$object"
    objcopy \
      --redefine-sym LLVMFuzzerTestOneInput="$symbol" \
      --redefine-sym LLVMFuzzerCustomMutator="${symbol}_private_mutator" \
      --redefine-sym LLVMFuzzerCustomCrossOver="${symbol}_private_crossover" \
      --redefine-sym cf_v2_pdf_unused_direct_entrypoint="${symbol}_unused_state" \
      --redefine-sym cf_v2_pdf_booklet_unused_direct_entrypoint="${symbol}_unused_booklet" \
      --redefine-sym cf_v2_pdf_nup_unused_direct_entrypoint="${symbol}_unused_nup" \
      --redefine-sym cf_v2_pdf_res_unused_direct_entrypoint="${symbol}_unused_resource" \
      --redefine-sym cf_v2_pdf_value_unused_direct_entrypoint="${symbol}_unused_value" \
      --redefine-sym cf_v2_pdf_graph_unused_entrypoint="${symbol}_unused_graph" \
      --redefine-sym __wrap_cfFilterOptionsCreate="${symbol}_private_wrap_options_create" \
      --redefine-sym __wrap_cfFilterOptionsDelete="${symbol}_private_wrap_options_delete" \
      --redefine-sym __wrap_fprintf="${symbol}_private_wrap_fprintf" \
      --redefine-sym __wrap_fputs="${symbol}_private_wrap_fputs" \
      --redefine-sym __wrap_malloc="${symbol}_private_wrap_malloc" \
      --redefine-sym __wrap_calloc="${symbol}_private_wrap_calloc" \
      --redefine-sym __wrap_realloc="${symbol}_private_wrap_realloc" \
      --redefine-sym __wrap_strdup="${symbol}_private_wrap_strdup" \
      --redefine-sym __wrap_free="${symbol}_private_wrap_free" \
      "$object"
    pdf_graph_objects+=("$object")
  }

  direct_source="$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c"
  build_pdf_graph_object annotation-direct \
    cf_v3_pdf_graph_annotation_direct_legacy "$direct_source" \
    -DCF_V2_MAX_DOCUMENT=4194304 -DCF_V2_VALIDATE_PDF_INTERACTIVE
  build_pdf_graph_object booklet-empty-direct \
    cf_v3_pdf_graph_booklet_empty_direct_legacy "$direct_source" \
    -DCF_V2_MAX_DOCUMENT=4194304 -DCF_V2_VALIDATE_PDF_DEPTH \
    -DCF_V2_OPTIONS_PDF_BOOKLET_EMPTY_BOUNDARY
  build_pdf_graph_object layout-direct \
    cf_v3_pdf_graph_layout_direct_legacy "$direct_source" \
    -DCF_V2_MAX_DOCUMENT=4194304 -DCF_V2_VALIDATE_PDF_DEPTH \
    -DCF_V2_OPTIONS_PDF_DEPTH
  build_pdf_graph_object nup-direct \
    cf_v3_pdf_graph_nup_direct_legacy "$direct_source" \
    -DCF_V2_MAX_DOCUMENT=4194304 -DCF_V2_VALIDATE_PDF_DEPTH \
    -DCF_V2_OPTIONS_PDF_NUP_BOUNDARY

  build_pdf_graph_object object-valid cf_v3_pdf_graph_object_valid_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pdf_valid_state.c" \
    -DCF_V2_PDF_OBJECT_VALID
  build_pdf_graph_object page-layout-valid \
    cf_v3_pdf_graph_page_layout_valid_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pdf_valid_state.c" \
    -DCF_V2_PDF_PAGE_LAYOUT_VALID
  build_pdf_graph_object booklet-order cf_v3_pdf_graph_booklet_order_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pdf_booklet_order.c"
  build_pdf_graph_object nup-order cf_v3_pdf_graph_nup_order_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pdf_to_pdf_nup_order.c"

  remap_source="$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pdf_to_pdf_resource_remap.c"
  build_pdf_graph_object resource-remap \
    cf_v3_pdf_graph_resource_remap_legacy "$remap_source" \
    -DCF_V2_PDF_RES_LANE=0
  build_pdf_graph_object resource-continuation \
    cf_v3_pdf_graph_resource_continuation_legacy "$remap_source" \
    -DCF_V2_PDF_RES_LANE=1
  build_pdf_graph_object resource-refill \
    cf_v3_pdf_graph_resource_refill_legacy "$remap_source" \
    -DCF_V2_PDF_RES_MAGIC='"P2PREF01"' -DCF_V2_PDF_RES_LANE=4
  build_pdf_graph_object resource-lexical \
    cf_v3_pdf_graph_resource_lexical_legacy "$remap_source" \
    -DCF_V2_PDF_RES_LANE=2
  build_pdf_graph_object resource-long-name \
    cf_v3_pdf_graph_resource_long_name_legacy "$remap_source" \
    -DCF_V2_PDF_RES_LANE=3

  value_source="$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pdf_to_pdf_resource_value.c"
  build_pdf_graph_object resource-value \
    cf_v3_pdf_graph_resource_value_legacy "$value_source"
  build_pdf_graph_object resource-cross-type \
    cf_v3_pdf_graph_resource_cross_type_legacy "$value_source" \
    -DCF_V2_PDF_VALUE_MAGIC='"P2PXTY01"' \
    -DCF_V2_PDF_VALUE_CROSS_TYPE=1

  graph_relation_source="$ROOT/harnesses/libfuzzer/v2/parsers/pdf-to-pdf/fuzz_pdf_graph_relation.c"
  build_pdf_graph_object ascii85 cf_v3_pdf_graph_ascii85_legacy \
    "$graph_relation_source" -DCF_V2_PDF_GRAPH_LANE=1
  build_pdf_graph_object annotation cf_v3_pdf_graph_annotation_legacy \
    "$graph_relation_source" -DCF_V2_PDF_GRAPH_LANE=2
  build_pdf_graph_object flatten cf_v3_pdf_graph_flatten_legacy \
    "$graph_relation_source" -DCF_V2_PDF_GRAPH_LANE=3
  build_pdf_graph_object output-capacity \
    cf_v3_pdf_graph_output_capacity_legacy "$graph_relation_source" \
    -DCF_V2_PDF_GRAPH_LANE=4
  build_pdf_graph_object parent cf_v3_pdf_graph_parent_legacy \
    "$graph_relation_source" -DCF_V2_PDF_GRAPH_LANE=5

  build_pdf_filter_adapter
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${pdf_graph_flags[@]}" \
    "$V3_ROOT/implementations/fuzz_pdf_to_pdf_graph.c" \
    "$V3_ROOT/implementations/pdf_graph_route_bridge.c" \
    "$V3_ROOT/implementations/pdf_filter_lifecycle.c" \
    "$V3_ROOT/implementations/text_memfd_runtime.c" \
    "$V3_ROOT/mutators/pdf_graph_route_mutator.c" \
    "${pdf_graph_objects[@]}" "$PDF_FILTER_ADAPTER_OBJECT" \
    "${COMMON_LIBS[@]}" -lz \
    -Wl,--wrap=cfFilterOptionsCreate -Wl,--wrap=cfFilterOptionsDelete \
    -Wl,--wrap=fdopen -Wl,--wrap=fclose \
    -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
    -Wl,--wrap=strdup -Wl,--wrap=free \
    -Wl,--wrap=fprintf -Wl,--wrap=fputs \
    -Wl,--wrap=mkstemp -Wl,--wrap=tmpfile -Wl,--wrap=unlink \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$pdf_graph_target"
fi

ppd_loader_target=fuzz_v3_cupsfilters_ppd_loader
if selected "$ppd_loader_target"; then
  ppd_loader_cflags=()
  if [[ "${CF_V3_PPD_LOADER_FAITHFUL:-0}" == 1 ]]; then
    ppd_loader_cflags+=( -DCF_V3_PPD_LOADER_FAITHFUL )
  fi
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "${ppd_loader_cflags[@]}" \
    "$V3_ROOT/implementations/fuzz_ppd_loader.c" \
    "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$ppd_loader_target"
  if [[ "${CF_V3_BUILD_PPD_DIAGNOSTIC:-0}" == 1 ]]; then
    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      "$V3_ROOT/diagnostics/fuzz_ppd_open_close.c" \
      "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
      -o "$OUTPUT_ROOT/fuzz_v3_diagnostic_ppd_open_close"
  fi
fi

ppd_semantic_target=fuzz_v3_cupsfilters_ppd_semantic
if selected "$ppd_semantic_target"; then
  ppd_semantic_state_object="$BUILD_ROOT/cups-filters-v3-ppd-semantic-state.o"
  ppd_contract_state_object="$BUILD_ROOT/cups-filters-v3-ppd-contract-state.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" -c \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_ppd_semantic_state.c" \
    -o "$ppd_semantic_state_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_ppd_semantic_state_legacy \
    "$ppd_semantic_state_object"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" -c \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_ppd_contract_state.c" \
    -o "$ppd_contract_state_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_ppd_contract_state_legacy \
    "$ppd_contract_state_object"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_ppd_semantic.c" \
    "$V3_ROOT/implementations/ppd_semantic_bridge.c" \
    "$ROOT/harnesses/libfuzzer/v2/schemas/ppd_graph_relation_schema.c" \
    "$V3_ROOT/mutators/ppd_semantic_graph_mutator.c" \
    "$ppd_semantic_state_object" "$ppd_contract_state_object" \
    "${COMMON_LIBS[@]}" -Wl,--wrap=LLVMFuzzerTestOneInput \
    $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$ppd_semantic_target"
fi

ppd_cache_target=fuzz_v3_cupsfilters_ppd_cache_ipp
if selected "$ppd_cache_target"; then
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_STATE_PREFIX_SIZE=8 \
    -DCF_V2_STATE_SELECTOR_SIZE=16 \
    -DCF_V2_STATE_MIN_PAYLOAD=1 \
    "$V3_ROOT/implementations/fuzz_ppd_cache_ipp.c" \
    "$ROOT/harnesses/libfuzzer/v2/mutators/compact_state_mutator.c" \
    "${COMMON_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$ppd_cache_target"
fi

ppd_profile_target=fuzz_v3_cupsfilters_ppd_profile
if selected "$ppd_profile_target"; then
  ppd_profile_state_object="$BUILD_ROOT/cups-filters-v3-ppd-profile-state.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" -c \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_ppd_profile_state.c" \
    -o "$ppd_profile_state_object"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_ppd_profile.c" \
    "$V3_ROOT/implementations/ppd_profile_deep_adapter.c" \
    "$V3_ROOT/implementations/ppd_profile_faithful_adapter.c" \
    "$V3_ROOT/mutators/ppd_profile_mode_mutator.c" \
    "$ppd_profile_state_object" \
    "${COMMON_LIBS[@]}" -Wl,--wrap=LLVMFuzzerTestOneInput \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$ppd_profile_target"
fi

pwg_pdf_target=fuzz_v3_cupsfilters_pwg_to_pdf
if selected "$pwg_pdf_target"; then
  pwg_direct_pdf_object="$BUILD_ROOT/cups-filters-v3-pwg-direct-pdf.o"
  pwg_direct_pclm_object="$BUILD_ROOT/cups-filters-v3-pwg-direct-pclm.o"
  pwg_job_pdf_object="$BUILD_ROOT/cups-filters-v3-pwg-job-pdf.o"
  pwg_job_pclm_object="$BUILD_ROOT/cups-filters-v3-pwg-job-pclm.o"
  pwg_page_object="$BUILD_ROOT/cups-filters-v3-pwg-page-writer.o"
  pwg_strip_object="$BUILD_ROOT/cups-filters-v3-pwg-strip-partition.o"
  pwg_flate_object="$BUILD_ROOT/cups-filters-v3-pwg-flate-object.o"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -include "$V3_ROOT/implementations/pwg_filter_adapter.h" \
    -DCF_V2_FILTER_FUNCTION=cf_v3_pwg_filter \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_pdf"' \
    -DCF_V2_INPUT_MIME='"image/pwg-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/pdf"' \
    -DCF_V2_VALIDATE_RASTER -DCF_V2_RASTER_PDF_COLORSPACE \
    -DCF_V2_OUTPUT_FORMAT=CF_FILTER_OUT_FORMAT_PDF \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    -o "$pwg_direct_pdf_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_direct_pdf_legacy \
    "$pwg_direct_pdf_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -include "$V3_ROOT/implementations/pwg_filter_adapter.h" \
    -DCF_V2_FILTER_FUNCTION=cf_v3_pwg_filter \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_pdf"' \
    -DCF_V2_INPUT_MIME='"image/pwg-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/PCLm"' \
    -DCF_V2_VALIDATE_RASTER -DCF_V2_RASTER_PDF_COLORSPACE \
    -DCF_V2_OUTPUT_FORMAT=CF_FILTER_OUT_FORMAT_PCLM \
    -DCF_V2_NEEDS_PCLM_ATTRS \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    -o "$pwg_direct_pclm_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_direct_pclm_legacy \
    "$pwg_direct_pclm_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -include "$V3_ROOT/implementations/pwg_filter_adapter.h" \
    -DCF_V2_FILTER_FUNCTION=cf_v3_pwg_filter \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_pdf"' \
    -DCF_V2_INPUT_MIME='"image/pwg-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/pdf"' \
    -DCF_V2_OUTPUT_FORMAT=CF_FILTER_OUT_FORMAT_PDF \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -o "$pwg_job_pdf_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_pwg_job_pdf_legacy \
    "$pwg_job_pdf_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -include "$V3_ROOT/implementations/pwg_filter_adapter.h" \
    -DCF_V2_FILTER_FUNCTION=cf_v3_pwg_filter \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_pdf"' \
    -DCF_V2_INPUT_MIME='"image/pwg-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/PCLm"' \
    -DCF_V2_OUTPUT_FORMAT=CF_FILTER_OUT_FORMAT_PCLM \
    -DCF_V2_NEEDS_PCLM_ATTRS \
    -DCF_V2_POST_PPD_LOAD_HOOK=cf_v3_pwg_post_ppd_load \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -o "$pwg_job_pclm_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_pwg_job_pclm_legacy \
    "$pwg_job_pclm_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_PWG_TO_PDF_SOURCE="\"$LIBCUPSFILTERS_SOURCE/cupsfilters/pwgtopdf.c\"" \
    -DCF_V2_OPTIONS_CM_CALIBRATION \
    -c "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pwg_to_pdf_page_state.c" \
    -o "$pwg_page_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_pwg_page_writer_legacy \
    "$pwg_page_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_PWG_TO_PDF_SOURCE="\"$LIBCUPSFILTERS_SOURCE/cupsfilters/pwgtopdf.c\"" \
    -c "$ROOT/harnesses/libfuzzer/v2/states/fuzz_pwg_to_pclm_strip_state.c" \
    -o "$pwg_strip_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_strip_partition_legacy \
    "$pwg_strip_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_PWG_TO_PDF_SOURCE="\"$LIBCUPSFILTERS_SOURCE/cupsfilters/pwgtopdf.c\"" \
    -c "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_pwg_to_pclm_flate_object_oracle.c" \
    -o "$pwg_flate_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_flate_object_legacy \
    "$pwg_flate_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V3_PWG_TO_PDF_SOURCE="\"$LIBCUPSFILTERS_SOURCE/cupsfilters/pwgtopdf.c\"" \
    "$V3_ROOT/implementations/fuzz_pwg_to_pdf.c" \
    "$V3_ROOT/implementations/pwg_route_bridge.c" \
    "$V3_ROOT/implementations/pwg_filter_adapter.c" \
    "$V3_ROOT/mutators/pwg_route_mutator.c" \
    "$pwg_direct_pdf_object" "$pwg_direct_pclm_object" \
    "$pwg_job_pdf_object" "$pwg_job_pclm_object" \
    "$pwg_page_object" "$pwg_strip_object" "$pwg_flate_object" \
    "${COMMON_LIBS[@]}" -lz $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$pwg_pdf_target"
fi

pwg_raster_target=fuzz_v3_cupsfilters_pwg_to_raster
if selected "$pwg_raster_target"; then
  pwg_raster_direct_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-direct.o"
  pwg_raster_job_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-job.o"
  pwg_raster_scale_up_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-scale-up.o"
  pwg_raster_scale_down_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-scale-down.o"
  pwg_raster_relation_h_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-relation-h.o"
  pwg_raster_relation_v_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-relation-v.o"
  pwg_raster_relation_p_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-relation-p.o"
  pwg_raster_relation_mutator_object="$BUILD_ROOT/cups-filters-v3-pwg-raster-relation-mutator.o"
  pwg_raster_arithmetic_objects=()

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=cfFilterPWGToRaster \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_raster"' \
    -DCF_V2_INPUT_MIME='"image/pwg-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/vnd.cups-raster"' \
    -DCF_V2_VALIDATE_RASTER \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    -o "$pwg_raster_direct_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_raster_direct_legacy \
    "$pwg_raster_direct_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=cfFilterPWGToRaster \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_raster"' \
    -DCF_V2_INPUT_MIME='"image/pwg-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/vnd.cups-raster"' \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -o "$pwg_raster_job_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_raster_job_legacy \
    "$pwg_raster_job_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_PWG_SCALE_UP \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_pwg_scale_state.c" \
    -o "$pwg_raster_scale_up_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_raster_scale_up_legacy \
    "$pwg_raster_scale_up_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_PWG_SCALE_DOWN \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_pwg_scale_state.c" \
    -o "$pwg_raster_scale_down_object"
  objcopy --redefine-sym \
    LLVMFuzzerTestOneInput=cf_v3_pwg_raster_scale_down_legacy \
    "$pwg_raster_scale_down_object"

  build_pwg_raster_relation_object() {
    local object="$1" lane="$2" symbol="$3"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      -DCF_V2_PWG_RELATION_PROGRAM -DCF_V2_PWG_RELATION_LANE="$lane" \
      -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_pwg_scale_state.c" \
      -o "$object"
    objcopy --redefine-sym LLVMFuzzerTestOneInput="$symbol" "$object"
  }
  build_pwg_raster_relation_object "$pwg_raster_relation_h_object" 1 \
    cf_v3_pwg_raster_relation_h_legacy
  build_pwg_raster_relation_object "$pwg_raster_relation_v_object" 2 \
    cf_v3_pwg_raster_relation_v_legacy
  build_pwg_raster_relation_object "$pwg_raster_relation_p_object" 3 \
    cf_v3_pwg_raster_relation_p_legacy

  build_pwg_raster_arithmetic_object() {
    local suffix="$1" projection="$2" depth="$3"
    local prefix="cf_v3_pwg_raster_arith_${suffix}"
    local object="$BUILD_ROOT/cups-filters-v3-pwg-raster-arith-${suffix}.o"
    local flags=(-D"$projection" \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_pwg_to_raster"')

    [[ "$depth" == 1 ]] && flags+=(-DCF_V2_ARITHMETIC_DEEP)
    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${flags[@]}" \
      -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_arithmetic_geometry.c" \
      -o "$object"
    # Bind each legacy object's calls to its own ownership wrappers first,
    # then namespace those wrappers so six independently tracked routes can
    # coexist in one libFuzzer process.
    objcopy \
      --redefine-sym __real_cfJoinJobOptionsAndAttrs=cfJoinJobOptionsAndAttrs \
      --redefine-sym cfJoinJobOptionsAndAttrs=__wrap_cfJoinJobOptionsAndAttrs \
      --redefine-sym __real_cupsFreeOptions=cupsFreeOptions \
      --redefine-sym cupsFreeOptions=__wrap_cupsFreeOptions \
      --redefine-sym __real_cupsRasterWriteHeader2=cupsRasterWriteHeader2 \
      --redefine-sym cupsRasterWriteHeader2=__wrap_cupsRasterWriteHeader2 \
      "$object"
    objcopy \
      --redefine-sym LLVMFuzzerTestOneInput="${prefix}_legacy" \
      --redefine-sym __wrap_cfJoinJobOptionsAndAttrs="${prefix}_join" \
      --redefine-sym __wrap_cupsFreeOptions="${prefix}_free_options" \
      --redefine-sym __wrap_cupsRasterWriteHeader2="${prefix}_write_header" \
      "$object"
    pwg_raster_arithmetic_objects+=("$object")
  }
  build_pwg_raster_arithmetic_object h_boundary \
    CF_V2_ARITHMETIC_PWG_HORIZONTAL 0
  build_pwg_raster_arithmetic_object h_deep \
    CF_V2_ARITHMETIC_PWG_HORIZONTAL 1
  build_pwg_raster_arithmetic_object v_boundary \
    CF_V2_ARITHMETIC_PWG_VERTICAL 0
  build_pwg_raster_arithmetic_object v_deep \
    CF_V2_ARITHMETIC_PWG_VERTICAL 1
  build_pwg_raster_arithmetic_object p_boundary \
    CF_V2_ARITHMETIC_PWG_PLANAR 0
  build_pwg_raster_arithmetic_object p_deep \
    CF_V2_ARITHMETIC_PWG_PLANAR 1

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DLLVMFuzzerCustomMutator=cf_v3_pwg_raster_relation_mutator \
    -DLLVMFuzzerCustomCrossOver=cf_v3_pwg_raster_relation_crossover \
    -c "$ROOT/harnesses/libfuzzer/v2/mutators/relation_program_mutator.c" \
    -o "$pwg_raster_relation_mutator_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_pwg_to_raster.c" \
    "$V3_ROOT/implementations/pwg_raster_bridge.c" \
    "$V3_ROOT/implementations/pwg_raster_lcms_adapter.c" \
    "$V3_ROOT/mutators/pwg_raster_route_mutator.c" \
    "$ROOT/harnesses/libfuzzer/v2/schemas/arithmetic_layout_schema.c" \
    "$pwg_raster_relation_mutator_object" \
    "$pwg_raster_direct_object" "$pwg_raster_job_object" \
    "$pwg_raster_scale_up_object" "$pwg_raster_scale_down_object" \
    "$pwg_raster_relation_h_object" "$pwg_raster_relation_v_object" \
    "$pwg_raster_relation_p_object" \
    "${pwg_raster_arithmetic_objects[@]}" \
    "${COMMON_LIBS[@]}" -lm \
    -Wl,--wrap=cmsBuildGamma -Wl,--wrap=cmsFreeToneCurve \
    $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$pwg_raster_target"
fi

raster_pwg_target=fuzz_v3_cupsfilters_raster_to_pwg
if selected "$raster_pwg_target"; then
  raster_pwg_objects=()

  build_raster_pwg_direct_object() {
    local suffix="$1" output_mime="$2"
    local object="$BUILD_ROOT/cups-filters-v3-raster-pwg-direct-${suffix}.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      -DCF_V2_FILTER_FUNCTION=cfFilterRasterToPWG \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_pwg"' \
      -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
      -DCF_V2_OUTPUT_MIME="\"$output_mime\"" \
      -DCF_V2_VALIDATE_RASTER \
      -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
      -o "$object"
    objcopy --redefine-sym \
      LLVMFuzzerTestOneInput="cf_v3_raster_pwg_direct_${suffix}_legacy" \
      "$object"
    raster_pwg_objects+=("$object")
  }
  build_raster_pwg_direct_object pwg image/pwg-raster
  build_raster_pwg_direct_object apple image/urf
  build_raster_pwg_direct_object pclm application/PCLm

  build_raster_pwg_state_object() {
    local suffix="$1" output_mime="$2"
    local object="$BUILD_ROOT/cups-filters-v3-raster-pwg-state-${suffix}.o"
    local filter_function=cfFilterRasterToPWG
    local flags=()

    if [[ "$suffix" == pclm ]]; then
      filter_function=cf_v2_filter_raster_to_pclm
      flags+=(
        -DCF_V2_RASTER_OUTPUT_PCLM_CHAIN
        -DCF_V2_NEEDS_PCLM_ATTRS
        -DcfFilterPWGToPDF=cf_v3_pwg_filter
        -include "$V3_ROOT/implementations/pwg_filter_adapter.h"
      )
    fi
    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${flags[@]}" \
      -DCF_V2_FILTER_FUNCTION="$filter_function" \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_pwg"' \
      -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
      -DCF_V2_OUTPUT_MIME="\"$output_mime\"" \
      -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_raster_output_state.c" \
      -o "$object"
    objcopy --redefine-sym \
      LLVMFuzzerTestOneInput="cf_v3_raster_pwg_state_${suffix}_legacy" \
      "$object"
    raster_pwg_objects+=("$object")
  }
  build_raster_pwg_state_object pwg image/pwg-raster
  build_raster_pwg_state_object apple image/urf
  build_raster_pwg_state_object pclm application/PCLm

  build_raster_pwg_output_oracle_object() {
    local suffix="$1" output_mime="$2"
    local object="$BUILD_ROOT/cups-filters-v3-raster-pwg-oracle-${suffix}.o"
    local flags=()

    [[ "$suffix" == apple ]] && flags+=( -DCF_V2_RPWG_APPLE )
    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "${flags[@]}" \
      -DCF_V2_FILTER_FUNCTION=cfFilterRasterToPWG \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_pwg"' \
      -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
      -DCF_V2_OUTPUT_MIME="\"$output_mime\"" \
      -c "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_raster_to_pwg_output_oracle.c" \
      -o "$object"
    objcopy --redefine-sym \
      LLVMFuzzerTestOneInput="cf_v3_raster_pwg_oracle_${suffix}_legacy" \
      "$object"
    raster_pwg_objects+=("$object")
  }
  build_raster_pwg_output_oracle_object pwg image/pwg-raster
  build_raster_pwg_output_oracle_object apple image/urf

  build_raster_pwg_backside_object() {
    local suffix="$1" output_mime="$2"
    shift 2
    local object="$BUILD_ROOT/cups-filters-v3-raster-pwg-backside-${suffix}.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "$@" \
      -DCF_V2_FILTER_FUNCTION=cfFilterRasterToPWG \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_pwg"' \
      -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
      -DCF_V2_OUTPUT_MIME="\"$output_mime\"" \
      -c "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_raster_to_pwg_backside.c" \
      -o "$object"
    objcopy \
      --redefine-sym LLVMFuzzerTestOneInput="cf_v3_raster_pwg_backside_${suffix}_legacy" \
      --redefine-sym __wrap_cupsRasterWriteHeader2="cf_v3_raster_pwg_backside_${suffix}_write_header" \
      "$object"
    raster_pwg_objects+=("$object")
  }
  build_raster_pwg_backside_object pwg image/pwg-raster
  build_raster_pwg_backside_object apple image/urf -DCF_V2_BACKSIDE_APPLE
  build_raster_pwg_backside_object native image/pwg-raster \
    -DCF_V2_BACKSIDE_NATIVE_BOUNDARY
  build_raster_pwg_backside_object manual image/urf \
    -DCF_V2_BACKSIDE_APPLE -DCF_V2_BACKSIDE_MANUAL_BOUNDARY

  raster_pwg_metadata_object="$BUILD_ROOT/cups-filters-v3-raster-pwg-metadata.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -c "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_raster_to_pwg_metadata_oracle.c" \
    -o "$raster_pwg_metadata_object"
  objcopy \
    --redefine-sym LLVMFuzzerTestOneInput=cf_v3_raster_pwg_metadata_legacy \
    --redefine-sym LLVMFuzzerCustomMutator=cf_v3_raster_pwg_metadata_mutator \
    --redefine-sym __wrap_cupsRasterWriteHeader2=cf_v3_raster_pwg_metadata_write_header \
    "$raster_pwg_metadata_object"
  raster_pwg_objects+=("$raster_pwg_metadata_object")

  raster_pwg_name_object="$BUILD_ROOT/cups-filters-v3-raster-pwg-name.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -c "$ROOT/harnesses/libfuzzer/v2/boundaries/fuzz_raster_to_pwg_unsupported_page_size_name.c" \
    -o "$raster_pwg_name_object"
  objcopy \
    --redefine-sym LLVMFuzzerTestOneInput=cf_v3_raster_pwg_name_legacy \
    --redefine-sym LLVMFuzzerCustomMutator=cf_v3_raster_pwg_name_mutator \
    --redefine-sym __wrap_cupsRasterWriteHeader2=cf_v3_raster_pwg_name_write_header \
    "$raster_pwg_name_object"
  raster_pwg_objects+=("$raster_pwg_name_object")

  raster_pwg_relation_mutator_object="$BUILD_ROOT/cups-filters-v3-raster-pwg-relation-mutator.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DLLVMFuzzerCustomMutator=cf_v3_raster_pwg_relation_mutator \
    -DLLVMFuzzerCustomCrossOver=cf_v3_raster_pwg_relation_crossover \
    -c "$ROOT/harnesses/libfuzzer/v2/mutators/relation_program_mutator.c" \
    -o "$raster_pwg_relation_mutator_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V3_PWG_TO_PDF_SOURCE="\"$LIBCUPSFILTERS_SOURCE/cupsfilters/pwgtopdf.c\"" \
    "$V3_ROOT/implementations/fuzz_raster_to_pwg.c" \
    "$V3_ROOT/implementations/raster_pwg_bridge.c" \
    "$V3_ROOT/implementations/raster_pwg_packed_oracle.c" \
    "$V3_ROOT/implementations/raster_pwg_wrapper_bridge.c" \
    "$V3_ROOT/implementations/pwg_filter_adapter.c" \
    "$V3_ROOT/mutators/raster_pwg_route_mutator.c" \
    "$ROOT/harnesses/libfuzzer/v2/schemas/arithmetic_layout_schema.c" \
    "$raster_pwg_relation_mutator_object" \
    "${raster_pwg_objects[@]}" \
    "${COMMON_LIBS[@]}" -lz \
    -Wl,--wrap=cupsRasterWriteHeader2 \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$raster_pwg_target"
fi

ps_target=fuzz_v3_cupsfilters_ps_to_ps
if selected "$ps_target"; then
  ps_job_object="$BUILD_ROOT/cups-filters-v3-ps-job.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=ppdFilterPSToPS \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_ps_to_ps"' \
    -DCF_V2_INPUT_MIME='"application/postscript"' \
    -DCF_V2_OUTPUT_MIME='"application/postscript"' \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -o "$ps_job_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_ps_job_legacy \
    "$ps_job_object"

  ps_raw_object="$BUILD_ROOT/cups-filters-v3-ps-raw.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=ppdFilterPSToPS \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_ps_to_ps"' \
    -DCF_V2_INPUT_MIME='"application/postscript"' \
    -DCF_V2_OUTPUT_MIME='"application/postscript"' \
    -DCF_V2_MAX_DOCUMENT=4194304 \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    -o "$ps_raw_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_ps_raw_legacy \
    "$ps_raw_object"

  ps_dsc_object="$BUILD_ROOT/cups-filters-v3-ps-dsc.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=ppdFilterPSToPS \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_ps_to_ps"' \
    -DCF_V2_INPUT_MIME='"application/postscript"' \
    -DCF_V2_OUTPUT_MIME='"application/postscript"' \
    -DCF_V2_PS_DSC_STATE_OPTIONS \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_ps_dsc_state.c" \
    -o "$ps_dsc_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_ps_dsc_legacy \
    "$ps_dsc_object"

  ps_page_object="$BUILD_ROOT/cups-filters-v3-ps-page-eof.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=ppdFilterPSToPS \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_ps_to_ps"' \
    -DCF_V2_INPUT_MIME='"application/postscript"' \
    -DCF_V2_OUTPUT_MIME='"application/postscript"' \
    -c "$ROOT/harnesses/libfuzzer/v2/boundaries/fuzz_ps_page_range_eof.c" \
    -o "$ps_page_object"
  objcopy \
    --redefine-sym LLVMFuzzerTestOneInput=cf_v3_ps_page_legacy \
    --redefine-sym cf_v2_ps_page_range_unused_entrypoint=cf_v3_ps_page_unused \
    --redefine-sym __wrap_fork=cf_v3_ps_page_wrap_fork \
    --redefine-sym __wrap_exit=cf_v3_ps_page_wrap_exit \
    "$ps_page_object"

  build_ps_sequence_object() {
    local suffix="$1" symbol="$2"
    shift 2
    local object="$BUILD_ROOT/cups-filters-v3-ps-sequence-${suffix}.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      -DCF_V2_FILTER_FUNCTION=ppdFilterPSToPS \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_ps_to_ps"' \
      -DCF_V2_INPUT_MIME='"application/postscript"' \
      -DCF_V2_OUTPUT_MIME='"application/postscript"' "$@" \
      -c "$ROOT/harnesses/libfuzzer/v2/boundaries/fuzz_ps_sequence_relation.c" \
      -o "$object"
    objcopy \
      --redefine-sym LLVMFuzzerTestOneInput="$symbol" \
      --redefine-sym cf_v2_ps_sequence_unused_entrypoint="${symbol}_unused" \
      --redefine-sym __wrap_fork="${symbol}_wrap_fork" \
      --redefine-sym __wrap_exit="${symbol}_wrap_exit" \
      "$object"
  }
  build_ps_sequence_object exact cf_v3_ps_sequence_legacy
  build_ps_sequence_object deep cf_v3_ps_sequence_deep_legacy \
    -DCF_V2_PS_SEQUENCE_DEEP
  ps_sequence_object="$BUILD_ROOT/cups-filters-v3-ps-sequence-exact.o"
  ps_sequence_deep_object="$BUILD_ROOT/cups-filters-v3-ps-sequence-deep.o"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_ps_to_ps.c" \
    "$V3_ROOT/implementations/ps_route_bridge.c" \
    "$V3_ROOT/implementations/ps_wrapper_bridge.c" \
    "$V3_ROOT/implementations/ps_memfd_runtime.c" \
    "$V3_ROOT/mutators/ps_route_mutator.c" \
    "$ps_job_object" "$ps_raw_object" "$ps_dsc_object" \
    "$ps_page_object" "$ps_sequence_object" "$ps_sequence_deep_object" \
    "${COMMON_LIBS[@]}" \
    -Wl,--wrap=fork -Wl,--wrap=exit \
    -Wl,--wrap=cupsGetOption \
    -Wl,--wrap=mkstemp -Wl,--wrap=tmpfile -Wl,--wrap=unlink \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$ps_target"
fi

raster_ps_target=fuzz_v3_cupsfilters_raster_to_ps
if selected "$raster_ps_target"; then
  raster_ps_frontier_object="$BUILD_ROOT/cups-filters-v3-raster-ps-frontier.o"
  raster_ps_validated_object="$BUILD_ROOT/cups-filters-v3-raster-ps-validated.o"
  raster_ps_job_object="$BUILD_ROOT/cups-filters-v3-raster-ps-job.o"
  raster_ps_state_object="$BUILD_ROOT/cups-filters-v3-raster-ps-state.o"
  raster_ps_lifecycle_object="$BUILD_ROOT/cups-filters-v3-raster-ps-lifecycle.o"
  raster_ps_write_object="$BUILD_ROOT/cups-filters-v3-raster-ps-write.o"

  build_raster_ps_direct_object() {
    local object="$1" symbol="$2"
    shift 2

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "$@" \
      -DCF_V2_FILTER_FUNCTION=ppdFilterRasterToPS \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_ps"' \
      -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
      -DCF_V2_OUTPUT_MIME='"application/postscript"' \
      -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
      -o "$object"
    objcopy --redefine-sym LLVMFuzzerTestOneInput="$symbol" "$object"
  }
  build_raster_ps_direct_object "$raster_ps_frontier_object" \
    cf_v3_raster_ps_frontier_legacy
  build_raster_ps_direct_object "$raster_ps_validated_object" \
    cf_v3_raster_ps_validated_legacy -DCF_V2_VALIDATE_RASTER

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=ppdFilterRasterToPS \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_ps"' \
    -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/postscript"' \
    -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -o "$raster_ps_job_object"
  objcopy --redefine-sym LLVMFuzzerTestOneInput=cf_v3_raster_ps_job_legacy \
    "$raster_ps_job_object"

  build_raster_ps_state_object() {
    local object="$1" symbol="$2"
    shift 2

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" "$@" \
      -DCF_V2_RASTER_OUTPUT_PS \
      -DCF_V2_FILTER_FUNCTION=ppdFilterRasterToPS \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_ps"' \
      -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
      -DCF_V2_OUTPUT_MIME='"application/postscript"' \
      -c "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_raster_output_state.c" \
      -o "$object"
    objcopy --redefine-sym LLVMFuzzerTestOneInput="$symbol" "$object"
  }
  build_raster_ps_state_object "$raster_ps_state_object" \
    cf_v3_raster_ps_state_legacy
  build_raster_ps_state_object "$raster_ps_lifecycle_object" \
    cf_v3_raster_ps_lifecycle_legacy \
    -DCF_V2_RASTER_OUTPUT_PS_LIFECYCLE -DCF_V2_DIRECT_FAULT_INJECTION
  build_raster_ps_state_object "$raster_ps_write_object" \
    cf_v3_raster_ps_write_legacy \
    -DCF_V2_RASTER_OUTPUT_PS_WRITE_ERROR_BOUNDARY \
    -DCF_V2_DIRECT_FAULT_INJECTION

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_FILTER_FUNCTION=ppdFilterRasterToPS \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_ps"' \
    -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"' \
    -DCF_V2_OUTPUT_MIME='"application/postscript"' \
    "$V3_ROOT/implementations/fuzz_raster_to_ps.c" \
    "$V3_ROOT/implementations/raster_ps_bridge.c" \
    "$V3_ROOT/implementations/raster_ps_oracle.c" \
    "$V3_ROOT/mutators/raster_ps_route_mutator.c" \
    "$raster_ps_frontier_object" "$raster_ps_validated_object" \
    "$raster_ps_job_object" "$raster_ps_state_object" \
    "$raster_ps_lifecycle_object" "$raster_ps_write_object" \
    "${COMMON_LIBS[@]}" -lz $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$raster_ps_target"
fi

text_target=fuzz_v3_cupsfilters_text_to_text
if selected "$text_target"; then
  text_objects=()
  text_common_flags=(
    -DCF_V2_FILTER_FUNCTION=cfFilterTextToText
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_text_to_text"'
    -DCF_V2_INPUT_MIME='"text/plain"'
    -DCF_V2_OUTPUT_MIME='"text/plain"'
  )

  build_text_object() {
    local name="$1" symbol="$2" source="$3"
    shift 3
    local object="$BUILD_ROOT/cups-filters-v3-text-$name.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      "${text_common_flags[@]}" "$@" -c "$source" -o "$object"
    objcopy --redefine-sym LLVMFuzzerTestOneInput="$symbol" "$object"
    text_objects+=("$object")
  }

  build_text_object job cf_v3_text_job_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    -DCF_V2_JOB_OPTION_MASK=0x780U
  build_text_object raw cf_v3_text_raw_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c"
  build_text_object layout cf_v3_text_layout_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_state.c" \
    -DCF_V2_TEXTTOTEXT_STATE_OPTIONS
  build_text_object determinism cf_v3_text_determinism_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_direct_determinism.c"
  build_text_object selection cf_v3_text_selection_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_text_page_order.c" \
    -DCF_V2_TEXTTOTEXT_STATE_OPTIONS
  build_text_object encoding cf_v3_text_encoding_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_encoding_oracle.c"
  build_text_object tail cf_v3_text_tail_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_encoding_tail.c"
  build_text_object illegal cf_v3_text_illegal_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_illegal_utf8.c"
  build_text_object line cf_v3_text_line_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_line_layout_oracle.c"
  build_text_object line-continuation cf_v3_text_line_continuation_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_line_layout_oracle.c" \
    -DCF_V2_TEXT_LINE_CONTINUATION
  build_text_object page-content cf_v3_text_page_content_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_text_page_content_order.c"
  build_text_object page-array cf_v3_text_page_array_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_text_page_order.c" \
    -DCF_V2_TEXTTOTEXT_STATE_OPTIONS \
    -DCF_V2_TEXTTOTEXT_PAGE_ARRAY_BOUNDARY
  build_text_object shared-contract cf_v3_text_shared_contract_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_to_text_state.c" \
    -DCF_V2_TEXTTOTEXT_STATE_OPTIONS -DCF_V2_TEXT_SHARED_CONTRACT
  build_text_object boundary-contract cf_v3_text_boundary_contract_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_job_contract.c" \
    -DCF_V2_TEXT_JOB_ROUTE_TEXT
  build_text_object deep-contract cf_v3_text_deep_contract_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_job_contract.c" \
    -DCF_V2_TEXT_JOB_ROUTE_TEXT -DCF_V2_TEXT_JOB_DEEP

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "${text_common_flags[@]}" \
    "$V3_ROOT/implementations/fuzz_text_to_text.c" \
    "$V3_ROOT/implementations/text_route_bridge.c" \
    "$V3_ROOT/implementations/text_memfd_runtime.c" \
    "$V3_ROOT/mutators/text_route_mutator.c" \
    "${text_objects[@]}" "${COMMON_LIBS[@]}" \
    -Wl,--wrap=mkstemp -Wl,--wrap=tmpfile -Wl,--wrap=unlink \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$text_target"
fi

text_pdf_target=fuzz_v3_cupsfilters_text_to_pdf
if selected "$text_pdf_target"; then
  text_pdf_objects=()
  text_pdf_common_flags=(
    -DCF_V2_FILTER_FUNCTION=cfFilterTextToPDF
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_text_to_pdf"'
    -DCF_V2_OUTPUT_MIME='"application/pdf"'
    -DCF_V2_TEXTTOPDF_PARAMETERS
  )

  build_text_pdf_object() {
    local name="$1" symbol="$2" source="$3" input_mime="$4" charset="$5"
    shift 5
    local object="$BUILD_ROOT/cups-filters-v3-text-pdf-$name.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      "${text_pdf_common_flags[@]}" \
      -DCF_V2_INPUT_MIME="\"$input_mime\"" \
      -DCF_V2_CHARSET="\"$charset\"" \
      "$@" -c "$source" -o "$object"
    objcopy \
      --redefine-sym LLVMFuzzerTestOneInput="$symbol" \
      --redefine-sym LLVMFuzzerCustomMutator="${symbol}_private_mutator" \
      --redefine-sym LLVMFuzzerCustomCrossOver="${symbol}_private_crossover" \
      --redefine-sym cf_v2_text_layout_direct_test_one_input="${symbol}_unused_layout" \
      --redefine-sym cf_v2_text_pdf_unused_direct_entrypoint="${symbol}_unused_output" \
      --redefine-sym cf_v2_text_direction_unused_entrypoint="${symbol}_unused_direction" \
      --redefine-sym cf_v2_text_duplex_unused_entrypoint="${symbol}_unused_duplex" \
      --redefine-sym cf_v2_text_title_unused_entrypoint="${symbol}_unused_title" \
      --redefine-sym cf_v2_text_title_relation_unused_entrypoint="${symbol}_unused_title_relation" \
      --redefine-sym cf_v2_text_job_unused_entry="${symbol}_unused_contract" \
      --redefine-sym __wrap_FcInit="${symbol}_private_wrap_FcInit" \
      --redefine-sym __wrap_strdup="${symbol}_private_wrap_strdup" \
      --redefine-sym __wrap__cfFontEmbedEmbNew="${symbol}_private_wrap_font_new" \
      --redefine-sym __wrap__cfFontEmbedEmbClose="${symbol}_private_wrap_font_close" \
      --redefine-sym __wrap__cfPDFOutNew="${symbol}_private_wrap_pdf_new" \
      --redefine-sym __wrap__cfPDFOutFree="${symbol}_private_wrap_pdf_free" \
      --redefine-sym __wrap_free="${symbol}_private_wrap_free" \
      "$object"
    text_pdf_objects+=("$object")
  }

  build_text_pdf_object job-plain cf_v3_text_pdf_job_plain_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    text/plain utf-8 -DCF_V2_JOB_OPTION_MASK=0x70U
  build_text_pdf_object job-plain-ascii \
    cf_v3_text_pdf_job_plain_ascii_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    text/plain us-ascii -DCF_V2_JOB_OPTION_MASK=0x70U
  build_text_pdf_object job-c cf_v3_text_pdf_job_c_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_job_filter.c" \
    application/x-csource us-ascii
  build_text_pdf_object direct-plain cf_v3_text_pdf_direct_plain_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    text/plain utf-8
  build_text_pdf_object direct-plain-ascii \
    cf_v3_text_pdf_direct_plain_ascii_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    text/plain us-ascii
  build_text_pdf_object direct-c cf_v3_text_pdf_direct_c_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    application/x-csource us-ascii
  build_text_pdf_object direct-shell cf_v3_text_pdf_direct_shell_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    application/x-shell us-ascii
  build_text_pdf_object direct-perl cf_v3_text_pdf_direct_perl_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_direct_filter.c" \
    application/x-perl us-ascii

  text_pdf_special_flags=(
    -DCF_V2_TEXT_LAYOUT_OPTIONS
    -DCF_V2_TEXTTOPDF_LEAK_GUARD
  )
  build_text_pdf_object layout-utf8 cf_v3_text_pdf_layout_utf8_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_layout_state.c" \
    text/plain utf-8 "${text_pdf_special_flags[@]}"
  build_text_pdf_object layout-ascii cf_v3_text_pdf_layout_ascii_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_layout_state.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}"
  build_text_pdf_object output-oracle cf_v3_text_pdf_output_oracle_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_pdf_output_state.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}"
  build_text_pdf_object output-continuation \
    cf_v3_text_pdf_output_continuation_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_pdf_output_state.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_PDF_WRITER_CONTINUATION
  build_text_pdf_object direction cf_v3_text_pdf_direction_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_pdf_direction_state.c" \
    text/plain utf-8 "${text_pdf_special_flags[@]}"
  build_text_pdf_object duplex-boundary \
    cf_v3_text_pdf_duplex_boundary_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_pdf_duplex_geometry.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}"
  build_text_pdf_object duplex-continuation \
    cf_v3_text_pdf_duplex_continuation_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_pdf_duplex_geometry.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_DUPLEX_SAFE_CONTINUATION
  build_text_pdf_object title-utf8 cf_v3_text_pdf_title_utf8_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_title_utf8_state.c" \
    application/x-csource utf-8 "${text_pdf_special_flags[@]}"
  build_text_pdf_object title-relation \
    cf_v3_text_pdf_title_relation_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_title_relation.c" \
    application/x-csource utf-8 "${text_pdf_special_flags[@]}"
  build_text_pdf_object title-deep cf_v3_text_pdf_title_deep_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_title_relation.c" \
    application/x-csource us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_TITLE_RELATION_DEEP
  build_text_pdf_object shared-output cf_v3_text_pdf_shared_output_legacy \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_text_to_pdf_output_state.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_PDF_WRITER_CONTINUATION -DCF_V2_TEXT_SHARED_CONTRACT
  build_text_pdf_object boundary-plain \
    cf_v3_text_pdf_boundary_plain_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_job_contract.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_JOB_ROUTE_PDF
  build_text_pdf_object boundary-c cf_v3_text_pdf_boundary_c_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_job_contract.c" \
    application/x-csource us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_JOB_ROUTE_PDF -DCF_V2_TEXT_JOB_C_SOURCE
  build_text_pdf_object deep-plain cf_v3_text_pdf_deep_plain_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_job_contract.c" \
    text/plain us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_JOB_ROUTE_PDF -DCF_V2_TEXT_JOB_DEEP
  build_text_pdf_object deep-c cf_v3_text_pdf_deep_c_legacy \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_text_job_contract.c" \
    application/x-csource us-ascii "${text_pdf_special_flags[@]}" \
    -DCF_V2_TEXT_JOB_ROUTE_PDF -DCF_V2_TEXT_JOB_DEEP \
    -DCF_V2_TEXT_JOB_C_SOURCE

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "${text_pdf_common_flags[@]}" \
    -DCF_V2_INPUT_MIME='"text/plain"' -DCF_V2_CHARSET='"utf-8"' \
    "$V3_ROOT/implementations/fuzz_text_to_pdf.c" \
    "$V3_ROOT/implementations/text_pdf_route_bridge.c" \
    "$V3_ROOT/implementations/text_pdf_lifecycle.c" \
    "$V3_ROOT/implementations/text_memfd_runtime.c" \
    "$V3_ROOT/mutators/text_pdf_route_mutator.c" \
    "${text_pdf_objects[@]}" "${COMMON_LIBS[@]}" \
    -Wl,--wrap=_cfPDFOutNew -Wl,--wrap=_cfPDFOutFree \
    -Wl,--wrap=_cfFontEmbedEmbNew -Wl,--wrap=_cfFontEmbedEmbClose \
    -Wl,--wrap=FcInit -Wl,--wrap=strdup -Wl,--wrap=free \
    -Wl,--wrap=mkstemp -Wl,--wrap=tmpfile -Wl,--wrap=unlink \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$text_pdf_target"
fi

escpx_job_target=fuzz_v3_cupsfilters_raster_to_escpx_job
if selected "$escpx_job_target"; then
  escpx_job_objects=()
  escpx_job_common_flags=(
    -DCF_V2_LEGACY_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_escpx_job"'
    -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"'
    -DCF_V2_OUTPUT_MIME='"application/vnd.epson-escp"'
  )

  build_escpx_job_part() {
    local prefix="$1" role="$2" source="$3"
    shift 3
    local object="$BUILD_ROOT/cups-filters-v3-${prefix}-${role}.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      "${escpx_job_common_flags[@]}" "$@" -c "$source" -o "$object"
    namespace_v3_route_object "$prefix" "$role" "$object"
    escpx_job_objects+=("$object")
  }

  legacy_source="$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_legacy_filter.c"
  build_escpx_job_part cf_v3_escpx_job_validated harness "$legacy_source" \
    -DCF_V2_VALIDATE_RASTER -DCF_V2_RASTER_ESCPX_SAFE_WEAVE
  build_escpx_job_part cf_v3_escpx_job_frontier harness "$legacy_source"
  build_escpx_job_part cf_v3_escpx_job_coupled harness "$legacy_source" \
    -DCF_V2_COUPLED_PPD
  build_escpx_job_part cf_v3_escpx_job_coupled mutator \
    "$ROOT/harnesses/libfuzzer/v2/mutators/coupled_mutator.c" \
    -DCF_V2_COUPLED_PPD
  build_escpx_job_part cf_v3_escpx_job_full harness "$legacy_source" \
    -DCF_V2_JOB_INPUT
  build_escpx_job_part cf_v3_escpx_job_full mutator \
    "$ROOT/harnesses/libfuzzer/v2/mutators/job_mutator.c" \
    -DCF_V2_JOB_INPUT

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_raster_to_escpx_job.c" \
    "$V3_ROOT/implementations/raster_escpx_job_bridge.c" \
    "$V3_ROOT/implementations/legacy_options_lifecycle.c" \
    "$V3_ROOT/mutators/raster_escpx_job_mutator.c" \
    "${escpx_job_objects[@]}" "${COMMON_LIBS[@]}" \
    -Wl,--wrap=cupsParseOptions -Wl,--wrap=cupsFreeOptions \
    -Wl,--wrap=ppdOpenFile \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$escpx_job_target"
fi

escpx_state_target=fuzz_v3_cupsfilters_raster_to_escpx_state
if selected "$escpx_state_target"; then
  escpx_state_objects=()
  escpx_state_source_define=(
    -DCUPSFILTERS_PACKED_RASTER_FILTER_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  )

  build_escpx_state_object() {
    local route="$1" source="$2"
    shift 2
    local prefix="cf_v3_escpx_state_r$route"
    local object="$BUILD_ROOT/cups-filters-v3-escpx-state-r$route.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_escpx_state"' \
      "$@" -c "$source" -o "$object"
    namespace_v3_route_object "$prefix" harness "$object"
    escpx_state_objects+=("$object")
  }

  compact_source="$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_compact_raster_state.c"
  for lane in 1 2 3 4; do
    route=$((lane - 1))
    build_escpx_state_object "$route" "$compact_source" \
      -DCUPSFILTERS_PACKED_RASTER_ESCPX \
      -DCUPSFILTERS_PACKED_RASTER_ESCPX_RELATION_PROGRAM \
      -DCF_V2_ESCPX_RELATION_LANE="$lane" \
      "${escpx_state_source_define[@]}"
  done
  build_escpx_state_object 4 \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_rastertoescpx_band_queue.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  build_escpx_state_object 5 \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_rastertoescpx_packbits_state.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  build_escpx_state_object 6 \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_rastertoescpx_output_band_state.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  build_escpx_state_object 7 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX \
    -DCUPSFILTERS_PACKED_RASTER_CONTINUATION \
    "${escpx_state_source_define[@]}"
  build_escpx_state_object 8 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX \
    -DCUPSFILTERS_PACKED_RASTER_CONTINUATION \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX_WEAVE_STATE \
    "${escpx_state_source_define[@]}"
  build_escpx_state_object 9 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX \
    -DCUPSFILTERS_PACKED_RASTER_CONTINUATION \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX_PAGE_STATE \
    "${escpx_state_source_define[@]}"
  build_escpx_state_object 10 \
    "$ROOT/harnesses/libfuzzer/v2/states/fuzz_raster_to_escpx_staggered.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  objcopy --globalize-symbol=cf_v3_escpx_state_r10_harness_cf_v2_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-escpx-state-r10.o"
  build_escpx_state_object 11 \
    "$ROOT/harnesses/libfuzzer/v2/constraints/fuzz_raster_to_escpx_ppd_lut_bitplanes.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  objcopy --globalize-symbol=cf_v3_escpx_state_r11_harness_cf_v2_escpx_lut_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-escpx-state-r11.o"
  build_escpx_state_object 12 \
    "$ROOT/harnesses/libfuzzer/v2/constraints/fuzz_raster_to_escpx_black_head.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\""
  objcopy --globalize-symbol=cf_v3_escpx_state_r12_harness_cf_v2_escpx_lut_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-escpx-state-r12.o"
  build_escpx_state_object 13 \
    "$ROOT/harnesses/libfuzzer/v2/constraints/fuzz_raster_to_escpx_black_head.c" \
    -DCF_V2_RASTERTOESCPX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertoescpx.c\"" \
    -DCF_V2_ESCPBLACK_BOUNDARY
  objcopy --globalize-symbol=cf_v3_escpx_state_r13_harness_cf_v2_escpx_lut_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-escpx-state-r13.o"

  raster_job_flags=(
    -DCUPSFILTERS_PACKED_RASTER_ESCPX
    -DCUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
    -DCUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
    "${escpx_state_source_define[@]}"
  )
  build_escpx_state_object 14 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_ESCPX_PAGE_SETUP
  build_escpx_state_object 15 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_ESCPX_PAGE_SETUP \
    -DCF_V2_RASTER_JOB_ESCPX_HORIZONTAL_RESOLUTION
  build_escpx_state_object 16 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_ESCPX_PAGE_SETUP \
    -DCF_V2_RASTER_JOB_ESCPX_VERTICAL_RESOLUTION
  build_escpx_state_object 17 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_ESCPX_PAGE_SETUP \
    -DCF_V2_RASTER_JOB_ESCPX_PAGE_CARDINALITY
  build_escpx_state_object 18 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_ESCPX_SOFTWEAVE_LAYOUT
  build_escpx_state_object 19 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX \
    -DCUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT \
    "${escpx_state_source_define[@]}"
  build_escpx_state_object 20 "$compact_source" "${raster_job_flags[@]}"
  build_escpx_state_object 21 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_DEEP
  build_escpx_state_object 22 "$compact_source" \
    "${raster_job_flags[@]}" -DCF_V2_RASTER_JOB_LAYOUT_BOUNDARY

  escpx_safe_contract_object="$BUILD_ROOT/cups-filters-v3-escpx-state-safe-contract.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_escpx_state"' \
    -DCUPSFILTERS_PACKED_RASTER_ESCPX \
    -DCUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT \
    -DCUPSFILTERS_PACKED_RASTER_CONTINUATION \
    "${escpx_state_source_define[@]}" \
    -c "$compact_source" -o "$escpx_safe_contract_object"
  namespace_v3_route_object cf_v3_escpx_state_safe_contract harness \
    "$escpx_safe_contract_object"
  escpx_state_objects+=("$escpx_safe_contract_object")

  escpx_relation_schema_object="$BUILD_ROOT/cups-filters-v3-escpx-relation-schema.o"
  escpx_relation_mutator_object="$BUILD_ROOT/cups-filters-v3-escpx-relation-mutator.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -c "$ROOT/harnesses/libfuzzer/v2/schemas/raster_job_relation_schema.c" \
    -o "$escpx_relation_schema_object"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DLLVMFuzzerCustomMutator=cf_v3_escpx_relation_mutator \
    -DLLVMFuzzerCustomCrossOver=cf_v3_escpx_relation_crossover \
    -c "$ROOT/harnesses/libfuzzer/v2/mutators/relation_program_mutator.c" \
    -o "$escpx_relation_mutator_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_raster_to_escpx_state.c" \
    "$V3_ROOT/implementations/raster_escpx_state_bridge.c" \
    "$V3_ROOT/mutators/raster_escpx_state_mutator.c" \
    "$escpx_relation_schema_object" "$escpx_relation_mutator_object" \
    "${escpx_state_objects[@]}" "${COMMON_LIBS[@]}" \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$escpx_state_target"
fi

pclx_job_target=fuzz_v3_cupsfilters_raster_to_pclx_job
if selected "$pclx_job_target"; then
  pclx_job_objects=()
  pclx_job_common_flags=(
    -DCF_V2_LEGACY_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertopclx.c\""
    -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_pclx_job"'
    -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"'
    -DCF_V2_OUTPUT_MIME='"application/vnd.hp-pcl"'
    -DCF_V2_RESET_PCLX_GLOBALS
  )

  build_pclx_job_part() {
    local prefix="$1" role="$2" source="$3"
    shift 3
    local object="$BUILD_ROOT/cups-filters-v3-${prefix}-${role}.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      "${pclx_job_common_flags[@]}" "$@" -c "$source" -o "$object"
    namespace_v3_route_object "$prefix" "$role" "$object"
    pclx_job_objects+=("$object")
  }

  legacy_source="$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_legacy_filter.c"
  build_pclx_job_part cf_v3_pclx_job_validated harness "$legacy_source" \
    -DCF_V2_VALIDATE_RASTER
  build_pclx_job_part cf_v3_pclx_job_frontier harness "$legacy_source"
  build_pclx_job_part cf_v3_pclx_job_coupled harness "$legacy_source" \
    -DCF_V2_COUPLED_PPD
  build_pclx_job_part cf_v3_pclx_job_coupled_safe harness "$legacy_source" \
    -DCF_V2_COUPLED_PPD -DCF_V2_VALIDATE_RASTER
  build_pclx_job_part cf_v3_pclx_job_coupled mutator \
    "$ROOT/harnesses/libfuzzer/v2/mutators/coupled_mutator.c" \
    -DCF_V2_COUPLED_PPD
  build_pclx_job_part cf_v3_pclx_job_full harness "$legacy_source" \
    -DCF_V2_JOB_INPUT
  build_pclx_job_part cf_v3_pclx_job_full_safe harness "$legacy_source" \
    -DCF_V2_JOB_INPUT -DCF_V2_VALIDATE_RASTER
  build_pclx_job_part cf_v3_pclx_job_full mutator \
    "$ROOT/harnesses/libfuzzer/v2/mutators/job_mutator.c" \
    -DCF_V2_JOB_INPUT

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_raster_to_pclx_job.c" \
    "$V3_ROOT/implementations/raster_pclx_job_bridge.c" \
    "$V3_ROOT/implementations/legacy_options_lifecycle.c" \
    "$V3_ROOT/mutators/raster_pclx_job_mutator.c" \
    "${pclx_job_objects[@]}" \
    "$CUPSFILTERS_SOURCE/filter/pcl-common.c" \
    "${COMMON_LIBS[@]}" \
    -Wl,--wrap=cupsParseOptions -Wl,--wrap=cupsFreeOptions \
    -Wl,--wrap=ppdOpenFile \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$pclx_job_target"
fi

pclx_state_target=fuzz_v3_cupsfilters_raster_to_pclx_state
if selected "$pclx_state_target"; then
  pclx_state_objects=()
  pclx_state_filter_source=(
    -DCUPSFILTERS_PACKED_RASTER_FILTER_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertopclx.c\""
  )
  pclx_state_special_source=(
    -DCF_V2_RASTERTOPCLX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertopclx.c\""
    -DCF_V2_PCL_COMMON_SOURCE="\"$CUPSFILTERS_SOURCE/filter/pcl-common.c\""
  )

  build_pclx_state_object() {
    local route="$1" source="$2"
    shift 2
    local prefix="cf_v3_pclx_state_r$route"
    local object="$BUILD_ROOT/cups-filters-v3-pclx-state-r$route.o"

    "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
      -DCF_V2_TARGET_NAME='"fuzz_v3_cupsfilters_raster_to_pclx_state"' \
      "$@" -c "$source" -o "$object"
    namespace_v3_route_object "$prefix" harness "$object"
    pclx_state_objects+=("$object")
  }

  compact_source="$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_compact_raster_state.c"
  for lane in 1 2 3 4; do
    route=$((lane - 1))
    build_pclx_state_object "$route" "$compact_source" \
      -DCUPSFILTERS_PACKED_RASTER_PCLX \
      -DCUPSFILTERS_PACKED_RASTER_PCLX_RELATION_PROGRAM \
      -DCF_V2_PCLX_RELATION_LANE="$lane" \
      -DCF_V2_FILTER_DATA_CONTINUATION \
      "${pclx_state_filter_source[@]}"
  done

  pclx_legacy_source="$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_legacy_filter.c"
  pclx_legacy_flags=(
    -DCF_V2_LEGACY_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertopclx.c\""
    -DCF_V2_INPUT_MIME='"application/vnd.cups-raster"'
    -DCF_V2_OUTPUT_MIME='"application/vnd.hp-pcl"'
    -DCF_V2_VALIDATE_RASTER
    -DCF_V2_RESET_PCLX_GLOBALS
  )
  build_pclx_state_object 4 "$pclx_legacy_source" \
    "${pclx_legacy_flags[@]}" -DCF_V2_RASTER_POLICY_COMPRESSION_3 \
    -DCF_V2_RASTER_POLICY_MULTIROW
  build_pclx_state_object 6 "$pclx_legacy_source" \
    "${pclx_legacy_flags[@]}" -DCF_V2_RASTER_POLICY_COMPRESSION_10

  build_pclx_state_object 8 \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_rastertopclx_compress_state.c" \
    -DCF_V2_RASTERTOPCLX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertopclx.c\"" \
    -DCF_V2_PCLX_MODE3_CODEC
  build_pclx_state_object 9 \
    "$ROOT/harnesses/libfuzzer/v2/implementations/fuzz_rastertopclx_compress_state.c" \
    -DCF_V2_RASTERTOPCLX_SOURCE="\"$CUPSFILTERS_SOURCE/filter/rastertopclx.c\"" \
    -DCF_V2_PCLX_MODE10_CODEC
  build_pclx_state_object 10 "$pclx_legacy_source" \
    "${pclx_legacy_flags[@]}" -DCF_V2_RASTER_POLICY_COMPRESSION_2
  build_pclx_state_object 11 "$pclx_legacy_source" \
    "${pclx_legacy_flags[@]}" -DCF_V2_RASTER_POLICY_COMPRESSION_1

  build_pclx_state_object 12 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_PCLX \
    -DCUPSFILTERS_PACKED_RASTER_CONTINUATION \
    -DCF_V2_FILTER_DATA_CONTINUATION \
    "${pclx_state_filter_source[@]}"
  build_pclx_state_object 13 \
    "$ROOT/harnesses/libfuzzer/v2/states/fuzz_raster_to_pclx_six_plane_crd.c" \
    "${pclx_state_special_source[@]}"
  objcopy --globalize-symbol=cf_v3_pclx_state_r13_harness_cf_v2_pclx6_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-pclx-state-r13.o"
  build_pclx_state_object 14 \
    "$ROOT/harnesses/libfuzzer/v2/states/fuzz_raster_to_pclx_raw_plane_writer.c" \
    "${pclx_state_special_source[@]}"
  objcopy --globalize-symbol=cf_v3_pclx_state_r14_harness_cf_v2_pclxraw_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-pclx-state-r14.o"
  build_pclx_state_object 15 \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_raster_to_pclx_endjob_oracle.c" \
    "${pclx_state_special_source[@]}"
  objcopy --globalize-symbol=cf_v3_pclx_state_r15_harness_cf_v2_pclxend_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-pclx-state-r15.o"
  build_pclx_state_object 16 \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_raster_to_pclx_two_bit_planes.c" \
    "${pclx_state_special_source[@]}"
  objcopy --globalize-symbol=cf_v3_pclx_state_r16_harness_cf_v2_pclx2_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-pclx-state-r16.o"
  build_pclx_state_object 17 \
    "$ROOT/harnesses/libfuzzer/v2/oracles/fuzz_raster_to_pclx_two_bit_planes.c" \
    -DCF_V2_PCLX2_SAFE_CONTINUATION \
    "${pclx_state_special_source[@]}"
  objcopy --globalize-symbol=cf_v3_pclx_state_r17_harness_cf_v2_pclx2_environment_installed \
    "$BUILD_ROOT/cups-filters-v3-pclx-state-r17.o"

  build_pclx_state_object 18 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_PCLX \
    -DCUPSFILTERS_PACKED_RASTER_CONTINUATION \
    "${pclx_state_filter_source[@]}"
  build_pclx_state_object 19 "$compact_source" \
    -DCUPSFILTERS_PACKED_RASTER_PCLX \
    -DCUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT \
    -DCF_V2_FILTER_DATA_CONTINUATION \
    "${pclx_state_filter_source[@]}"

  pclx_job_state_flags=(
    -DCUPSFILTERS_PACKED_RASTER_PCLX
    -DCUPSFILTERS_PACKED_RASTER_GENERIC_CONTRACT
    -DCUPSFILTERS_PACKED_RASTER_JOB_PROGRAM
    -DCF_V2_FILTER_DATA_CONTINUATION
    "${pclx_state_filter_source[@]}"
  )
  build_pclx_state_object 20 "$compact_source" "${pclx_job_state_flags[@]}"
  build_pclx_state_object 21 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_DEEP
  build_pclx_state_object 22 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_LAYOUT_BOUNDARY
  build_pclx_state_object 23 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_FORMAT_STORAGE
  build_pclx_state_object 24 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_PROFILE_CARDINALITY
  build_pclx_state_object 25 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_STORAGE_CHANNELS
  build_pclx_state_object 26 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_CODEC_ROW
  build_pclx_state_object 27 "$compact_source" \
    "${pclx_job_state_flags[@]}" -DCF_V2_RASTER_JOB_PCLX_ENDJOB_OPAQUE

  pclx_relation_schema_object="$BUILD_ROOT/cups-filters-v3-pclx-relation-schema.o"
  pclx_relation_mutator_object="$BUILD_ROOT/cups-filters-v3-pclx-relation-mutator.o"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -c "$ROOT/harnesses/libfuzzer/v2/schemas/raster_job_relation_schema.c" \
    -o "$pclx_relation_schema_object"
  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    -DLLVMFuzzerCustomMutator=cf_v3_pclx_relation_mutator \
    -DLLVMFuzzerCustomCrossOver=cf_v3_pclx_relation_crossover \
    -c "$ROOT/harnesses/libfuzzer/v2/mutators/relation_program_mutator.c" \
    -o "$pclx_relation_mutator_object"

  "$CC" $CFLAGS "${COMMON_CFLAGS[@]}" \
    "$V3_ROOT/implementations/fuzz_raster_to_pclx_state.c" \
    "$V3_ROOT/implementations/raster_pclx_state_bridge.c" \
    "$V3_ROOT/implementations/raster_pclx_state_lifecycle.c" \
    "$V3_ROOT/mutators/raster_pclx_state_mutator.c" \
    "$pclx_relation_schema_object" "$pclx_relation_mutator_object" \
    "${pclx_state_objects[@]}" \
    "$CUPSFILTERS_SOURCE/filter/pcl-common.c" \
    "${COMMON_LIBS[@]}" \
    -Wl,--wrap=cfJoinJobOptionsAndAttrs \
    -Wl,--wrap=cupsParseOptions -Wl,--wrap=cupsFreeOptions \
    $LIB_FUZZING_ENGINE -o "$OUTPUT_ROOT/$pclx_state_target"
fi

raster_hp_target=fuzz_v3_cupsfilters_raster_to_hp
if selected "$raster_hp_target"; then
  raster_hp_relation_mutator_object="$BUILD_ROOT/cups-filters-v3-raster-hp-relation-mutator.o"
  raster_hp_flags=()

  if [[ ! -f "$CUPS_SOURCE/filter/rastertohp.c" ]]; then
    echo "missing CUPS rastertohp source: $CUPS_SOURCE/filter/rastertohp.c" >&2
    exit 2
  fi
  if grep -q 'ColorBits' "$CUPS_SOURCE/filter/rastertohp.c"; then
    raster_hp_flags+=( -DCF_V3_CUPS_HP_LEGACY_COLORBITS )
  fi
  if grep -Eq \
      'bytes[[:space:]]*=[[:space:]]*header->cupsBytesPerLine[[:space:]]*/[[:space:]]*NumPlanes' \
      "$CUPS_SOURCE/filter/rastertohp.c"; then
    raster_hp_flags+=( -DCF_V3_CUPS_HP_PLANAR_BYTES_FIXED )
  fi

  "$CC" $CFLAGS -I"$V3_ROOT" -I"$ROOT/harnesses/libfuzzer/v2/include" \
    -DLLVMFuzzerCustomMutator=cf_v3_raster_hp_relation_mutator \
    -DLLVMFuzzerCustomCrossOver=cf_v3_raster_hp_relation_crossover \
    -c "$ROOT/harnesses/libfuzzer/v2/mutators/relation_program_mutator.c" \
    -o "$raster_hp_relation_mutator_object"

  "$CC" $CFLAGS \
    -I"$V3_ROOT" -I"$ROOT/harnesses/libfuzzer/v2/include" \
    -I"$CUPS_SOURCE" -I"$CUPS_CONFIG_ROOT" "${CUPS_CFLAGS[@]}" \
    "${raster_hp_flags[@]}" \
    -DCF_V3_CUPS_RASTERTOHP_SOURCE="\"$CUPS_SOURCE/filter/rastertohp.c\"" \
    "$V3_ROOT/implementations/fuzz_raster_to_hp.c" \
    "$V3_ROOT/implementations/raster_hp_bridge.c" \
    "$V3_ROOT/implementations/raster_hp_runtime.c" \
    "$V3_ROOT/mutators/raster_hp_route_mutator.c" \
    "$ROOT/harnesses/libfuzzer/v2/schemas/arithmetic_layout_schema.c" \
    "$raster_hp_relation_mutator_object" \
    "${CUPS_LINK_LIBS[@]}" $LIB_FUZZING_ENGINE \
    -o "$OUTPUT_ROOT/$raster_hp_target"
fi

for asset in cups-data fonts fonts.conf; do
  if [[ -e "$ROOT/work/libfuzzer/bin/$asset" && ! -e "$OUTPUT_ROOT/$asset" ]]; then
    cp -a "$ROOT/work/libfuzzer/bin/$asset" "$OUTPUT_ROOT/"
  fi
done

for target in "${SELECTED_TARGETS[@]}"; do
  [[ -x "$OUTPUT_ROOT/$target" ]] || {
    echo "V3 target was not built: $target" >&2
    exit 2
  }
  echo "$OUTPUT_ROOT/$target"
done
