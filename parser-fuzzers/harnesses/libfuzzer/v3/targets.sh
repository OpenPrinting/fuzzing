#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

CF_V3_TARGETS=(
  fuzz_v3_cupsfilters_banner_to_pdf
  fuzz_v3_cupsfilters_pclm_raw
  fuzz_v3_cupsfilters_pclm_graph
  fuzz_v3_cupsfilters_command_to_escpx
  fuzz_v3_cupsfilters_command_to_pclx
  fuzz_v3_cupsfilters_foomatic_jcl
  fuzz_v3_cupsfilters_cups_raster_reader
  fuzz_v3_cupsfilters_image_jpeg_decoder
  fuzz_v3_cupsfilters_image_png_decoder
  fuzz_v3_cupsfilters_image_tiff_decoder
  fuzz_v3_cupsfilters_image_to_pdf
  fuzz_v3_cupsfilters_image_to_raster
  fuzz_v3_cupsfilters_image_to_ps
  fuzz_v3_cupsfilters_pdf_to_pdf_graph
  fuzz_v3_cupsfilters_pdf_to_pdf_raw
  fuzz_v3_cupsfilters_pdfio_document
  fuzz_v3_cupsfilters_pdfio_stream
  fuzz_v3_cupsfilters_ppd_loader
  fuzz_v3_cupsfilters_ppd_semantic
  fuzz_v3_cupsfilters_ppd_cache_ipp
  fuzz_v3_cupsfilters_ppd_profile
  fuzz_v3_cupsfilters_ps_to_ps
  fuzz_v3_cupsfilters_pwg_to_pdf
  fuzz_v3_cupsfilters_pwg_to_raster
  fuzz_v3_cupsfilters_raster_to_hp
  fuzz_v3_cupsfilters_raster_to_escpx_job
  fuzz_v3_cupsfilters_raster_to_escpx_state
  fuzz_v3_cupsfilters_raster_to_pclx_job
  fuzz_v3_cupsfilters_raster_to_pclx_state
  fuzz_v3_cupsfilters_raster_to_ps
  fuzz_v3_cupsfilters_raster_to_pwg
  fuzz_v3_cupsfilters_text_to_pdf
  fuzz_v3_cupsfilters_text_to_text
)

CF_V3_DEPLOY_TARGETS=(
  fuzz_v3_cupsfilters_banner_to_pdf
  fuzz_v3_cupsfilters_command_to_escpx
  fuzz_v3_cupsfilters_command_to_pclx
  fuzz_v3_cupsfilters_foomatic_jcl
  fuzz_v3_cupsfilters_image_jpeg_decoder
  fuzz_v3_cupsfilters_image_png_decoder
  fuzz_v3_cupsfilters_image_tiff_decoder
  fuzz_v3_cupsfilters_image_to_pdf
  fuzz_v3_cupsfilters_image_to_raster
  fuzz_v3_cupsfilters_image_to_ps
  fuzz_v3_cupsfilters_pdf_to_pdf_graph
  fuzz_v3_cupsfilters_pclm_graph
  fuzz_v3_cupsfilters_ppd_semantic
  fuzz_v3_cupsfilters_ppd_cache_ipp
  fuzz_v3_cupsfilters_ppd_profile
  fuzz_v3_cupsfilters_ps_to_ps
  fuzz_v3_cupsfilters_pwg_to_pdf
  fuzz_v3_cupsfilters_pwg_to_raster
  fuzz_v3_cupsfilters_raster_to_hp
  fuzz_v3_cupsfilters_raster_to_escpx_state
  fuzz_v3_cupsfilters_raster_to_pclx_state
  fuzz_v3_cupsfilters_raster_to_ps
  fuzz_v3_cupsfilters_raster_to_pwg
  fuzz_v3_cupsfilters_text_to_pdf
  fuzz_v3_cupsfilters_text_to_text
)

CF_V3_DISCOVERY_TARGETS=(
  fuzz_v3_cupsfilters_pclm_raw
  fuzz_v3_cupsfilters_pdf_to_pdf_raw
  fuzz_v3_cupsfilters_ppd_loader
  fuzz_v3_cupsfilters_raster_to_escpx_job
  fuzz_v3_cupsfilters_raster_to_pclx_job
)

# Direct dependency probes stay available for local/upstream qualification,
# but the compact cups-filters project does not duplicate their OSS-Fuzz jobs.
CF_V3_DEPENDENCY_TARGETS=(
  fuzz_v3_cupsfilters_cups_raster_reader
  fuzz_v3_cupsfilters_pdfio_document
  fuzz_v3_cupsfilters_pdfio_stream
)

CF_V3_CANDIDATE_TARGETS=()

# Preserve the existing OSS-Fuzz raw-PDF corpus while exporting the converged
# targets under stable, version-free names. Compatibility targets reuse an
# existing V3 owner and therefore do not add another ownership row.
CF_V3_COMPATIBILITY_TARGETS=(
  fuzz_v3_cupsfilters_pdf_to_pdf_raw
)

cf_v3_list_targets() {
  local set="${1:-all}"

  case "$set" in
    all)
      printf '%s\n' "${CF_V3_TARGETS[@]}"
      ;;
    deploy|deploy-qualified)
      printf '%s\n' "${CF_V3_DEPLOY_TARGETS[@]}"
      ;;
    discovery|experimental)
      printf '%s\n' "${CF_V3_DISCOVERY_TARGETS[@]}"
      ;;
    dependency|dependencies)
      printf '%s\n' "${CF_V3_DEPENDENCY_TARGETS[@]}"
      ;;
    candidate|qualification)
      if ((${#CF_V3_CANDIDATE_TARGETS[@]})); then
        printf '%s\n' "${CF_V3_CANDIDATE_TARGETS[@]}"
      fi
      ;;
    package|oss-fuzz)
      printf '%s\n' \
        "${CF_V3_DEPLOY_TARGETS[@]}" \
        "${CF_V3_COMPATIBILITY_TARGETS[@]}"
      ;;
    compatibility|compat)
      printf '%s\n' "${CF_V3_COMPATIBILITY_TARGETS[@]}"
      ;;
    external-package)
      cf_v3_list_external_targets package
      ;;
    candidate-light)
      for target in "${CF_V3_CANDIDATE_TARGETS[@]}"; do
        [[ "$target" == fuzz_v3_cupsfilters_image_to_raster ]] ||
          printf '%s\n' "$target"
      done
      ;;
    pilot|pclm)
      printf '%s\n' \
        fuzz_v3_cupsfilters_pclm_raw \
        fuzz_v3_cupsfilters_pclm_graph
      ;;
    command)
      printf '%s\n' \
        fuzz_v3_cupsfilters_command_to_escpx \
        fuzz_v3_cupsfilters_command_to_pclx
      ;;
    banner|banner-to-pdf)
      printf '%s\n' fuzz_v3_cupsfilters_banner_to_pdf
      ;;
    foomatic|jcl)
      printf '%s\n' fuzz_v3_cupsfilters_foomatic_jcl
      ;;
    raster-reader|cups-raster-reader)
      printf '%s\n' fuzz_v3_cupsfilters_cups_raster_reader
      ;;
    image-codecs|decoders)
      printf '%s\n' \
        fuzz_v3_cupsfilters_image_jpeg_decoder \
        fuzz_v3_cupsfilters_image_png_decoder \
        fuzz_v3_cupsfilters_image_tiff_decoder
      ;;
    image-ps|image-to-ps)
      printf '%s\n' fuzz_v3_cupsfilters_image_to_ps
      ;;
    image-pdf|image-to-pdf)
      printf '%s\n' fuzz_v3_cupsfilters_image_to_pdf
      ;;
    image-raster|image-to-raster)
      printf '%s\n' fuzz_v3_cupsfilters_image_to_raster
      ;;
    pdfio-document)
      printf '%s\n' fuzz_v3_cupsfilters_pdfio_document
      ;;
    pdf|pdf-to-pdf)
      printf '%s\n' \
        fuzz_v3_cupsfilters_pdf_to_pdf_raw \
        fuzz_v3_cupsfilters_pdf_to_pdf_graph
      ;;
    pdf-to-pdf-raw)
      printf '%s\n' fuzz_v3_cupsfilters_pdf_to_pdf_raw
      ;;
    pdf-to-pdf-graph|pdf-graph)
      printf '%s\n' fuzz_v3_cupsfilters_pdf_to_pdf_graph
      ;;
    pdfio-stream)
      printf '%s\n' fuzz_v3_cupsfilters_pdfio_stream
      ;;
    ppd-profile)
      printf '%s\n' fuzz_v3_cupsfilters_ppd_profile
      ;;
    ps|ps-to-ps)
      printf '%s\n' fuzz_v3_cupsfilters_ps_to_ps
      ;;
    ppd|ppd-semantic)
      printf '%s\n' \
        fuzz_v3_cupsfilters_ppd_loader \
        fuzz_v3_cupsfilters_ppd_semantic \
        fuzz_v3_cupsfilters_ppd_cache_ipp
      ;;
    ppd-loader)
      printf '%s\n' fuzz_v3_cupsfilters_ppd_loader
      ;;
    ppd-cache|ppd-cache-ipp)
      printf '%s\n' fuzz_v3_cupsfilters_ppd_cache_ipp
      ;;
    pwg-pdf|pwg-to-pdf)
      printf '%s\n' fuzz_v3_cupsfilters_pwg_to_pdf
      ;;
    pwg-raster|pwg-to-raster)
      printf '%s\n' fuzz_v3_cupsfilters_pwg_to_raster
      ;;
    raster-pwg|raster-to-pwg)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_pwg
      ;;
    raster-ps|raster-to-ps)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_ps
      ;;
    raster-hp|raster-to-hp)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_hp
      ;;
    raster-escpx|raster-to-escpx)
      printf '%s\n' \
        fuzz_v3_cupsfilters_raster_to_escpx_job \
        fuzz_v3_cupsfilters_raster_to_escpx_state
      ;;
    raster-to-escpx-job)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_escpx_job
      ;;
    raster-to-escpx-state|escpx-state)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_escpx_state
      ;;
    raster-pclx|raster-to-pclx)
      printf '%s\n' \
        fuzz_v3_cupsfilters_raster_to_pclx_job \
        fuzz_v3_cupsfilters_raster_to_pclx_state
      ;;
    raster-to-pclx-job)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_pclx_job
      ;;
    raster-to-pclx-state|pclx-state)
      printf '%s\n' fuzz_v3_cupsfilters_raster_to_pclx_state
      ;;
    text)
      printf '%s\n' \
        fuzz_v3_cupsfilters_text_to_pdf \
        fuzz_v3_cupsfilters_text_to_text
      ;;
    text-pdf|text-to-pdf)
      printf '%s\n' fuzz_v3_cupsfilters_text_to_pdf
      ;;
    text-to-text)
      printf '%s\n' fuzz_v3_cupsfilters_text_to_text
      ;;
    fuzz_v3_*)
      printf '%s\n' "$set"
      ;;
    *)
      return 2
      ;;
  esac
}

cf_v3_target_external_name() {
  case "$1" in
    fuzz_v3_cupsfilters_pdf_to_pdf_raw)
      printf '%s\n' fuzz_pdf
      ;;
    fuzz_v3_cupsfilters_*)
      printf 'fuzz_%s\n' "${1#fuzz_v3_}"
      ;;
    *)
      return 2
      ;;
  esac
}

cf_v3_list_external_targets() {
  local set="${1:-package}"
  local target

  while read -r target; do
    [[ -n "$target" ]] && cf_v3_target_external_name "$target"
  done < <(cf_v3_list_targets "$set")
}

cf_v3_target_package_tier() {
  local target="$1"

  if printf '%s\n' "${CF_V3_COMPATIBILITY_TARGETS[@]}" | grep -Fxq "$target"; then
    printf '%s\n' compatibility
  elif printf '%s\n' "${CF_V3_DEPLOY_TARGETS[@]}" | grep -Fxq "$target"; then
    printf '%s\n' deploy
  else
    return 2
  fi
}

cf_v3_target_max_len() {
  case "$1" in
    fuzz_v3_cupsfilters_banner_to_pdf) printf '%s\n' 1048576 ;;
    fuzz_v3_cupsfilters_pclm_raw) printf '%s\n' 4194320 ;;
    fuzz_v3_cupsfilters_pclm_graph) printf '%s\n' 4152 ;;
    fuzz_v3_cupsfilters_command_to_escpx|fuzz_v3_cupsfilters_command_to_pclx)
      printf '%s\n' 16416
      ;;
    fuzz_v3_cupsfilters_foomatic_jcl) printf '%s\n' 1056 ;;
    fuzz_v3_cupsfilters_cups_raster_reader) printf '%s\n' 4194304 ;;
    fuzz_v3_cupsfilters_image_jpeg_decoder|fuzz_v3_cupsfilters_image_png_decoder|fuzz_v3_cupsfilters_image_tiff_decoder)
      printf '%s\n' 2097152
      ;;
    fuzz_v3_cupsfilters_image_to_pdf) printf '%s\n' 2097192 ;;
    fuzz_v3_cupsfilters_image_to_raster) printf '%s\n' 2097200 ;;
    fuzz_v3_cupsfilters_image_to_ps) printf '%s\n' 280 ;;
    fuzz_v3_cupsfilters_pdfio_document) printf '%s\n' 4194305 ;;
    fuzz_v3_cupsfilters_pdf_to_pdf_graph) printf '%s\n' 4194360 ;;
    fuzz_v3_cupsfilters_pdf_to_pdf_raw) printf '%s\n' 4194344 ;;
    fuzz_v3_cupsfilters_pdfio_stream) printf '%s\n' 1034 ;;
    fuzz_v3_cupsfilters_ppd_loader) printf '%s\n' 262144 ;;
    fuzz_v3_cupsfilters_ppd_semantic) printf '%s\n' 328 ;;
    fuzz_v3_cupsfilters_ppd_cache_ipp) printf '%s\n' 88 ;;
    fuzz_v3_cupsfilters_ppd_profile) printf '%s\n' 32769 ;;
    fuzz_v3_cupsfilters_ps_to_ps) printf '%s\n' 4194352 ;;
    fuzz_v3_cupsfilters_pwg_to_pdf) printf '%s\n' 4120 ;;
    fuzz_v3_cupsfilters_pwg_to_raster) printf '%s\n' 4184 ;;
    fuzz_v3_cupsfilters_raster_to_ps) printf '%s\n' 2097192 ;;
    fuzz_v3_cupsfilters_raster_to_hp) printf '%s\n' 4184 ;;
    fuzz_v3_cupsfilters_raster_to_escpx_job) printf '%s\n' 4194320 ;;
    fuzz_v3_cupsfilters_raster_to_escpx_state) printf '%s\n' 262217 ;;
    fuzz_v3_cupsfilters_raster_to_pclx_job) printf '%s\n' 4194320 ;;
    fuzz_v3_cupsfilters_raster_to_pclx_state) printf '%s\n' 262217 ;;
    fuzz_v3_cupsfilters_raster_to_pwg) printf '%s\n' 4184 ;;
    fuzz_v3_cupsfilters_text_to_pdf) printf '%s\n' 8240 ;;
    fuzz_v3_cupsfilters_text_to_text) printf '%s\n' 4136 ;;
    *) return 2 ;;
  esac
}

cf_v3_target_timeout() {
  case "$1" in
    fuzz_v3_cupsfilters_banner_to_pdf) printf '%s\n' 15 ;;
    fuzz_v3_cupsfilters_pclm_raw) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_pclm_graph) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_command_to_escpx|fuzz_v3_cupsfilters_command_to_pclx)
      printf '%s\n' 5
      ;;
    fuzz_v3_cupsfilters_foomatic_jcl) printf '%s\n' 5 ;;
    fuzz_v3_cupsfilters_cups_raster_reader) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_image_jpeg_decoder|fuzz_v3_cupsfilters_image_png_decoder|fuzz_v3_cupsfilters_image_tiff_decoder)
      printf '%s\n' 10
      ;;
    fuzz_v3_cupsfilters_image_to_pdf) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_image_to_raster) printf '%s\n' 15 ;;
    fuzz_v3_cupsfilters_image_to_ps) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_pdfio_document) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_pdf_to_pdf_graph) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_pdf_to_pdf_raw) printf '%s\n' 15 ;;
    fuzz_v3_cupsfilters_pdfio_stream) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_ppd_loader|fuzz_v3_cupsfilters_ppd_semantic|fuzz_v3_cupsfilters_ppd_cache_ipp)
      printf '%s\n' 10
      ;;
    fuzz_v3_cupsfilters_ppd_profile) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_ps_to_ps) printf '%s\n' 10 ;;
    fuzz_v3_cupsfilters_pwg_to_pdf) printf '%s\n' 15 ;;
    fuzz_v3_cupsfilters_pwg_to_raster) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_raster_to_ps) printf '%s\n' 15 ;;
    fuzz_v3_cupsfilters_raster_to_hp) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_raster_to_escpx_job) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_raster_to_escpx_state) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_raster_to_pclx_job) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_raster_to_pclx_state) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_raster_to_pwg) printf '%s\n' 20 ;;
    fuzz_v3_cupsfilters_text_to_pdf) printf '%s\n' 15 ;;
    fuzz_v3_cupsfilters_text_to_text) printf '%s\n' 10 ;;
    *) return 2 ;;
  esac
}

cf_v3_target_rss_limit_mb() {
  case "$1" in
    fuzz_v3_cupsfilters_banner_to_pdf) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_pclm_raw) printf '%s\n' 2048 ;;
    fuzz_v3_cupsfilters_pclm_graph) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_command_to_escpx|fuzz_v3_cupsfilters_command_to_pclx)
      printf '%s\n' 512
      ;;
    fuzz_v3_cupsfilters_foomatic_jcl) printf '%s\n' 512 ;;
    fuzz_v3_cupsfilters_cups_raster_reader) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_image_jpeg_decoder|fuzz_v3_cupsfilters_image_png_decoder|fuzz_v3_cupsfilters_image_tiff_decoder)
      printf '%s\n' 1024
      ;;
    fuzz_v3_cupsfilters_image_to_pdf) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_image_to_raster) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_image_to_ps) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_pdfio_document) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_pdf_to_pdf_graph) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_pdf_to_pdf_raw) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_pdfio_stream) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_ppd_loader|fuzz_v3_cupsfilters_ppd_semantic|fuzz_v3_cupsfilters_ppd_cache_ipp)
      printf '%s\n' 1024
      ;;
    fuzz_v3_cupsfilters_ppd_profile) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_ps_to_ps) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_pwg_to_pdf) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_pwg_to_raster) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_raster_to_ps) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_raster_to_hp) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_raster_to_escpx_job) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_raster_to_escpx_state) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_raster_to_pclx_job) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_raster_to_pclx_state) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_raster_to_pwg) printf '%s\n' 1536 ;;
    fuzz_v3_cupsfilters_text_to_pdf) printf '%s\n' 1024 ;;
    fuzz_v3_cupsfilters_text_to_text) printf '%s\n' 1024 ;;
    *) return 2 ;;
  esac
}
