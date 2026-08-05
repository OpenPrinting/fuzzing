#!/usr/bin/env bash

CF_CORE12_TARGETS=(
  fuzz_cupsfilters_format_cups_raster
  fuzz_cupsfilters_format_image_jpeg_bounded
  fuzz_cupsfilters_format_image_png_bounded
  fuzz_cupsfilters_format_image_tiff_bounded
  fuzz_cupsfilters_state_pwg_to_raster_scale_down
  fuzz_cupsfilters_state_pwg_to_raster_scale_up
  fuzz_cupsfilters_state_raster_to_apple
  fuzz_cupsfilters_state_raster_to_pwg
  fuzz_cupsfilters_raster_to_pclx_mode3_codec
  fuzz_cupsfilters_raster_to_pclx_mode10_codec
  fuzz_cupsfilters_state_text_to_text_layout
  fuzz_cupsfilters_text_to_text_selection_oracle
)

core12_list_targets() {
  printf '%s\n' "${CF_CORE12_TARGETS[@]}"
}

core12_has_target() {
  local requested="$1" target
  for target in "${CF_CORE12_TARGETS[@]}"; do
    [[ "$target" == "$requested" ]] && return 0
  done
  return 1
}

core12_target_max_len() {
  case "$1" in
    *format_cups_raster) printf '%s\n' $((4 * 1024 * 1024)) ;;
    *format_image_*) printf '%s\n' $((2 * 1024 * 1024)) ;;
    *state_pwg_to_raster_scale_*) printf '%s\n' 4111 ;;
    *state_raster_to_*) printf '%s\n' 4112 ;;
    *raster_to_pclx_mode3_codec|*raster_to_pclx_mode10_codec)
      printf '%s\n' 4116 ;;
    *state_text_to_text_layout) printf '%s\n' 4120 ;;
    *text_to_text_selection_oracle) printf '%s\n' 280 ;;
    *) return 2 ;;
  esac
}

core12_target_rss_limit_mb() {
  case "$1" in
    *state_pwg_to_raster_scale_*|*state_raster_to_*) printf '%s\n' 768 ;;
    *) printf '%s\n' 1024 ;;
  esac
}

core12_target_timeout_sec() {
  core12_has_target "$1" || return 2
  printf '%s\n' 15
}

core12_target_detect_leaks() {
  core12_has_target "$1" || return 2
  printf '%s\n' 1
}
