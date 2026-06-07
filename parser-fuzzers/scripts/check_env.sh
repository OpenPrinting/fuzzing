#!/usr/bin/env bash
set -u

strict=0
if [[ "${1:-}" == "--strict" ]]; then
  strict=1
fi

missing_required=0

check_cmd() {
  local name="$1"
  local required="$2"
  if command -v "$name" >/dev/null 2>&1; then
    echo "[ok] $name: $(command -v "$name")"
  else
    if [[ "$required" == "yes" ]]; then
      echo "[missing] $name is required"
      missing_required=1
    else
      echo "[optional-missing] $name is not in PATH"
    fi
  fi
}

check_python_module() {
  local module="$1"
  local required="$2"
  if python3 -c "import ${module}" >/dev/null 2>&1; then
    echo "[ok] python module ${module}"
  else
    if [[ "$required" == "yes" ]]; then
      echo "[missing] python module ${module}; run: python3 -m pip install -r requirements.txt"
      missing_required=1
    else
      echo "[optional-missing] python module ${module}"
    fi
  fi
}

check_cmd python3 yes
check_cmd clang no
check_cmd llvm-cov no
check_cmd afl-fuzz no
check_cmd afl-clang-fast no
check_python_module yaml yes
check_python_module z3 yes

if [[ "$strict" == "1" && "$missing_required" != "0" ]]; then
  exit 1
fi

if [[ "$missing_required" != "0" ]]; then
  echo "[note] required runtime dependencies are missing for strict SMT runs; default smoke can still test the wiring."
fi

exit 0
