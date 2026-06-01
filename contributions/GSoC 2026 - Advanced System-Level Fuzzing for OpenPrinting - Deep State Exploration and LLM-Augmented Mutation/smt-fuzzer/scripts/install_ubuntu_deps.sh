#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/install_ubuntu_deps.sh [mode] [options]

Modes:
  --minimal          Python smoke dependencies only
  --system-filters   minimal + Ubuntu CUPS/cups-filters runtime
  --asan-build       minimal + local OpenPrinting ASan build tools/deps
  --afl              minimal + AFL++ tooling
  --all              install all groups (default)

Options:
  --dry-run          print apt-get commands without installing
  --no-update        skip apt-get update
  -y, --yes          pass -y to apt-get install
  -h, --help         show this help

Examples:
  scripts/install_ubuntu_deps.sh --dry-run
  scripts/install_ubuntu_deps.sh --minimal
  scripts/install_ubuntu_deps.sh --asan-build -y
  scripts/install_ubuntu_deps.sh --all -y
EOF
}

print_shell_command() {
  printf '[dry-run]'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
}

mode="all"
dry_run=0
apt_update=1
assume_yes=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --minimal|--system-filters|--asan-build|--afl|--all)
      mode="${1#--}"
      ;;
    --dry-run)
      dry_run=1
      ;;
    --no-update)
      apt_update=0
      ;;
    -y|--yes)
      assume_yes=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"ubuntu"* && "${ID_LIKE:-}" != *"debian"* ]]; then
    echo "[warn] this script is tuned for Ubuntu/Debian; detected ID=${ID:-unknown}" >&2
  fi
fi

sudo_cmd=()
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    sudo_cmd=(sudo)
  else
    echo "sudo is required when not running as root" >&2
    exit 2
  fi
fi

minimal_packages=(
  ca-certificates
  curl
  git
  make
  pkg-config
  python3
  python3-dev
  python3-pip
  python3-venv
)

system_filter_packages=(
  cups
  cups-client
  cups-filters
  cups-ppdc
  ghostscript
  poppler-utils
  qpdf
)

asan_build_packages=(
  autoconf
  automake
  autopoint
  build-essential
  clang
  dbus
  gettext
  gdb
  libavahi-client-dev
  libavahi-common-dev
  libcups2-dev
  libcupsimage2-dev
  libdbus-1-dev
  libexif-dev
  libfontconfig1-dev
  libfreetype6-dev
  libglib2.0-dev
  libijs-dev
  libjpeg-dev
  liblcms2-dev
  libldap2-dev
  libnss-mdns
  libpam0g-dev
  libpaper-dev
  libpng-dev
  libpoppler-cpp-dev
  libpoppler-glib-dev
  libqpdf-dev
  libssl-dev
  libtiff-dev
  libtool
  libxml2-dev
  lld
  llvm
  mupdf-tools
  zlib1g-dev
)

afl_packages=(
  afl++
  clang
  lld
  llvm
)

packages=("${minimal_packages[@]}")
case "$mode" in
  minimal)
    ;;
  system-filters)
    packages+=("${system_filter_packages[@]}")
    ;;
  asan-build)
    packages+=("${asan_build_packages[@]}")
    ;;
  afl)
    packages+=("${afl_packages[@]}")
    ;;
  all)
    packages+=("${system_filter_packages[@]}" "${asan_build_packages[@]}" "${afl_packages[@]}")
    ;;
  *)
    echo "internal error: unknown mode $mode" >&2
    exit 2
    ;;
esac

mapfile -t packages < <(
  for package in "${packages[@]}"; do
    echo "$package"
  done | sort -u
)

available_packages=()
missing_packages=()
for package in "${packages[@]}"; do
  if apt-cache show "$package" >/dev/null 2>&1; then
    available_packages+=("$package")
  else
    missing_packages+=("$package")
  fi
done

install_args=(install)
if [[ "$assume_yes" == "1" ]]; then
  install_args+=(-y)
fi
install_args+=("${available_packages[@]}")

echo "[info] mode: $mode"
echo "[info] packages: ${#available_packages[@]} available"
if [[ "${#missing_packages[@]}" -gt 0 ]]; then
  echo "[warn] unavailable package names on this apt index: ${missing_packages[*]}" >&2
fi

if [[ "$dry_run" == "1" ]]; then
  if [[ "$apt_update" == "1" ]]; then
    print_shell_command "${sudo_cmd[@]}" apt-get update
  fi
  print_shell_command "${sudo_cmd[@]}" apt-get "${install_args[@]}"
  exit 0
fi

if [[ "$apt_update" == "1" ]]; then
  "${sudo_cmd[@]}" apt-get update
fi

"${sudo_cmd[@]}" apt-get "${install_args[@]}"

cat <<'EOF'

[next]
  python3 -m venv .venv
  . .venv/bin/activate
  python3 -m pip install -U pip
  python3 -m pip install -e .
EOF
