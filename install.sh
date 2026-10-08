#!/bin/sh
set -eu

VERSION="1.0.1"
PREFIX="${HOME}/.local"
FORCE=0
DRY_RUN=0
UNINSTALL=0
VERIFY=1
REPOSITORY="https://github.com/devdasx/wallet-hd-derivation-kit"

usage() {
  printf '%s\n' "Usage: install.sh [--version VERSION] [--prefix PATH] [--force] [--dry-run] [--no-verify] [--uninstall]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version requires a value}"; shift 2 ;;
    --prefix) PREFIX="${2:?--prefix requires a value}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-verify) VERIFY=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

destination="${PREFIX}/bin/wallethd"
if [ "$UNINSTALL" -eq 1 ]; then
  [ "$DRY_RUN" -eq 1 ] && { printf 'Would remove %s\n' "$destination"; exit 0; }
  rm -f "$destination"
  printf 'Removed %s\n' "$destination"
  exit 0
fi

case "$(uname -s)" in
  Darwin) os=macos ;;
  Linux) os=linux ;;
  *) printf 'Unsupported operating system\n' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch=arm64 ;;
  x86_64|amd64) arch=x86_64 ;;
  *) printf 'Unsupported architecture\n' >&2; exit 1 ;;
esac

artifact="wallethd-v${VERSION}-${os}-${arch}.tar.gz"
release="${REPOSITORY}/releases/download/v${VERSION}"
if [ "$DRY_RUN" -eq 1 ]; then
  printf 'Would download %s/%s, verify it, and install to %s\n' "$release" "$artifact" "$destination"
  exit 0
fi
if [ -e "$destination" ] && [ "$FORCE" -ne 1 ]; then
  printf '%s exists; pass --force to replace it\n' "$destination" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl --fail --location --proto '=https' --tlsv1.2 "${release}/${artifact}" --output "${tmp}/${artifact}"
if [ "$VERIFY" -eq 1 ]; then
  curl --fail --location --proto '=https' --tlsv1.2 "${release}/SHA256SUMS" --output "${tmp}/SHA256SUMS"
  expected="$(awk -v file="$artifact" '$2 == file {print $1}' "${tmp}/SHA256SUMS")"
  [ -n "$expected" ] || { printf 'Artifact is absent from SHA256SUMS\n' >&2; exit 1; }
  actual="$(shasum -a 256 "${tmp}/${artifact}" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || { printf 'Checksum verification failed\n' >&2; exit 1; }
fi
tar -xzf "${tmp}/${artifact}" -C "$tmp"
mkdir -p "${PREFIX}/bin"
install -m 0755 "${tmp}/wallethd" "$destination"
"$destination" version
printf 'Installed %s. Add %s/bin to PATH if needed.\n' "$destination" "$PREFIX"
