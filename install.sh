#!/bin/sh
# Installs the adera CLI. The console serves this script at /cli/install.sh with
# ADERA_CLI_DOWNLOAD_URL set to the organisation's release mirror.
#
#   curl -fsSL https://secrets.example.com/cli/install.sh | sh
#
# Environment: ADERA_CLI_DOWNLOAD_URL (required when run standalone),
#              ADERA_INSTALL_DIR (default /usr/local/bin if writable, else ~/.local/bin).
set -eu

base="${ADERA_CLI_DOWNLOAD_URL:-}"
[ -n "$base" ] || { echo "adera install: set ADERA_CLI_DOWNLOAD_URL" >&2; exit 1; }
case "$base" in https://*) ;; *) echo "adera install: ADERA_CLI_DOWNLOAD_URL must be https" >&2; exit 1 ;; esac
base="${base%/}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "adera install: unsupported OS $(uname -s); download the binary manually from $base" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "adera install: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then sha="sha256sum"
elif command -v shasum >/dev/null 2>&1; then sha="shasum -a 256"
else echo "adera install: need sha256sum or shasum to verify the download" >&2; exit 1; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
name="adera_${os}_${arch}"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$name" "$base/$name"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
expected="$(grep " $name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
actual="$(cd "$tmp" && $sha "$name" | cut -d' ' -f1)"
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "adera install: checksum mismatch for $name" >&2; exit 1; }

dir="${ADERA_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/$name" "$dir/adera"
echo "Installed $("$dir/adera" version) to $dir/adera"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to your PATH." ;; esac
