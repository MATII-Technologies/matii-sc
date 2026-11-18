#!/bin/sh
# Builds release binaries into dist/: adera_<os>_<arch>[.exe] and SHA256SUMS.
# Usage: scripts/dist.sh VERSION
set -eu
version="${1:?usage: scripts/dist.sh VERSION}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/dist"
rm -rf "$out" && mkdir -p "$out"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  ext=""; [ "$os" = windows ] && ext=".exe"
  (cd "$root/go" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out/adera_${os}_${arch}${ext}" ./cmd/adera)
done
(cd "$out" && sha256sum adera_* > SHA256SUMS)
cp "$root/install.sh" "$out/install.sh"
echo "dist/ ready for $version"
