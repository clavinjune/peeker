#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(go env GOVERSION)" = go1.27.3 || { echo 'Go 1.27.3 is required; no substitution permitted.' >&2; exit 1; }
test "$(uname -s)/$(uname -m)" = Darwin/arm64 || { echo 'This bootstrap pins the verified macOS arm64 archives. Select and verify official archives for another platform.' >&2; exit 1; }
mkdir -p .tools .local
DOWNLOAD=$(mktemp -d "$PWD/.local/download.XXXXXX")
trap 'rm -rf "$DOWNLOAD"' EXIT
if ! test -d .tools/node; then
  curl --fail --location --silent --show-error https://nodejs.org/dist/v26.13.0/node-v26.13.0-darwin-arm64.tar.gz -o "$DOWNLOAD/node.tar.gz"
  printf '%s  %s\n' d38bd5e5a2ddce6bbb5ce45e46e208337da4d51fffe611e567fd32073d6439f6 "$DOWNLOAD/node.tar.gz" | shasum -a 256 -c -
  tar -xzf "$DOWNLOAD/node.tar.gz" -C "$DOWNLOAD"
  mv "$DOWNLOAD/node-v26.13.0-darwin-arm64" .tools/node
fi
test "$(.tools/node/bin/node --version)" = v26.13.0
if ! test -d .tools/istio; then
  curl --fail --location --silent --show-error https://github.com/istio/istio/releases/download/1.32.0/istio-1.32.0-osx-arm64.tar.gz -o "$DOWNLOAD/istio.tar.gz"
  curl --fail --location --silent --show-error https://github.com/istio/istio/releases/download/1.32.0/istio-1.32.0-osx-arm64.tar.gz.sha256 -o "$DOWNLOAD/istio.sha256"
  EXPECTED=$(awk '{print $1}' "$DOWNLOAD/istio.sha256")
  printf '%s  %s\n' "$EXPECTED" "$DOWNLOAD/istio.tar.gz" | shasum -a 256 -c -
  tar -xzf "$DOWNLOAD/istio.tar.gz" -C "$DOWNLOAD"
  mv "$DOWNLOAD/istio-1.32.0" .tools/istio
fi
.tools/istio/bin/istioctl version --remote=false
test "$(bun --version)" = 1.4.2
printf 'Toolchain verified. Use: export PATH="%s/.tools/node/bin:$PATH"\n' "$PWD"
