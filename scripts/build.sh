#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/node/bin:$PATH"
test "$(go env GOVERSION)" = go1.27.3
test "$(node --version)" = v26.13.0
test "$(bun --version)" = 1.4.2
bun install --frozen-lockfile --cwd web
bun run --cwd web build
python3 scripts/check-dist.py
go build -o bin/peeker ./cmd/peeker
