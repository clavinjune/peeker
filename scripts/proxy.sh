#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec kubectl --context rancher-desktop --as=system:serviceaccount:peeker-system:peeker-reader --as-group=system:serviceaccounts --as-group=system:serviceaccounts:peeker-system --as-group=system:authenticated proxy --address=127.0.0.1 --port=8001 --accept-hosts='^127\.0\.0\.1$,^localhost$,^\[::1\]$' --reject-methods='POST,PUT,PATCH,DELETE,CONNECT,TRACE'
