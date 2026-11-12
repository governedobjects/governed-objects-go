#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brafford Labs, LLC
# Launcher for the Go conformance adapter: builds it against the runtime in ../ (the
# module root that contains this directory) and runs it, speaking the adapter protocol
# on stdin/stdout. The conformance runner treats this exactly like a third-party adapter:
#
#   python -m runner --adapter-command "path/to/governed-objects-go/conformance-adapter/launch.sh"
#
# Requirements: a Go toolchain on PATH (or CONFORMANCE_GO_BIN pointing at its bin
# directory). Nothing is downloaded: GOTOOLCHAIN=local and GOPROXY=off are forced.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${CONFORMANCE_GO_BIN:-}" ]]; then
  export PATH="$CONFORMANCE_GO_BIN:$PATH"
fi
command -v go >/dev/null || { echo "launch.sh: no go toolchain on PATH (set CONFORMANCE_GO_BIN)" >&2; exit 127; }
export GOTOOLCHAIN=local GOPROXY=off GOWORK=off
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
(cd "$here" && go build -o "$tmp/adapter" .) >&2
"$tmp/adapter"
