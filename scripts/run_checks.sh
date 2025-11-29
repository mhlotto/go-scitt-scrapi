#!/usr/bin/env bash
set -euo pipefail

# Basic lint/security checks for this repo. Installs tools locally (GOBIN or GOPATH/bin) if missing.

STATICCHECK=${STATICCHECK:-"$(command -v staticcheck || true)"}
GOSEC=${GOSEC:-"$(command -v gosec || true)"}

install_tool() {
  local pkg=$1
  echo "Installing $pkg"
  go install "$pkg"
}

if [[ -z "$STATICCHECK" ]]; then
  install_tool honnef.co/go/tools/cmd/staticcheck@latest
  STATICCHECK=$(command -v staticcheck)
fi

if [[ -z "$GOSEC" ]]; then
  install_tool github.com/securego/gosec/v2/cmd/gosec@latest
  GOSEC=$(command -v gosec)
fi

echo "Running staticcheck..."
"$STATICCHECK" ./...

echo "Running gosec..."
"$GOSEC" ./...

echo "Checks completed."
