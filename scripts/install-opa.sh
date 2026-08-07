#!/usr/bin/env bash
set -euo pipefail

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

case "${OS}" in
  linux) ASSET="opa_linux_${ARCH}_static" ;;
  darwin) ASSET="opa_darwin_${ARCH}" ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    exit 1
    ;;
esac

curl -fsSL -o opa "https://openpolicyagent.org/downloads/latest/${ASSET}"
chmod +x opa

if [[ "${EUID}" -eq 0 ]]; then
  mv opa /usr/local/bin/opa
else
  sudo mv opa /usr/local/bin/opa
fi

opa version
