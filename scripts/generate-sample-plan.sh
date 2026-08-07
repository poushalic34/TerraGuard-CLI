#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-examples/terraform/vulnerable-aws}"

if [[ "${TARGET}" != /* ]]; then
  TARGET="${ROOT_DIR}/${TARGET}"
fi

if [[ ! -d "${TARGET}" ]]; then
  echo "Terraform directory not found: ${TARGET}" >&2
  exit 1
fi

cd "${TARGET}"

terraform init -input=false -backend=false
terraform validate
terraform plan -out=tfplan -input=false -lock=false
terraform show -json tfplan > tfplan.json

echo "Wrote ${TARGET}/tfplan"
echo "Wrote ${TARGET}/tfplan.json"
