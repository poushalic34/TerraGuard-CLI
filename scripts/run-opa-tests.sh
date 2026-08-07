#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "==> OPA tests: aws-foundation"
opa test policy-packs/aws-foundation/policies policy-packs/aws-foundation/tests

echo "==> OPA tests: aws-eks"
opa test policy-packs/aws-eks/policies policy-packs/aws-eks/tests

echo "All Rego policy tests passed."
