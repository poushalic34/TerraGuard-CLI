#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PLAN_JSON="${1:-tests/fixtures/tfplans/aws_foundation_violations.json}"

echo "==> TerraGuard scan"
.venv/bin/python -m terraguard scan --plan-json "${PLAN_JSON}" --policy-pack aws-foundation --format json --output /tmp/tg-bench.json || true
python - <<'PY'
import json
from pathlib import Path
data = json.loads(Path("/tmp/tg-bench.json").read_text())
print(f"TerraGuard findings: {data['summary']['total']}")
PY

if command -v checkov >/dev/null 2>&1; then
  echo "==> Checkov scan (if installed)"
  checkov -f "${PLAN_JSON}" --framework terraform_plan -o json --compact > /tmp/checkov-bench.json || true
  python - <<'PY'
import json
from pathlib import Path
raw = Path("/tmp/checkov-bench.json").read_text().strip()
if not raw:
    print("Checkov produced empty output")
else:
    data = json.loads(raw)
    failed = data.get("summary", {}).get("failed") or data.get("results", {}).get("failed_checks")
    print(f"Checkov summary failed field: {failed}")
PY
else
  echo "Checkov not installed; skipping comparison. pip install checkov to enable."
fi
