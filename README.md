# TerraGuard CLI

Shift-left Terraform and OpenTofu security validation using OPA/Rego policy as code.

TerraGuard scans infrastructure plans **before** `apply`, evaluates AWS and EKS resources against versioned policy packs, explains violations with remediation guidance, and produces CI-friendly reports — including SARIF and sticky GitHub PR comments.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why TerraGuard?

Platform and cloud security teams need a developer-facing gate that:

- Works on real `terraform show -json` / `tofu show -json` output
- Groups rules into packs (not a flat pile of scripts)
- Fails CI on severity thresholds
- Supports suppressions with expiry and ownership
- Explains *why* a finding matters and how to fix it

## Features

- **Plan-first scanning** — binary plans (`--tfplan`) or plan JSON (`--plan-json`)
- **OpenTofu support** — auto-detects `terraform` or `tofu`, or set `--terraform-binary`
- **Built-in packs** — `aws-foundation` and `aws-eks` (28 policies)
- **Custom packs** — `--policy-dir` or `terraguard packs add` (path or git)
- **Severity gate** — `--fail-on` / `fail_on` in `.terraguard.yml`
- **Changed-only mode** — evaluate create/update/delete/replace resources
- **Suppressions** — `.terraguard-ignore.yml` with expiry, owner, ticket, reason
- **Coverage** — which plan resource types are covered by policies
- **Outputs** — console, JSON, Markdown, HTML, SARIF, PR comment
- **Sticky PR comments** — `terraguard comment --post` upserts one GitHub comment
- **Explanations** — CIS/FSBP control IDs + optional HCL fix snippets
- **Generators** — GitHub Action, pre-commit config, policy scaffolding
- **OPA Rego tests** — pack-level unit tests run in CI

## Requirements

- Python 3.10+
- [OPA](https://www.openpolicyagent.org/) on `PATH`
- Terraform and/or OpenTofu (needed for `--tfplan`)

## Install

```bash
# From source (recommended while developing)
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Install OPA (macOS)
brew install opa

# Or via project script (Linux/macOS)
bash scripts/install-opa.sh
```

Entry point:

```bash
terraguard --help
python -m terraguard --help
```

## Quick start

```bash
# Optional project bootstrap
terraguard init
terraguard doctor

# From a Terraform root
terraform init
terraform plan -out=tfplan
terraguard scan --tfplan tfplan

# Or from plan JSON
terraform show -json tfplan > tfplan.json
terraguard scan --plan-json tfplan.json --format json --output terraguard-results.json
```

Demo against checked-in fixtures (no cloud account):

```bash
terraguard scan \
  --plan-json tests/fixtures/tfplans/aws_foundation_violations.json \
  --policy-pack aws-foundation \
  --format console
```

Offline example stacks (mock AWS provider):

```bash
./scripts/generate-sample-plan.sh examples/terraform/vulnerable-aws
terraguard scan --plan-json examples/terraform/vulnerable-aws/tfplan.json --policy-pack aws-foundation
```

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create `.terraguard.yml`, `.terraguard/`, `.terraguard-ignore.yml` |
| `scan` | Evaluate a plan against selected packs |
| `explain` | Show why a policy matters and how to fix it |
| `list-policies` | List packs/policies (`--as-json`) |
| `validate` | Validate config + Rego syntax |
| `report` | Re-render scan JSON (`markdown`, `html`, `json`, `sarif`, `pr-comment`) |
| `comment` | Render or post a sticky GitHub PR comment |
| `coverage` | Map plan resource types to covering policies |
| `packs add\|list` | Install/list custom packs under `.terraguard/packs` |
| `generate` | Scaffold `github-action`, `pre-commit`, or a new policy |
| `doctor` | Check terraform/tofu, opa, config, packs, suppressions |
| `version` | Print version information |

### Scan examples

```bash
# Multiple packs + severity gate
terraguard scan --tfplan tfplan \
  --policy-pack aws-foundation \
  --policy-pack aws-eks \
  --fail-on high

# Diff-aware (skip no-op / read)
terraguard scan --plan-json tfplan.json --changed-only

# OpenTofu binary plan
terraguard scan --tfplan tfplan --terraform-binary tofu

# SARIF for code scanning
terraguard scan --tfplan tfplan --format sarif --output terraguard.sarif

# Suppressions file
terraguard scan --plan-json tfplan.json --suppressions .terraguard-ignore.yml
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Pass |
| `1` | Findings at/above fail threshold, or expired suppressions |
| `2` | User/config/dependency/plan error |

### Explain

```bash
terraguard explain TG_AWS_SG_001
terraguard explain --as-json TG_AWS_EKS_001
```

### Sticky PR comment

```bash
terraguard scan --tfplan tfplan --format json --output terraguard-results.json || true
terraguard comment --input terraguard-results.json --post --title "TerraGuard Policy Scan"
```

Requires `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and a PR number (`--pr` or GitHub Actions event payload). Re-runs update the same comment using the `<!-- terraguard-scan-report -->` marker.

### Coverage

```bash
terraguard coverage --plan-json tfplan.json --as-json
```

### Custom packs

```bash
terraguard packs add ./my-org-pack
terraguard packs add https://github.com/org/terraguard-packs.git --name org-baseline
terraguard packs list

terraguard scan --plan-json tfplan.json --policy-dir .terraguard/packs --policy-pack org-baseline
```

### Generators

```bash
terraguard generate github-action
terraguard generate pre-commit
terraguard generate policy \
  --id TG_AWS_RDS_003 \
  --resource-type aws_db_instance \
  --pack aws-foundation \
  --resource rds \
  --title "RDS backup retention"
```

## Configuration

`.terraguard.yml` (see `.terraguard.yml.example`):

```yaml
version: 1
policy_packs:
  - aws-foundation
  - aws-eks
fail_on: high
changed_only: false
# policy_dirs:
#   - .terraguard/packs
# suppressions_path: .terraguard-ignore.yml
# terraform_binary: terraform
output:
  format: console
  path: null
```

### Suppressions

`.terraguard-ignore.yml` (see `.terraguard-ignore.yml.example`):

```yaml
suppressions:
  - policy_id: TG_AWS_SG_001
    resource: aws_security_group\.legacy_bastion
    expires: "2026-12-31"
    owner: platform@example.com
    ticket: SEC-123
    reason: Pending SSM migration
```

- `resource` is a full-match regex against the Terraform address
- Expired suppressions **fail** the scan even if no active findings remain

## Policy packs

### `aws-foundation`

S3 public access / versioning, EC2 IMDSv2, EBS encryption, KMS rotation, security groups (SSH/RDP/all-ports), VPC flow logs, IAM wildcards and trust principals, RDS encryption/public access, CloudTrail, load balancer HTTP/TLS.

### `aws-eks`

Public endpoint controls and CIDRs, control plane logging (including audit/authenticator), secrets encryption, public node subnets, node SSH remote access, addon version pins, IRSA trust wildcards, private endpoint guidance.

Policies declare optional CIS / AWS Foundational Security Best Practices control IDs in `pack.yml`, surfaced by `explain` and `list-policies`.

Run Rego unit tests:

```bash
bash scripts/run-opa-tests.sh
# or
opa test policy-packs/aws-foundation/policies policy-packs/aws-foundation/tests
opa test policy-packs/aws-eks/policies policy-packs/aws-eks/tests
```

## CI/CD

### Recommended pipeline

```bash
terraguard doctor
terraform init -input=false
terraform validate
terraform plan -out=tfplan -input=false
terraguard validate
terraguard scan --tfplan tfplan --format json --output terraguard-results.json
terraguard report --input terraguard-results.json --format markdown --output terraguard-report.md
terraguard comment --input terraguard-results.json --post   # on pull_request
```

### In this repo

- `.github/workflows/test.yml` — lint, pytest, OPA tests
- `.github/workflows/terraguard-demo.yml` — plan example stacks, assert findings, upload SARIF, post PR comments
- `examples/ci/github-actions.yml` — copy-paste starter for consuming repos
- `terraguard generate github-action` — scaffold a workflow with SARIF + sticky comments

## Examples

| Path | Purpose |
|------|---------|
| `examples/terraform/vulnerable-aws` | Intentionally insecure AWS resources |
| `examples/terraform/secure-aws` | Hardened counterpart |
| `examples/terraform/eks-vulnerable` | Insecure EKS settings |
| `examples/terraform/eks-secure` | Hardened EKS settings |
| `examples/reports/sample-*` | Sample scan JSON / Markdown |
| `tests/fixtures/tfplans/` | Deterministic plan JSON for tests |

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
bash scripts/run-opa-tests.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [Architecture](docs/architecture.md)
- [CLI reference](docs/cli-reference.md)
- [Repository layout](docs/file-structure.md)
- [Terraform plan JSON quirks](docs/terraform-plan-quirks.md)

## Findings schema

Machine-readable scan output includes `schema_version` and follows
[`terraguard/schema/findings.schema.json`](terraguard/schema/findings.schema.json).

## License

MIT — see [LICENSE](LICENSE).
