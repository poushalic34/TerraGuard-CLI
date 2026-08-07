# CLI Reference

TerraGuard command interface (implemented).

## Commands

| Command | Purpose |
|---------|---------|
| `init` | Create `.terraguard.yml`, `.terraguard/`, `.terraguard-ignore.yml` |
| `scan` | Evaluate a Terraform/OpenTofu plan against policy packs |
| `explain` | Explain a policy ID (controls, remediation, suggested HCL) |
| `generate` | Scaffold github-action, pre-commit, or policy files |
| `list-policies` | List packs/policies (`--as-json`) |
| `validate` | Validate config + Rego via `opa fmt` |
| `report` | Re-render scan JSON as markdown/html/json/sarif/pr-comment |
| `comment` | Render or post a sticky GitHub PR comment from scan JSON |
| `coverage` | Show plan resource types vs covering policies |
| `packs add\|list` | Install/list custom packs under `.terraguard/packs` |
| `doctor` | Check terraform/tofu, opa, config, packs, suppressions |
| `version` | Print version |

## `terraguard scan`

```bash
terraguard scan --tfplan tfplan
terraguard scan --plan-json plan.json --policy-pack aws-foundation --fail-on high
terraguard scan --plan-json plan.json --changed-only --suppressions .terraguard-ignore.yml
terraguard scan --tfplan tfplan --terraform-binary tofu --format sarif --output terraguard.sarif
```

Key options:

- `--tfplan` / `--plan-json`
- `--policy-pack` (repeatable)
- `--policy-dir` (repeatable custom pack roots)
- `--suppressions`
- `--changed-only`
- `--terraform-binary` (`terraform` or `tofu`)
- `--fail-on`
- `--format` (`console`, `json`, `markdown`, `html`, `sarif`)
- `--output`

Exit codes: `0` pass, `1` failed threshold or expired suppressions, `2` usage/dependency/config error.

## Suppressions

`.terraguard-ignore.yml`:

```yaml
suppressions:
  - policy_id: TG_AWS_SG_001
    resource: aws_security_group\.legacy
    expires: "2026-12-31"
    owner: platform@example.com
    ticket: SEC-123
    reason: Pending SSM migration
```

Expired suppressions fail the scan even if no active findings remain.

## `terraguard generate`

```bash
terraguard generate github-action
terraguard generate pre-commit
terraguard generate policy --id TG_AWS_RDS_003 --resource-type aws_db_instance --pack aws-foundation --resource rds
```

## `terraguard coverage`

```bash
terraguard coverage --plan-json plan.json --as-json
```

## `terraguard packs`

```bash
terraguard packs add ./my-org-pack
terraguard packs add https://github.com/org/terraguard-packs.git --name org-baseline
terraguard packs list
```

## `terraguard comment`

Render a sticky PR comment body, or post/update it on GitHub.

```bash
terraguard comment --input terraguard-results.json --output comment.md
terraguard comment --input terraguard-results.json --post --title "TerraGuard Policy Scan"
```

`--post` uses `GITHUB_TOKEN` / `GH_TOKEN`, `GITHUB_REPOSITORY`, and the PR number from
`--pr`, `GITHUB_PR_NUMBER`, or `GITHUB_EVENT_PATH`. Comments are upserted using the
`<!-- terraguard-scan-report -->` marker so re-runs update the same thread.

## Findings schema

Scan JSON includes `schema_version` and conforms to
`terraguard/schema/findings.schema.json`.
