# CLI Reference

This document describes the planned TerraGuard command interface.

## Global Options

```bash
terraguard [COMMAND] [OPTIONS]
```

Planned global options:

- `--config PATH`: path to `.terraguard.yml`
- `--policy-dir PATH`: additional custom policy directory
- `--no-color`: disable colored terminal output
- `--verbose`: enable detailed logs
- `--quiet`: print only essential output

## `terraguard init`

Initialize TerraGuard in the current repository.

```bash
terraguard init
```

Planned options:

- `--force`: overwrite existing generated files
- `--policy-pack NAME`: add a default policy pack to the generated config

Creates:

- `.terraguard.yml`
- `.terraguard/`
- optional starter policy and report folders

## `terraguard scan`

Scan a Terraform plan against selected OPA/Rego policy packs.

```bash
terraguard scan --tfplan tfplan
```

Planned options:

- `--tfplan PATH`: Terraform binary plan file created by `terraform plan -out=tfplan`
- `--plan-json PATH`: Terraform plan JSON file created by `terraform show -json`
- `--dir PATH`: Terraform project directory
- `--policy-pack NAME`: policy pack to use, repeatable
- `--fail-on SEVERITY`: minimum severity that causes a non-zero exit
- `--format FORMAT`: output format, such as `console`, `json`, `markdown`, `html`, or `sarif`
- `--output PATH`: write output to a file

Examples:

```bash
terraguard scan --tfplan tfplan
terraguard scan --tfplan tfplan --policy-pack aws-foundation --policy-pack aws-eks
terraguard scan --tfplan tfplan --fail-on high
terraguard scan --tfplan tfplan --format json --output terraguard-results.json
```

## `terraguard explain`

Explain a policy or finding.

```bash
terraguard explain TG_AWS_S3_001
```

Planned options:

- `--policy-pack NAME`: restrict lookup to a policy pack
- `--json`: print explanation as JSON

Output should include:

- Policy ID
- Title
- Severity
- Why it matters
- What resources it checks
- Example failure
- Remediation guidance

## `terraguard generate`

Generate starter files.

```bash
terraguard generate github-action
```

Planned generators:

- `policy`: create a starter Rego policy
- `github-action`: create a GitHub Actions workflow
- `gitlab-ci`: create a GitLab CI workflow
- `sample-terraform`: create vulnerable or secure Terraform examples
- `config`: create a TerraGuard config file

Examples:

```bash
terraguard generate policy --resource s3
terraguard generate github-action
terraguard generate sample-terraform --stack eks --profile vulnerable
```

## `terraguard list-policies`

List available policy packs and policies.

```bash
terraguard list-policies
```

Planned options:

- `--policy-pack NAME`: list policies from one pack
- `--resource RESOURCE`: filter by resource area
- `--severity SEVERITY`: filter by severity
- `--format FORMAT`: output as `table` or `json`

Examples:

```bash
terraguard list-policies
terraguard list-policies --policy-pack aws-eks
terraguard list-policies --resource s3
terraguard list-policies --severity high
```

## `terraguard validate`

Validate TerraGuard config and policy syntax.

```bash
terraguard validate
```

Planned options:

- `--config PATH`: validate a specific config file
- `--policies PATH`: validate a policy directory
- `--policy-pack NAME`: validate a built-in policy pack

Examples:

```bash
terraguard validate
terraguard validate --config .terraguard.yml
terraguard validate --policy-pack aws-foundation
```

## `terraguard report`

Render a report from scan results.

```bash
terraguard report --input terraguard-results.json --format markdown
```

Planned options:

- `--input PATH`: scan result JSON file
- `--format FORMAT`: `markdown`, `html`, `json`, or `sarif`
- `--output PATH`: report output path

Examples:

```bash
terraguard report --input terraguard-results.json --format markdown --output terraguard-report.md
terraguard report --input terraguard-results.json --format html --output terraguard-report.html
terraguard report --input terraguard-results.json --format sarif --output terraguard.sarif
```

## `terraguard doctor`

Check whether the local environment is ready to run TerraGuard.

```bash
terraguard doctor
```

Checks:

- Terraform is installed
- OPA is installed
- `.terraguard.yml` exists and is valid
- Selected policy packs are available
- Terraform plan input can be parsed

Planned options:

- `--json`: print machine-readable diagnostics

## `terraguard version`

Print TerraGuard version information.

```bash
terraguard version
```

Planned output:

- TerraGuard version
- Python version
- Terraform version, when available
- OPA version, when available
