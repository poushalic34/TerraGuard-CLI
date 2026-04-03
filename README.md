# TerraGuard CLI

TerraGuard CLI is a personal platform engineering and DevSecOps project for shift-left Terraform security validation using OPA/Rego policy as code.

The goal is to build a realistic developer-facing CLI that scans Terraform plans before `terraform apply`, evaluates AWS and EKS infrastructure against policy packs, explains violations clearly, and produces CI-friendly reports.

## Project Positioning

TerraGuard is designed to demonstrate practical knowledge across:

- Terraform plan workflows
- OPA/Rego policy authoring
- AWS cloud security controls
- EKS platform security
- Python CLI and backend engineering
- CI/CD policy gates
- Developer experience for platform tooling

The portfolio story:

> I built a Python CLI that validates Terraform plans against OPA/Rego policy packs for AWS and EKS security, produces developer-friendly explanations and CI-ready reports, and demonstrates shift-left cloud governance.

## Core Workflow

```text
Developer writes Terraform
        |
        v
terraform plan -out=tfplan
        |
        v
TerraGuard reads Terraform plan
        |
        v
terraform show -json tfplan
        |
        v
OPA evaluates Rego policy packs
        |
        v
Findings, explanations, reports, CI exit code
```

The preferred developer workflow is:

```bash
terraform plan -out=tfplan
terraguard scan --tfplan tfplan
```

TerraGuard should handle the `terraform show -json` conversion internally so users do not need to create intermediate JSON files by hand.

## Target Scope

TerraGuard is AWS-first and EKS-focused. The first version validates Terraform-defined AWS infrastructure, especially resources commonly owned by platform and cloud security teams.

Primary resource areas:

- S3
- EC2
- EKS
- EBS
- KMS
- Security Groups
- VPC
- IAM

## Planned Commands

```bash
terraguard init
terraguard scan
terraguard explain
terraguard generate
terraguard list-policies
terraguard validate
terraguard report
terraguard doctor
terraguard version
```

Command intent:

- `init`: create `.terraguard.yml` and starter local folders
- `scan`: run Terraform plan validation against selected policy packs
- `explain`: explain a policy or finding with remediation guidance
- `generate`: scaffold policies, CI config, sample Terraform, or reports
- `list-policies`: show available built-in policies
- `validate`: validate TerraGuard config and Rego policy syntax
- `report`: generate JSON, Markdown, HTML, or SARIF reports
- `doctor`: verify local dependencies and project readiness
- `version`: print TerraGuard version information

## Policy Packs

Policies should be grouped as packs rather than kept as one flat rules folder.

Planned built-in packs:

- `aws-foundation`
- `aws-storage`
- `aws-networking`
- `aws-compute`
- `aws-iam`
- `aws-eks`

Example policies:

- S3 public access must be blocked
- S3 buckets must use server-side encryption
- EC2 instances must require IMDSv2
- EBS volumes must be encrypted
- KMS key rotation must be enabled
- Security groups must not expose SSH or RDP to `0.0.0.0/0`
- VPC flow logs must be enabled
- EKS public endpoint access must be disabled or restricted
- EKS control plane logging must be enabled
- EKS secrets encryption must use KMS
- EKS node groups must not run in public subnets
- IAM policies must avoid wildcard actions and resources

## Recommended Local Sequence

First-time setup:

```bash
terraguard init
terraguard doctor
```

Normal developer loop:

```bash
terraform init
terraform validate
terraform plan -out=tfplan
terraguard scan --tfplan tfplan
```

After a violation:

```bash
terraguard explain TG_AWS_S3_001
```

Optional report:

```bash
terraguard report --input terraguard-results.json --format markdown
```

## Recommended CI Sequence

```bash
terraguard doctor
terraform init -input=false
terraform validate
terraform plan -out=tfplan -input=false
terraguard validate
terraguard scan --tfplan tfplan --format json --output terraguard-results.json
terraguard report --input terraguard-results.json --format markdown --output terraguard-report.md
```

The scan command should return non-zero when violations meet or exceed the configured failure threshold.

## MVP

The first useful version includes:

- Python CLI using Typer or Click
- Terraform binary plan support through `terraform show -json`
- OPA execution through the local `opa` binary
- Built-in AWS foundation and AWS EKS policy packs
- Human-readable terminal output
- JSON output for CI
- `.terraguard.yml` config support
- Policy explanations with remediation guidance
- Rego syntax validation
- Sample vulnerable Terraform
- GitHub Actions example
- Unit tests for core parsing, policy loading, findings, and output formatting

## Later Enhancements

- SARIF output for GitHub code scanning
- HTML reports
- `terraguard generate github-action`
- `terraguard generate sample-terraform --stack eks`
- Custom organization policy packs
- Pre-commit integration
- Docker image
- FastAPI service for scan APIs
- Kubernetes manifest scanning for EKS workloads
- Policy test runner with fixtures

## Documentation

- [Architecture](docs/architecture.md)
- [File Structure](docs/file-structure.md)
- [CLI Reference](docs/cli-reference.md)
