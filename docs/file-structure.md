# File Structure

Planned repository structure for TerraGuard CLI.

```text
TerraGuard-CLI/
  README.md
  pyproject.toml
  LICENSE
  .gitignore
  .terraguard.yml.example

  terraguard/
    __init__.py
    __main__.py
    cli.py
    config.py
    constants.py
    exceptions.py

    commands/
      __init__.py
      init.py
      scan.py
      explain.py
      generate.py
      list_policies.py
      validate.py
      report.py
      doctor.py
      version.py

    core/
      __init__.py
      terraform.py
      opa.py
      scanner.py
      findings.py
      policy_loader.py
      severity.py

    output/
      __init__.py
      console.py
      json.py
      markdown.py
      html.py
      sarif.py

    templates/
      terraguard.yml
      github-actions.yml
      pre-commit-config.yml

  policy-packs/
    aws-foundation/
      pack.yml
      policies/
        s3.rego
        ec2.rego
        ebs.rego
        kms.rego
        iam.rego
        security_group.rego
        vpc.rego
      tests/
        s3_test.rego
        ec2_test.rego
        security_group_test.rego

    aws-eks/
      pack.yml
      policies/
        eks_cluster.rego
        eks_node_group.rego
        eks_addons.rego
        eks_networking.rego
        eks_iam.rego
      tests/
        eks_cluster_test.rego
        eks_node_group_test.rego

  examples/
    terraform/
      vulnerable-aws/
        main.tf
        variables.tf
        outputs.tf
        README.md

      secure-aws/
        main.tf
        variables.tf
        outputs.tf
        README.md

      eks-vulnerable/
        main.tf
        variables.tf
        outputs.tf
        README.md

      eks-secure/
        main.tf
        variables.tf
        outputs.tf
        README.md

    ci/
      github-actions.yml
      gitlab-ci.yml

    reports/
      sample-report.md
      sample-results.json

  tests/
    unit/
      test_config.py
      test_policy_loader.py
      test_findings.py
      test_severity.py
      test_terraform.py
      test_opa.py

    integration/
      test_scan_tfplan.py
      test_cli_scan.py
      test_cli_validate.py
      test_cli_report.py

    fixtures/
      tfplans/
        s3_public.json
        eks_public_endpoint.json
        security_group_open_ssh.json
      policies/
        sample_policy.rego
      configs/
        valid_terraguard.yml
        invalid_terraguard.yml

  docs/
    architecture.md
    file-structure.md
    cli-reference.md
    policy-authoring.md
    ci-integration.md
    examples.md

  scripts/
    install-opa.sh
    generate-sample-plan.sh

  .github/
    workflows/
      test.yml
      lint.yml
      terraguard-demo.yml
```

## Root Files

- `README.md`: project overview, product plan, workflows, and MVP scope.
- `pyproject.toml`: Python package metadata, dependencies, CLI entry point, and tooling config.
- `LICENSE`: project license.
- `.gitignore`: ignored local, Python, Terraform, and generated report files.
- `.terraguard.yml.example`: example project configuration.

## Python Package

- `terraguard/`: main Python package for the CLI application.
- `terraguard/__init__.py`: package metadata and version exports.
- `terraguard/__main__.py`: enables `python -m terraguard`.
- `terraguard/cli.py`: root command registration and global options.
- `terraguard/config.py`: configuration loading and validation.
- `terraguard/constants.py`: shared constants such as default paths and policy pack names.
- `terraguard/exceptions.py`: custom exception types and CLI error mapping.

## Commands

- `terraguard/commands/init.py`: creates starter config and local project folders.
- `terraguard/commands/scan.py`: runs Terraform plan policy evaluation.
- `terraguard/commands/explain.py`: prints policy and violation explanations.
- `terraguard/commands/generate.py`: scaffolds policies, CI files, examples, and reports.
- `terraguard/commands/list_policies.py`: lists policy packs and rules.
- `terraguard/commands/validate.py`: validates config and Rego syntax.
- `terraguard/commands/report.py`: renders reports from scan result files.
- `terraguard/commands/doctor.py`: checks local dependencies and project readiness.
- `terraguard/commands/version.py`: prints version and environment details.

## Core Logic

- `terraguard/core/terraform.py`: handles Terraform plan conversion and plan JSON parsing.
- `terraguard/core/opa.py`: runs OPA evaluations and parses decisions.
- `terraguard/core/scanner.py`: coordinates config, plan loading, policy loading, OPA, and findings.
- `terraguard/core/findings.py`: defines the normalized finding model.
- `terraguard/core/policy_loader.py`: discovers built-in and custom policy packs.
- `terraguard/core/severity.py`: parses and compares severity thresholds.

## Output

- `terraguard/output/console.py`: human-readable terminal output.
- `terraguard/output/json.py`: machine-readable JSON output.
- `terraguard/output/markdown.py`: Markdown report rendering.
- `terraguard/output/html.py`: HTML report rendering.
- `terraguard/output/sarif.py`: SARIF output for code scanning integrations.

## Policy Packs

- `policy-packs/aws-foundation/`: baseline AWS security rules.
- `policy-packs/aws-foundation/pack.yml`: metadata for the AWS foundation policy pack.
- `policy-packs/aws-foundation/policies/`: Rego policies for S3, EC2, EBS, KMS, IAM, security groups, and VPC.
- `policy-packs/aws-foundation/tests/`: Rego tests for foundation policies.
- `policy-packs/aws-eks/`: EKS-specific platform security rules.
- `policy-packs/aws-eks/pack.yml`: metadata for the AWS EKS policy pack.
- `policy-packs/aws-eks/policies/`: Rego policies for EKS clusters, node groups, addons, networking, and IAM.
- `policy-packs/aws-eks/tests/`: Rego tests for EKS policies.

## Examples

- `examples/terraform/vulnerable-aws/`: intentionally insecure AWS Terraform for demo scans.
- `examples/terraform/secure-aws/`: corrected AWS Terraform for passing scans.
- `examples/terraform/eks-vulnerable/`: intentionally insecure EKS Terraform for demo scans.
- `examples/terraform/eks-secure/`: corrected EKS Terraform for passing scans.
- `examples/ci/`: reusable GitHub Actions and GitLab CI examples.
- `examples/reports/`: sample generated scan results and reports.

## Tests

- `tests/unit/`: focused tests for Python functions and models.
- `tests/integration/`: CLI and scanner tests using fixture plans and policies.
- `tests/fixtures/tfplans/`: Terraform plan JSON fixtures for repeatable scans.
- `tests/fixtures/policies/`: sample Rego policies for tests.
- `tests/fixtures/configs/`: valid and invalid TerraGuard config examples.

## Docs And Scripts

- `docs/architecture.md`: architecture diagrams and data flow.
- `docs/file-structure.md`: planned repository layout with file descriptions.
- `docs/cli-reference.md`: command reference and planned options.
- `docs/policy-authoring.md`: policy writing conventions and examples.
- `docs/ci-integration.md`: CI/CD setup guidance.
- `docs/examples.md`: walkthroughs for sample Terraform projects.
- `scripts/install-opa.sh`: helper script for installing OPA in CI or local demos.
- `scripts/generate-sample-plan.sh`: helper script for producing sample Terraform plan fixtures.
