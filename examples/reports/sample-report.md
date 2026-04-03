# TerraGuard Report

- Failed: `true`
- Failure threshold: `high`
- Total findings: `1`

## Findings

### TG_AWS_SG_001: Security groups must not expose SSH to the internet

- Severity: `critical`
- Resource: `aws_security_group.open_ssh`
- Resource type: `aws_security_group`
- Message: Security group allows SSH ingress from 0.0.0.0/0.
- Remediation: Restrict SSH ingress to approved CIDR ranges or use SSM Session Manager.

