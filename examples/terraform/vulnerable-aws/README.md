# Vulnerable AWS Example

Intentionally insecure AWS Terraform for TerraGuard demos.

Includes violations for:

- S3 public access block disabled
- EC2 IMDSv1 (`http_tokens = optional`)
- Unencrypted EBS
- KMS key rotation disabled
- SSH open to `0.0.0.0/0`
- VPC without flow logs
- IAM wildcard admin policy

## Offline plan + scan

```bash
# from repo root
./scripts/generate-sample-plan.sh examples/terraform/vulnerable-aws
terraguard scan --plan-json examples/terraform/vulnerable-aws/tfplan.json \
  --policy-pack aws-foundation \
  --format json
```

The AWS provider is configured with mock credentials and skip flags so `terraform plan` works without a real AWS account.
