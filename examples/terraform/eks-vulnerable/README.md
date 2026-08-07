# Vulnerable EKS Example

Intentionally insecure EKS Terraform for TerraGuard demos.

Includes violations for:

- Public cluster endpoint
- Empty control plane logging
- Missing secrets encryption
- Node group subnet IDs containing `public`

## Offline plan + scan

```bash
# from repo root
./scripts/generate-sample-plan.sh examples/terraform/eks-vulnerable
terraguard scan --plan-json examples/terraform/eks-vulnerable/tfplan.json \
  --policy-pack aws-eks \
  --format json
```

The AWS provider uses mock credentials so planning works without a real AWS account.
