# Secure EKS Example

Hardened counterpart to `eks-vulnerable`.

```bash
./scripts/generate-sample-plan.sh examples/terraform/eks-secure
terraguard scan --plan-json examples/terraform/eks-secure/tfplan.json --policy-pack aws-eks
```
