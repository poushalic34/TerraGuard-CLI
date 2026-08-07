# Secure AWS Example

Hardened counterpart to `vulnerable-aws` for demo contrast.

```bash
./scripts/generate-sample-plan.sh examples/terraform/secure-aws
terraguard scan --plan-json examples/terraform/secure-aws/tfplan.json --policy-pack aws-foundation
```
