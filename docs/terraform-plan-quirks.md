# Plan JSON Quirks

Real `terraform show -json` output is not the same shape as hand-written fixtures.
TerraGuard policies were adjusted after scanning live plans from the example stacks.

## EC2 `metadata_options`

In HCL this looks like a block/object:

```hcl
metadata_options {
  http_tokens = "optional"
}
```

In plan JSON it is often an **array**:

```json
"metadata_options": [
  { "http_tokens": "optional", "http_endpoint": "enabled" }
]
```

`TG_AWS_EC2_001` accepts both object and array forms.

## EKS `enabled_cluster_log_types`

Setting `enabled_cluster_log_types = []` in HCL can serialize as `null` in the plan.
`count(null) == 0` does not match in Rego, so logging checks use
`not has_cluster_logs(after)` instead of a direct count comparison.

## Diff-aware scanning

Plan entries include `change.actions`. TerraGuard `--changed-only` keeps
`create` / `update` / `delete` / `replace` and drops `no-op` / `read`.
Fixtures that omit `actions` are treated as in-scope so unit tests stay simple.

## Takeaway

Keep a plan-fidelity suite: regenerate example plans with
`scripts/generate-sample-plan.sh` and assert policy IDs still fire.
