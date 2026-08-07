# Contributing

Thanks for your interest in TerraGuard CLI.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
bash scripts/install-opa.sh   # or: brew install opa
```

## Checks

```bash
ruff check .
pytest
bash scripts/run-opa-tests.sh
```

## Adding a policy

```bash
terraguard generate policy \
  --id TG_AWS_EXAMPLE_001 \
  --resource-type aws_example \
  --pack aws-foundation \
  --resource example \
  --title "Example policy"
```

Then:

1. Implement the Rego deny rule
2. Register the policy in `policy-packs/<pack>/pack.yml` (include `controls` when applicable)
3. Add Rego tests under `policy-packs/<pack>/tests/`
4. Add or extend a plan fixture under `tests/fixtures/tfplans/`
5. Run `pytest` and `bash scripts/run-opa-tests.sh`

## Pull requests

- Keep changes focused
- Include tests for new behavior
- Update docs when commands or policy packs change
