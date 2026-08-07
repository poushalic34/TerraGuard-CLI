# Repository Layout

```text
TerraGuard-CLI/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── pyproject.toml
├── .terraguard.yml.example
├── .terraguard-ignore.yml.example
├── .github/workflows/
│   ├── test.yml
│   └── terraguard-demo.yml
├── docs/
│   ├── architecture.md
│   ├── cli-reference.md
│   ├── file-structure.md
│   └── terraform-plan-quirks.md
├── examples/
│   ├── ci/github-actions.yml
│   ├── reports/sample-*.md|json
│   └── terraform/
│       ├── vulnerable-aws/
│       ├── secure-aws/
│       ├── eks-vulnerable/
│       └── eks-secure/
├── policy-packs/
│   ├── aws-foundation/
│   │   ├── pack.yml
│   │   ├── policies/
│   │   └── tests/
│   └── aws-eks/
│       ├── pack.yml
│       ├── policies/
│       └── tests/
├── scripts/
│   ├── install-opa.sh
│   ├── run-opa-tests.sh
│   ├── generate-sample-plan.sh
│   └── benchmark.sh
├── terraguard/                 # Python package
│   ├── cli.py
│   ├── commands/
│   ├── core/
│   ├── output/
│   └── schema/
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

## Notes

- Built-in policies ship under `policy-packs/` and are loaded from the repo root at runtime.
- Custom packs install to `.terraguard/packs/` (gitignored) via `terraguard packs add`.
- Example Terraform stacks use mock AWS credentials so `terraform plan` works offline.
