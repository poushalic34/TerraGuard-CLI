#!/usr/bin/env bash
set -euo pipefail

terraform init
terraform validate
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

