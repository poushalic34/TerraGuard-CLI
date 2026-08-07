import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def opa_bin() -> str:
    path = shutil.which("opa")
    if path is None:
        pytest.skip("opa is not installed")
    return path


def test_aws_foundation_rego_tests(opa_bin: str) -> None:
    completed = subprocess.run(
        [
            opa_bin,
            "test",
            str(ROOT / "policy-packs/aws-foundation/policies"),
            str(ROOT / "policy-packs/aws-foundation/tests"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_aws_eks_rego_tests(opa_bin: str) -> None:
    completed = subprocess.run(
        [
            opa_bin,
            "test",
            str(ROOT / "policy-packs/aws-eks/policies"),
            str(ROOT / "policy-packs/aws-eks/tests"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
