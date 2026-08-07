import pytest

from terraguard.core.policy_loader import (
    find_policy,
    list_policy_packs,
    load_policy_pack,
    policy_files,
)
from terraguard.exceptions import PolicyError


def test_builtin_policy_packs_load() -> None:
    packs = list_policy_packs()
    names = {pack.name for pack in packs}

    assert "aws-foundation" in names
    assert "aws-eks" in names


def test_find_policy() -> None:
    policy = find_policy("TG_AWS_S3_001")

    assert policy is not None
    assert policy.resource == "s3"
    assert policy.remediation
    assert policy.why


def test_load_policy_pack_missing() -> None:
    with pytest.raises(PolicyError):
        load_policy_pack("does-not-exist")


def test_policy_files_for_foundation() -> None:
    files = policy_files(("aws-foundation",))
    assert files
    assert all(path.suffix == ".rego" for path in files)
