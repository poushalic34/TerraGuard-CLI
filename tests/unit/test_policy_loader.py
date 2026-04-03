from terraguard.core.policy_loader import find_policy, list_policy_packs


def test_builtin_policy_packs_load() -> None:
    packs = list_policy_packs()
    names = {pack.name for pack in packs}

    assert "aws-foundation" in names
    assert "aws-eks" in names


def test_find_policy() -> None:
    policy = find_policy("TG_AWS_S3_001")

    assert policy is not None
    assert policy.resource == "s3"

