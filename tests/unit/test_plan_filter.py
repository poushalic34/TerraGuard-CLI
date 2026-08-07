from terraguard.core.plan_filter import changed_resource_addresses, filter_changed_resources


def test_filter_changed_resources_skips_noop() -> None:
    plan = {
        "resource_changes": [
            {"address": "a.create", "change": {"actions": ["create"]}},
            {"address": "a.noop", "change": {"actions": ["no-op"]}},
            {"address": "a.read", "change": {"actions": ["read"]}},
        ]
    }
    filtered = filter_changed_resources(plan)
    addresses = [item["address"] for item in filtered["resource_changes"]]
    assert addresses == ["a.create"]
    assert changed_resource_addresses(plan) == ("a.create",)


def test_missing_actions_kept_for_fixtures() -> None:
    plan = {"resource_changes": [{"address": "a.x", "change": {"after": {}}}]}
    assert len(filter_changed_resources(plan)["resource_changes"]) == 1
