from terraguard.core.severity import meets_threshold


def test_meets_threshold() -> None:
    assert meets_threshold("critical", "high")
    assert meets_threshold("high", "high")
    assert not meets_threshold("medium", "high")

