from terraguard.core.findings import Finding, ScanResult


def test_scan_result_failed_when_finding_meets_threshold() -> None:
    finding = Finding(
        policy_id="TG_TEST_001",
        title="Test finding",
        severity="high",
        resource_type="aws_s3_bucket",
        resource_address="aws_s3_bucket.demo",
        message="Demo violation",
        remediation="Fix the demo violation.",
    )

    result = ScanResult(findings=(finding,), fail_on="high")

    assert result.failed
    assert result.to_dict()["summary"]["high"] == 1

