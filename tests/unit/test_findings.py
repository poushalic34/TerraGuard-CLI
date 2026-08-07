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
    payload = result.to_dict()
    assert payload["summary"]["high"] == 1
    assert payload["schema_version"] == "1.0.0"


def test_expired_suppressions_fail_scan() -> None:
    result = ScanResult(
        findings=(),
        fail_on="high",
        expired_suppressions=({"policy_id": "TG_AWS_SG_001", "expires": "2020-01-01"},),
    )
    assert result.failed is True

