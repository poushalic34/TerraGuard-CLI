package terraguard

import rego.v1

test_rds_unencrypted_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_db_instance.open",
		"type": "aws_db_instance",
		"change": {"after": {
			"storage_encrypted": false,
			"publicly_accessible": false,
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_RDS_001"]) == 1
}

test_rds_public_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_db_instance.public",
		"type": "aws_db_instance",
		"change": {"after": {
			"storage_encrypted": true,
			"publicly_accessible": true,
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_RDS_002"]) == 1
}

test_rds_secure_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_db_instance.secure",
		"type": "aws_db_instance",
		"change": {"after": {
			"storage_encrypted": true,
			"publicly_accessible": false,
		}},
	}]}
	not rds_findings(result)
}

rds_findings(result) if {
	some finding in result
	startswith(finding.policy_id, "TG_AWS_RDS_")
}
