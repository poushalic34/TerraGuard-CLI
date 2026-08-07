package terraguard

import rego.v1

test_cloudtrail_single_region_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_cloudtrail.single",
		"type": "aws_cloudtrail",
		"change": {"after": {
			"is_multi_region_trail": false,
			"enable_log_file_validation": true,
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_CT_001"]) == 1
}

test_cloudtrail_log_validation_disabled_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_cloudtrail.novalidation",
		"type": "aws_cloudtrail",
		"change": {"after": {
			"is_multi_region_trail": true,
			"enable_log_file_validation": false,
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_CT_002"]) == 1
}

test_cloudtrail_secure_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_cloudtrail.secure",
		"type": "aws_cloudtrail",
		"change": {"after": {
			"is_multi_region_trail": true,
			"enable_log_file_validation": true,
		}},
	}]}
	not cloudtrail_findings(result)
}

cloudtrail_findings(result) if {
	some finding in result
	startswith(finding.policy_id, "TG_AWS_CT_")
}
