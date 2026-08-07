package terraguard

import rego.v1

test_iam_wildcard_admin_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_iam_policy.admin",
		"type": "aws_iam_policy",
		"change": {"after": {
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
		}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_IAM_001"
}

test_iam_scoped_policy_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_iam_policy.readonly",
		"type": "aws_iam_policy",
		"change": {"after": {
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::example/*\"}]}",
		}},
	}]}
	not iam_findings(result)
}

test_iam_trust_all_principals_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_iam_role.open_trust",
		"type": "aws_iam_role",
		"change": {"after": {
			"assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"sts:AssumeRole\"}]}",
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_IAM_002"]) == 1
}

test_iam_scoped_trust_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_iam_role.scoped",
		"type": "aws_iam_role",
		"change": {"after": {
			"assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}",
		}},
	}]}
	not iam_trust_findings(result)
}

iam_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_IAM_001"
}

iam_trust_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_IAM_002"
}
