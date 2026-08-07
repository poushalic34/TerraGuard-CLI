package terraguard

import rego.v1

test_vpc_without_flow_logs_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_vpc.main",
		"type": "aws_vpc",
		"change": {"after": {"cidr_block": "10.0.0.0/16"}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_VPC_001"
}

test_vpc_with_flow_logs_allows if {
	result := deny with input as {"resource_changes": [
		{
			"address": "aws_vpc.main",
			"type": "aws_vpc",
			"change": {"after": {"cidr_block": "10.0.0.0/16"}},
		},
		{
			"address": "aws_flow_log.main",
			"type": "aws_flow_log",
			"change": {"after": {"resource_id": "aws_vpc.main"}},
		},
	]}
	not vpc_findings(result)
}

vpc_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_VPC_001"
}
