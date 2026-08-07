package terraguard

import rego.v1

test_security_group_open_ssh_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_security_group.open_ssh",
		"type": "aws_security_group",
		"change": {"after": {"ingress": [{
			"from_port": 22,
			"to_port": 22,
			"cidr_blocks": ["0.0.0.0/0"],
		}]}},
	}]}
	count(result) == 1
	some finding in result
	finding.policy_id == "TG_AWS_SG_001"
}

test_security_group_restricted_ssh_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_security_group.restricted",
		"type": "aws_security_group",
		"change": {"after": {"ingress": [{
			"from_port": 22,
			"to_port": 22,
			"cidr_blocks": ["10.0.0.0/8"],
		}]}},
	}]}
	not sg_findings(result)
}

test_security_group_open_rdp_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_security_group.open_rdp",
		"type": "aws_security_group",
		"change": {"after": {"ingress": [{
			"from_port": 3389,
			"to_port": 3389,
			"cidr_blocks": ["0.0.0.0/0"],
		}]}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_SG_002"]) == 1
}

test_security_group_all_ports_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_security_group.open_all",
		"type": "aws_security_group",
		"change": {"after": {"ingress": [{
			"from_port": 0,
			"to_port": 65535,
			"protocol": "tcp",
			"cidr_blocks": ["0.0.0.0/0"],
		}]}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_SG_003"]) == 1
}

test_security_group_protocol_all_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_security_group.proto_all",
		"type": "aws_security_group",
		"change": {"after": {"ingress": [{
			"from_port": 0,
			"to_port": 0,
			"protocol": "-1",
			"cidr_blocks": ["0.0.0.0/0"],
		}]}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_SG_003"]) == 1
}

sg_findings(result) if {
	some finding in result
	startswith(finding.policy_id, "TG_AWS_SG_")
}
