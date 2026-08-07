package terraguard

import rego.v1

test_elb_http_listener_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_lb_listener.http",
		"type": "aws_lb_listener",
		"change": {"after": {"protocol": "HTTP"}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_ELB_001"]) == 1
}

test_elb_weak_tls_policy_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_lb_listener.legacy_tls",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS-1-1-2017-01",
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_ELB_002"]) == 1
}

test_elb_secure_https_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_lb_listener.secure",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
		}},
	}]}
	not elb_findings(result)
}

test_elb_tls12_policy_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_lb_listener.tls12",
		"type": "aws_lb_listener",
		"change": {"after": {
			"protocol": "HTTPS",
			"ssl_policy": "ELBSecurityPolicy-TLS-1-2-2017-01",
		}},
	}]}
	not elb_findings(result)
}

elb_findings(result) if {
	some finding in result
	startswith(finding.policy_id, "TG_AWS_ELB_")
}
