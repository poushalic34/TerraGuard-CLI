package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_lb_listener"
	after := resource.change.after
	upper(after.protocol) == "HTTP"

	finding := {
		"policy_id": "TG_AWS_ELB_001",
		"title": "Load balancer listeners must not use plain HTTP",
		"severity": "high",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "Load balancer listener uses HTTP instead of HTTPS/TLS.",
		"remediation": "Use HTTPS or TLS listeners with a modern security policy.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_lb_listener"
	after := resource.change.after
	upper(after.protocol) == "HTTPS"
	policy := object.get(after, "ssl_policy", "")
	policy != ""
	not startswith(policy, "ELBSecurityPolicy-TLS13-")
	not startswith(policy, "ELBSecurityPolicy-TLS-1-2")

	finding := {
		"policy_id": "TG_AWS_ELB_002",
		"title": "Load balancer TLS policy must be modern",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": sprintf("Load balancer TLS policy %v is below the approved floor.", [policy]),
		"remediation": "Use a TLS1.2+ or TLS1.3 ELB security policy.",
	}
}
