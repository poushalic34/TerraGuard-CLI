package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	after := resource.change.after
	ingress := after.ingress[_]
	ingress.cidr_blocks[_] == "0.0.0.0/0"
	port_allowed(ingress, 22)

	finding := {
		"policy_id": "TG_AWS_SG_001",
		"title": "Security groups must not expose SSH to the internet",
		"severity": "critical",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": "Security group allows SSH ingress from 0.0.0.0/0.",
		"remediation": "Restrict SSH ingress to approved CIDR ranges or use SSM Session Manager.",
	}
}

port_allowed(ingress, port) if {
	ingress.from_port <= port
	ingress.to_port >= port
}

