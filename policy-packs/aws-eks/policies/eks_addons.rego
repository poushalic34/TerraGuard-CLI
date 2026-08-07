package terraguard

import rego.v1

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_addon"
	after := resource.change.after
	addon := object.get(after, "addon_name", "")
	critical_addon(addon)
	version := object.get(after, "addon_version", null)
	version == null

	finding := {
		"policy_id": "TG_AWS_EKS_009",
		"title": "Critical EKS addons must pin a version",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": sprintf("EKS addon %v does not pin addon_version.", [addon]),
		"remediation": "Set addon_version explicitly for vpc-cni, kube-proxy, and coredns.",
	}
}

deny contains finding if {
	resource := input.resource_changes[_]
	resource.type == "aws_eks_addon"
	after := resource.change.after
	addon := object.get(after, "addon_name", "")
	critical_addon(addon)
	version := object.get(after, "addon_version", "")
	version == ""

	finding := {
		"policy_id": "TG_AWS_EKS_009",
		"title": "Critical EKS addons must pin a version",
		"severity": "medium",
		"resource_type": resource.type,
		"resource_address": resource.address,
		"message": sprintf("EKS addon %v does not pin addon_version.", [addon]),
		"remediation": "Set addon_version explicitly for vpc-cni, kube-proxy, and coredns.",
	}
}

critical_addon(name) if name == "vpc-cni"
critical_addon(name) if name == "kube-proxy"
critical_addon(name) if name == "coredns"
