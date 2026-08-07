package terraguard

import rego.v1

test_eks_addon_unpinned_version_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_addon.vpc_cni",
		"type": "aws_eks_addon",
		"change": {"after": {
			"addon_name": "vpc-cni",
			"addon_version": null,
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_009"]) == 1
}

test_eks_addon_empty_version_denied if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_addon.coredns",
		"type": "aws_eks_addon",
		"change": {"after": {
			"addon_name": "coredns",
			"addon_version": "",
		}},
	}]}
	count([finding | some finding in result; finding.policy_id == "TG_AWS_EKS_009"]) == 1
}

test_eks_addon_pinned_version_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_addon.kube_proxy",
		"type": "aws_eks_addon",
		"change": {"after": {
			"addon_name": "kube-proxy",
			"addon_version": "v1.29.0-eksbuild.1",
		}},
	}]}
	not addon_findings(result)
}

test_eks_noncritical_addon_unpinned_allows if {
	result := deny with input as {"resource_changes": [{
		"address": "aws_eks_addon.ebs_csi",
		"type": "aws_eks_addon",
		"change": {"after": {
			"addon_name": "aws-ebs-csi-driver",
			"addon_version": null,
		}},
	}]}
	not addon_findings(result)
}

addon_findings(result) if {
	some finding in result
	finding.policy_id == "TG_AWS_EKS_009"
}
