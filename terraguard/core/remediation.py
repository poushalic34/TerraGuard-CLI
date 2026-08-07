"""Suggested HCL remediation snippets for high-signal policies."""

from __future__ import annotations

REMEDIATION_HCL: dict[str, str] = {
    "TG_AWS_S3_001": """\
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
""",
    "TG_AWS_EC2_001": """\
resource "aws_instance" "example" {
  # ...
  metadata_options {
    http_tokens = "required"
  }
}
""",
    "TG_AWS_EBS_001": """\
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = true
  kms_key_id        = aws_kms_key.example.arn
}
""",
    "TG_AWS_SG_001": """\
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"] # not 0.0.0.0/0
}
""",
    "TG_AWS_EKS_001": """\
resource "aws_eks_cluster" "example" {
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}
""",
    "TG_AWS_EKS_003": """\
encryption_config {
  provider {
    key_arn = aws_kms_key.eks.arn
  }
  resources = ["secrets"]
}
""",
}


def remediation_hcl(policy_id: str) -> str | None:
    return REMEDIATION_HCL.get(policy_id)
