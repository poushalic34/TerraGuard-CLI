terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_s3_bucket" "demo" {
  bucket = "terraguard-secure-${var.environment}"
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.demo.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_instance" "secure" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_ebs_volume" "secure" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = true
}

resource "aws_kms_key" "secure" {
  description         = "TerraGuard secure demo key"
  enable_key_rotation = true
}

resource "aws_security_group" "restricted" {
  name        = "terraguard-restricted-ssh"
  description = "Restricted SSH"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
  log_destination_type = "cloud-watch-logs"
  log_destination      = "arn:aws:logs:us-east-1:123456789012:log-group:terraguard"
  iam_role_arn         = "arn:aws:iam::123456789012:role/flow"
}

resource "aws_iam_policy" "readonly" {
  name = "terraguard-secure-readonly"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::example/*"]
    }]
  })
}

resource "aws_db_instance" "secure" {
  identifier             = "terraguard-secure"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "demo"
  password               = "demo-password-change-me"
  skip_final_snapshot    = true
  storage_encrypted      = true
  publicly_accessible    = false
}

variable "environment" {
  type    = string
  default = "demo"
}
