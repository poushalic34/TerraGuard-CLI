output "security_group_id" {
  value = aws_security_group.open_ssh.id
}

output "bucket_name" {
  value = aws_s3_bucket.demo.bucket
}

output "vpc_id" {
  value = aws_vpc.main.id
}
