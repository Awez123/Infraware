terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
# test-chagne
# This bucket is vulnerable and should be caught by our rule
resource "aws_s3_bucket" "my_vulnerable_bucket" {
  bucket = "my-test-bucket-12345-vulnerable"
  acl    = "public-read"
}

# This bucket is safe and should be ignored
resource "aws_s3_bucket" "my_safe_bucket" {
  bucket = "my-safe-bucket-67890-secure"
  acl    = "private"
}

# (add this to the bottom of the file)
resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = false # <-- This is the vulnerability
}