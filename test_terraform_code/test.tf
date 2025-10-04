terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# This provider block is important for the cost analyzer to detect the region.
provider "aws" {
  region = "us-east-1"
}

# --- Resources for Security Scanning ---

# VULNERABLE: Triggers the S3 public read rule (AWS-S3-001)
# This is also a good candidate to test the 'ignore' functionality.
resource "aws_s3_bucket" "public_website_bucket" {
  bucket = "my-public-website-bucket-12345"
  acl    = "public-read"
}

# SAFE: This bucket is configured correctly and should NOT trigger a finding.
resource "aws_s3_bucket" "private_logs_bucket" {
  bucket = "my-private-logs-bucket-67890"
  acl    = "private"
}

# VULNERABLE: Triggers the unencrypted EBS volume rule (AWS-EBS-001)
resource "aws_ebs_volume" "unencrypted_data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false 
}

# VULNERABLE: This will trigger the complex security group rule (AWS-SG-001)
# that we created in a previous step.
resource "aws_security_group" "unrestricted_ssh" {
  name        = "unrestricted-ssh-sg"
  description = "Allows SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


# --- Resources for Cost Analysis ---

# COST: This EC2 instance will be picked up by the cost analyzer.
# The 't3.small' instance type is in our pricing.yaml file.
resource "aws_instance" "web_server" {
  # A common Amazon Linux 2 AMI for us-east-1
  ami           = "ami-0c55b159cbfafe1f0" 
  instance_type = "t3.small"

  tags = {
    Name = "TestWebServer"
  }
}

# COST: This EBS volume will also be picked up by the cost analyzer.
resource "aws_ebs_volume" "data_storage" {
  availability_zone = "us-east-1a"
  size              = 40
  type              = "gp3" # This type is in our pricing.yaml file
}