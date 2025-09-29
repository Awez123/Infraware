resource "aws_s3_bucket" "my_vulnerable_bucket" {
  bucket = "my-test-bucket-12345"
  acl    = "public-read" # This is the vulnerability our rule looks for

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket" "my_safe_bucket" {
  bucket = "my-safe-bucket-67890"
  acl    = "private"
}