terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

provider "azurerm" {
  features {}
}

provider "google" {
  project = "my-gcp-project"
  region  = "us-central1"
}

# AWS S3 bucket with public ACL and no versioning
resource "aws_s3_bucket" "public_bucket" {
  bucket = "advanced-public-bucket"
  acl    = "public-read"
}

# AWS EBS volume unencrypted
resource "aws_ebs_volume" "unencrypted_ebs" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

# Azure Storage Account with public access
resource "azurerm_storage_account" "public_storage" {
  name                     = "advancestorageacct"
  resource_group_name      = "myResourceGroup"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = true
}

# Google Cloud Storage bucket with public access
resource "google_storage_bucket" "public_gcs_bucket" {
  name          = "advanced-public-gcs"
  location      = "US"
  force_destroy = true
  uniform_bucket_level_access = false
}

# AWS Security Group with open ingress
resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Security group with open ingress"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Azure Network Security Group with open rule
resource "azurerm_network_security_group" "open_nsg" {
  name                = "open-nsg"
  location            = "eastus"
  resource_group_name = "myResourceGroup"

  security_rule {
    name                       = "AllowAll"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# GCP Firewall with open ingress
resource "google_compute_firewall" "open_firewall" {
  name    = "open-firewall"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}
