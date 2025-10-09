# Real-World Multi-Cloud Kubernetes Infrastructure
# Production-grade EKS, AKS, and GKE deployment

# AWS EKS Cluster
resource "aws_eks_cluster" "production" {
  name     = "production-eks"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.27"

  vpc_config {
    subnet_ids              = [aws_subnet.private[0].id, aws_subnet.private[1].id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs    = ["0.0.0.0/0"]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
  ]

  tags = {
    Name = "production-eks"
  }
}

resource "aws_eks_node_group" "production" {
  cluster_name    = aws_eks_cluster.production.name
  node_group_name = "production-nodes"
  node_role_arn   = aws_iam_role.eks_node_group.arn
  subnet_ids      = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.medium", "t3.large"]

  scaling_config {
    desired_size = 3
    max_size     = 10
    min_size     = 2
  }

  update_config {
    max_unavailable = 1
  }

  remote_access {
    ec2_ssh_key = aws_key_pair.eks_nodes.key_name
    source_security_group_ids = [aws_security_group.eks_nodes.id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node,
    aws_iam_role_policy_attachment.eks_cni,
    aws_iam_role_policy_attachment.eks_container_registry,
  ]

  tags = {
    Name = "production-eks-nodes"
  }
}

# EKS IAM roles
resource "aws_iam_role" "eks_cluster" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_node_group" {
  name = "eks-node-group-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_cni" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_group.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_group.name
}

# KMS key for EKS encryption
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7

  tags = {
    Name = "eks-encryption-key"
  }
}

# Key pair for EKS nodes
resource "aws_key_pair" "eks_nodes" {
  key_name   = "eks-nodes-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."  # Replace with actual public key
}

# Security group for EKS nodes
resource "aws_security_group" "eks_nodes" {
  name_prefix = "eks-nodes-sg"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    Name = "eks-nodes-security-group"
  }
}

# Azure AKS Cluster
resource "azurerm_resource_group" "aks" {
  name     = "production-aks-rg"
  location = "East US"

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_kubernetes_cluster" "production" {
  name                = "production-aks"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  dns_prefix          = "production-aks"

  default_node_pool {
    name                = "default"
    node_count          = 3
    vm_size            = "Standard_D2s_v3"
    type               = "VirtualMachineScaleSets"
    availability_zones = ["1", "2", "3"]
    
    enable_auto_scaling = true
    min_count          = 2
    max_count          = 10

    # Advanced networking
    vnet_subnet_id = azurerm_subnet.aks.id
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }

  role_based_access_control {
    enabled = true

    azure_active_directory {
      managed = true
      admin_group_object_ids = [data.azuread_group.aks_admins.object_id]
    }
  }

  addon_profile {
    oms_agent {
      enabled                    = true
      log_analytics_workspace_id = azurerm_log_analytics_workspace.aks.id
    }

    kube_dashboard {
      enabled = false
    }
  }

  tags = {
    Environment = "Production"
  }
}

# Azure networking for AKS
resource "azurerm_virtual_network" "aks" {
  name                = "aks-vnet"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  address_space       = ["172.16.0.0/16"]

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = azurerm_resource_group.aks.name
  virtual_network_name = azurerm_virtual_network.aks.name
  address_prefixes     = ["172.16.1.0/24"]
}

# Log Analytics for AKS monitoring
resource "azurerm_log_analytics_workspace" "aks" {
  name                = "aks-log-analytics"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Environment = "Production"
  }
}

# Azure Container Registry
resource "azurerm_container_registry" "production" {
  name                = "productionacr${random_id.acr_suffix.hex}"
  resource_group_name = azurerm_resource_group.aks.name
  location            = azurerm_resource_group.aks.location
  sku                 = "Premium"
  admin_enabled       = false

  georeplications {
    location                = "West US"
    zone_redundancy_enabled = true
    tags = {}
  }

  tags = {
    Environment = "Production"
  }
}

# GCP GKE Cluster
resource "google_container_cluster" "production" {
  name     = "production-gke"
  location = "us-central1"

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.gke.name
  subnetwork = google_compute_subnetwork.gke.name

  # Networking configuration
  networking_mode = "VPC_NATIVE"
  
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  # Security configuration
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = "${data.google_project.current.project_id}.svc.id.goog"
  }

  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # Maintenance window
  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"
    }
  }

  # Enable various cluster features
  addons_config {
    http_load_balancing {
      disabled = false
    }

    horizontal_pod_autoscaling {
      disabled = false
    }

    network_policy_config {
      disabled = false
    }
  }

  network_policy {
    enabled = true
  }
}

resource "google_container_node_pool" "production_nodes" {
  name       = "production-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.production.name
  node_count = 2

  autoscaling {
    min_node_count = 2
    max_node_count = 10
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    preemptible  = false
    machine_type = "e2-medium"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    labels = {
      env = "production"
    }

    tags = ["gke-node", "production"]

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }
}

# GCP networking for GKE
resource "google_compute_network" "gke" {
  name                    = "gke-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gke" {
  name          = "gke-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.gke.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "192.168.0.0/18"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "192.168.64.0/18"
  }
}

# GCP service account for GKE nodes
resource "google_service_account" "gke_nodes" {
  account_id   = "gke-nodes-sa"
  display_name = "GKE Nodes Service Account"
}

# Data sources
data "azuread_group" "aks_admins" {
  display_name = "AKS Admins"
}

data "google_project" "current" {}

# Random ID for unique naming
resource "random_id" "acr_suffix" {
  byte_length = 4
}

# Shared networking components (referenced from aws_production.tf)
# VPC and subnets are assumed to exist from the main AWS infrastructure