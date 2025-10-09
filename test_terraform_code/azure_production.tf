# Real-World Azure Production Infrastructure
# Multi-tier application with monitoring and security

# Resource Group
resource "azurerm_resource_group" "production" {
  name     = "production-rg"
  location = "East US"

  tags = {
    Environment = "Production"
    CostCenter  = "Engineering"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "production" {
  name                = "production-vnet"
  address_space       = ["10.1.0.0/16"]
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  tags = {
    Environment = "Production"
  }
}

# Subnets
resource "azurerm_subnet" "web" {
  name                 = "web-subnet"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.1.1.0/24"]
}

resource "azurerm_subnet" "app" {
  name                 = "app-subnet"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.1.2.0/24"]
}

resource "azurerm_subnet" "database" {
  name                 = "database-subnet"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.1.3.0/24"]
  
  delegation {
    name = "sql-delegation"
    service_delegation {
      name = "Microsoft.Sql/managedInstances"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action",
        "Microsoft.Network/virtualNetworks/subnets/unprepareNetworkPolicies/action"
      ]
    }
  }
}

# Network Security Groups
resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  security_rule {
    name                       = "HTTP"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTPS"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_network_security_group" "app" {
  name                = "app-nsg"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  security_rule {
    name                       = "AppPort"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8080"
    source_address_prefix      = "10.1.1.0/24"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "Production"
  }
}

# Public IP for Load Balancer
resource "azurerm_public_ip" "lb" {
  name                = "production-lb-pip"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  allocation_method   = "Static"
  sku                = "Standard"

  tags = {
    Environment = "Production"
  }
}

# Load Balancer
resource "azurerm_lb" "production" {
  name                = "production-lb"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  sku                = "Standard"

  frontend_ip_configuration {
    name                 = "primary"
    public_ip_address_id = azurerm_public_ip.lb.id
  }

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_lb_backend_address_pool" "web" {
  loadbalancer_id = azurerm_lb.production.id
  name            = "web-backend-pool"
}

resource "azurerm_lb_probe" "web" {
  loadbalancer_id = azurerm_lb.production.id
  name            = "web-health-probe"
  port            = 80
  protocol        = "Http"
  request_path    = "/"
}

resource "azurerm_lb_rule" "web" {
  loadbalancer_id                = azurerm_lb.production.id
  name                           = "web-lb-rule"
  protocol                       = "Tcp"
  frontend_port                  = 80
  backend_port                   = 80
  frontend_ip_configuration_name = "primary"
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.web.id]
  probe_id                       = azurerm_lb_probe.web.id
}

# Virtual Machine Scale Set
resource "azurerm_linux_virtual_machine_scale_set" "web" {
  name                = "web-vmss"
  resource_group_name = azurerm_resource_group.production.name
  location            = azurerm_resource_group.production.location
  sku                 = "Standard_D2s_v3"
  instances           = 3

  admin_username                  = "azureuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts-gen2"
    version   = "latest"
  }

  os_disk {
    storage_account_type = "Premium_LRS"
    caching              = "ReadWrite"
  }

  network_interface {
    name    = "web-nic"
    primary = true

    ip_configuration {
      name                                   = "internal"
      primary                                = true
      subnet_id                              = azurerm_subnet.web.id
      load_balancer_backend_address_pool_ids = [azurerm_lb_backend_address_pool.web.id]
    }
  }

  custom_data = base64encode(<<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y nginx
              systemctl start nginx
              systemctl enable nginx
              echo "<h1>Production Web Server - Azure</h1>" > /var/www/html/index.html
              EOF
  )

  tags = {
    Environment = "Production"
  }
}

# Auto Scale Settings
resource "azurerm_monitor_autoscale_setting" "web" {
  name                = "web-autoscale"
  resource_group_name = azurerm_resource_group.production.name
  location            = azurerm_resource_group.production.location
  target_resource_id  = azurerm_linux_virtual_machine_scale_set.web.id

  profile {
    name = "defaultProfile"

    capacity {
      default = 3
      minimum = 2
      maximum = 10
    }

    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_linux_virtual_machine_scale_set.web.id
        time_grain         = "PT1M"
        statistic          = "Average"
        time_window        = "PT5M"
        time_aggregation   = "Average"
        operator           = "GreaterThan"
        threshold          = 75
      }

      scale_action {
        direction = "Increase"
        type      = "ChangeCount"
        value     = "1"
        cooldown  = "PT1M"
      }
    }

    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_linux_virtual_machine_scale_set.web.id
        time_grain         = "PT1M"
        statistic          = "Average"
        time_window        = "PT5M"
        time_aggregation   = "Average"
        operator           = "LessThan"
        threshold          = 25
      }

      scale_action {
        direction = "Decrease"
        type      = "ChangeCount"
        value     = "1"
        cooldown  = "PT1M"
      }
    }
  }

  tags = {
    Environment = "Production"
  }
}

# Azure SQL Database
resource "azurerm_mssql_server" "production" {
  name                         = "production-sqlserver-${random_id.sql_suffix.hex}"
  resource_group_name          = azurerm_resource_group.production.name
  location                     = azurerm_resource_group.production.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd123!"

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_mssql_database" "production" {
  name           = "production-database"
  server_id      = azurerm_mssql_server.production.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  sku_name       = "S1"
  max_size_gb    = 250

  tags = {
    Environment = "Production"
  }
}

# Azure Redis Cache
resource "azurerm_redis_cache" "production" {
  name                = "production-redis-${random_id.redis_suffix.hex}"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
    maxclients = 1000
  }

  tags = {
    Environment = "Production"
  }
}

# Storage Account
resource "azurerm_storage_account" "production" {
  name                     = "prodstorage${random_id.storage_suffix.hex}"
  resource_group_name      = azurerm_resource_group.production.name
  location                 = azurerm_resource_group.production.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"

  blob_properties {
    versioning_enabled = true
    
    delete_retention_policy {
      days = 30
    }
  }

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_storage_container" "assets" {
  name                  = "assets"
  storage_account_name  = azurerm_storage_account.production.name
  container_access_type = "blob"
}

# CDN Profile and Endpoint
resource "azurerm_cdn_profile" "production" {
  name                = "production-cdn"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  sku                 = "Standard_Microsoft"

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_cdn_endpoint" "assets" {
  name                = "production-assets-${random_id.cdn_suffix.hex}"
  profile_name        = azurerm_cdn_profile.production.name
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name

  origin {
    name      = "storage"
    host_name = azurerm_storage_account.production.primary_blob_host
  }

  delivery_rule {
    name  = "EnforceHTTPS"
    order = 1

    request_scheme_condition {
      operator     = "Equal"
      match_values = ["HTTP"]
    }

    url_redirect_action {
      redirect_type = "Found"
      protocol      = "Https"
    }
  }

  tags = {
    Environment = "Production"
  }
}

# Function App
resource "azurerm_service_plan" "functions" {
  name                = "functions-plan"
  resource_group_name = azurerm_resource_group.production.name
  location            = azurerm_resource_group.production.location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_linux_function_app" "production" {
  name                = "production-functions-${random_id.function_suffix.hex}"
  resource_group_name = azurerm_resource_group.production.name
  location            = azurerm_resource_group.production.location

  storage_account_name       = azurerm_storage_account.production.name
  storage_account_access_key = azurerm_storage_account.production.primary_access_key
  service_plan_id            = azurerm_service_plan.functions.id

  site_config {
    application_stack {
      python_version = "3.9"
    }
  }

  app_settings = {
    "WEBSITE_RUN_FROM_PACKAGE" = "1"
    "SQL_CONNECTION_STRING"    = "Server=tcp:${azurerm_mssql_server.production.fully_qualified_domain_name},1433;Initial Catalog=${azurerm_mssql_database.production.name};Persist Security Info=False;User ID=${azurerm_mssql_server.production.administrator_login};Password=${azurerm_mssql_server.production.administrator_login_password};MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
    "REDIS_CONNECTION_STRING"  = azurerm_redis_cache.production.primary_connection_string
  }

  tags = {
    Environment = "Production"
  }
}

# Application Gateway
resource "azurerm_subnet" "gateway" {
  name                 = "gateway-subnet"
  resource_group_name  = azurerm_resource_group.production.name
  virtual_network_name = azurerm_virtual_network.production.name
  address_prefixes     = ["10.1.4.0/24"]
}

resource "azurerm_public_ip" "gateway" {
  name                = "gateway-pip"
  resource_group_name = azurerm_resource_group.production.name
  location            = azurerm_resource_group.production.location
  allocation_method   = "Static"
  sku                = "Standard"

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_application_gateway" "production" {
  name                = "production-appgw"
  resource_group_name = azurerm_resource_group.production.name
  location            = azurerm_resource_group.production.location

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 2
  }

  gateway_ip_configuration {
    name      = "gateway-ip-configuration"
    subnet_id = azurerm_subnet.gateway.id
  }

  frontend_port {
    name = "frontend-port"
    port = 80
  }

  frontend_ip_configuration {
    name                 = "frontend-ip-configuration"
    public_ip_address_id = azurerm_public_ip.gateway.id
  }

  backend_address_pool {
    name = "backend-pool"
  }

  backend_http_settings {
    name                  = "backend-http-settings"
    cookie_based_affinity = "Disabled"
    path                  = "/"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 60
  }

  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-ip-configuration"
    frontend_port_name             = "frontend-port"
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = "routing-rule"
    rule_type                  = "Basic"
    http_listener_name         = "http-listener"
    backend_address_pool_name  = "backend-pool"
    backend_http_settings_name = "backend-http-settings"
    priority                   = 100
  }

  tags = {
    Environment = "Production"
  }
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "production" {
  name                = "production-logs"
  location            = azurerm_resource_group.production.location
  resource_group_name = azurerm_resource_group.production.name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  tags = {
    Environment = "Production"
  }
}

# Key Vault
resource "azurerm_key_vault" "production" {
  name                        = "production-kv-${random_id.kv_suffix.hex}"
  location                    = azurerm_resource_group.production.location
  resource_group_name         = azurerm_resource_group.production.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get",
    ]

    secret_permissions = [
      "Get", "Set", "List", "Delete", "Recover", "Backup", "Restore"
    ]

    storage_permissions = [
      "Get",
    ]
  }

  tags = {
    Environment = "Production"
  }
}

# Random IDs for unique naming
resource "random_id" "sql_suffix" {
  byte_length = 4
}

resource "random_id" "redis_suffix" {
  byte_length = 4
}

resource "random_id" "storage_suffix" {
  byte_length = 4
}

resource "random_id" "cdn_suffix" {
  byte_length = 4
}

resource "random_id" "function_suffix" {
  byte_length = 4
}

resource "random_id" "kv_suffix" {
  byte_length = 4
}

# Data sources
data "azurerm_client_config" "current" {}