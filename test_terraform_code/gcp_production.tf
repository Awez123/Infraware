# Real-World GCP Production Infrastructure
# Serverless application with monitoring and data pipeline

# VPC Network
resource "google_compute_network" "production" {
  name                    = "production-network"
  auto_create_subnetworks = false
  routing_mode           = "REGIONAL"
}

# Subnets
resource "google_compute_subnetwork" "web" {
  name          = "web-subnet"
  ip_cidr_range = "10.3.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.production.id

  secondary_ip_range {
    range_name    = "web-pods"
    ip_cidr_range = "192.168.1.0/24"
  }

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata            = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "app" {
  name          = "app-subnet"
  ip_cidr_range = "10.3.2.0/24"
  region        = "us-central1"
  network       = google_compute_network.production.id

  secondary_ip_range {
    range_name    = "app-pods"
    ip_cidr_range = "192.168.2.0/24"
  }
}

resource "google_compute_subnetwork" "data" {
  name          = "data-subnet"
  ip_cidr_range = "10.3.3.0/24"
  region        = "us-central1"
  network       = google_compute_network.production.id
}

# Cloud NAT for private instances
resource "google_compute_router" "production" {
  name    = "production-router"
  region  = "us-central1"
  network = google_compute_network.production.id
}

resource "google_compute_router_nat" "production" {
  name                               = "production-nat"
  router                             = google_compute_router.production.name
  region                             = "us-central1"
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall Rules
resource "google_compute_firewall" "allow_http" {
  name    = "allow-http"
  network = google_compute_network.production.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-server"]
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal"
  network = google_compute_network.production.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.3.0.0/16"]
}

# Managed Instance Group
resource "google_compute_instance_template" "web" {
  name_prefix  = "web-template-"
  machine_type = "e2-medium"
  region       = "us-central1"

  tags = ["web-server"]

  disk {
    source_image = "projects/ubuntu-os-cloud/global/images/family/ubuntu-2004-lts"
    auto_delete  = true
    boot         = true
    disk_type    = "pd-ssd"
    disk_size_gb = 20
  }

  network_interface {
    subnetwork = google_compute_subnetwork.web.name
    
    access_config {
      // Ephemeral public IP
    }
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y nginx
    systemctl start nginx
    systemctl enable nginx
    echo "<h1>Production Web Server - GCP</h1>" > /var/www/html/index.html
    
    # Install monitoring agent
    curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
    sudo bash add-google-cloud-ops-agent-repo.sh --also-install
  EOF

  service_account {
    email  = google_service_account.compute.email
    scopes = ["cloud-platform"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_region_instance_group_manager" "web" {
  name   = "web-igm"
  region = "us-central1"

  version {
    instance_template = google_compute_instance_template.web.id
  }

  base_instance_name = "web"
  target_size        = 3

  named_port {
    name = "http"
    port = 80
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.web.id
    initial_delay_sec = 300
  }
}

# Health Check
resource "google_compute_health_check" "web" {
  name = "web-health-check"

  timeout_sec        = 5
  check_interval_sec = 30

  http_health_check {
    port         = 80
    request_path = "/"
  }
}

# Auto Scaler
resource "google_compute_region_autoscaler" "web" {
  name   = "web-autoscaler"
  region = "us-central1"
  target = google_compute_region_instance_group_manager.web.id

  autoscaling_policy {
    max_replicas    = 10
    min_replicas    = 2
    cooldown_period = 60

    cpu_utilization {
      target = 0.7
    }
  }
}

# Global Load Balancer
resource "google_compute_global_address" "web" {
  name = "web-global-ip"
}

resource "google_compute_global_forwarding_rule" "web" {
  name       = "web-forwarding-rule"
  target     = google_compute_target_http_proxy.web.id
  port_range = "80"
  ip_address = google_compute_global_address.web.address
}

resource "google_compute_target_http_proxy" "web" {
  name    = "web-target-proxy"
  url_map = google_compute_url_map.web.id
}

resource "google_compute_url_map" "web" {
  name            = "web-url-map"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_backend_service" "web" {
  name        = "web-backend-service"
  port_name   = "http"
  protocol    = "HTTP"
  timeout_sec = 10

  backend {
    group = google_compute_region_instance_group_manager.web.instance_group
  }

  health_checks = [google_compute_health_check.web.id]
}

# Cloud Storage Buckets
resource "google_storage_bucket" "assets" {
  name     = "production-assets-${random_id.bucket_suffix.hex}"
  location = "US"

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  cors {
    origin          = ["*"]
    method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }
}

resource "google_storage_bucket" "data_lake" {
  name     = "production-datalake-${random_id.bucket_suffix.hex}"
  location = "US"

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }
}

# Cloud SQL Database
resource "google_sql_database_instance" "production" {
  name             = "production-db-${random_id.db_suffix.hex}"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier              = "db-n1-standard-2"
    availability_type = "REGIONAL"
    disk_type         = "PD_SSD"
    disk_size         = 100
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.production.id
      require_ssl     = true
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

resource "google_sql_database" "production" {
  name     = "production"
  instance = google_sql_database_instance.production.name
}

resource "google_sql_user" "production" {
  name     = "app_user"
  instance = google_sql_database_instance.production.name
  password = "secure_password_123!"
}

# Private Service Connection for Cloud SQL
resource "google_compute_global_address" "private_ip_address" {
  name          = "private-ip-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.production.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.production.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

# BigQuery Dataset and Tables
resource "google_bigquery_dataset" "analytics" {
  dataset_id  = "production_analytics"
  location    = "US"
  description = "Production analytics dataset"

  access {
    role          = "OWNER"
    user_by_email = google_service_account.bigquery.email
  }

  access {
    role   = "READER"
    domain = "example.com"
  }
}

resource "google_bigquery_table" "events" {
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  table_id   = "user_events"

  time_partitioning {
    type  = "DAY"
    field = "event_timestamp"
  }

  clustering = ["user_id", "event_type"]

  schema = <<EOF
[
  {
    "name": "user_id",
    "type": "STRING",
    "mode": "REQUIRED",
    "description": "User identifier"
  },
  {
    "name": "event_type",
    "type": "STRING",
    "mode": "REQUIRED",
    "description": "Type of event"
  },
  {
    "name": "event_timestamp",
    "type": "TIMESTAMP",
    "mode": "REQUIRED",
    "description": "Event timestamp"
  },
  {
    "name": "properties",
    "type": "JSON",
    "mode": "NULLABLE",
    "description": "Event properties"
  }
]
EOF
}

# Cloud Functions
resource "google_cloudfunctions_function" "data_processor" {
  name        = "data-processor"
  description = "Process incoming data events"
  runtime     = "python39"

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.assets.name
  source_archive_object = "function-source.zip"
  trigger {
    event_type = "google.storage.object.finalize"
    resource   = google_storage_bucket.data_lake.name
  }
  entry_point = "process_data"

  environment_variables = {
    DATABASE_URL = "postgresql://${google_sql_user.production.name}:${google_sql_user.production.password}@${google_sql_database_instance.production.private_ip_address}:5432/${google_sql_database.production.name}"
    BIGQUERY_DATASET = google_bigquery_dataset.analytics.dataset_id
  }

  service_account_email = google_service_account.functions.email
}

resource "google_cloudfunctions_function" "api_handler" {
  name        = "api-handler"
  description = "Handle API requests"
  runtime     = "python39"

  available_memory_mb          = 512
  source_archive_bucket        = google_storage_bucket.assets.name
  source_archive_object        = "api-source.zip"
  trigger {
    https_trigger {
      security_level = "SECURE_ALWAYS"
    }
  }
  entry_point = "handle_request"

  environment_variables = {
    DATABASE_URL = "postgresql://${google_sql_user.production.name}:${google_sql_user.production.password}@${google_sql_database_instance.production.private_ip_address}:5432/${google_sql_database.production.name}"
  }

  service_account_email = google_service_account.functions.email
}

# Pub/Sub Topics and Subscriptions
resource "google_pubsub_topic" "events" {
  name = "user-events"

  message_retention_duration = "86400s"
}

resource "google_pubsub_subscription" "events_processor" {
  name  = "events-processor"
  topic = google_pubsub_topic.events.name

  message_retention_duration = "1200s"
  retain_acked_messages      = true

  ack_deadline_seconds = 20

  expiration_policy {
    ttl = "300000.5s"
  }
}

# Cloud Run Service
resource "google_cloud_run_service" "api" {
  name     = "production-api"
  location = "us-central1"

  template {
    spec {
      containers {
        image = "gcr.io/${data.google_project.current.project_id}/api:latest"
        
        env {
          name  = "DATABASE_URL"
          value = "postgresql://${google_sql_user.production.name}:${google_sql_user.production.password}@${google_sql_database_instance.production.private_ip_address}:5432/${google_sql_database.production.name}"
        }

        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }
      }

      service_account_name = google_service_account.cloudrun.email
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale" = "100"
        "run.googleapis.com/cpu-throttling" = "false"
        "run.googleapis.com/vpc-access-connector" = google_vpc_access_connector.connector.name
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

# VPC Access Connector for Cloud Run
resource "google_vpc_access_connector" "connector" {
  name          = "production-connector"
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.production.name
  region        = "us-central1"
}

# Service Accounts
resource "google_service_account" "compute" {
  account_id   = "compute-sa"
  display_name = "Compute Engine Service Account"
}

resource "google_service_account" "functions" {
  account_id   = "functions-sa"
  display_name = "Cloud Functions Service Account"
}

resource "google_service_account" "cloudrun" {
  account_id   = "cloudrun-sa"
  display_name = "Cloud Run Service Account"
}

resource "google_service_account" "bigquery" {
  account_id   = "bigquery-sa"
  display_name = "BigQuery Service Account"
}

# IAM Bindings
resource "google_project_iam_member" "compute_sa_logging" {
  project = data.google_project.current.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

resource "google_project_iam_member" "compute_sa_monitoring" {
  project = data.google_project.current.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.compute.email}"
}

resource "google_project_iam_member" "functions_sa_sql" {
  project = data.google_project.current.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

resource "google_project_iam_member" "functions_sa_bigquery" {
  project = data.google_project.current.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.functions.email}"
}

# Data sources
data "google_project" "current" {}

# Random IDs for unique naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "random_id" "db_suffix" {
  byte_length = 4
}