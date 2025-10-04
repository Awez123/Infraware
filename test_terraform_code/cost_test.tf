resource "aws_instance" "web_server" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.medium"
  
  tags = {
    Name = "WebServer"
  }
}

resource "aws_ebs_volume" "storage" {
  availability_zone = "us-west-2a"
  size              = 100
  type             = "gp3"
  
  tags = {
    Name = "Storage"
  }
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-data-bucket-12345"
}

resource "google_compute_instance" "app_server" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }
}

resource "azurerm_virtual_machine" "db_server" {
  name     = "db-server"
  vm_size  = "Standard_B2s"
  location = "East US"
}