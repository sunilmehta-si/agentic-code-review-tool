resource "aws_security_group" "bastion" {
  name = "bastion"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "azurerm_storage_account" "data" {
  name                            = "demodata"
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = true
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                    = "demo"
  private_cluster_enabled = false
  local_account_disabled  = false
}

resource "aws_instance" "inference" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "g5.xlarge"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_s3_bucket_policy" "models" {
  bucket = "acme-models"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::acme-models/*" }]
  })
}

resource "aws_kms_key" "data" {
  enable_key_rotation = false
}

resource "aws_cloudtrail" "org" {
  name           = "org"
  s3_bucket_name = "acme-trail"
  enable_logging = false
}

resource "google_storage_bucket" "datasets" {
  name                        = "acme-datasets"
  location                    = "EU"
  uniform_bucket_level_access = false
}

resource "aws_lambda_function_url" "webhook" {
  function_name      = "webhook"
  authorization_type = "NONE"
}

resource "azurerm_key_vault" "app" {
  name                     = "acme-app"
  purge_protection_enabled = false
}
