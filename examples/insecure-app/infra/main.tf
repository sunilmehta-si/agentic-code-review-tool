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
