# fp-terraform.tf: Simple variable — no security-sensitive resources
variable "environment" {
  type    = string
  default = "production"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

output "env_name" {
  value = var.environment
}
