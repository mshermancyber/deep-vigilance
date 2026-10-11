# tp-terraform.tf: Insecure security group — 0.0.0.0/0 CIDR
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Insecure security group"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
