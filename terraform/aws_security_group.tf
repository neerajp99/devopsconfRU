resource "aws_security_group" "api_server" {
  description = "Dev webapp security group"

  # Restoring desired state: restored missing description and Owner tag
  tags = {
    Environment = "dev"
    Owner       = "platform"
  }
}