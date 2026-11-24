# Synthetic local HCL; no initialization, provider or module downloads.
resource "aws_security_group_rule" "synthetic" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = "sg-synthetic"
  description       = "Synthetic SSH rule"
}
