###############################################################################
# ALB settings that decide whether long calls survive.
#
# Only relevant if you terminate WebSockets on an ALB (ECS, EKS, EC2). The
# API Gateway sample needs none of this -- and gets no say in its own timeouts,
# which is the trade-off documented in samples/aws-apigw-lambda/README.md.
###############################################################################

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate. Twilio requires a real CA-issued cert; it will not connect to a self-signed one."
  type        = string
}

resource "aws_lb" "relay" {
  name               = "twilio-relay"
  load_balancer_type = "application"
  subnets            = var.subnet_ids
  security_groups    = [aws_security_group.relay_alb.id]

  # ---------------------------------------------------------------------------
  # The setting that matters.
  #
  # Default is 60 seconds, and it is an IDLE timeout. A caller placed on hold
  # sends nothing, your bot sends nothing, and 60 seconds later the ALB closes a
  # perfectly healthy call. Raise it, and ALSO send application-level pings
  # (see samples/gcp-cloud-run/src/relay.ts) -- the ping traffic is what keeps
  # the connection from ever looking idle.
  #
  # 4000 is the maximum ALB accepts.
  # ---------------------------------------------------------------------------
  idle_timeout = 4000

  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "relay"
    enabled = true
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.relay.arn
  port              = 443
  protocol          = "HTTPS"

  # TLS 1.2 floor. Twilio requires wss:// and a valid certificate chain.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }
}

resource "aws_lb_target_group" "relay" {
  name        = "twilio-relay-tg"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  # Health checks are plain HTTP; they do not perform a WebSocket upgrade.
  # Keep /health unauthenticated but boring -- no session counts that reveal
  # traffic patterns, no build identifiers.
  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  # Give in-flight calls a chance to finish on deploy instead of cutting them.
  deregistration_delay = 120

  stickiness {
    type            = "lb_cookie"
    enabled         = false # Twilio is not a browser and will not return cookies
    cookie_duration = 86400
  }
}

resource "aws_security_group" "relay_alb" {
  name        = "twilio-relay-alb"
  description = "Ingress for Twilio WebSocket handshakes"
  vpc_id      = var.vpc_id

  # 0.0.0.0/0 on purpose, and worth stating plainly: Twilio publishes no fixed
  # egress ranges for Media Streams or ConversationRelay and documents that you
  # should accept connections from any public IP. Authentication happens in the
  # application, at the upgrade request. A narrower CIDR here would break calls
  # without adding security.
  ingress {
    description      = "TLS from Twilio (no fixed source ranges exist)"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_s3_bucket" "alb_logs" {
  bucket_prefix = "twilio-relay-alb-logs-"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ALB access logs record the full query string, which means they record the
# connection token. The token expires in 90 seconds, so this is a low-severity
# leak -- but it is still a credential sitting in a log bucket. Keep retention
# short and the bucket tightly scoped.
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}
