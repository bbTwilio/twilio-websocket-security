###############################################################################
# AWS WAF in front of a Twilio WebSocket endpoint.
#
# Read this before tuning anything: a WAF inspects the HTTP upgrade request and
# nothing after it. Once the 101 goes back, frames flow past untouched -- no
# managed rule, no rate rule, no logging rule sees a single one. Every control
# here therefore applies exactly once per connection, at the handshake.
#
# What that means in practice:
#   - The WAF cannot protect the conversation. Only your app can.
#   - The WAF is still worth having, because the handshake is where floods,
#     scanners and junk traffic show up.
#   - Do NOT try to allowlist Twilio source IPs. Twilio publishes no fixed
#     egress ranges for this and explicitly says to allow any public IP:
#     https://www.twilio.com/docs/global-infrastructure/firewall-configurations/media-streams-configuration
###############################################################################

variable "ws_path" {
  description = "Path of the WebSocket upgrade endpoint."
  type        = string
  default     = "/ws"
}

variable "alb_arn" {
  description = "ARN of the ALB to associate. Leave null for CloudFront-only use."
  type        = string
  default     = null
}

resource "aws_wafv2_web_acl" "relay" {
  name  = "twilio-relay-acl"
  scope = "REGIONAL" # use "CLOUDFRONT" (in us-east-1) for a CloudFront distribution

  default_action {
    allow {}
  }

  # --------------------------------------------------------------------------
  # 1. Rate-limit the upgrade path.
  #
  # The most useful rule you can write. One WebSocket connection = one request
  # here, so a low threshold that would be absurd for a web page is exactly
  # right for a handshake endpoint: legitimate traffic opens one socket per
  # call, and nothing else.
  #
  # 100 per 5-minute window per IP. Raise it only if you have measured your
  # real concurrency; Twilio connects from many source IPs, so this is a
  # blunt-force flood control, not per-tenant fairness.
  # --------------------------------------------------------------------------
  rule {
    name     = "rate-limit-upgrade"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string         = var.ws_path
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-upgrade"
      sampled_requests_enabled   = false # would sample the token in the query string
    }
  }

  # --------------------------------------------------------------------------
  # 2. Require the Twilio signature header to be present.
  #
  # Cheap structural filter, not authentication -- the header's *value* is
  # verified in your application, because only your app has the auth token.
  # This just drops scanners that never send one, before they reach compute.
  # --------------------------------------------------------------------------
  rule {
    name     = "require-twilio-signature-header"
    priority = 2

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string         = var.ws_path
            positional_constraint = "STARTS_WITH"

            field_to_match {
              uri_path {}
            }

            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }

        statement {
          not_statement {
            statement {
              size_constraint_statement {
                comparison_operator = "GT"
                size                = 0

                field_to_match {
                  single_header {
                    name = "x-twilio-signature"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "require-twilio-signature-header"
      sampled_requests_enabled   = false
    }
  }

  # --------------------------------------------------------------------------
  # 3. Managed rules -- with the upgrade path excluded.
  #
  # This is the rule group that breaks people. A ConversationRelay handshake is
  # an unusual-looking GET: Upgrade/Connection headers, no body, and a long
  # base64url JWT in the query string. Managed rules flag exactly that shape.
  #
  # The usual culprits:
  #   - SizeRestrictions_QUERYSTRING       long JWT in ?t=
  #   - GenericRFI_QUERYARGUMENTS          dots and slashes in the JWT
  #   - NoUserAgent_HEADER                 Twilio sends no User-Agent on upgrade
  #   - CrossSiteScripting_QUERYARGUMENTS  false-positives on base64url payloads
  #
  # The failure is miserable to diagnose because the call simply never connects
  # and Twilio reports error 64102 with no detail. If a handshake works locally
  # and dies behind the WAF, look here first -- check the WAF sampled requests
  # for BLOCK actions on your ws path.
  #
  # Scoping the managed group to everything EXCEPT the upgrade path is the
  # cleaner move: the upgrade request carries no body and no user input beyond a
  # token you cryptographically verify yourself, so there is very little for
  # these rules to usefully protect.
  # --------------------------------------------------------------------------
  rule {
    name     = "aws-managed-common-except-upgrade"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        scope_down_statement {
          not_statement {
            statement {
              byte_match_statement {
                search_string         = var.ws_path
                positional_constraint = "STARTS_WITH"

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-managed-common-except-upgrade"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "twilio-relay-acl"
    sampled_requests_enabled   = false
  }

  tags = {
    Purpose = "twilio-websocket-handshake-protection"
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.alb_arn == null ? 0 : 1
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.relay.arn
}
