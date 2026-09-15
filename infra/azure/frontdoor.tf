###############################################################################
# Azure Front Door + WAF for a Twilio WebSocket.
#
# Front Door Standard and Premium both support WebSockets with no extra
# configuration -- but this platform has the sharpest edge of the three, and it
# is a silent one. See the caching note below; it is the whole reason this file
# has so many comments.
#
# Front Door's WAF inspects only the establishment phase. Microsoft documents
# this explicitly: "WAF inspections are applied during the WebSocket
# establishment phase. After the connection is established, the WAF doesn't
# perform further inspections."
# https://learn.microsoft.com/azure/frontdoor/standard-premium/websocket
###############################################################################

variable "resource_group_name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "origin_host" {
  description = "Backend host serving the WebSocket, e.g. relay.azurewebsites.net"
  type        = string
}

variable "ws_path" {
  type    = string
  default = "/ws"
}

resource "azurerm_cdn_frontdoor_profile" "relay" {
  name                = "twilio-relay-fd"
  resource_group_name = var.resource_group_name

  # Premium is required for managed WAF rule sets. Standard supports WebSockets
  # but only custom WAF rules.
  sku_name = "Premium_AzureFrontDoor"

  # Front Door closes a WebSocket after 5 minutes idle and 2 hours total. Both
  # are fixed -- you cannot raise them. Application-level pings are mandatory
  # here, not optional, because a caller on hold trips the idle timer.
  response_timeout_seconds = 120
}

resource "azurerm_cdn_frontdoor_endpoint" "relay" {
  name                     = "twilio-relay"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.relay.id
}

resource "azurerm_cdn_frontdoor_origin_group" "relay" {
  name                     = "relay-origins"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.relay.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  # Health probes speak plain HTTP. They do not perform a WebSocket upgrade, so
  # point them at a normal HTTP endpoint, never at the ws path.
  health_probe {
    path                = "/health"
    protocol            = "Https"
    request_type        = "GET"
    interval_in_seconds = 30
  }
}

resource "azurerm_cdn_frontdoor_origin" "relay" {
  name                          = "relay-origin"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.relay.id
  enabled                       = true

  host_name          = var.origin_host
  origin_host_header = var.origin_host
  https_port         = 443
  http_port          = 80
  priority           = 1
  weight             = 1

  certificate_name_check_enabled = true
}

###############################################################################
# THE ROUTE. Read the caching comment before changing anything here.
###############################################################################

resource "azurerm_cdn_frontdoor_route" "websocket" {
  name                          = "websocket-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.relay.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.relay.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.relay.id]

  supported_protocols    = ["Https"]
  patterns_to_match      = [var.ws_path, "${var.ws_path}/*"]
  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = true
  link_to_default_domain = true

  # ---------------------------------------------------------------------------
  # DO NOT ENABLE CACHING ON THIS ROUTE.
  #
  # This is the trap. From Microsoft's own documentation: for routes with caching
  # enabled, "Azure Front Door doesn't forward the WebSocket Upgrade header to
  # the origin and treats it as an HTTP request, disregarding cache rules. This
  # behavior results in a failed WebSocket upgrade request."
  #
  # So enabling caching does not slow your WebSocket down -- it stops it existing.
  # The upgrade header is dropped, your server sees an ordinary GET, no 101 is
  # ever returned, and Twilio reports error 64102. Nothing in the Front Door
  # metrics says "caching broke your WebSocket."
  #
  # In this provider, caching is off precisely when the `cache` block is absent.
  # Do not add one. If you inherit a route that has one, remove it.
  # ---------------------------------------------------------------------------
}

###############################################################################
# WAF policy
###############################################################################

resource "azurerm_cdn_frontdoor_firewall_policy" "relay" {
  name                = "twilioRelayWaf"
  resource_group_name = var.resource_group_name
  sku_name            = azurerm_cdn_frontdoor_profile.relay.sku_name
  enabled             = true
  mode                = "Prevention"

  # Rate-limit the handshake. One connection is one request at this layer, so a
  # low ceiling is correct.
  custom_rule {
    name                           = "RateLimitHandshake"
    enabled                        = true
    priority                       = 100
    rate_limit_duration_in_minutes = 5
    rate_limit_threshold           = 100
    type                           = "RateLimitRule"
    action                         = "Block"

    match_condition {
      match_variable     = "RequestUri"
      operator           = "Contains"
      match_values       = [var.ws_path]
      negation_condition = false
    }
  }

  # Structural check only -- the signature's value is verified in the app.
  custom_rule {
    name     = "RequireTwilioSignature"
    enabled  = true
    priority = 200
    type     = "MatchRule"
    action   = "Block"

    match_condition {
      match_variable     = "RequestUri"
      operator           = "Contains"
      match_values       = [var.ws_path]
      negation_condition = false
    }

    match_condition {
      match_variable     = "RequestHeader"
      selector           = "X-Twilio-Signature"
      operator           = "Any"
      negation_condition = true # block when the header is absent
      match_values       = []
    }
  }

  # Managed rules false-positive on the base64url JWT in the query string.
  # Exclude the token parameter rather than weakening the rule set as a whole.
  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"

    exclusion {
      match_variable = "QueryStringArgNames"
      operator       = "Equals"
      selector       = "t"
    }

    override {
      rule_group_name = "SQLI"

      exclusion {
        match_variable = "QueryStringArgNames"
        operator       = "Equals"
        selector       = "t"
      }
    }
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.0"
    action  = "Log" # Twilio sends no User-Agent on the upgrade and can look "bot-like"
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "relay" {
  name                     = "twilio-relay-security-policy"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.relay.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.relay.id

      association {
        patterns_to_match = ["/*"]

        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.relay.id
        }
      }
    }
  }
}

###############################################################################
# Note on Application Gateway
#
# If Front Door's fixed 5-minute idle / 2-hour maximum will not work for you,
# Azure Application Gateway v2 also supports WebSockets, has a configurable
# backend request timeout, and offers WAF_v2. It is regional rather than global,
# so you trade global anycast for control over the timeouts.
###############################################################################
