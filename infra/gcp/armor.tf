###############################################################################
# Cloud Armor + external Application Load Balancer for a Twilio WebSocket.
#
# Same rule as everywhere else: Cloud Armor evaluates the HTTP upgrade request
# and then stops. Once the connection is established, frames are proxied without
# inspection. Everything below is a handshake-time control.
#
# GCP's WebSocket support needs no enabling -- the Application Load Balancer
# proxies WebSockets natively. What GCP *does* need is timeout attention, and
# there are two separate timeouts that will each independently kill your calls.
###############################################################################

variable "project_id" {
  type = string
}

variable "ws_path" {
  type    = string
  default = "/ws"
}

variable "cloud_run_service_name" {
  type    = string
  default = "twilio-relay"
}

variable "region" {
  type    = string
  default = "us-central1"
}

resource "google_compute_security_policy" "relay" {
  name    = "twilio-relay-policy"
  project = var.project_id

  # --------------------------------------------------------------------------
  # Rate-limit the upgrade path.
  #
  # One connection = one request here, so a threshold that would throttle a
  # normal web page is correct for a handshake endpoint.
  # --------------------------------------------------------------------------
  rule {
    action   = "throttle"
    priority = 1000
    preview  = false

    match {
      expr {
        expression = "request.path.startsWith('${var.ws_path}')"
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"

      enforce_on_key = "IP"

      rate_limit_threshold {
        count        = 100
        interval_sec = 300
      }
    }

    description = "Throttle WebSocket handshake attempts per source IP"
  }

  # --------------------------------------------------------------------------
  # Drop upgrade attempts with no Twilio signature header.
  #
  # Structural filter only. The header's value is verified in the application,
  # which is the only place that holds the auth token.
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(401)"
    priority = 1100
    preview  = false

    match {
      expr {
        expression = <<-EOT
          request.path.startsWith('${var.ws_path}')
          && !has(request.headers['x-twilio-signature'])
        EOT
      }
    }

    description = "Require the X-Twilio-Signature header on handshakes"
  }

  # --------------------------------------------------------------------------
  # Preconfigured WAF rules, scoped AWAY from the upgrade path.
  #
  # A ConversationRelay handshake carries a long base64url JWT in its query
  # string, which the XSS and SQLi signature sets reliably false-positive on.
  # Start these in preview mode and read the logs before enforcing; a blocked
  # handshake surfaces only as Twilio error 64102 and a silent call.
  # --------------------------------------------------------------------------
  rule {
    action   = "deny(403)"
    priority = 2000
    preview  = true # flip to false only after reviewing Cloud Logging

    match {
      expr {
        expression = <<-EOT
          !request.path.startsWith('${var.ws_path}')
          && evaluatePreconfiguredExpr('xss-v33-stable')
        EOT
      }
    }

    description = "XSS signatures, excluding the WebSocket upgrade path"
  }

  # Default: allow. Twilio publishes no fixed egress ranges, so there is no
  # allowlist to build here -- authentication is the application's job.
  rule {
    action   = "allow"
    priority = 2147483647

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    description = "Default allow; Twilio has no fixed source ranges to allowlist"
  }

  advanced_options_config {
    json_parsing = "STANDARD"
    log_level    = "NORMAL"
  }
}

###############################################################################
# Load balancer wiring
###############################################################################

resource "google_compute_region_network_endpoint_group" "relay" {
  name                  = "twilio-relay-neg"
  project               = var.project_id
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = var.cloud_run_service_name
  }
}

resource "google_compute_backend_service" "relay" {
  name                  = "twilio-relay-backend"
  project               = var.project_id
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"

  security_policy = google_compute_security_policy.relay.id

  backend {
    group = google_compute_region_network_endpoint_group.relay.id
  }

  # ---------------------------------------------------------------------------
  # TIMEOUT #1 of 2: the backend service timeout.
  #
  # Defaults to THIRTY SECONDS. Leave it and your calls die about half a minute
  # in, which reads like a bug in your application rather than a load balancer
  # setting.
  #
  # Google's semantics here have differed between load balancer generations --
  # on some it bounds idle time, on others total connection duration. Rather
  # than depend on which, do both: raise this to an hour AND send application
  # -level pings so the connection never looks idle under either reading.
  # ---------------------------------------------------------------------------
  timeout_sec = 3600

  # Do NOT set protocol = "HTTP2" end-to-end: it breaks the WebSocket upgrade.

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}
