###############################################################################
# Cloud Run service settings.
#
# TIMEOUT #2 of 2. The backend service timeout in armor.tf is not enough on its
# own: Cloud Run independently caps a WebSocket at the SERVICE REQUEST TIMEOUT,
# which defaults to five minutes and maxes out at sixty. Both have to be raised.
# Get one and miss the other and your calls still drop, just at a different mark.
###############################################################################

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "public_host" {
  description = "Host only, no scheme. Must match the wss:// host in your TwiML."
  type        = string
}

variable "image" {
  description = "Container image. `gcloud run deploy --source .` builds this for you."
  type        = string
}

resource "google_secret_manager_secret" "twilio_auth_token" {
  project   = var.project_id
  secret_id = "twilio-auth-token"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "relay_token_secret" {
  project   = var.project_id
  secret_id = "relay-token-secret"

  replication {
    auto {}
  }
}

resource "google_service_account" "relay" {
  project      = var.project_id
  account_id   = "twilio-relay"
  display_name = "Twilio ConversationRelay WebSocket"
}

resource "google_secret_manager_secret_iam_member" "auth_token_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.twilio_auth_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.relay.email}"
}

resource "google_secret_manager_secret_iam_member" "token_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.relay_token_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.relay.email}"
}

resource "google_cloud_run_v2_service" "relay" {
  name     = "twilio-relay"
  project  = var.project_id
  location = var.region

  # Twilio cannot present Google IAM credentials, so the service is reachable
  # without IAM auth and authenticated at the application layer instead. That is
  # the design, not a shortcut -- see the upgrade handler in the Cloud Run sample.
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.relay.email

    # Best-effort only. Any state that must survive a reconnect belongs in
    # Memorystore or Firestore, never in an instance's memory -- which is also
    # why single-use token enforcement needs Redis once you scale past one
    # instance.
    session_affinity = true

    scaling {
      # Avoid a cold start on the upgrade request; Twilio will not wait long.
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      env {
        name  = "PUBLIC_HOST"
        value = var.public_host
      }

      env {
        name = "TWILIO_AUTH_TOKEN"

        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.twilio_auth_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "RELAY_TOKEN_SECRET"

        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.relay_token_secret.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        # An open WebSocket counts as an active request, so CPU stays allocated
        # and you are billed for the life of every call.
        cpu_idle = false
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 2
        period_seconds        = 5
        failure_threshold     = 5
      }
    }

    # ------------------------------------------------------------------------
    # The one people miss. Default is 300s (five minutes); 3600s is the ceiling.
    # A WebSocket on Cloud Run is a long-running HTTP request, so it cannot
    # outlive this value no matter what your app or your load balancer say.
    # ------------------------------------------------------------------------
    timeout = "3600s"

    max_instance_request_concurrency = 80
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.relay.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "service_url" {
  value = google_cloud_run_v2_service.relay.uri
}
