# Edge and WAF configuration

Terraform for the layer that silently breaks the other three.

> **Status:** these files are parse-checked HCL, not `terraform validate`d — the authoring environment had no Terraform binary or provider credentials. Run `terraform init && terraform validate` in your own account before applying, and treat resource arguments as reviewed reference material rather than known-good against a specific provider version.

## The one rule to internalise

**A WAF inspects the HTTP upgrade request and nothing after it.** Azure [documents this explicitly](https://learn.microsoft.com/azure/frontdoor/standard-premium/websocket); AWS WAF and Cloud Armor behave the same way. Once the `101` goes back, frames flow past untouched.

So every rule here fires exactly once per connection, at the handshake. The WAF cannot protect the conversation — only your application can.

## You cannot allowlist Twilio

The first thing every security team asks for, and it isn't available. Twilio's [Media Streams firewall docs](https://www.twilio.com/docs/global-infrastructure/firewall-configurations/media-streams-configuration) say to permit connections "from Twilio to your WebSocket servers from any public IP address," because Twilio runs on cloud infrastructure with no fixed egress ranges.

Ingress is therefore `0.0.0.0/0` on 443, deliberately, with authentication in the application. Document that decision before your auditor finds it.

## Files

| File | Covers |
|---|---|
| `aws/waf.tf` | Rate-limit the upgrade path, require the signature header, exclude managed rules from the ws path |
| `aws/alb.tf` | `idle_timeout = 4000`, TLS policy, access-log retention |
| `gcp/armor.tf` | Cloud Armor throttling, preconfigured rules in preview, `timeout_sec = 3600` |
| `gcp/cloud-run.tf` | `timeout = "3600s"`, secrets, session affinity |
| `azure/frontdoor.tf` | WAF policy, managed-rule exclusions, and the caching trap |

## Four invariants, every platform

1. **Don't cache the upgrade route.** On Front Door this doesn't degrade the connection, it prevents it.
2. **Forward `Upgrade` and `Connection`.**
3. **Raise the idle timeout, and send pings.** A caller on hold is indistinguishable from a dead connection.
4. **Rate-limit the upgrade path.** One connection is one request here, so thresholds that would be absurd for a web page are correct.

## Managed rules will false-positive

A ConversationRelay handshake is an unusual-looking GET: `Upgrade`/`Connection` headers, no body, no `User-Agent`, and a long base64url JWT in the query string. Signature rule sets flag exactly that shape.

Usual culprits on AWS: `SizeRestrictions_QUERYSTRING`, `GenericRFI_QUERYARGUMENTS`, `NoUserAgent_HEADER`, `CrossSiteScripting_QUERYARGUMENTS`. On Azure and GCP, the XSS and SQLi sets.

The failure is miserable to diagnose because the call simply never connects and Twilio reports [error 64102](https://www.twilio.com/docs/api/errors/64102) with no detail. **If a handshake works locally and dies behind the WAF, look here first** — check your WAF's sampled requests for `BLOCK` on the ws path.

These configs scope managed rules *away* from the upgrade path rather than weakening them globally. That upgrade request carries no user input beyond a token you cryptographically verify yourself, so there is little there for signature rules to usefully protect.

## Timeout reference

| Platform | Idle | Max duration | Adjustable |
|---|---|---|---|
| AWS ALB | 60s default | None | Yes, to 4000s |
| AWS API Gateway (WS) | 10 min | 2 h | **No** |
| GCP Cloud Run | — | 5 min default | Yes, to 60 min |
| GCP App Load Balancer | 30s default | 24 h | Yes |
| Azure Front Door | 5 min | 2 h | **No** |
| Azure App Gateway v2 | Configurable | — | Yes |

On GCP note that **two independent timeouts** each cap your calls: the Cloud Run request timeout and the backend service timeout. Raise both.

Google's documented semantics for whether the backend service timeout bounds idle time or total duration have differed between load balancer generations. Rather than depend on which applies to your setup, raise it *and* send pings — correct under either reading.

## Sampled requests and access logs

These configs set `sampled_requests_enabled = false` on AWS rules touching the ws path, because sampling captures the query string and therefore the connection token. The token expires in 90 seconds, so this is low severity — but it is still a credential in a log store. Access-log retention is capped at 30 days for the same reason.
