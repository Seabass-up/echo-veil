resource "cloudflare_zero_trust_access_service_token" "echo_veil_runtime" {
  account_id = var.cloudflare_account_id
  name       = "Echo Veil runtime"
  duration   = "2160h"

  lifecycle {
    create_before_destroy = true
  }
}
resource "cloudflare_zero_trust_device_posture_rule" "warp_enrolled" {
  account_id  = var.cloudflare_account_id
  name        = "Echo Veil - Cloudflare One enrolled"
  description = "Require the free Cloudflare One client to be connected."
  type        = "warp"
  expiration  = "10m"
  schedule    = "5m"
}

resource "cloudflare_zero_trust_device_posture_rule" "disk_encrypted" {
  account_id  = var.cloudflare_account_id
  name        = "Echo Veil - encrypted system disks"
  description = "Require all disks reported by the Cloudflare One client to be encrypted."
  type        = "disk_encryption"
  expiration  = "10m"
  schedule    = "5m"
  input = {
    require_all = true
  }
}

resource "cloudflare_zero_trust_access_policy" "runtime_service" {
  account_id       = var.cloudflare_account_id
  name             = "Echo Veil runtime service authentication"
  decision         = "non_identity"
  session_duration = "1h"
  include = [{
    service_token = {
      token_id = cloudflare_zero_trust_access_service_token.echo_veil_runtime.id
    }
  }]
}

resource "cloudflare_zero_trust_access_policy" "operator" {
  account_id       = var.cloudflare_account_id
  name             = "Echo Veil account-member operators"
  decision         = "allow"
  session_duration = "1h"
  include = [{
    cloudflare_account_member = {
      account_id = var.cloudflare_account_id
    }
  }]
  require = [
    {
      device_posture = {
        integration_uid = cloudflare_zero_trust_device_posture_rule.warp_enrolled.id
      }
    },
    {
      device_posture = {
        integration_uid = cloudflare_zero_trust_device_posture_rule.disk_encrypted.id
      }
    }
  ]
  mfa_config = {
    mfa_disabled           = false
    allowed_authenticators = ["totp", "biometrics", "security_key"]
    session_duration       = "1h"
  }
}

resource "cloudflare_zero_trust_access_application" "echo_veil" {
  account_id                  = var.cloudflare_account_id
  name                        = "Echo Veil confidential memory"
  domain                      = "memory.algo-cli.com"
  type                        = "self_hosted"
  app_launcher_visible        = false
  allow_authenticate_via_warp = true
  enable_binding_cookie       = true
  http_only_cookie_attribute  = true
  same_site_cookie_attribute  = "strict"
  service_auth_401_redirect   = true
  session_duration            = "1h"
  destinations = [{
    type = "public"
    uri  = "memory.algo-cli.com"
  }]
  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.runtime_service.id
      precedence = 1
    },
    {
      id         = cloudflare_zero_trust_access_policy.operator.id
      precedence = 2
    }
  ]
}

resource "cloudflare_dns_record" "enclave_origin" {
  zone_id = var.cloudflare_zone_id
  name    = "enclave-origin.algo-cli.com"
  type    = "A"
  content = var.enclave_origin_ipv4
  ttl     = 300
  proxied = false
  comment = "DNS-only Azure SEV-SNP origin for Echo Veil Worker mTLS"
  tags    = ["owner:echo-veil", "security:dns-only"]
}
