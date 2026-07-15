output "access_application_aud" {
  description = "Set CF_ACCESS_AUD to this value before rendering the Worker config."
  value       = cloudflare_zero_trust_access_application.echo_veil.aud
}
output "access_service_token_client_id" {
  description = "Store as CF_ACCESS_CLIENT_ID in the Echo Veil runtime secret manager."
  value       = cloudflare_zero_trust_access_service_token.echo_veil_runtime.client_id
  sensitive   = true
}

output "access_service_token_client_secret" {
  description = "Store as CF_ACCESS_CLIENT_SECRET and remove it from operator terminals."
  value       = cloudflare_zero_trust_access_service_token.echo_veil_runtime.client_secret
  sensitive   = true
}

output "access_team_domain" {
  value = "https://algo-cli.cloudflareaccess.com"
}

output "worker_custom_domain" {
  value = "memory.algo-cli.com"
}

output "enclave_origin_domain" {
  value = cloudflare_dns_record.enclave_origin.name
}
