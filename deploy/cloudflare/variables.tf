variable "cloudflare_account_id" {
  description = "Cloudflare account ID."
  type        = string
  sensitive   = true
}
variable "cloudflare_zone_id" {
  description = "Zone ID for algo-cli.com."
  type        = string
  sensitive   = true
}

variable "enclave_origin_ipv4" {
  description = "Static public IPv4 output by the Azure confidential-VM deployment."
  type        = string
  validation {
    condition     = can(cidrhost("${var.enclave_origin_ipv4}/32", 0))
    error_message = "enclave_origin_ipv4 must be a valid IPv4 address."
  }
}
