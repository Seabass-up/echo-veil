# Cloudflare deployment

This configuration creates the runtime Access service token, the Service Auth
policy, an operator policy restricted to Cloudflare account members, free WARP
and disk-encryption posture rules, the Access application for
`memory.algo-cli.com`, and the DNS-only enclave origin record.

Prerequisites:

1. Create or confirm the Zero Trust organization with team domain
   `algo-cli.cloudflareaccess.com` and the built-in Cloudflare identity provider.
2. Create a scoped API token with `Access: Apps and Policies Write`,
   `Access: Service Tokens Write`, `Zero Trust Write`, and DNS edit access for
   `algo-cli.com`. Export it as `CLOUDFLARE_API_TOKEN`.
3. Deploy Azure first and obtain its static public IPv4.
4. Use an encrypted remote Terraform/OpenTofu state backend. The service-token
   secret necessarily appears in state.

Apply:

```bash
terraform init
terraform apply \
  -var cloudflare_account_id="$CF_ACCOUNT_ID" \
  -var cloudflare_zone_id="$CF_ZONE_ID" \
  -var enclave_origin_ipv4="$ENCLAVE_ORIGIN_IPV4"
```

Copy the sensitive service-token outputs directly into Azure Key Vault or the
runtime's equivalent secret injection. Do not write them into `.env` files or
source control.

Next, upload the Worker-to-origin client certificate with Wrangler, capture its
certificate ID, set the Worker origin secret, and deploy:

```bash
cd cloudflare/enclave-gateway
npx wrangler mtls-certificate upload --cert client.pem --key client.key
npx wrangler secret put ENCLAVE_ORIGIN_TOKEN
CF_ACCESS_AUD="$(terraform -chdir=../../deploy/cloudflare output -raw access_application_aud)" \
CF_MTLS_CERTIFICATE_ID="$CF_MTLS_CERTIFICATE_ID" \
npm run deploy
```

The generated Worker configuration is ignored by Git. Deployment refuses to
render without a real Access audience and mTLS certificate ID.
