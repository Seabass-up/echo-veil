import { writeFileSync } from "node:fs";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const config = {
  $schema: "node_modules/wrangler/config-schema.json",
  name: "echo-veil-enclave-gateway",
  main: "src/index.ts",
  compatibility_date: "2026-07-19",
  compatibility_flags: ["nodejs_compat"],
  workers_dev: false,
  routes: [{ pattern: "memory.algo-cli.com", custom_domain: true }],
  vars: {
    TEAM_DOMAIN:
      process.env.CF_ACCESS_TEAM_DOMAIN?.trim() ||
      "https://algo-cli.cloudflareaccess.com",
    POLICY_AUD: required("CF_ACCESS_AUD"),
    ENCLAVE_ORIGIN:
      process.env.ECHO_VEIL_ENCLAVE_ORIGIN?.trim() ||
      "https://enclave-origin.algo-cli.com",
  },
  mtls_certificates: [
    {
      binding: "ENCLAVE_MTLS",
      certificate_id: required("CF_MTLS_CERTIFICATE_ID"),
    },
  ],
  observability: {
    enabled: true,
    logs: { enabled: true, head_sampling_rate: 1, invocation_logs: true },
    traces: { enabled: true, head_sampling_rate: 0.01 },
  },
};

writeFileSync(
  new URL("../.wrangler.generated.json", import.meta.url),
  `${JSON.stringify(config, null, 2)}\n`,
  { mode: 0o600 },
);
