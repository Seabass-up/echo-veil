import { chmodSync, lstatSync, writeFileSync } from "node:fs";

function validate(name, value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value !== value.trim() ||
    new TextEncoder().encode(value).byteLength > 4096 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function required(name) {
  return validate(name, process.env[name]);
}

function optional(name, fallback) {
  const value = process.env[name];
  return value === undefined ? fallback : validate(name, value);
}

const config = {
  $schema: "node_modules/wrangler/config-schema.json",
  name: "echo-veil-enclave-gateway",
  main: "src/index.ts",
  compatibility_date: "2026-07-21",
  compatibility_flags: ["nodejs_compat"],
  workers_dev: false,
  routes: [{ pattern: "memory.algo-cli.com", custom_domain: true }],
  vars: {
    TEAM_DOMAIN: optional(
      "CF_ACCESS_TEAM_DOMAIN",
      "https://algo-cli.cloudflareaccess.com",
    ),
    POLICY_AUD: required("CF_ACCESS_AUD"),
    ENCLAVE_ORIGIN: optional(
      "ECHO_VEIL_ENCLAVE_ORIGIN",
      "https://enclave-origin.algo-cli.com",
    ),
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

const output = new URL("../.wrangler.generated.json", import.meta.url);
try {
  if (lstatSync(output).isSymbolicLink()) {
    throw new Error("generated Wrangler config must not be a symbolic link");
  }
} catch (error) {
  if (!(error && typeof error === "object" && error.code === "ENOENT")) {
    throw error;
  }
}
writeFileSync(
  output,
  `${JSON.stringify(config, null, 2)}\n`,
  { mode: 0o600 },
);
chmodSync(output, 0o600);
