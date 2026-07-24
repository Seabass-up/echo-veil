import {
  closeSync,
  fchmodSync,
  fsyncSync,
  mkdtempSync,
  openSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

function required(environment, name) {
  return validate(name, environment[name]);
}

function optional(environment, name, fallback) {
  const value = environment[name];
  return value === undefined ? fallback : validate(name, value);
}

export function buildConfig(environment = process.env) {
  return {
    $schema: "node_modules/wrangler/config-schema.json",
    name: "echo-veil-enclave-gateway",
    main: "src/index.ts",
    compatibility_date: "2026-07-21",
    compatibility_flags: ["nodejs_compat"],
    workers_dev: false,
    routes: [{ pattern: "memory.algo-cli.com", custom_domain: true }],
    vars: {
      TEAM_DOMAIN: optional(
        environment,
        "CF_ACCESS_TEAM_DOMAIN",
        "https://algo-cli.cloudflareaccess.com",
      ),
      POLICY_AUD: required(environment, "CF_ACCESS_AUD"),
      ENCLAVE_ORIGIN: optional(
        environment,
        "ECHO_VEIL_ENCLAVE_ORIGIN",
        "https://enclave-origin.algo-cli.com",
      ),
    },
    mtls_certificates: [
      {
        binding: "ENCLAVE_MTLS",
        certificate_id: required(environment, "CF_MTLS_CERTIFICATE_ID"),
      },
    ],
    observability: {
      enabled: true,
      logs: { enabled: true, head_sampling_rate: 1, invocation_logs: true },
      traces: { enabled: true, head_sampling_rate: 0.01 },
    },
  };
}

const output = new URL("../.wrangler.generated.json", import.meta.url);

export function writeGeneratedConfig(config, destination) {
  const outputPath =
    destination instanceof URL ? fileURLToPath(destination) : resolve(destination);
  const temporaryDirectory = mkdtempSync(
    join(dirname(outputPath), ".wrangler-config-"),
  );
  const temporaryPath = join(temporaryDirectory, "config.json");
  try {
    const descriptor = openSync(temporaryPath, "wx", 0o600);
    try {
      writeFileSync(descriptor, `${JSON.stringify(config, null, 2)}\n`, "utf8");
      fchmodSync(descriptor, 0o600);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporaryPath, outputPath);
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  writeGeneratedConfig(buildConfig(), output);
}
