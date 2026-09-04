import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED_TOOLS = [
  "echo_veil_remember",
  "echo_veil_refresh_live",
  "echo_veil_promote",
  "echo_veil_recall",
  "echo_veil_context",
  "echo_veil_forget",
  "echo_veil_list",
  "echo_veil_doctor",
  "echo_veil_reindex",
];
const ENV_ALLOWLIST = [
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "WINDIR",
];

function fail(message, result) {
  const detail = result
    ? `\nstdout:\n${result.stdout || ""}\nstderr:\n${result.stderr || ""}`
    : "";
  throw new Error(`${message}${detail}`);
}

const pluginRoot = realpathSync(
  join(dirname(fileURLToPath(import.meta.url)), ".."),
);
const stateDir = mkdtempSync(join(tmpdir(), "echo-veil-openclaw-loader-"));
const configPath = join(stateDir, "openclaw.json");
const environment = {
  OPENCLAW_STATE_DIR: stateDir,
  OPENCLAW_CONFIG_PATH: configPath,
};
for (const name of ENV_ALLOWLIST) {
  const value = process.env[name];
  if (typeof value === "string") environment[name] = value;
}
const command = process.env.OPENCLAW_COMMAND?.trim() || "openclaw";

function run(args) {
  return spawnSync(command, args, {
    cwd: pluginRoot,
    encoding: "utf8",
    env: environment,
    shell: false,
    timeout: 60_000,
  });
}

try {
  // Newer hosts require explicit trust for non-ClawHub sources. Opt in only
  // after reviewing this package; --force is confined to this fresh temp state.
  const confirmLocalSource = process.argv.includes("--confirm-local-source");
  const installed = run([
    "plugins", "install", "-l", pluginRoot,
    ...(confirmLocalSource ? ["--force", "--accept-capabilities"] : []),
  ]);
  if (installed.status !== 0) fail("isolated plugin install failed", installed);

  for (const setting of [
    "plugins.entries.echo-veil.hooks.allowConversationAccess",
    "plugins.entries.echo-veil.hooks.allowPromptInjection",
  ]) {
    const configured = run(["config", "set", setting, "true", "--strict-json"]);
    if (configured.status !== 0) {
      fail(`failed to enable required hook policy ${setting}`, configured);
    }
  }

  const inspected = run([
    "plugins",
    "inspect",
    "echo-veil",
    "--runtime",
    "--json",
  ]);
  if (inspected.status !== 0) fail("runtime inspection failed", inspected);
  let inspection;
  try {
    inspection = JSON.parse(inspected.stdout);
  } catch {
    fail("runtime inspection did not return JSON", inspected);
  }
  const plugin = inspection?.plugin;
  if (
    plugin?.status !== "loaded" ||
    plugin?.kind !== "memory" ||
    plugin?.memorySlotSelected !== true
  ) {
    fail("Echo Veil did not load as the selected memory slot", inspected);
  }
  if (JSON.stringify(plugin.toolNames) !== JSON.stringify(EXPECTED_TOOLS)) {
    fail("Echo Veil did not register the exact nine-tool contract", inspected);
  }
  const typedHookNames = inspection?.typedHooks?.map((hook) => hook.name).sort();
  if (
    JSON.stringify(typedHookNames) !==
    JSON.stringify([
      "before_agent_reply",
      "before_agent_run",
      "before_prompt_build",
    ])
  ) {
    fail("Echo Veil did not register all three protected turn hooks", inspected);
  }
  if (
    !Array.isArray(inspection.diagnostics) ||
    inspection.diagnostics.length !== 0
  ) {
    fail("runtime inspection reported diagnostics", inspected);
  }

  const config = JSON.parse(readFileSync(configPath, "utf8"));
  if (config?.plugins?.slots?.memory !== "echo-veil") {
    fail("isolated install did not select Echo Veil as memory authority");
  }
  const hookPolicy = config?.plugins?.entries?.["echo-veil"]?.hooks;
  if (
    hookPolicy?.allowConversationAccess !== true ||
    hookPolicy?.allowPromptInjection !== true
  ) {
    fail("isolated install did not retain the required hook policy");
  }

  const doctor = run(["plugins", "doctor"]);
  if (
    doctor.status !== 0 ||
    ![
      "No plugin issues detected",
      "No plugin issues detected.",
      'Plugin discovery, module loading, compatibility, and configuration checks passed. Run "openclaw health" to check the running Gateway, including runtime quarantines and fallbacks.',
    ].includes(doctor.stdout.trim())
  ) {
    fail("isolated plugin doctor failed", doctor);
  }
  process.stdout.write(
    "OpenClaw loader validation passed: Echo Veil owns the isolated memory slot, registered nine tools, and loaded all three protected turn hooks.\n",
  );
} finally {
  rmSync(stateDir, { recursive: true, force: true });
}
