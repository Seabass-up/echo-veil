import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "openclaw/plugin-sdk/plugin-entry": fileURLToPath(
        new URL("./tests/openclaw-plugin-entry.ts", import.meta.url),
      ),
      "openclaw/plugin-sdk/tool-results": fileURLToPath(
        new URL("./tests/openclaw-tool-results.ts", import.meta.url),
      ),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
