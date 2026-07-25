declare module "openclaw/plugin-sdk/plugin-entry" {
  import type { TSchema } from "typebox";

  export type AgentToolResult<TDetails = unknown> = {
    content: Array<{ type: "text"; text: string }>;
    details: TDetails;
  };

  export type AnyAgentTool = {
    name: string;
    label: string;
    description: string;
    parameters: TSchema;
    execute: (
      toolCallId: string,
      params: unknown,
      signal?: AbortSignal,
      onUpdate?: unknown,
    ) => Promise<AgentToolResult>;
  };

  export type MemoryPromptSectionBuilder = (params: {
    availableTools: Set<string>;
    citationsMode?: string;
  }) => string[];

  export type OpenClawPluginApi = {
    config?: Record<string, unknown>;
    pluginConfig?: Record<string, unknown>;
    runtime: {
      config: {
        current: () => Record<string, unknown>;
      };
    };
    on: {
      (
        hookName: "before_agent_reply",
        handler: (
          event: { cleanedBody: string },
          context: {
            runId?: string;
            sessionId?: string;
            sessionKey?: string;
          },
        ) =>
          | {
              handled: boolean;
              reply?: { text: string };
              reason?: string;
            }
          | Promise<{
              handled: boolean;
              reply?: { text: string };
              reason?: string;
            }>,
        options?: { priority?: number; timeoutMs?: number },
      ): void;
      (
        hookName: "before_prompt_build",
        handler: (
          event: { prompt: string; messages: unknown[] },
          context: {
            runId?: string;
            sessionId?: string;
            sessionKey?: string;
          },
        ) =>
          | {
              prependContext?: string;
              prependSystemContext?: string;
            }
          | Promise<{
              prependContext?: string;
              prependSystemContext?: string;
            }>,
        options?: { priority?: number; timeoutMs?: number },
      ): void;
      (
        hookName: "before_agent_run",
        handler: (
          event: {
            prompt: string;
            messages: unknown[];
            systemPrompt?: string;
          },
          context: {
            runId?: string;
            sessionId?: string;
            sessionKey?: string;
          },
        ) =>
          | { outcome: "pass" }
          | {
              outcome: "block";
              reason: string;
              message?: string;
              category?: string;
            }
          | Promise<
              | { outcome: "pass" }
              | {
                  outcome: "block";
                  reason: string;
                  message?: string;
                  category?: string;
                }
            >,
        options?: { priority?: number; timeoutMs?: number },
      ): void;
    };
    registerTool: (
      tool: AnyAgentTool,
      options?: { name?: string; names?: string[]; optional?: boolean },
    ) => void;
    registerMemoryCapability: (capability: {
      promptBuilder?: MemoryPromptSectionBuilder;
    }) => void;
  };

  export type DefinedPluginEntry = {
    readonly id: string;
    readonly name: string;
    readonly description: string;
    readonly configSchema: TSchema;
    readonly register: (api: OpenClawPluginApi) => void;
  };

  export function definePluginEntry(definition: DefinedPluginEntry): DefinedPluginEntry;
}

declare module "openclaw/plugin-sdk/tool-results" {
  import type { AgentToolResult } from "openclaw/plugin-sdk/plugin-entry";

  export function jsonResult<TDetails>(
    payload: TDetails,
  ): AgentToolResult<TDetails>;
}
