declare module "@earendil-works/pi-coding-agent" {
  export type ToolResult = {
    content: Array<{ type: "text"; text: string }>;
    details: unknown;
  };

  export type ToolDefinition = {
    name: string;
    label: string;
    description: string;
    parameters: unknown;
    execute: (
      toolCallId: string,
      params: any,
      signal: AbortSignal,
      onUpdate?: unknown,
      context?: unknown,
    ) => Promise<ToolResult>;
  };

  export type ExtensionAPI = {
    registerTool(tool: ToolDefinition): void;
    registerCommand(
      name: string,
      command: {
        description: string;
        handler: (
          args: string,
          context: {
            ui: {
              notify(
                message: string,
                level?: "info" | "warning" | "error",
              ): void;
            };
          },
        ) => Promise<void> | void;
      },
    ): void;
    on(
      event: "session_start" | "agent_settled",
      handler: () => Promise<void> | void,
    ): void;
    on(
      event: "agent_start",
      handler: (
        input: { type: "agent_start" },
        context: {
          abort(): void;
          ui: {
            notify(
              message: string,
              level?: "info" | "warning" | "error",
            ): void;
          };
        },
      ) => Promise<void> | void,
    ): void;
    on(
      event: "input",
      handler: (
        input: {
          text: string;
          source: "interactive" | "rpc" | "extension";
          streamingBehavior?: "steer" | "followUp";
        },
        context: {
          ui: {
            notify(
              message: string,
              level?: "info" | "warning" | "error",
            ): void;
          };
        },
      ) => Promise<
        | { action: "continue" }
        | { action: "handled" }
        | { action: "transform"; text: string }
      > | {
        action: "continue" | "handled";
      },
    ): void;
    on(
      event: "before_agent_start",
      handler: (
        input: {
          prompt: string;
          systemPrompt: string;
        },
        context: {
          ui: {
            notify(
              message: string,
              level?: "info" | "warning" | "error",
            ): void;
          };
        },
      ) => {
        systemPrompt: string;
      } | Promise<{
        systemPrompt: string;
      }>,
    ): void;
    on(
      event: "tool_call",
      handler: () => {
        block: true;
        reason: string;
      } | undefined,
    ): void;
  };

  export function defineTool<T extends ToolDefinition>(tool: T): T;
}
