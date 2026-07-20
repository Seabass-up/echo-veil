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
  };

  export function defineTool<T extends ToolDefinition>(tool: T): T;
}
