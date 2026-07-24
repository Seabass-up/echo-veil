declare module "openclaw/plugin-sdk/tool-plugin" {
  import type { Static, TSchema } from "typebox";

  type ToolContext = { signal?: AbortSignal };
  type ToolDefinition<TParams extends TSchema, TConfig> = {
    name: string;
    label: string;
    description: string;
    optional?: boolean;
    parameters: TParams;
    execute: (
      argumentsValue: Static<TParams>,
      config: TConfig,
      context: ToolContext,
    ) => Promise<unknown>;
  };

  type ToolFactory<TConfig> = <TParams extends TSchema>(
    definition: ToolDefinition<TParams, TConfig>,
  ) => ToolDefinition<TParams, TConfig>;

  export type DefinedToolPluginEntry = {
    readonly id: string;
    readonly name: string;
  };

  export function defineToolPlugin<TConfigSchema extends TSchema>(definition: {
    id: string;
    name: string;
    description: string;
    configSchema: TConfigSchema;
    tools: (
      tool: ToolFactory<Static<TConfigSchema>>,
    ) => Array<ToolDefinition<TSchema, Static<TConfigSchema>>>;
  }): DefinedToolPluginEntry;

  export function getToolPluginMetadata(entry: unknown):
    | { tools: Array<{ name: string }> }
    | undefined;
}
