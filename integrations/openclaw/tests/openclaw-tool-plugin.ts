type ToolDefinition = { name: string };
type PluginDefinition = {
  tools: (tool: <T extends ToolDefinition>(definition: T) => T) => ToolDefinition[];
};

export function defineToolPlugin(definition: PluginDefinition) {
  return {
    tools: definition.tools((tool) => tool),
  };
}

export function getToolPluginMetadata(entry: unknown) {
  return entry as { tools: ToolDefinition[] };
}
