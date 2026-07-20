# Echo Veil for Claude Code

This plugin starts Echo Veil's stdio MCP server from the containing source
checkout and uses the isolated `claude-code` profile.

```bash
claude plugin validate ./integrations/claude-code
```

For a standalone installation, install `echo-veil-agent` and add it directly:

```bash
claude mcp add --transport stdio --scope user echo-veil -- \
  echo-veil-agent --profile claude-code mcp
```

Claude Code asks before trusting project MCP configuration. Review this plugin
and keep remember/forget under user approval.
