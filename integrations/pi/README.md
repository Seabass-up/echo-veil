# Echo Veil for Pi

This native Pi extension registers `echo_veil_remember`, `echo_veil_recall`,
`echo_veil_forget`, and `echo_veil_doctor` without adding a shell-enabled tool.
It sends bounded JSON to `echo-veil-agent` over stdin and uses the isolated
`pi` profile by default.

From an Echo Veil checkout:

```bash
npm --prefix integrations/pi ci --ignore-scripts
npm --prefix integrations/pi run check
npm --prefix integrations/pi test
pi install ./integrations/pi
```

The linked checkout is detected automatically. For a standalone package,
install the `echo-veil-agent` command or set `ECHO_VEIL_AGENT_COMMAND` to its
executable path. Remember and forget remain explicit user-authorized actions;
the extension does not capture prompts automatically or replace Pi's context.
