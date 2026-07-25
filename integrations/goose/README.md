# Echo Veil for Goose

Goose has two Echo Veil modes with different guarantees.

## Shielded headless mode

Use the installed `echo-veil-shielded-run` command for a required one-prompt
headless boundary:

```bash
printf '%s' 'Review the current task and report the next safe action.' |
  echo-veil-shielded-run goose \
    --provider ollama \
    --model qwen3.6:35b-mlx \
    --max-turns 10 \
    --goose-builtin developer
```

The launcher reads the prompt only from stdin, completes a direct protected
doctor and semantic recall preflight, and starts Goose only after that succeeds.
It then launches Goose with `--no-profile`, `--no-session`, and one explicit
Echo MCP extension. This excludes default profile extensions and session
resumption. The optional `developer` builtin is the only reviewed builtin the
launcher currently accepts. Protected context and the user prompt travel to
Goose through child stdin rather than command-line arguments.

If Echo, Qwen3, profile integrity, or protected recall fails, the launcher
returns a generic error before a Goose process exists. It never substitutes
degraded lexical recall for the required semantic preflight. A separate mutable
memory extension must not be added to this mode.

## Portable recipe mode

Validate and run the portable recipe when policy guidance and the ordinary
Goose profile are acceptable:

```bash
goose recipe validate integrations/goose/echo-veil.yaml
goose run --recipe integrations/goose/echo-veil.yaml
```

The normal recipe remains policy-driven: Goose can load the Echo tools and
instructions, but its current `UserPromptSubmit` hook path is non-blocking and
does not provide a repository-owned root model gate. Do not describe recipe
loading alone as fail-closed.

For the recipe, do not add `--no-profile`; Goose 1.41.0 suppresses
recipe-defined extensions in that mode. This differs from the shielded launcher,
which supplies Echo explicitly with `--with-extension` while intentionally
excluding the default profile.

Both modes expose Echo's nine ordinary memory tools. Profile-key rotation and
retirement remain operator-only and are not available to Goose.
