# claude-secret-guard

A Claude Code `PreToolUse` hook that stops the agent from printing your API keys.

Coding agents with shell access will sometimes "check" a credential by echoing it. That puts the key in the transcript, in logs, and in anything you share. This hook blocks the common paths and tells Claude why, so it changes approach.

## Blocks
- `echo` / `printf` / `Write-Output` of variables named like `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`
- bare `$env:SECRET` in PowerShell, `GetEnvironmentVariable('..._KEY')`
- whole-environment dumps: `printenv`, `env`, `set`, `Get-ChildItem env:`
- printing `.env`, `.env.local`, `.env.production`, … (`cat`, `head`, `Get-Content`, …)
- the `Read` tool on `.env*` files
- `Write` / `Edit` content containing live-looking Google, Anthropic, OpenAI, GitHub or Slack keys, or private key blocks

## Allows
- presence checks: `[ -n "$GEMINI_API_KEY" ] && echo set`, `[bool]$env:GEMINI_API_KEY`
- `.env.example`
- everything else

## Install
1. Copy `.claude/hooks/guard_secrets.py` into your project.
2. Add this to `.claude/settings.json`, or merge it into the existing file:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [{ "type": "command", "command": "python .claude/hooks/guard_secrets.py", "timeout": 10 }]
      }
    ]
  },
  "permissions": { "deny": ["Read(./.env)", "Read(./.env.*)"] }
}
```
3. Restart Claude Code. Ask it to `echo $SOME_API_KEY` and it will be blocked with a reason.

Requires Python 3.8+. No dependencies.

## Limits
This is pattern matching. A command that reads the environment in an unusual way (for example, a one-off script that prints `os.environ`) can get past it. Use it as a seatbelt, and layer it with a pre-commit secret scanner, scoped and rotatable keys, provider billing alerts, and the habit of never pasting keys into chats or screenshots.

Found a bypass? Open an issue with the command. It becomes a test case in `tests/test_guard_secrets.py`.

## Tests
```bash
pip install pytest && python -m pytest
```

## Part of Switchboard
This hook ships inside **Switchboard**, a Claude Code + Gemini multi-model kit with a resilient Gemini broker (fallback chain, quota circuit breaker, usage telemetry), a research subagent, and `/research` and `/second-opinion` commands, sold by Fable & Fuse Studios: https://fable-and-fuse.github.io/brainrot-colour-chaos-site/switchboard/

MIT licensed. Not affiliated with Anthropic.
