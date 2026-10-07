#!/usr/bin/env python3
"""Claude Code PreToolUse hook: stop the agent from exposing secrets.

Blocks (exit code 2, reason on stderr, which Claude sees and adapts to):
  * shell commands that print secret-looking env vars or dump the whole environment
  * shell commands that print .env files
  * Read of .env files (but .env.example is allowed)
  * writes that put a live-looking API key into any file

Wire it up in .claude/settings.json (already done in this template).
"""
from __future__ import annotations

import json
import re
import sys

SECRET_VAR = r"[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*"
ENV_FILE = r"(?:^|[\s'\"/\\])\.env(?:\.(?!example\b)[\w.-]+)?(?=$|[\s'\"|;&)])"

SHELL_RULES = [
    (rf"\b(?:echo|printf|print|Write-(?:Host|Output))\b[^|;&\n]*\$(?:env:)?\{{?{SECRET_VAR}\b",
     "prints a secret environment variable"),
    (rf"\$env:{SECRET_VAR}\s*(?:$|[|;])", "evaluates a secret environment variable to output"),
    (r"(?:^|[|;&]\s*)(?:printenv|env|set|export\s+-p|Get-ChildItem\s+env:|gci\s+env:|ls\s+env:|dir\s+env:)\s*(?:$|[|;&>])",
     "dumps the whole environment"),
    (rf"\bprintenv\s+{SECRET_VAR}\b", "prints a secret environment variable"),
    (rf"GetEnvironmentVariable\(\s*['\"]{SECRET_VAR}['\"]", "reads a secret environment variable"),
    (rf"\b(?:cat|type|more|less|head|tail|bat|Get-Content|gc|nl|strings)\b[^|;&\n]*{ENV_FILE}",
     "prints a .env file"),
]

KEY_PATTERNS = [
    r"AIza[0-9A-Za-z_\-]{35}",            # Google API key (classic)
    r"\bAQ\.[0-9A-Za-z_\-]{40,}",         # Google auth key (AI Studio, newer format)
    r"sk-ant-[0-9A-Za-z_\-]{20,}",        # Anthropic
    r"sk-(?:proj-)?[0-9A-Za-z_\-]{32,}",  # OpenAI-style
    r"gh[pousr]_[0-9A-Za-z]{30,}",        # GitHub
    r"xox[abposr]-[0-9A-Za-z\-]{10,}",    # Slack
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
]


def check(event: dict) -> str | None:
    tool = event.get("tool_name", "")
    inp = event.get("tool_input") or {}
    if tool in ("Bash", "PowerShell"):
        cmd = inp.get("command", "")
        for pattern, why in SHELL_RULES:
            if re.search(pattern, cmd, re.IGNORECASE):
                return f"Blocked: this command {why}. Check presence instead, e.g. [ -n \"$VAR\" ] && echo set."
    if tool == "Read":
        path = inp.get("file_path", "")
        if re.search(ENV_FILE, " " + path):
            return "Blocked: reading .env files exposes secrets. Ask the user which variable names exist instead."
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        blob = json.dumps(inp)
        for pattern in KEY_PATTERNS:
            if re.search(pattern, blob):
                return "Blocked: the content contains what looks like a live credential. Use an env var reference."
    return None


def main() -> int:
    try:
        # utf-8-sig: some Windows shells prepend a BOM, which would otherwise make the hook fail open.
        event = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except ValueError:
        return 0  # never break the session on malformed input
    reason = check(event)
    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
