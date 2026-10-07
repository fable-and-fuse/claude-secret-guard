import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / ".claude" / "hooks" / "guard_secrets.py"
spec = importlib.util.spec_from_file_location("guard_secrets", HOOK)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def bash(cmd, tool="Bash"):
    return guard.check({"tool_name": tool, "tool_input": {"command": cmd}})


@pytest.mark.parametrize("cmd", [
    "echo $GEMINI_API_KEY",
    'echo "key is ${OPENAI_API_KEY}"',
    "printf '%s' $GITHUB_TOKEN",
    "printenv ANTHROPIC_API_KEY",
    "printenv",
    "env | grep KEY",
    "cat .env",
    "cat ./config/.env.local",
    "head -n 5 .env.production",
])
def test_blocks_secret_exposing_shell(cmd):
    assert bash(cmd)


@pytest.mark.parametrize("cmd", [
    "$env:GEMINI_API_KEY",
    "Write-Output $env:GEMINI_API_KEY",
    "Get-ChildItem env:",
    "Get-Content .env",
    "[Environment]::GetEnvironmentVariable('GEMINI_API_KEY','User')",
])
def test_blocks_secret_exposing_powershell(cmd):
    assert bash(cmd, tool="PowerShell")


@pytest.mark.parametrize("cmd", [
    '[ -n "$GEMINI_API_KEY" ] && echo set',
    '"present: $([bool]$env:GEMINI_API_KEY)"',
    "cat .env.example",
    "python -m switchboard selftest",
    "git commit -m 'update env docs'",
    "set -euo pipefail; make test",
    "echo $HOME",
])
def test_allows_safe_commands(cmd):
    assert bash(cmd) is None


def test_read_rules():
    assert guard.check({"tool_name": "Read", "tool_input": {"file_path": "/repo/.env"}})
    assert guard.check({"tool_name": "Read", "tool_input": {"file_path": r"C:\repo\.env.local"}})
    assert guard.check({"tool_name": "Read", "tool_input": {"file_path": "/repo/.env.example"}}) is None
    assert guard.check({"tool_name": "Read", "tool_input": {"file_path": "/repo/src/environment.py"}}) is None


def test_blocks_writing_live_credentials():
    fake_google = "AIza" + "A" * 35
    fake_gh = "ghp_" + "b" * 36
    for secret in (fake_google, fake_gh):
        ev = {"tool_name": "Write", "tool_input": {"file_path": "cfg.py", "content": f"KEY = '{secret}'"}}
        assert guard.check(ev)
    ok = {"tool_name": "Write", "tool_input": {"file_path": "cfg.py", "content": "KEY = os.environ['GEMINI_API_KEY']"}}
    assert guard.check(ok) is None


def test_hook_protocol_exit_codes():
    def run(event):
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event),
                              capture_output=True, text=True)
    blocked = run({"tool_name": "Bash", "tool_input": {"command": "echo $GEMINI_API_KEY"}})
    assert blocked.returncode == 2 and "Blocked" in blocked.stderr
    assert run({"tool_name": "Bash", "tool_input": {"command": "ls"}}).returncode == 0
    bad = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True)
    assert bad.returncode == 0
    # A UTF-8 BOM (PowerShell pipes add one) must not make the hook fail open.
    bom = b"\xef\xbb\xbf" + json.dumps({"tool_name": "Bash", "tool_input": {"command": "printenv"}}).encode()
    assert subprocess.run([sys.executable, str(HOOK)], input=bom, capture_output=True).returncode == 2
