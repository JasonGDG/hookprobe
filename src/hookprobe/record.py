"""Watch individual handlers during a real run, without changing what they do.

The heartbeat in watch.py proves that *some* hook fired. It cannot say which
one, so a guard that quietly dies while the logging hooks keep beating stays
invisible -- the limitation the README admits to.

This closes that gap the only way it can be closed from outside: each configured
command is replaced by a recorder that runs the original and writes down what
happened. The recorder is transparent by construction. It forwards stdin, hands
through stdout and stderr byte for byte, and exits with the original's exit code,
because stdout carries the decision and the exit code *is* the verdict. If the
recorder itself cannot start the original, it says so on stderr and exits 0 --
the same thing Claude Code does with a handler it cannot launch, so wrapping can
never be stricter than not wrapping.

What it buys: per-hook liveness during ordinary work, the exit code each handler
returned, how long it took, and which ones stopped appearing.

Compared with the alternative -- `clooks` converts command hooks into HTTP hooks
behind a daemon -- this leaves the handlers, the settings shape and the failure
modes exactly as they were. It only adds a witness.
"""

from __future__ import annotations

import json
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MARKER = "hookprobe-record"
LOG = Path.home() / ".claude" / "hookprobe-calls.jsonl"

RECORDER = '''#!/usr/bin/env python3
"""Written by hookprobe. Runs the original handler and writes down the result.

Transparent on purpose: stdin is forwarded, stdout and stderr are handed through
unchanged, and the exit status is the original's. Nothing here may change a
verdict; if this script cannot do its job it gets out of the way.
"""
import json
import os
import subprocess
import sys
import time

LOG = os.path.expanduser("~/.claude/hookprobe-calls.jsonl")
LABEL = os.environ.get("HOOKPROBE_LABEL", "?")
EVENT = os.environ.get("HOOKPROBE_EVENT", "?")
ORIGINAL = os.environ.get("HOOKPROBE_ORIGINAL", "")


def record(**fields):
    try:
        fields["at"] = time.time()
        fields["label"] = LABEL
        fields["event"] = EVENT
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(fields) + "\\n")
    except Exception:
        pass


payload = sys.stdin.buffer.read()
started = time.monotonic()
try:
    finished = subprocess.run(
        ORIGINAL,
        shell=True,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
except Exception as error:
    record(outcome="recorder-failed", detail=str(error)[:200])
    sys.stderr.write("hookprobe recorder could not start the handler\\n")
    sys.exit(0)  # never stricter than the unwrapped handler would have been

duration = time.monotonic() - started
sys.stdout.buffer.write(finished.stdout)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(finished.stderr)
sys.stderr.buffer.flush()
record(
    outcome="ran",
    exit_code=finished.returncode,
    duration_ms=int(duration * 1000),
    stdout_bytes=len(finished.stdout),
    blocked=finished.returncode == 2,
)
sys.exit(finished.returncode)
'''


@dataclass
class Call:
    at: float
    label: str
    event: str
    outcome: str
    exit_code: int | None = None
    duration_ms: int | None = None
    blocked: bool = False


def _settings_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / "settings.local.json"


def _recorder_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / "hooks" / "hookprobe-recorder.py"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text("utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def label_for(event: str, command: str) -> str:
    """A stable, readable name for one handler."""
    token = shlex.split(command)[-1] if command.strip() else command
    return f"{event}:{Path(token).name or command[:20]}"


def wrap(project_dir: Path, hooks: list) -> list[str]:
    """Route every command handler through the recorder. Reversible."""
    recorder = _recorder_path(project_dir)
    recorder.parent.mkdir(parents=True, exist_ok=True)
    recorder.write_text(RECORDER, "utf-8")
    recorder.chmod(0o755)

    settings_path = _settings_path(project_dir)
    settings = _load(settings_path)
    hook_config = settings.setdefault("hooks", {})
    wrapped: list[str] = []

    for hook in hooks:
        if hook.type != "command" or not isinstance(hook.command, str):
            continue
        if MARKER in hook.command:
            continue
        label = label_for(hook.event, hook.command)
        entry: dict[str, Any] = {
            "type": "command",
            "command": (
                f"HOOKPROBE_LABEL={shlex.quote(label)} "
                f"HOOKPROBE_EVENT={shlex.quote(hook.event)} "
                f"HOOKPROBE_ORIGINAL={shlex.quote(hook.command)} "
                f"{shlex.quote(str(recorder))}"
            ),
        }
        if isinstance(hook.timeout, (int, float)):
            entry["timeout"] = hook.timeout
        group: dict = {"hooks": [entry]}
        if hook.matcher is not None:
            group["matcher"] = hook.matcher
        hook_config.setdefault(hook.event, []).append(group)
        wrapped.append(label)

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")
    return wrapped


def unwrap(project_dir: Path) -> int:
    """Remove every recorder entry; leave everything else untouched."""
    settings_path = _settings_path(project_dir)
    settings = _load(settings_path)
    hook_config = settings.get("hooks", {})
    removed = 0
    for event in list(hook_config):
        groups = hook_config.get(event) or []
        kept = []
        for group in groups:
            if isinstance(group, dict) and MARKER in json.dumps(group):
                removed += 1
                continue
            kept.append(group)
        if kept:
            hook_config[event] = kept
        else:
            hook_config.pop(event, None)
    if settings_path.exists():
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")
    recorder = _recorder_path(project_dir)
    if recorder.exists():
        recorder.unlink()
    return removed


def is_wrapped(project_dir: Path) -> bool:
    return MARKER in json.dumps(_load(_settings_path(project_dir)).get("hooks", {}))


def read_calls(window: float = 3600.0) -> list[Call]:
    if not LOG.exists():
        return []
    cutoff = time.time() - window
    calls: list[Call] = []
    try:
        lines = LOG.read_text("utf-8", "replace").splitlines()[-5000:]
    except OSError:
        return []
    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        at = float(data.get("at") or 0)
        if at < cutoff:
            continue
        calls.append(
            Call(
                at=at,
                label=str(data.get("label") or "?"),
                event=str(data.get("event") or "?"),
                outcome=str(data.get("outcome") or "?"),
                exit_code=data.get("exit_code"),
                duration_ms=data.get("duration_ms"),
                blocked=bool(data.get("blocked")),
            )
        )
    return calls


def render(_project_dir: Path, hooks: list, window: float) -> str:
    """One row per configured handler: did it run, what did it say, when last."""
    calls = read_calls(window)
    by_label: dict[str, list[Call]] = {}
    for call in calls:
        by_label.setdefault(call.label, []).append(call)

    rows: list[tuple[str, str, str, str, str]] = []
    silent: list[str] = []
    for hook in hooks:
        if hook.type != "command" or not isinstance(hook.command, str):
            continue
        if MARKER in hook.command:
            continue
        label = label_for(hook.event, hook.command)
        seen = by_label.get(label, [])
        if not seen:
            rows.append((label, "0", "-", "-", "never"))
            silent.append(label)
            continue
        last = max(seen, key=lambda call: call.at)
        blocks = sum(1 for call in seen if call.blocked)
        failures = sum(1 for call in seen if call.outcome != "ran")
        verdict = f"exit {last.exit_code}" + (f", {blocks} blocked" if blocks else "")
        if failures:
            verdict += f", {failures} could not start"
        age = int(time.time() - last.at)
        rows.append(
            (
                label,
                str(len(seen)),
                verdict,
                f"{last.duration_ms} ms" if last.duration_ms is not None else "-",
                f"{age}s ago" if age < 3600 else f"{age // 3600}h ago",
            )
        )

    if not rows:
        return "No command handlers are being recorded. Run --record-install first.\n"

    headers = ("Handler", "calls", "last result", "took", "last seen")
    widths = [
        max(len(headers[index]), max(len(row[index]) for row in rows))
        for index in range(5)
    ]
    out = ["  ".join(headers[i].ljust(widths[i]) for i in range(5)).rstrip()]
    out.append("-" * min(sum(widths) + 8, 100))
    for row in rows:
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(5)).rstrip())
    out.append("")

    active = [row for row in rows if row[1] != "0"]
    if silent and active:
        out.append(
            f"{len(silent)} of {len(rows)} handlers never ran while the others did: "
            + ", ".join(silent)
        )
        out.append(
            "That is the case a one-off probe cannot see. Check whether their event "
            "simply did not occur before treating it as a defect."
        )
    elif not active:
        out.append("Nothing ran in this window. Work in the project, then look again.")
    else:
        out.append(f"All {len(rows)} recorded handlers ran in this window.")
    return "\n".join(out) + "\n"
