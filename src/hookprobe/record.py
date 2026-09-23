"""Watch individual handlers during a real run, without changing what they do.

The heartbeat in watch.py proves that *some* hook fired. It cannot say which
one, so a guard that quietly dies while the logging hooks keep beating stays
invisible -- the limitation the README admits to.

This closes that gap the only way it can be closed from outside: each configured
command is replaced -- in the settings file it actually lives in -- by a recorder
that runs the original and writes down what happened. Replacing rather than adding
matters: an added entry leaves the original registered as well, and Claude Code
then runs the handler twice. That was measured, not assumed (one PreToolUse hook,
one Bash call: 1 invocation before, 2 after), and it is why this module edits the
original entry in place and restores it on --record-remove.

The recorder is transparent by construction. It forwards stdin, hands through
stdout and stderr byte for byte, and exits with the original's exit code, because
stdout carries the decision and the exit code *is* the verdict. If the recorder
itself cannot start the original, it says so on stderr and exits 0 -- the same
thing Claude Code does with a handler it cannot launch, so wrapping can never be
stricter than not wrapping.

What it cannot touch: managed settings (enterprise policy), plugin hooks (their
${CLAUDE_PLUGIN_ROOT} is only set when Claude Code calls them as plugin hooks, so
a copy elsewhere would break) and agent frontmatter. Those are named and skipped
rather than silently half-wrapped.

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


# Only these can be rewritten in place: JSON settings files hookprobe may own.
# managed = enterprise policy, plugin = needs ${CLAUDE_PLUGIN_ROOT} from Claude Code,
# agent-frontmatter = markdown, not JSON.
WRITABLE_KINDS = frozenset({"project", "local", "user"})
SKIP_REASON = {
    "managed": "managed settings are enterprise policy and stay untouched",
    "plugin": "plugin hooks need ${CLAUDE_PLUGIN_ROOT}, which only Claude Code sets",
    "agent-frontmatter": "lives in agent markdown, not in a settings file",
}


@dataclass
class WrapResult:
    wrapped: list[str]
    skipped: list[tuple[str, str]]
    files: list[Path]


INPLACE = "HOOKPROBE_MODE=inplace"


def _wrapper_command(label: str, event: str, original: str, recorder: Path) -> str:
    # The mode marker is what tells --record-remove whether this entry replaced a
    # handler (restore it) or was appended next to one by an older version
    # (delete it, or the handler is left registered twice).
    return (
        f"{INPLACE} "
        f"HOOKPROBE_LABEL={shlex.quote(label)} "
        f"HOOKPROBE_EVENT={shlex.quote(event)} "
        f"HOOKPROBE_ORIGINAL={shlex.quote(original)} "
        f"{shlex.quote(str(recorder))}"
    )


def original_of(command: str) -> str | None:
    """Read the wrapped command back out of a recorder invocation.

    Unwrapping reads this rather than a backup file, so an unrelated edit to the
    settings file between install and remove cannot be clobbered.
    """
    if MARKER not in command:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    for token in tokens:
        if token.startswith("HOOKPROBE_ORIGINAL="):
            return token[len("HOOKPROBE_ORIGINAL="):]
    return None


def _handler_at(settings: dict, hook) -> dict | None:
    """The handler dict this HookEntry came from, or None if the file moved on."""
    groups = settings.get("hooks", {}).get(hook.event)
    if not isinstance(groups, list) or hook.group_index >= len(groups):
        return None
    group = groups[hook.group_index]
    if not isinstance(group, dict):
        return None
    handlers = group.get("hooks")
    if not isinstance(handlers, list) or hook.handler_index >= len(handlers):
        return None
    handler = handlers[hook.handler_index]
    return handler if isinstance(handler, dict) else None


def wrap(project_dir: Path, hooks: list) -> WrapResult:
    """Replace every writable command handler with the recorder. Reversible."""
    recorder = _recorder_path(project_dir)
    recorder.parent.mkdir(parents=True, exist_ok=True)
    recorder.write_text(RECORDER, "utf-8")
    recorder.chmod(0o755)

    by_file: dict[Path, dict] = {}
    wrapped: list[str] = []
    skipped: list[tuple[str, str]] = []

    for hook in hooks:
        if hook.type != "command" or not isinstance(hook.command, str):
            continue
        if MARKER in hook.command:
            continue
        label = label_for(hook.event, hook.command)
        kind = hook.source.kind
        if kind not in WRITABLE_KINDS:
            skipped.append((label, SKIP_REASON.get(kind, f"source {kind} is not writable")))
            continue
        path = hook.source.path
        settings = by_file.get(path)
        if settings is None:
            settings = _load(path)
            by_file[path] = settings
        handler = _handler_at(settings, hook)
        if handler is None or handler.get("command") != hook.command:
            skipped.append((label, f"could not be located in {path.name}"))
            continue
        handler["command"] = _wrapper_command(label, hook.event, hook.command, recorder)
        wrapped.append(label)

    touched: list[Path] = []
    for path, settings in by_file.items():
        if MARKER not in json.dumps(settings):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")
        touched.append(path)
    return WrapResult(wrapped=wrapped, skipped=skipped, files=touched)


def _candidate_files(project_dir: Path) -> list[Path]:
    return [
        project_dir / ".claude" / "settings.json",
        project_dir / ".claude" / "settings.local.json",
        Path.home() / ".claude" / "settings.json",
    ]


def _drop_legacy_groups(settings: dict) -> int:
    """Remove entries an older version appended beside the original handler."""
    hook_config = settings.get("hooks")
    if not isinstance(hook_config, dict):
        return 0
    dropped = 0
    for event in list(hook_config):
        groups = hook_config.get(event)
        if not isinstance(groups, list):
            continue
        kept = []
        for group in groups:
            blob = json.dumps(group) if isinstance(group, dict) else ""
            if MARKER in blob and INPLACE not in blob:
                dropped += 1
                continue
            kept.append(group)
        if kept:
            hook_config[event] = kept
        else:
            hook_config.pop(event, None)
    return dropped


def unwrap(project_dir: Path) -> int:
    """Put every wrapped command back. Leaves unrelated edits alone."""
    restored = 0
    for path in _candidate_files(project_dir):
        if not path.exists():
            continue
        settings = _load(path)
        dropped = _drop_legacy_groups(settings)
        restored += dropped
        changed = bool(dropped)
        hook_config = settings.get("hooks")
        if isinstance(hook_config, dict):
            for groups in hook_config.values():
                if not isinstance(groups, list):
                    continue
                for group in groups:
                    if not isinstance(group, dict):
                        continue
                    handlers = group.get("hooks")
                    if not isinstance(handlers, list):
                        continue
                    for handler in handlers:
                        if not isinstance(handler, dict):
                            continue
                        command = handler.get("command")
                        if not isinstance(command, str):
                            continue
                        original = original_of(command)
                        if original is None:
                            continue
                        handler["command"] = original
                        restored += 1
                        changed = True
        if changed:
            path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")

    recorder = _recorder_path(project_dir)
    if recorder.exists():
        recorder.unlink()
    return restored


def is_wrapped(project_dir: Path) -> bool:
    return any(
        MARKER in json.dumps(_load(path).get("hooks", {}))
        for path in _candidate_files(project_dir)
        if path.exists()
    )


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
        original = original_of(hook.command)
        if original is None:
            continue  # not wrapped: nothing is being recorded for this handler
        label = label_for(hook.event, original)
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
