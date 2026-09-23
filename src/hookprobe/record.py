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
original entry in place, remembers every file it touched in a manifest, and
restores them on --record-remove.

The recorder is transparent by construction. It forwards stdin, hands through
stdout and stderr byte for byte, runs the original under the same shell Claude
Code would use (`/bin/sh -c`, or bash when the handler says `"shell": "bash"`),
hides its own environment variables from the handler, and exits with the
original's exit code, because stdout carries the decision and the exit code *is*
the verdict. If the recorder itself cannot start the original, it says so on
stderr and exits 0 -- the same thing Claude Code does with a handler it cannot
launch, so wrapping can never be stricter than not wrapping.

What it will not touch, and says so: managed settings (enterprise policy), plugin
hooks (their ${CLAUDE_PLUGIN_ROOT} is only set when Claude Code calls them as
plugin hooks), agent frontmatter (markdown, not JSON), exec-form handlers with
`args` (no shell to replay through) and handlers with a shell the recorder
cannot run.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

MARKER = "hookprobe-record"
INPLACE = "HOOKPROBE_MODE=inplace"
RECORDER_NAME = "hookprobe-recorder.py"
MANIFEST_NAME = "hookprobe-record.json"
LOG = Path.home() / ".claude" / "hookprobe-calls.jsonl"

# Only these can be rewritten in place: JSON settings files hookprobe may own.
WRITABLE_KINDS = frozenset({"project", "local", "user"})
SKIP_REASON = {
    "managed": "managed settings are enterprise policy and stay untouched",
    "plugin": "plugin hooks need ${CLAUDE_PLUGIN_ROOT}, which only Claude Code sets",
    "agent-frontmatter": "lives in agent markdown, not in a settings file",
}

RECORDER_TEMPLATE = '''#!__PYTHON__
"""Written by hookprobe. Runs the original handler and writes down the result.

Transparent on purpose: stdin is forwarded, stdout and stderr are handed through
unchanged, the original runs under the shell Claude Code would use, it does not
see the recorder's own variables, and the exit status is the original's. Nothing
here may change a verdict; if this script cannot do its job it gets out of the
way.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

LOG = os.path.expanduser("~/.claude/hookprobe-calls.jsonl")
FIELDS = {
    name[len("HOOKPROBE_"):].lower(): value
    for name, value in os.environ.items()
    if name.startswith("HOOKPROBE_")
}
ORIGINAL = FIELDS.get("original", "")
# The handler must not be able to tell that it is being recorded.
ENV = {name: value for name, value in os.environ.items() if not name.startswith("HOOKPROBE_")}


def record(**extra):
    try:
        entry = {
            "at": time.time(),
            "key": FIELDS.get("key", "?"),
            "label": FIELDS.get("label", "?"),
            "event": FIELDS.get("event", "?"),
        }
        entry.update(extra)
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\\n")
    except Exception:
        pass


payload = sys.stdin.buffer.read()
if FIELDS.get("shell") == "bash":
    argv = [shutil.which("bash") or "/bin/bash", "-c", ORIGINAL]
else:
    argv = ["/bin/sh", "-c", ORIGINAL]

started = time.monotonic()
try:
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=ENV,
        start_new_session=True,
    )
except Exception as error:
    record(outcome="recorder-failed", detail=str(error)[:200])
    sys.stderr.write("hookprobe recorder could not start the handler\\n")
    sys.exit(0)  # never stricter than the unwrapped handler would have been


def _take_down(signum, _frame):
    # Claude Code timed the hook out. Take the handler down with us instead of
    # leaving it running detached, then get out of the way.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        pass
    record(outcome="terminated", signal=int(signum))
    sys.exit(0)


signal.signal(signal.SIGTERM, _take_down)

out, err = proc.communicate(payload)
duration = time.monotonic() - started
sys.stdout.buffer.write(out)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(err)
sys.stderr.buffer.flush()
code = proc.returncode if proc.returncode >= 0 else 128 - proc.returncode
record(
    outcome="ran",
    exit_code=code,
    duration_ms=int(duration * 1000),
    stdout_bytes=len(out),
    blocked=code == 2,
)
sys.exit(code)
'''


@dataclass
class Call:
    at: float
    key: str
    label: str
    event: str
    outcome: str
    exit_code: int | None = None
    duration_ms: int | None = None
    blocked: bool = False


@dataclass
class WrapResult:
    wrapped: list[str] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# --- paths and files ---------------------------------------------------------


def _settings_local(project_dir: Path) -> Path:
    return project_dir / ".claude" / "settings.local.json"


def _recorder_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / "hooks" / RECORDER_NAME


def _manifest_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / MANIFEST_NAME


def _user_settings() -> Path:
    config_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR", os.fspath(Path.home() / ".claude")))
    return config_dir / "settings.json"


def _candidate_files(project_dir: Path) -> list[Path]:
    """Where a wrapper could be, when no manifest says so."""
    return [
        project_dir / ".claude" / "settings.json",
        _settings_local(project_dir),
        _user_settings(),
    ]


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(path: Path, settings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")


def _handlers(settings: dict) -> Iterator[dict]:
    hook_config = settings.get("hooks")
    if not isinstance(hook_config, dict):
        return
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
                if isinstance(handler, dict):
                    yield handler


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


# --- naming ------------------------------------------------------------------


def _safe_split(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def label_for(event: str, command: str) -> str:
    """A readable name: the script, not `run`, `--strict` or `null`.

    Display only. Two handlers may share a label; they never share a key.
    """
    from .probe import _is_interpreter

    tokens = _safe_split(command)
    candidates = [
        token
        for token in tokens
        if token and not token.startswith("-") and not _is_interpreter(token)
        and "=" not in token.split("/")[0] and not token.startswith(("<", ">", "2>", "|", "&"))
    ]
    chosen = next((t for t in candidates if "/" in t or "." in t), None)
    if chosen is None:
        chosen = candidates[0] if candidates else (tokens[0] if tokens else command[:20])
    return f"{event}:{Path(chosen).name or command[:20]}"


def key_of(hook) -> str:
    """Unique per handler: file, event, matcher and command."""
    raw = f"{hook.source.path}\0{hook.event}\0{hook.matcher}\0{hook.command}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]


# --- the wrapper command -----------------------------------------------------


def _wrapper_command(fields: dict[str, str], recorder: Path) -> str:
    # The mode marker is what tells --record-remove whether this entry replaced a
    # handler (restore it) or was appended next to one by an older version
    # (delete it, or the handler is left registered twice).
    parts = [INPLACE]
    parts.extend(f"HOOKPROBE_{name.upper()}={shlex.quote(value)}" for name, value in fields.items())
    parts.append(shlex.quote(str(recorder)))
    return " ".join(parts)


def wrapper_fields(command: str) -> dict[str, str] | None:
    """Parse a recorder invocation; None for anything that is not one.

    An entry counts as a wrapper only when its last token is the recorder script.
    A matcher or a command that merely contains the marker text is left alone.
    """
    if MARKER not in command:
        return None
    tokens = _safe_split(command)
    if not tokens or Path(tokens[-1]).name != RECORDER_NAME:
        return None
    fields: dict[str, str] = {"recorder": tokens[-1]}
    for token in tokens[:-1]:
        if token.startswith("HOOKPROBE_") and "=" in token:
            name, value = token.split("=", 1)
            fields[name[len("HOOKPROBE_"):].lower()] = value
    return fields


def original_of(command: str) -> str | None:
    """The wrapped command, read back out of an in-place wrapper.

    Unwrapping reads this rather than a backup, so an unrelated edit to the
    settings file between install and remove is left alone.
    """
    fields = wrapper_fields(command)
    if fields is None or fields.get("mode") != "inplace":
        return None
    return fields.get("original")


def _is_legacy(command: str) -> bool:
    fields = wrapper_fields(command)
    return fields is not None and fields.get("mode") != "inplace"


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
            handlers = group.get("hooks") if isinstance(group, dict) else None
            legacy = isinstance(handlers, list) and any(
                isinstance(h, dict) and isinstance(h.get("command"), str) and _is_legacy(h["command"])
                for h in handlers
            )
            if legacy:
                dropped += 1
                continue
            kept.append(group)
        if kept:
            hook_config[event] = kept
        else:
            hook_config.pop(event, None)
    return dropped


# --- install / remove --------------------------------------------------------


def _shebang() -> str:
    # The PATH Claude Code gives a hook need not contain python3; the one that
    # ran --record-install demonstrably exists. A space in that path would break
    # the shebang line, so fall back to env in that case.
    executable = sys.executable or ""
    return executable if executable and " " not in executable else "/usr/bin/env python3"


def wrap(project_dir: Path, hooks: list) -> WrapResult:
    """Replace every writable command handler with the recorder. Reversible."""
    recorder = _recorder_path(project_dir)
    recorder.parent.mkdir(parents=True, exist_ok=True)
    recorder.write_text(RECORDER_TEMPLATE.replace("__PYTHON__", _shebang()), "utf-8")
    recorder.chmod(0o755)

    # An older version appended its wrapper beside the original. Installing over
    # that would wrap the original in place and keep the appended copy -- the
    # double run again. Clear it first.
    legacy_file = _settings_local(project_dir)
    if legacy_file.exists():
        legacy_settings = _load(legacy_file)
        if _drop_legacy_groups(legacy_settings):
            _write(legacy_file, legacy_settings)

    result = WrapResult()
    by_file: dict[Path, dict] = {}
    warned: set[Path] = set()

    for hook in hooks:
        if hook.type != "command" or not isinstance(hook.command, str):
            continue
        kind = hook.source.kind
        display = f"{hook.event}:{hook.name}"
        if kind not in WRITABLE_KINDS:
            result.skipped.append((display, SKIP_REASON.get(kind, f"source {kind} is not writable")))
            continue
        if wrapper_fields(hook.command) is not None:
            continue  # already recorded
        if "args" in hook.handler:
            result.skipped.append(
                (display, "exec-form handler with args: there is no shell line to replay")
            )
            continue
        shell = hook.shell
        if shell not in (None, "bash"):
            result.skipped.append((display, f"shell {shell!r} is not one the recorder can run"))
            continue

        path = hook.source.path
        settings = by_file.get(path)
        if settings is None:
            settings = _load(path)
            by_file[path] = settings
        handler = _handler_at(settings, hook)
        if handler is None or handler.get("command") != hook.command:
            result.skipped.append((display, f"could not be located in {path.name}"))
            continue

        label = label_for(hook.event, hook.command)
        fields = {
            "key": key_of(hook),
            "label": label,
            "event": hook.event,
            "original": hook.command,
        }
        if shell == "bash":
            fields["shell"] = "bash"
        handler["command"] = _wrapper_command(fields, recorder)
        result.wrapped.append(label)
        if kind == "project" and path not in warned:
            warned.add(path)
            result.warnings.append(
                f"{path} is the shared project file: do not commit it while recording, "
                "the wrapper points at a script on this machine."
            )

    for path, settings in by_file.items():
        if not any(
            isinstance(h.get("command"), str) and wrapper_fields(h["command"]) is not None
            for h in _handlers(settings)
        ):
            continue
        _write(path, settings)
        result.files.append(path)

    manifest = _manifest_path(project_dir)
    known = _load(manifest).get("files", []) if manifest.exists() else []
    files = list(dict.fromkeys([*(str(p) for p in known if isinstance(p, str)), *(str(p) for p in result.files)]))
    _write(manifest, {"version": 1, "recorder": str(recorder), "files": files, "at": time.time()})
    return result


def unwrap(project_dir: Path) -> int:
    """Put every wrapped command back. Leaves unrelated edits alone."""
    recorder = _recorder_path(project_dir)
    manifest = _manifest_path(project_dir)
    files: list[Path] = []
    for item in _load(manifest).get("files", []):
        if isinstance(item, str):
            files.append(Path(item))
    for candidate in _candidate_files(project_dir):
        if candidate not in files:
            files.append(candidate)

    restored = 0
    for path in files:
        if not path.exists():
            continue
        settings = _load(path)
        dropped = _drop_legacy_groups(settings)
        restored += dropped
        changed = dropped > 0
        for handler in _handlers(settings):
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
            _write(path, settings)

    if manifest.exists():
        manifest.unlink()
    if recorder.exists():
        recorder.unlink()
    return restored


def is_wrapped(project_dir: Path) -> bool:
    if _manifest_path(project_dir).exists():
        return True
    return any(
        isinstance(h.get("command"), str) and wrapper_fields(h["command"]) is not None
        for path in _candidate_files(project_dir)
        if path.exists()
        for h in _handlers(_load(path))
    )


# --- reading back ------------------------------------------------------------


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
                key=str(data.get("key") or "?"),
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
    """One row per recorded handler: did it run, what did it say, when last."""
    calls = read_calls(window)
    by_key: dict[str, list[Call]] = {}
    for call in calls:
        by_key.setdefault(call.key, []).append(call)

    rows: list[tuple[str, str, str, str, str]] = []
    silent: list[str] = []
    for hook in hooks:
        if hook.type != "command" or not isinstance(hook.command, str):
            continue
        fields = wrapper_fields(hook.command)
        if fields is None or fields.get("mode") != "inplace":
            continue  # not recorded
        key = fields.get("key", "?")
        label = fields.get("label") or label_for(hook.event, fields.get("original", ""))
        seen = by_key.get(key, [])
        if not seen:
            rows.append((label, "0", "-", "-", "never"))
            silent.append(label)
            continue
        last = max(seen, key=lambda call: call.at)
        blocks = sum(1 for call in seen if call.blocked)
        failures = sum(1 for call in seen if call.outcome != "ran")
        verdict = f"exit {last.exit_code}" + (f", {blocks} blocked" if blocks else "")
        if failures:
            verdict += f", {failures} did not finish"
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
