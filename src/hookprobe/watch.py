"""Keep watching: do the hooks still fire while you work?

A probe proves the moment of the test. The failures it cannot see are the ones
that happen later: hooks that stop firing mid-session (#76322), a log that grows
until the handler dies (#16047), a single `cd` that ends a watcher for the rest
of the session (#95440). None of those can be caught by running a check once.

So this module turns the question around. Instead of asking the harness whether
a hook fired, it has the hooks say so themselves: a heartbeat handler appends
one line per event to a file. Comparing that file against the session
transcripts answers the only question that matters during a run --

    the session is working, but has anything called a hook in the last N minutes?

An empty heartbeat while a session is clearly active is the signal. The reverse
is not an error: a quiet heartbeat during a quiet session means nothing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MARKER = "hookprobe-heartbeat"
HEARTBEAT_FILE = Path.home() / ".claude" / "hookprobe-heartbeat.jsonl"

# Events chosen so that ordinary work touches at least one of them, without
# adding a handler to anything that can block.
WATCHED_EVENTS = ("UserPromptSubmit", "PostToolUse", "Stop")

HEARTBEAT_SCRIPT = '''#!/usr/bin/env python3
"""Written by hookprobe. Appends one line per hook event; never blocks."""
import json
import os
import sys
import time

RECORD = os.path.expanduser("~/.claude/hookprobe-heartbeat.jsonl")

try:
    raw = sys.stdin.read()
except Exception:
    raw = ""
try:
    payload = json.loads(raw) if raw.strip() else {}
except Exception:
    payload = {}

line = json.dumps(
    {
        "at": time.time(),
        "event": payload.get("hook_event_name") or os.environ.get("HOOKPROBE_EVENT", "?"),
        "session": payload.get("session_id"),
        "cwd": payload.get("cwd") or os.getcwd(),
    }
)
try:
    os.makedirs(os.path.dirname(RECORD), exist_ok=True)
    with open(RECORD, "a", encoding="utf-8") as handle:
        handle.write(line + "\\n")
except Exception:
    pass  # a heartbeat must never break the session it observes
sys.exit(0)
'''


@dataclass
class Beat:
    at: float
    event: str
    session: str | None
    cwd: str | None


@dataclass
class WatchStatus:
    installed: bool
    beats: list[Beat]
    last_beat: float | None
    last_session_activity: float | None
    session_paths: list[Path]
    verdict: str
    alarm: bool


def _settings_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / "settings.local.json"


def _script_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / "hooks" / "hookprobe-heartbeat.py"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text("utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def install(project_dir: Path) -> list[str]:
    """Add the heartbeat handler. Additive and clearly marked, never blocking."""
    script = _script_path(project_dir)
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(HEARTBEAT_SCRIPT, "utf-8")
    script.chmod(0o755)

    settings_path = _settings_path(project_dir)
    settings = _load(settings_path)
    hooks = settings.setdefault("hooks", {})
    added: list[str] = []
    for event in WATCHED_EVENTS:
        groups = hooks.setdefault(event, [])
        if any(
            MARKER in json.dumps(group) for group in groups if isinstance(group, dict)
        ):
            continue
        groups.append(
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": str(script),
                        "timeout": 5,
                    }
                ]
            }
        )
        added.append(event)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")
    return added


def uninstall(project_dir: Path) -> list[str]:
    """Remove only what install() added; leave every other hook untouched."""
    settings_path = _settings_path(project_dir)
    settings = _load(settings_path)
    hooks = settings.get("hooks", {})
    removed: list[str] = []
    for event in list(hooks):
        groups = hooks.get(event) or []
        kept = [
            group
            for group in groups
            if not (isinstance(group, dict) and MARKER in json.dumps(group))
        ]
        if len(kept) != len(groups):
            removed.append(event)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if settings_path.exists():
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", "utf-8")
    script = _script_path(project_dir)
    if script.exists():
        script.unlink()
    return removed


def is_installed(project_dir: Path) -> bool:
    settings = _load(_settings_path(project_dir))
    return MARKER in json.dumps(settings.get("hooks", {})) or _script_path(
        project_dir
    ).exists()


def read_beats(since: float | None = None, limit: int = 2000) -> list[Beat]:
    if not HEARTBEAT_FILE.exists():
        return []
    beats: list[Beat] = []
    try:
        lines = HEARTBEAT_FILE.read_text("utf-8", "replace").splitlines()[-limit:]
    except OSError:
        return []
    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        at = float(data.get("at") or 0)
        if since is not None and at < since:
            continue
        beats.append(
            Beat(at=at, event=str(data.get("event") or "?"), session=data.get("session"), cwd=data.get("cwd"))
        )
    return beats


def transcript_dir(project_dir: Path) -> Path:
    """Claude Code stores a project's transcripts under an encoded path name."""
    encoded = str(project_dir.resolve()).replace("/", "-")
    return Path.home() / ".claude" / "projects" / encoded


def session_activity(
    project_dir: Path, window: float = 900.0
) -> tuple[float | None, list[Path]]:
    """Newest transcript write for THIS project in the window.

    Scoped on purpose: the heartbeat is installed per project, so comparing it
    against every session on the machine would raise an alarm whenever another
    project is busy.
    """
    root = transcript_dir(project_dir)
    if not root.is_dir():
        return None, []
    newest: float | None = None
    active: list[Path] = []
    cutoff = time.time() - window
    try:
        for path in root.glob("*.jsonl"):
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if mtime >= cutoff:
                active.append(path)
                newest = mtime if newest is None else max(newest, mtime)
    except OSError:
        return None, []
    return newest, sorted(active, key=lambda p: p.stat().st_mtime, reverse=True)[:5]


def status(project_dir: Path, window: float = 900.0) -> WatchStatus:
    """Compare heartbeat against session activity in the same window."""
    installed = is_installed(project_dir)
    since = time.time() - window
    beats = read_beats(since=since)
    last_beat = max((beat.at for beat in beats), default=None)
    last_activity, paths = session_activity(project_dir, window)

    alarm = False
    if not installed:
        verdict = "The heartbeat is not installed -- nothing is being watched."
    elif last_activity is None:
        verdict = (
            "No session activity for this project in the window; a quiet heartbeat "
            "means nothing. Work in the project, then look again."
        )
    elif last_beat is None:
        alarm = True
        verdict = (
            "This project's session wrote to its transcript in the window, but no "
            "hook reported in. The hooks are not running."
        )
    elif last_activity - last_beat > 300:
        alarm = True
        verdict = (
            f"The last hook report is {int(last_activity - last_beat) // 60} minutes "
            "older than the last session write -- the hooks stopped mid-session."
        )
    else:
        verdict = "Hooks reported in alongside session activity."
    return WatchStatus(
        installed=installed,
        beats=beats,
        last_beat=last_beat,
        last_session_activity=last_activity,
        session_paths=paths,
        verdict=verdict,
        alarm=alarm,
    )


def _ago(value: float | None) -> str:
    if value is None:
        return "never"
    delta = max(0, int(time.time() - value))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    return f"{delta // 3600}h ago"


def render(state: WatchStatus, window: float) -> str:
    out: list[str] = []
    out.append(f"Heartbeat installed : {'yes' if state.installed else 'no'}")
    out.append(f"Last hook report    : {_ago(state.last_beat)}")
    out.append(f"Last session write  : {_ago(state.last_session_activity)}")
    out.append("")
    if state.beats:
        counts: dict[str, int] = {}
        for beat in state.beats:
            counts[beat.event] = counts.get(beat.event, 0) + 1
        width = max(len(event) for event in counts)
        out.append(f"Events in the last {int(window) // 60} minutes:")
        for event, count in sorted(counts.items(), key=lambda item: -item[1]):
            out.append(f"  {event.ljust(width)}  {count}")
        out.append("")
    out.append(("ALARM: " if state.alarm else "") + state.verdict)
    return "\n".join(out) + "\n"


def follow(project_dir: Path, interval: float = 30.0, window: float = 900.0) -> int:
    """Print a line whenever the verdict changes. Ctrl-C to stop."""
    previous: str | None = None
    try:
        while True:
            state = status(project_dir, window)
            if state.verdict != previous:
                stamp = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
                marker = "ALARM" if state.alarm else "ok"
                print(f"[{stamp}] {marker}: {state.verdict}", flush=True)
                previous = state.verdict
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0
