"""Ask, do not decide.

A hook that is off is not always a defect. The execute bit may be missing on
purpose while someone rewrites the script; disableAllHooks may be set for a
demo machine. hookprobe cannot know that, so the default run reports and
exits 1, every time. This module is the opt-in middle ground: walk through
every hook that is off, say why in one line, show what would fix it, and ask.

Three answers. "Yes, on purpose" is remembered in .claude/hookprobe-accepted.json
with the reason and the date; the default report then lists that hook under
"off on purpose" instead of counting it as broken, and the exit code follows.
"No, fix it" applies the repair when there is a safe one (the execute bit, or
disableAllHooks in a file hookprobe may write) and otherwise prints the manual
step. "Skip" changes nothing.

An acceptance is tied to the hook's event, its command and the exact set of
problems accepted. A new problem on the same hook is asked about again; a
changed command starts from zero. Nothing here runs without a terminal.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable

ACCEPTED_NAME = "hookprobe-accepted.json"
DISABLE_KEY = "disableAllHooks"
DISABLE_CODE = "P03.HOOKS_DISABLED"
WRITABLE_KINDS = frozenset({"project", "local", "user"})

PROMPT = "  Is this off on purpose?  [y]es, keep it   [n]o, fix it   [s]kip (Enter)  > "
WHY = "  Why? (one line, optional) > "

Answer = Callable[[str], str]
Say = Callable[[str], None]


@dataclass
class Accepted:
    key: str
    hook: str
    event: str
    command: str
    codes: list[str]
    reason: str
    at: str


@dataclass
class AskOutcome:
    accepted: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    settings_changed: bool = False


def accepted_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / ACCEPTED_NAME


def key_for(hook) -> str:
    """One acceptance per handler: the file it lives in, event, matcher, command.

    Two hooks with the same command in different files or behind different
    matchers are different guards; accepting one must not accept the other.
    """
    # realpath, or /var/... and /private/var/... would be two different guards.
    where = os.path.realpath(hook.source.path)
    raw = f"{where}\0{hook.event}\0{hook.matcher}\0{hook.command}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def disable_key(config) -> str:
    """disableAllHooks, keyed by the files that set it, so a second file that
    later switches everything off is asked about again."""
    files = sorted(os.path.realpath(s.path) for s in config.sources if _sets_disable(s.path))
    return hashlib.sha256(("disableAllHooks\0" + "\0".join(files)).encode("utf-8")).hexdigest()[:16]


def load_accepted(project_dir: Path) -> dict[str, Accepted]:
    path = accepted_path(project_dir)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    items = raw.get("accepted", []) if isinstance(raw, dict) else []
    entries: dict[str, Accepted] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            entry = Accepted(
                key=str(item["key"]),
                hook=str(item.get("hook", "?")),
                event=str(item["event"]),
                command=str(item["command"]),
                codes=[str(code) for code in item.get("codes", [])],
                reason=str(item.get("reason", "")),
                at=str(item.get("at", "")),
            )
        except (KeyError, TypeError):
            continue
        entries[entry.key] = entry
    return entries


def save_accepted(project_dir: Path, entries: dict[str, Accepted]) -> Path:
    path = accepted_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "accepted": [asdict(entry) for entry in entries.values()]}
    path.write_text(json.dumps(payload, indent=2) + "\n", "utf-8")
    return path


def signature(probe) -> list[str]:
    """The codes that make this probe broken.

    is_broken can be true from state alone (starts False without a catalogued
    finding, say), so a synthetic code stands in when no critical finding does.
    """
    codes = sorted({f.code for f in probe.findings if f.severity == "critical"})
    if codes:
        return codes
    if probe.starts is False:
        return ["STATE.NO_START"]
    if probe.answers is False:
        return ["STATE.NO_ANSWER"]
    if probe.can_block is False:
        return ["STATE.CANNOT_BLOCK"]
    return []


def is_accepted(probe, entries: dict[str, Accepted] | None) -> Accepted | None:
    """The acceptance covering this probe, or None if anything new turned up."""
    if not entries:
        return None
    entry = entries.get(key_for(probe.hook))
    if entry is None:
        return None
    if not set(signature(probe)) <= set(entry.codes):
        return None
    return entry


def disable_accepted(entries: dict[str, Accepted] | None, config) -> Accepted | None:
    if not entries:
        return None
    return entries.get(disable_key(config))


# --- the two repairs that are safe to apply ---------------------------------


def fix_execute_bit(probe, project_dir: Path) -> Path | None:
    from .probe import _script_path

    path = _script_path(probe.hook, project_dir)
    if path is None:
        return None
    if not path.is_absolute():
        path = project_dir / path  # the selected project, not the process cwd
    if not path.exists():
        return None
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IRUSR)
    return path


def _sets_disable(path: Path) -> bool:
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data.get(DISABLE_KEY) is True


def fix_disable_all(config) -> list[Path]:
    """Set disableAllHooks to false in every file that sets it and that hookprobe
    may write. Managed settings are policy and stay exactly as they are."""
    changed: list[Path] = []
    for source in config.sources:
        if source.kind not in WRITABLE_KINDS or not _sets_disable(source.path):
            continue
        data = json.loads(source.path.read_text("utf-8"))
        data[DISABLE_KEY] = False
        source.path.write_text(json.dumps(data, indent=2) + "\n", "utf-8")
        changed.append(source.path)
    return changed


# --- the walk ---------------------------------------------------------------


@dataclass
class _Item:
    title: str
    lines: list[str]
    key: str
    hook_name: str
    event: str
    command: str
    codes: list[str]
    repair: str
    fix: Callable[[], list[str]] | None


def _items(project_dir: Path, config, probes, entries) -> list[_Item]:
    from . import evidence
    from .report import _short

    items: list[_Item] = []

    if config.disable_all_hooks and disable_accepted(entries, config) is None:
        entry = evidence.lookup(DISABLE_CODE)
        where = [s.label for s in config.sources if _sets_disable(s.path)]
        items.append(
            _Item(
                title="disableAllHooks -- every hook in this project",
                lines=[
                    f"  off because: {entry.title}  [{DISABLE_CODE}]",
                    f"      set in: {', '.join(where) or 'a file hookprobe could not read'}",
                ],
                key=disable_key(config),
                hook_name="disableAllHooks",
                event="*",
                command=DISABLE_KEY,
                codes=[DISABLE_CODE],
                repair=entry.repair,
                fix=lambda: [
                    f"disableAllHooks set to false in {path}"
                    for path in fix_disable_all(config)
                ],
            )
        )

    for probe in probes:
        if not probe.is_broken or is_accepted(probe, entries) is not None:
            continue
        codes = signature(probe)
        lines: list[str] = []
        repair = ""
        for finding in probe.findings:
            if finding.severity != "critical":
                continue
            lines.append(f"  off because: {finding.message}  [{finding.code}]")
            if finding.detail:
                lines.append(f"      {finding.detail}")
            if not repair:
                repair = evidence.lookup(finding.code).repair
        if not lines:
            lines.append(f"  off because: {', '.join(codes)}")

        fix: Callable[[], list[str]] | None = None
        if "P01.NOT_EXECUTABLE" in codes:

            def fix(p=probe) -> list[str]:
                path = fix_execute_bit(p, project_dir)
                return [f"execute bit restored on {path}"] if path else []

        items.append(
            _Item(
                title=f"{probe.hook.event} · {_short(probe.hook)}  ({probe.hook.source.label})",
                lines=lines,
                key=key_for(probe.hook),
                hook_name=probe.hook.name,
                event=probe.hook.event,
                command=str(probe.hook.command),
                codes=codes,
                repair=repair,
                fix=fix,
            )
        )
    return items


def _choose(answer: Answer, say: Say) -> str:
    while True:
        try:
            raw = answer(PROMPT).strip().lower()
        except EOFError:
            return "s"
        if raw in {"y", "yes"}:
            return "y"
        if raw in {"n", "no"}:
            return "n"
        if raw in {"s", "skip", ""}:
            return "s"
        say("  y, n or s.")


def walk(project_dir: Path, config, probes, answer: Answer, say: Say = print) -> AskOutcome:
    """One question per hook that is off. Returns what was decided."""
    entries = load_accepted(project_dir)
    items = _items(project_dir, config, probes, entries)
    outcome = AskOutcome()
    if not items:
        say("Nothing is off that has not been accepted already. Nothing to ask.")
        return outcome

    say(f"{len(items)} thing(s) are off. One at a time:")
    say("")
    for index, item in enumerate(items, 1):
        say(f"[{index}/{len(items)}] {item.title}")
        for line in item.lines:
            say(line)
        if item.repair:
            say(f"  fix would be: {item.repair}")
        choice = _choose(answer, say)
        if choice == "y":
            try:
                reason = answer(WHY).strip()
            except EOFError:
                reason = ""
            entries[item.key] = Accepted(
                key=item.key,
                hook=item.hook_name,
                event=item.event,
                command=item.command,
                codes=item.codes,
                reason=reason,
                at=date.today().isoformat(),
            )
            outcome.accepted.append(item.hook_name)
            say("  kept. It will be listed as off on purpose from now on.")
        elif choice == "n":
            if item.fix is None:
                say("  hookprobe cannot fix this itself. By hand:")
                say(f"    {item.repair or 'see --explain'}")
                outcome.manual.append(item.hook_name)
            else:
                done = item.fix()
                if done:
                    for line in done:
                        say(f"  {line}")
                    outcome.fixed.append(item.hook_name)
                    if item.codes == [DISABLE_CODE]:
                        outcome.settings_changed = True
                else:
                    say("  the fix did not apply (file gone?). By hand:")
                    say(f"    {item.repair or 'see --explain'}")
                    outcome.manual.append(item.hook_name)
        else:
            outcome.skipped.append(item.hook_name)
            say("  skipped.")
        say("")

    if outcome.accepted:
        path = save_accepted(project_dir, entries)
        say(f"Accepted entries written to {path}. Delete one to be asked again.")
    return outcome
