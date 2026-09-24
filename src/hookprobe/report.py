"""Rendering: the table, the findings, and the machine-readable form."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .checks import Finding
from .config import Configuration
from .probe import HookProbe

YES = "yes"
NO = "no"
NA = "n/a"
UNKNOWN = "?"

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _stamp(mtime: float | None) -> str:
    if mtime is None:
        return "unknown"
    from datetime import datetime, timezone

    return datetime.fromtimestamp(mtime, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _flag(value: bool | None, *, na: bool = False) -> str:
    if value is True:
        return YES
    if value is False:
        return NO
    return NA if na else UNKNOWN


def _block_flag(probe: "HookProbe") -> str:
    """Three states: blocks, cannot block, or nothing to reject in this probe."""
    from .probe import BLOCKING_EVENTS

    from .probe import REJECTABLE_EVENTS

    if probe.hook.event not in BLOCKING_EVENTS:
        return NA
    if probe.hook.event not in REJECTABLE_EVENTS and probe.can_block is None:
        return NA
    if probe.can_block is True:
        return YES
    if probe.can_block is False:
        return NO
    return "untested"


def _column_widths(rows: list[list[str]], headers: list[str]) -> list[int]:
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    return widths


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    widths = _column_widths(rows, headers)
    lines = [
        "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)).rstrip()
    ]
    lines.append("-" * min(sum(widths) + 2 * (len(widths) - 1), 100))
    for row in rows:
        lines.append(
            "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()
        )
    return lines


def _rejectable() -> frozenset[str]:
    from .probe import REJECTABLE_EVENTS

    return REJECTABLE_EVENTS


def _accepted_probes(probes: list["HookProbe"], accepted: dict | None) -> dict[str, Any]:
    """Broken probes whose every current problem the user accepted with --ask."""
    if not accepted:
        return {}
    from .ask import is_accepted

    found: dict[str, Any] = {}
    for probe in probes:
        entry = is_accepted(probe, accepted)
        if entry is not None and probe.is_broken:
            found[probe.name] = entry
    return found


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.code))


def render_text(
    config: Configuration,
    probes: list[HookProbe],
    schema_findings: list[Finding],
    live_ran: bool = False,
    channel_verdict: bool | None = None,
    accepted: dict | None = None,
) -> str:
    """The human-facing report."""
    from . import evidence
    from .ask import disable_accepted

    accepted_probes = _accepted_probes(probes, accepted)
    disable_entry = disable_accepted(accepted, config) if config.disable_all_hooks else None

    out: list[str] = []

    if config.disable_all_hooks:
        if disable_entry is not None:
            out.append(
                f"disableAllHooks is set -- accepted on {disable_entry.at}: "
                f"{disable_entry.reason or 'no reason given'}"
            )
        else:
            out.append("disableAllHooks is set -- no hook in this project runs at all.")
        out.append("")

    critical_schema = [
        f
        for f in schema_findings
        if f.severity == "critical"
        and not (f.code == "P03.HOOKS_DISABLED" and disable_entry is not None)
    ]
    if critical_schema:
        out.append("Configuration problems that switch hooks off:")
        for finding in _sorted_findings(critical_schema):
            out.append(f"  {finding.message}")
            if finding.detail:
                out.append(f"      {finding.detail}")
        out.append("")

    # Non-critical configuration findings used to vanish; one unreadable agent
    # file per line would drown the table, so they are grouped by code.
    soft_schema = [f for f in schema_findings if f.severity != "critical"]
    if soft_schema:
        by_code: dict[str, list[Finding]] = {}
        for finding in soft_schema:
            by_code.setdefault(finding.code, []).append(finding)
        out.append("Configuration, worth a look (nothing here switches a hook off):")
        for code, items in by_code.items():
            entry = evidence.lookup(code)
            sample = (items[0].detail or items[0].message).replace("\n", " ")[:100]
            out.append(f"  {len(items)}x {entry.title} ({code}) -- e.g. {sample}")
        out.append("")

    if not probes:
        out.append("No hook handlers found.")
        out.append(f"Looked at: {', '.join(s.label for s in config.sources) or 'nothing'}")
        return "\n".join(out)

    headers = ["Hook", "source", "starts", "answers", "can block"]
    if live_ran:
        headers.append("effective")
    rows: list[list[str]] = []
    for probe in probes:
        row = [
            f"{probe.hook.event} · {_short(probe.hook)}",
            probe.hook.source.kind,
            _flag(probe.starts),
            _flag(probe.answers),
            _block_flag(probe),
        ]
        if live_ran:
            row.append(_flag(getattr(probe, "effective", None), na=True))
        rows.append(row)
    out.extend(_table(headers, rows))
    out.append("")

    # The count alone can mislead. A configuration where five logging hooks work
    # and all three guards are dead reads as "3 of 8" -- true, and useless. Name
    # the case where nothing is left that could stop anything.
    from .probe import _intends_to_decide

    guards = [
        p
        for p in probes
        if p.hook.event in _rejectable()
        and _intends_to_decide(p.hook, Path(config.project_dir))
    ]
    dead_guards = [p for p in guards if p.is_broken or p.can_block is False]
    if guards and len(dead_guards) == len(guards):
        out.append(
            f"No working guard left: all {len(guards)} handlers that could block "
            "are broken. The rest of this configuration only observes."
        )
        out.append("")

    broken = [p for p in probes if p.is_broken and p.name not in accepted_probes]
    remaining = [p for p in probes if p.name not in accepted_probes]
    if broken:
        verb = "is" if len(broken) == 1 else "are"
        out.append(
            f"{len(broken)} of {len(probes)} hooks {verb} not protecting anything."
        )
        out.append("")
        for probe in broken:
            findings = [f for f in _sorted_findings(probe.findings) if f.severity != "info"]
            # A static diagnosis ("no execute bit") and the runtime confirmation
            # ("Permission denied") are one fact seen twice. Both stay on the
            # record; the report shows the second as a line under the first.
            static_launch = [
                f
                for f in findings
                if f.code.startswith("P01.")
                and f.code not in ("P01.SPAWN_FAILED", "P01.NOT_TESTED")
                and f.severity == "critical"
            ]
            runtime = next((f for f in findings if f.code == "P01.SPAWN_FAILED"), None)
            folded = runtime if (runtime is not None and static_launch) else None
            for finding in findings:
                if finding is folded:
                    continue
                entry = evidence.lookup(finding.code)
                out.append(f"  {_short(probe.hook)}")
                out.append(f"      {finding.message}")
                if finding.detail:
                    out.append(f"      {finding.detail}")
                if folded is not None and finding is static_launch[0] and folded.detail:
                    out.append(f"      confirmed at runtime: {folded.detail}")
                if entry.repair:
                    out.append(f"      fix: {entry.repair}")
                if entry.references:
                    out.append(f"      evidence: {', '.join(entry.references)}")
                out.append("")
    else:
        unverified = [
            probe
            for probe in remaining
            if any(f.code == "P01.NOT_TESTED" for f in probe.findings)
            or (probe.hook.event in _rejectable() and probe.can_block is None)
        ]
        if not remaining:
            out.append("Every hook here is off on purpose (see below).")
        elif unverified:
            out.append(
                f"{len(remaining)} hooks start and answer; {len(unverified)} could not "
                "be verified any further (see below)."
            )
        elif accepted_probes:
            out.append(f"All {len(remaining)} remaining hooks start and answer.")
        else:
            out.append(f"All {len(probes)} hooks start and answer.")
        out.append("")

    warnings = [
        (probe, finding)
        for probe in probes
        if not probe.is_broken
        for finding in probe.findings
        if finding.severity == "warning"
    ]
    if warnings:
        out.append("Worth a look:")
        for probe, finding in warnings:
            out.append(f"  {_short(probe.hook)}: {finding.message}")
        out.append("")

    if accepted_probes:
        out.append("Off on purpose (accepted with --ask; delete the entry in "
                   ".claude/hookprobe-accepted.json to be asked again):")
        for probe in probes:
            entry = accepted_probes.get(probe.name)
            if entry is None:
                continue
            out.append(
                f"  {_short(probe.hook)}: {', '.join(entry.codes)} -- "
                f"{entry.reason or 'no reason given'} ({entry.at})"
            )
        out.append("")

    if live_ran:
        if channel_verdict is True:
            out.append(
                "Channel check: a deny verdict does take effect here -- measured "
                "against two disposable sessions."
            )
        elif channel_verdict is False:
            out.append(
                "Channel check: a deny verdict did NOT take effect here. Every "
                "verdict your hooks return is decoration in this channel."
            )
        else:
            out.append("Channel check: inconclusive, see the message above.")
    else:
        out.append(
            "Effectiveness (did the verdict change the call?) was not measured."
        )
        out.append("Run with --live to check it against a real session.")
    out.append("")
    out.append(
        "A probe proves the moment of the test. For the failures that happen "
        "later -- a hook that stops firing mid-session -- install the heartbeat "
        "and leave --watch running: hookprobe --install-heartbeat"
    )
    return "\n".join(out).rstrip() + "\n"


def _short(hook: Any) -> str:
    """A readable label: the script, not the last word of the command line."""
    from .probe import _script_path

    try:
        path = _script_path(hook, Path.cwd())
    except Exception:
        path = None
    if path is not None and path.name:
        return path.name
    command = hook.command if isinstance(hook.command, str) else str(hook.type)
    if not isinstance(command, str) or not command.strip():
        return hook.name
    return command.strip().split()[0].rsplit("/", 1)[-1] or hook.name


def render_json(
    config: Configuration,
    probes: list[HookProbe],
    schema_findings: list[Finding],
    live_ran: bool = False,
    accepted: dict | None = None,
) -> str:
    accepted_probes = _accepted_probes(probes, accepted)
    payload: dict[str, Any] = {
        "version": 1,
        "project": str(config.project_dir),
        "sources": [
            {"kind": s.kind, "path": str(s.path), "label": s.label} for s in config.sources
        ],
        "disableAllHooks": config.disable_all_hooks,
        "configurationFindings": [asdict(f) for f in schema_findings],
        "hooks": [],
        "liveRan": live_ran,
    }
    for probe in probes:
        payload["hooks"].append(
            {
                "name": probe.hook.name,
                "event": probe.hook.event,
                "matcher": probe.hook.matcher,
                "command": probe.hook.command,
                "source": probe.hook.source.kind,
                "sourcePath": str(probe.hook.source.path),
                "identity": (
                    {
                        "resolvedPath": probe.identity.path,
                        "exists": probe.identity.exists,
                        "size": probe.identity.size,
                        "mtime": probe.identity.mtime,
                        "sha256": probe.identity.sha256,
                        "symlinkTo": probe.identity.symlink_to,
                        "note": probe.identity.note,
                    }
                    if getattr(probe, "identity", None) is not None
                    else None
                ),
                "starts": probe.starts,
                "answers": probe.answers,
                "canBlock": probe.can_block,
                "effective": getattr(probe, "effective", None),
                "broken": probe.is_broken,
                "acceptedAsOff": probe.name in accepted_probes,
                "findings": [asdict(f) for f in probe.findings],
            }
        )
    payload["accepted"] = [asdict(entry) for entry in (accepted or {}).values()]
    payload["summary"] = {
        "hooks": len(probes),
        "broken": sum(1 for p in probes if p.is_broken and p.name not in accepted_probes),
        "acceptedAsOff": len(accepted_probes),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_explain(name: str, probes: list[HookProbe]) -> str:
    """Full detail for one hook, including the evidence behind each finding."""
    from . import evidence

    matches = [p for p in probes if name in p.hook.name or name in str(p.hook.command)]
    if not matches:
        known = ", ".join(_short(p.hook) for p in probes) or "none"
        return f"No hook matches {name!r}. Known hooks: {known}\n"

    out: list[str] = []
    for probe in matches:
        hook = probe.hook
        out.append(f"{hook.event} · {_short(hook)}")
        out.append(f"  configured in : {hook.source.label}")
        out.append(f"  settings file : {hook.source.path}")
        out.append(f"  command       : {hook.command}")
        identity = getattr(probe, "identity", None)
        if identity is not None:
            if identity.path:
                out.append(f"  resolves to   : {identity.path}")
                if identity.symlink_to:
                    out.append(f"  symlink to    : {identity.symlink_to}")
                if identity.sha256:
                    out.append(f"  sha256        : {identity.sha256}")
                    out.append(
                        f"  size / mtime  : {identity.size} bytes, "
                        f"{_stamp(identity.mtime)}"
                    )
                elif identity.note:
                    out.append(f"  fingerprint   : not taken -- {identity.note}")
                elif not identity.exists:
                    out.append("  fingerprint   : not taken -- the target does not exist")
            elif identity.note:
                out.append(f"  resolves to   : no single file -- {identity.note}")
        out.append(f"  matcher       : {hook.matcher if hook.matcher is not None else '(none)'}")
        out.append(f"  starts        : {_flag(probe.starts)}")
        out.append(f"  answers       : {_flag(probe.answers)}")
        out.append(f"  can block     : {_block_flag(probe)}")
        if probe.neutral is not None:
            out.append(
                f"  probe run     : exit {probe.neutral.exit_code}, "
                f"{probe.neutral.duration:.2f}s, {len(probe.neutral.stdout)} bytes on stdout"
            )
            if probe.neutral.stderr.strip():
                out.append(f"  stderr        : {probe.neutral.stderr.strip()[:200]}")
        out.append("")
        for finding in _sorted_findings(probe.findings):
            entry = evidence.lookup(finding.code)
            out.append(f"  [{finding.severity}] {entry.title}  ({finding.code})")
            out.append(f"      {finding.message}")
            if finding.detail:
                out.append(f"      {finding.detail}")
            out.append(f"      why: {entry.explanation}")
            if entry.repair:
                out.append(f"      fix: {entry.repair}")
            if entry.references:
                out.append(f"      evidence: {', '.join(entry.references)}")
            out.append("")
    return "\n".join(out).rstrip() + "\n"
