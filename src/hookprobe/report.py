"""Rendering: the table, the findings, and the machine-readable form."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Iterable

from .checks import Finding
from .config import Configuration
from .probe import HookProbe

YES = "yes"
NO = "no"
NA = "n/a"
UNKNOWN = "?"

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


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


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.code))


def render_text(
    config: Configuration,
    probes: list[HookProbe],
    schema_findings: list[Finding],
    live_ran: bool = False,
) -> str:
    """The human-facing report."""
    from . import evidence

    out: list[str] = []

    if config.disable_all_hooks:
        out.append("disableAllHooks is set -- no hook in this project runs at all.")
        out.append("")

    critical_schema = [f for f in schema_findings if f.severity == "critical"]
    if critical_schema:
        out.append("Configuration problems that switch hooks off:")
        for finding in _sorted_findings(critical_schema):
            out.append(f"  {finding.message}")
            if finding.detail:
                out.append(f"      {finding.detail}")
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

    broken = [p for p in probes if p.is_broken]
    if broken:
        verb = "is" if len(broken) == 1 else "are"
        out.append(
            f"{len(broken)} of {len(probes)} hooks {verb} not protecting anything."
        )
        out.append("")
        for probe in broken:
            for finding in _sorted_findings(probe.findings):
                if finding.severity == "info":
                    continue
                entry = evidence.lookup(finding.code)
                out.append(f"  {_short(probe.hook)}")
                out.append(f"      {finding.message}")
                if finding.detail:
                    out.append(f"      {finding.detail}")
                if entry.repair:
                    out.append(f"      fix: {entry.repair}")
                if entry.references:
                    out.append(f"      evidence: {', '.join(entry.references)}")
                out.append("")
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

    if not live_ran:
        out.append(
            "Effectiveness (did the verdict change the call?) was not measured."
        )
        out.append("Run with --live to check it against a real session.")
    out.append("")
    out.append(
        "A probe proves the moment of the test, not the future: time-dependent "
        "failures, state changes after the run and concurrency stay out of reach."
    )
    return "\n".join(out).rstrip() + "\n"


def _short(hook: Any) -> str:
    command = hook.command if isinstance(hook.command, str) else str(hook.type)
    token = command.strip().split()[-1] if command.strip() else command
    return token.rsplit("/", 1)[-1] or hook.name


def render_json(
    config: Configuration,
    probes: list[HookProbe],
    schema_findings: list[Finding],
    live_ran: bool = False,
) -> str:
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
                "starts": probe.starts,
                "answers": probe.answers,
                "canBlock": probe.can_block,
                "effective": getattr(probe, "effective", None),
                "broken": probe.is_broken,
                "findings": [asdict(f) for f in probe.findings],
            }
        )
    payload["summary"] = {
        "hooks": len(probes),
        "broken": sum(1 for p in probes if p.is_broken),
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
        out.append(f"  command       : {hook.command}")
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
