"""Command-line interface for hookprobe."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .checks import check_location, check_matcher, check_schema
from .config import load
from .probe import probe_hook


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hookprobe",
        description=(
            "Check whether your Claude Code hooks actually work: do they start, "
            "do they answer, and could they block? Configured and effective are "
            "different properties."
        ),
        epilog=(
            "The default run is offline: no network, no API key, no tokens. "
            "Only --live spends two real sessions."
        ),
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="project directory to inspect (default: the current one)",
    )
    parser.add_argument(
        "--settings",
        action="append",
        metavar="PATH",
        help="inspect only these settings files instead of discovering them",
    )
    parser.add_argument(
        "--no-home",
        action="store_true",
        help="skip the user-level settings in ~/.claude",
    )
    parser.add_argument(
        "--explain",
        metavar="HOOK",
        help="print everything known about one hook, with evidence and repair",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--live",
        action="store_true",
        help="also measure effectiveness with two real sessions (costs tokens)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="override the per-hook probe timeout",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="do not ask before starting the --live stage",
    )
    parser.add_argument("--version", action="version", version=f"hookprobe {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    from . import live as live_stage
    from . import report as report_module

    args = build_parser().parse_args(argv)
    project_dir = Path(args.directory).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"hookprobe: not a directory: {project_dir}", file=sys.stderr)
        return 2

    settings = [Path(p).expanduser() for p in args.settings] if args.settings else None
    config = load(project_dir, explicit_settings=settings, include_home=not args.no_home)

    schema_findings = check_schema(config)
    # Load problems that check_schema does not map (broken JSON, unreadable
    # file, unparsable frontmatter) must not vanish: a settings file that fails
    # to parse means none of its hooks are active.
    mapped = {finding.detail for finding in schema_findings}
    for issue in list(config.issues) + list(config.sandbox_issues):
        if issue.message in mapped or any(
            issue.message == finding.message for finding in schema_findings
        ):
            continue
        from .checks import Finding
        from . import evidence as evidence_module

        entry = evidence_module.lookup(issue.code)
        severity = entry.severity if entry.title != "Uncatalogued finding" else "critical"
        schema_findings.append(
            Finding(
                code=issue.code,
                hook=None,
                severity=severity,
                message=f"{issue.source.label}: {issue.message}",
                detail=issue.detail,
            )
        )
    probes = []
    for hook in config.hooks:
        probe = probe_hook(hook, project_dir, timeout=args.timeout)
        probe.findings.extend(check_matcher(hook))
        probe.findings.extend(check_location(hook))
        probes.append(probe)

    live_ran = False
    channel_verdict: bool | None = None
    if args.live:
        if not args.yes and sys.stdin.isatty():
            print(
                "--live starts two real Claude Code sessions in a throwaway directory "
                "and spends tokens for both.",
                file=sys.stderr,
            )
            answer = input("Continue? [y/N] ").strip().lower()
            if answer not in {"y", "yes"}:
                print("Stopped before the live stage.", file=sys.stderr)
                return 2
        result = live_stage.run(project_dir)
        live_ran = result.ran
        if result.ran:
            live_stage.apply(probes, result)
            channel_verdict = result.effective
        print(result.detail, file=sys.stderr)

    if args.explain:
        sys.stdout.write(report_module.render_explain(args.explain, probes))
        return 0

    if args.json:
        sys.stdout.write(
            report_module.render_json(config, probes, schema_findings, live_ran) + "\n"
        )
    else:
        sys.stdout.write(
            report_module.render_text(
                config, probes, schema_findings, live_ran, channel_verdict
            )
        )

    broken = any(probe.is_broken for probe in probes)
    critical_config = any(f.severity == "critical" for f in schema_findings)
    return 1 if (broken or critical_config or config.disable_all_hooks) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
