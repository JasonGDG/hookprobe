#!/usr/bin/env python3
"""Hard test: every fixture carries the verdict hookprobe is supposed to reach.

A tool that judges other people's guards has to be judged itself, and the only
honest way is a table of cases whose correct answer was written down first.
Three groups:

  healthy      -- must never be called broken (the expensive kind of mistake)
  broken       -- must be caught, with the right reason
  adversarial  -- built to fool the probe; here "unverifiable" is a pass and a
                  confident wrong answer is a failure

Run:  python tests/stress.py [-v]
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hookprobe.checks import check_location, check_matcher  # noqa: E402
from hookprobe.config import load  # noqa: E402
from hookprobe.probe import probe_hook  # noqa: E402

ALLOW = '{"permissionDecision": "allow"}'

PY_DENY = f"""#!/usr/bin/env python3
import json, sys
data = json.load(sys.stdin)
if "rm " in json.dumps(data):
    sys.exit(2)
print({json.dumps(ALLOW)})
"""

SH_ALLOW = f"""#!/bin/sh
read -r payload
echo '{ALLOW}'
"""


@dataclass
class Case:
    name: str
    group: str
    command: str | None = None
    event: str = "PreToolUse"
    matcher: str | None = "Bash"
    files: dict[str, str] = field(default_factory=dict)
    executable: tuple[str, ...] = ()
    handler: dict | None = None
    # Expectations. None means "do not care".
    starts: bool | None = None
    answers: bool | None = None
    can_block: bool | None = None
    broken: bool | None = None
    wants: tuple[str, ...] = ()
    forbids: tuple[str, ...] = ()
    note: str = ""


def py(body: str) -> str:
    return "#!/usr/bin/env python3\n" + body


CASES: list[Case] = [
    # ---------------------------------------------------------------- healthy
    Case(
        "plain script, exit 2 on the dangerous payload",
        "healthy",
        files={"g.py": PY_DENY},
        executable=("g.py",),
        command="{g.py}",
        starts=True, answers=True, can_block=True, broken=False,
    ),
    Case(
        "invoked through env",
        "healthy",
        files={"g.py": PY_DENY},
        command="/usr/bin/env python3 {g.py}",
        starts=True, can_block=True, broken=False,
        forbids=("P01.NO_SHEBANG", "P01.NOT_EXECUTABLE"),
    ),
    Case(
        "invoked through python3 with an option",
        "healthy",
        files={"g.py": PY_DENY},
        command="python3 -u {g.py}",
        starts=True, can_block=True, broken=False,
        forbids=("P01.NO_SHEBANG",),
    ),
    Case(
        "invoked through bash, no shebang needed",
        "healthy",
        files={"g.sh": "read -r p\necho '" + ALLOW + "'\n"},
        command="/bin/bash {g.sh}",
        starts=True, answers=True, broken=False,
        forbids=("P01.NO_SHEBANG", "P01.NOT_EXECUTABLE"),
    ),
    Case(
        "quoted path containing a space",
        "healthy",
        files={"my hooks/g.py": PY_DENY},
        executable=("my hooks/g.py",),
        command='"{my hooks/g.py}"',
        starts=True, can_block=True, broken=False,
    ),
    Case(
        "deny reason on stderr says 'permission denied'",
        "healthy",
        files={"g.py": py(
            "import json, sys\n"
            "data = json.load(sys.stdin)\n"
            'if "rm " in json.dumps(data):\n'
            '    sys.stderr.write("Permission denied by policy\\n")\n'
            "    sys.exit(2)\n"
            f"print({json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        starts=True, can_block=True, broken=False,
        note="the wording must not change the verdict",
    ),
    Case(
        "deny reason says 'not found'",
        "healthy",
        files={"g.py": py(
            "import json, sys\n"
            "data = json.load(sys.stdin)\n"
            'if "rm " in json.dumps(data):\n'
            '    sys.stderr.write("tool not found in allowlist\\n")\n'
            "    sys.exit(2)\n"
            f"print({json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        starts=True, can_block=True, broken=False,
    ),
    Case(
        "logging hook on PostToolUse, nothing to reject",
        "healthy",
        files={"log.sh": "#!/bin/sh\nread -r p\nexit 0\n"},
        executable=("log.sh",),
        command="{log.sh}",
        event="PostToolUse", matcher="Bash",
        starts=True, answers=True, broken=False,
        note="an observing hook is not a broken guard",
    ),
    Case(
        "context hook emitting plain text",
        "healthy",
        files={"ctx.sh": "#!/bin/sh\nread -r p\necho 'project uses uv'\n"},
        executable=("ctx.sh",),
        command="{ctx.sh}",
        event="UserPromptSubmit", matcher=None,
        starts=True, answers=True, broken=False,
        forbids=("P09.NOT_JSON",),
    ),
    Case(
        "JSON with hookSpecificOutput deny",
        "healthy",
        files={"g.py": py(
            "import json, sys\n"
            "data = json.load(sys.stdin)\n"
            'blocked = "rm " in json.dumps(data)\n'
            'out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", '
            '"permissionDecision": "deny" if blocked else "allow"}}\n'
            "print(json.dumps(out))\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        starts=True, answers=True, can_block=True, broken=False,
    ),
    Case(
        "unicode in the path",
        "healthy",
        files={"wächter/prüfen.py": PY_DENY},
        executable=("wächter/prüfen.py",),
        command="{wächter/prüfen.py}",
        starts=True, can_block=True, broken=False,
    ),
    Case(
        "symlink to the real script",
        "healthy",
        files={"real.py": PY_DENY},
        executable=("real.py",),
        command="{link.py}",
        starts=True, can_block=True, broken=False,
        note="link created by the runner",
    ),
    # ----------------------------------------------------------------- broken
    Case(
        "missing execute bit",
        "broken",
        files={"g.py": PY_DENY},
        command="{g.py}",
        starts=False, broken=True,
        wants=("P01.NOT_EXECUTABLE",),
    ),
    Case(
        "file does not exist",
        "broken",
        command="{gone.py}",
        starts=False, broken=True,
        wants=("P01.MISSING_FILE",),
    ),
    Case(
        "interpreter from the shebang is absent",
        "broken",
        files={"g.sh": "#!/usr/bin/nonexistent-interp\necho x\n"},
        executable=("g.sh",),
        command="{g.sh}",
        starts=False, broken=True,
        wants=("P01.MISSING_INTERPRETER",),
    ),
    Case(
        "unquoted path containing a space",
        "broken",
        files={"my hooks/g.py": PY_DENY},
        executable=("my hooks/g.py",),
        command="{my hooks/g.py}",
        starts=False, broken=True,
        wants=("P01.SPACE_IN_PATH",),
    ),
    Case(
        "script behind an interpreter is missing",
        "broken",
        command="python3 {gone.py}",
        starts=False, broken=True,
        wants=("P01.SPAWN_FAILED",),
        note="python exits 2 here -- must not read as a block",
    ),
    Case(
        "rejects with exit 1 instead of 2",
        "broken",
        files={"g.py": py(
            "import json, sys\n"
            "data = json.load(sys.stdin)\n"
            'if "rm " in json.dumps(data):\n'
            "    sys.exit(1)\n"
            f"print({json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        can_block=False, broken=True,
        wants=("P08.EXIT_ONE_ON_REJECT",),
    ),
    Case(
        "greeting from the shell profile before the JSON",
        "broken",
        files={"g.sh": "#!/bin/sh\nread -r p\necho 'welcome!'\necho '" + ALLOW + "'\n"},
        executable=("g.sh",),
        command="{g.sh}",
        broken=True,
        wants=("P09.PREAMBLE",),
    ),
    Case(
        "context above the documented cap",
        "broken",
        files={"g.py": py(
            "import json, sys\n"
            "sys.stdin.read()\n"
            'print(json.dumps({"additionalContext": "x" * 14000}))\n'
        )},
        executable=("g.py",),
        command="{g.py}",
        broken=True,
        wants=("P07.OVER_CAP",),
    ),
    Case(
        "never answers",
        "broken",
        files={"g.sh": "#!/bin/sh\nsleep 40\n"},
        executable=("g.sh",),
        command="{g.sh}",
        answers=False, broken=True,
    ),
    Case(
        "python script with a syntax error",
        "broken",
        files={"g.py": "#!/usr/bin/env python3\ndef broken(:\n"},
        executable=("g.py",),
        command="{g.py}",
        starts=False, broken=True,
        wants=("P01.SPAWN_FAILED",),
    ),
    Case(
        "imports a module that is not installed",
        "broken",
        files={"g.py": py("import definitely_not_installed_xyz\n")},
        executable=("g.py",),
        command="{g.py}",
        starts=False, broken=True,
        wants=("P01.SPAWN_FAILED",),
    ),
    Case(
        "path containing an apostrophe",
        "broken",
        files={"don't/g.py": PY_DENY},
        executable=("don't/g.py",),
        command="{don't/g.py}",
        starts=False, broken=True,
        note="found by accident: the harness put quotes in its own fixture path",
    ),
    # ------------------------------------------------------------ adversarial
    Case(
        "swallows its own failure",
        "adversarial",
        command="definitely-missing-guard 2>/dev/null || exit 0",
        broken=False,
        wants=("P01.NOT_TESTED",),
        note="undetectable from outside; must say so instead of passing it",
    ),
    Case(
        "valid JSON on stderr instead of stdout",
        "adversarial",
        files={"g.py": py(
            "import json, sys\n"
            "sys.stdin.read()\n"
            f"sys.stderr.write({json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        note="stdout is empty; must not be read as a working decision",
    ),
    Case(
        "behaves differently when it detects the probe",
        "adversarial",
        files={"g.py": py(
            "import json, os, sys\n"
            "data = json.load(sys.stdin)\n"
            'if os.environ.get("HOOKPROBE_CANARY") or "hookprobe" in json.dumps(data).lower():\n'
            f"    print({json.dumps(ALLOW)})\n"
            "    sys.exit(0)\n"
            "sys.exit(2)\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        note="a hook that games the probe; documents the limit",
    ),
    Case(
        "stateful: blocks only on the second call",
        "adversarial",
        files={"g.py": py(
            "import json, os, sys, tempfile\n"
            "sys.stdin.read()\n"
            "marker = os.path.join(tempfile.gettempdir(), 'hookprobe-stress-state')\n"
            "if os.path.exists(marker):\n"
            "    sys.exit(2)\n"
            "open(marker, 'w').close()\n"
            f"print({json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        note="the probe runs twice; state makes the second call differ",
    ),
    Case(
        "forks a background child and exits",
        "adversarial",
        files={"g.sh": "#!/bin/sh\nread -r p\n(sleep 30 &) >/dev/null 2>&1\necho '" + ALLOW + "'\n"},
        executable=("g.sh",),
        command="{g.sh}",
        starts=True, answers=True, broken=False,
        note="must not hang on the detached child",
    ),
    Case(
        "CRLF line endings",
        "adversarial",
        files={"g.sh": "#!/bin/sh\r\nread -r p\r\necho '" + ALLOW + "'\r\n"},
        executable=("g.sh",),
        command="{g.sh}",
        note="a classic Windows-checkout failure",
    ),
    Case(
        "byte order mark before the JSON",
        "adversarial",
        files={"g.py": py(
            "import json, sys\n"
            "sys.stdin.read()\n"
            f"sys.stdout.write('\\ufeff' + {json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        note="invisible character in front of the object",
    ),
    Case(
        "two JSON objects on separate lines",
        "adversarial",
        files={"g.py": py(
            "import json, sys\n"
            "sys.stdin.read()\n"
            'print(json.dumps({"log": 1}))\n'
            f"print({json.dumps(ALLOW)})\n"
        )},
        executable=("g.py",),
        command="{g.py}",
        note="documented as plain text by the harness",
    ),
    Case(
        "inline shell code instead of a script",
        "adversarial",
        command="sh -c 'read -r p; exit 2'",
        note="no script file exists to inspect",
    ),
    Case(
        "handler declares async",
        "adversarial",
        files={"g.py": PY_DENY},
        executable=("g.py",),
        handler={"type": "command", "command": "{g.py}", "async": True},
        can_block=False,
        wants=("P08.ASYNC_CANNOT_BLOCK",),
        note="decision fields are ineffective for async handlers",
    ),
    Case(
        "matcher that matches nothing",
        "adversarial",
        files={"g.py": PY_DENY},
        executable=("g.py",),
        command="{g.py}",
        matcher="ThisToolDoesNotExist",
        note="the hook is fine; the matcher makes it dead",
    ),
]


def build(case: Case, root: Path) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case.name)
    project = root / safe[:60]
    hooks_dir = project / ".claude" / "hooks"
    hooks_dir.mkdir(parents=True)

    written: dict[str, Path] = {}
    for name, body in case.files.items():
        target = hooks_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, "utf-8", newline="")
        written[name] = target
    for name in case.executable:
        path = hooks_dir / name
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)

    if "link.py" in (case.command or "") and "real.py" in written:
        link = hooks_dir / "link.py"
        link.symlink_to(written["real.py"])
        written["link.py"] = link

    def resolve(template: str) -> str:
        out = template
        for name in list(case.files) + ["gone.py", "link.py"]:
            out = out.replace("{" + name + "}", str(hooks_dir / name))
        return out

    handler = dict(case.handler) if case.handler else {"type": "command", "command": case.command}
    if "command" in handler and isinstance(handler["command"], str):
        handler["command"] = resolve(handler["command"])

    group: dict = {"hooks": [handler]}
    if case.matcher is not None:
        group["matcher"] = case.matcher
    settings = {"hooks": {case.event: [group]}}
    (project / ".claude" / "settings.json").write_text(
        json.dumps(settings, indent=2), "utf-8"
    )
    return project


def evaluate(case: Case, project: Path) -> tuple[bool, list[str]]:
    config = load(project, include_home=False)
    if not config.hooks:
        return False, ["configuration produced no hook"]
    hook = config.hooks[0]
    probe = probe_hook(hook, project, timeout=3.0)
    probe.findings.extend(check_matcher(hook))
    probe.findings.extend(check_location(hook))
    codes = {finding.code for finding in probe.findings}

    problems: list[str] = []
    for label, expected, actual in (
        ("starts", case.starts, probe.starts),
        ("answers", case.answers, probe.answers),
        ("can_block", case.can_block, probe.can_block),
        ("broken", case.broken, probe.is_broken),
    ):
        if expected is not None and expected != actual:
            problems.append(f"{label}: expected {expected}, got {actual}")
    for code in case.wants:
        if code not in codes:
            problems.append(f"missing finding {code}")
    for code in case.forbids:
        if code in codes:
            problems.append(f"unexpected finding {code}")
    return not problems, problems


def main() -> int:
    verbose = "-v" in sys.argv
    marker = Path(tempfile.gettempdir()) / "hookprobe-stress-state"
    if marker.exists():
        marker.unlink()

    root = Path(tempfile.mkdtemp(prefix="hookprobe-stress-"))
    results: list[tuple[Case, bool, list[str]]] = []
    try:
        for case in CASES:
            project = build(case, root)
            ok, problems = evaluate(case, project)
            results.append((case, ok, problems))
    finally:
        shutil.rmtree(root, ignore_errors=True)
        if marker.exists():
            marker.unlink()

    width = max(len(case.name) for case in CASES)
    for group in ("healthy", "broken", "adversarial"):
        rows = [row for row in results if row[0].group == group]
        passed = sum(1 for _, ok, _ in rows if ok)
        checked = [row for row in rows if _has_expectation(row[0])]
        print(f"\n{group.upper()}  ({passed}/{len(rows)} as specified, "
              f"{len(rows) - len(checked)} observation-only)")
        print("-" * (width + 30))
        for case, ok, problems in rows:
            if not _has_expectation(case):
                mark = "note"
            else:
                mark = "ok  " if ok else "FAIL"
            print(f"  {mark}  {case.name.ljust(width)}")
            if problems:
                for problem in problems:
                    print(f"        {problem}")
            elif verbose and case.note:
                print(f"        {case.note}")

    checked = [row for row in results if _has_expectation(row[0])]
    failed = [row for row in checked if not row[1]]
    print(
        f"\n{len(checked) - len(failed)}/{len(checked)} cases with a written-down "
        f"expectation were judged correctly."
    )
    if failed:
        print("Wrong verdicts:")
        for case, _, problems in failed:
            print(f"  {case.name}: {'; '.join(problems)}")
    return 1 if failed else 0


def _has_expectation(case: Case) -> bool:
    return any(
        value is not None
        for value in (case.starts, case.answers, case.can_block, case.broken)
    ) or bool(case.wants or case.forbids)


if __name__ == "__main__":
    raise SystemExit(main())
