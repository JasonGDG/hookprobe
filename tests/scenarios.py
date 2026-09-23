#!/usr/bin/env python3
"""Three whole configurations, not single hooks: does the report as a whole tell
the truth?

  all-on     every guard healthy and active        -> nothing to report, exit 0
  all-off    every guard broken, one way each      -> every one caught, exit 1
  inverted   the guards are dead, the noise lives  -> must not read as "mostly fine"

The third is the one that matters. A configuration where the logging hooks work
and the blocking hooks do not is the exact shape of a false sense of safety, and
a summary line of "3 of 8" would be technically true and practically useless.

Run:  python tests/scenarios.py [--keep]
"""

from __future__ import annotations

import io
import json
import stat
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hookprobe.cli import main  # noqa: E402

ALLOW = '{"permissionDecision": "allow"}'


def script(body: str) -> str:
    return "#!/usr/bin/env python3\n" + body


DENY_OK = script(
    "import json, sys\n"
    "data = json.load(sys.stdin)\n"
    'if "rm " in json.dumps(data):\n'
    '    sys.stderr.write("refused by policy\\n")\n'
    "    sys.exit(2)\n"
    f"print({ALLOW!r})\n"
)
DENY_EXIT_ONE = script(
    "import json, sys\n"
    "data = json.load(sys.stdin)\n"
    "target = json.dumps(data.get('tool_input', {}))\n"
    'if "ssh" in target or "sudoers" in target or "rm " in target:\n'
    "    sys.exit(1)\n"
    f"print({ALLOW!r})\n"
)
LOGGER = "#!/bin/sh\nread -r payload\nexit 0\n"
CONTEXT_OK = "#!/bin/sh\nread -r payload\necho 'this project uses uv'\n"
CONTEXT_HUGE = script(
    "import json, sys\n"
    "sys.stdin.read()\n"
    'print(json.dumps({"additionalContext": "x" * 14000}))\n'
)
NOISY = "#!/bin/sh\nread -r payload\necho 'welcome to my shell'\necho '" + ALLOW + "'\n"
HANGS = "#!/bin/sh\nsleep 40\n"
BAD_INTERP = "#!/usr/bin/nonexistent-interp\necho x\n"


def write(project: Path, name: str, body: str, executable: bool = True) -> Path:
    path = project / ".claude" / "hooks" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, "utf-8")
    mode = path.stat().st_mode
    if executable:
        path.chmod(mode | stat.S_IXUSR | stat.S_IRUSR)
    else:
        path.chmod(mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)
    return path


def settings(project: Path, entries: list[tuple[str, str | None, str]], **extra) -> None:
    hooks: dict[str, list] = {}
    for event, matcher, command in entries:
        group: dict = {"hooks": [{"type": "command", "command": command}]}
        if matcher is not None:
            group["matcher"] = matcher
        hooks.setdefault(event, []).append(group)
    payload = {"hooks": hooks}
    payload.update(extra)
    path = project / ".claude" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), "utf-8")


def build_all_on(root: Path) -> Path:
    project = root / "all-on"
    (project / ".claude" / "hooks").mkdir(parents=True)
    entries = [
        ("PreToolUse", "Bash", str(write(project, "deny-bash.py", DENY_OK))),
        ("PreToolUse", "Write|Edit", str(write(project, "deny-write.py", DENY_OK))),
        ("PreToolUse", "Bash", str(write(project, "audit.sh", LOGGER))),
        ("PostToolUse", "Bash", str(write(project, "log-after.sh", LOGGER))),
        ("UserPromptSubmit", None, str(write(project, "context.sh", CONTEXT_OK))),
        ("SessionStart", None, str(write(project, "session.sh", CONTEXT_OK))),
        ("Stop", None, str(write(project, "wrapup.sh", LOGGER))),
        ("PreCompact", None, str(write(project, "before-compact.sh", LOGGER))),
    ]
    settings(project, entries)
    return project


def build_all_off(root: Path) -> Path:
    project = root / "all-off"
    (project / ".claude" / "hooks").mkdir(parents=True)
    entries = [
        # each guard broken a different way
        ("PreToolUse", "Bash", str(write(project, "deny-bash.py", DENY_OK, executable=False))),
        ("PreToolUse", "Write|Edit", str(project / ".claude" / "hooks" / "gone.py")),
        ("PreToolUse", "Bash", str(write(project, "bad-interp.sh", BAD_INTERP))),
        ("PreToolUse", "Bash", str(write(project, "exit-one.py", DENY_EXIT_ONE))),
        ("PostToolUse", "Bash", "missing-linter --strict 2>/dev/null || exit 0"),
        ("UserPromptSubmit", None, str(write(project, "noisy.sh", NOISY))),
        ("SessionStart", None, str(write(project, "huge.py", CONTEXT_HUGE))),
        ("Stop", None, str(write(project, "hangs.sh", HANGS))),
    ]
    settings(project, entries)
    return project


def build_inverted(root: Path) -> Path:
    """The shape of a false sense of safety: the guards are dead, the noise lives."""
    project = root / "inverted"
    (project / ".claude" / "hooks").mkdir(parents=True)
    entries = [
        # supposed to protect -- dead
        ("PreToolUse", "Bash", str(write(project, "deny-bash.py", DENY_OK, executable=False))),
        ("PreToolUse", "Write|Edit", str(write(project, "deny-write.py", DENY_EXIT_ONE))),
        ("PreToolUse", "Bash", str(project / ".claude" / "hooks" / "vanished.py")),
        # supposed to be quiet -- very much alive
        ("PostToolUse", "Bash", str(write(project, "log-after.sh", LOGGER))),
        ("UserPromptSubmit", None, str(write(project, "context.sh", CONTEXT_OK))),
        ("SessionStart", None, str(write(project, "session.sh", CONTEXT_OK))),
        ("Stop", None, str(write(project, "wrapup.sh", LOGGER))),
        ("PreCompact", None, str(write(project, "before-compact.sh", LOGGER))),
    ]
    settings(project, entries)
    return project


def run(project: Path) -> tuple[int, str]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main([str(project), "--no-home"])
    return code, buffer.getvalue()


def summarise(text: str) -> tuple[int, int]:
    """(hooks in the table, hooks reported as not protecting)"""
    rows = 0
    broken = 0
    for line in text.splitlines():
        if " project  " in line or " project " in line and "·" in line:
            rows += 1
        if "not protecting anything" in line:
            broken = int(line.split()[0])
    return rows, broken


def main_entry() -> int:
    keep = "--keep" in sys.argv
    root = Path(tempfile.mkdtemp(prefix="guardscenarios-"))
    expectations = {
        "all-on": (0, 0),      # exit code, hooks reported broken
        # noisy.sh is legitimate plain text on UserPromptSubmit, and huge.py is a
        # context problem rather than a protection one -- both are warnings.
        "all-off": (1, 6),
        "inverted": (1, 3),
    }
    builders = {
        "all-on": build_all_on,
        "all-off": build_all_off,
        "inverted": build_inverted,
    }
    failures: list[str] = []

    for name, builder in builders.items():
        project = builder(root)
        code, text = run(project)
        rows, broken = summarise(text)
        want_code, want_broken = expectations[name]
        print("=" * 78)
        print(f"SCENARIO {name}   exit={code} (expected {want_code})   "
              f"reported broken={broken} (expected {want_broken})")
        print("=" * 78)
        print(text)
        if code != want_code:
            failures.append(f"{name}: exit {code}, expected {want_code}")
        if broken != want_broken:
            failures.append(f"{name}: {broken} broken, expected {want_broken}")

    if keep:
        print(f"fixtures kept in {root}")
    else:
        subprocess.run(["rm", "-rf", str(root)], check=False)

    if failures:
        print("\nMISMATCHES")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print("\nAll three scenarios matched their written-down expectation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_entry())
