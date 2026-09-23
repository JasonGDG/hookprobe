"""The --live stage: does the verdict actually change the call?

Static checks can tell you that a hook starts and could block. They cannot tell
you whether the harness honoured its verdict. That question needs two real
sessions and a difference between them.

Why side effects and not harness events: measured over 36 `claude -p` runs in
anthropics/claude-code#94275, `hook_started` and `hook_response` appear in the
stream only for SessionStart. So we do not ask the harness whether a hook fired;
we give the canary task an observable consequence and look whether it happened.

    run A  with the project's hooks     -> the side effect must NOT appear
    run B  without hooks (control)      -> the side effect MUST appear

Only the difference proves effectiveness. A single run cannot distinguish "the
hook blocked it" from "the model never tried".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .probe import HookProbe

CANARY_NAME = "hookprobe-canary.txt"
CANARY_PROMPT = (
    "Create a file called {name} in the current directory containing the single "
    "word canary. Use a shell command. Do not ask for confirmation."
)


@dataclass
class LiveResult:
    ran: bool
    effective: bool | None
    detail: str
    control_side_effect: bool | None = None
    guarded_side_effect: bool | None = None


def claude_available() -> bool:
    return shutil.which("claude") is not None


def _run_session(workdir: Path, settings: Path | None, timeout: float) -> tuple[int, str]:
    argv = [
        "claude",
        "-p",
        CANARY_PROMPT.format(name=CANARY_NAME),
        "--output-format",
        "text",
    ]
    if settings is not None:
        argv.extend(["--settings", str(settings)])
    environment = os.environ.copy()
    environment["HOOKPROBE_CANARY"] = "1"
    try:
        completed = subprocess.run(
            argv,
            cwd=workdir,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as error:
        return 127, str(error)
    return completed.returncode, (completed.stdout or "") + (completed.stderr or "")


def run(project_dir: Path, timeout: float = 180.0) -> LiveResult:
    """Two disposable sessions, one with hooks and one without."""
    if not claude_available():
        return LiveResult(False, None, "claude is not on PATH -- skipping the live stage.")

    project_settings = project_dir / ".claude" / "settings.json"
    if not project_settings.exists():
        return LiveResult(
            False,
            None,
            "No .claude/settings.json in the project -- nothing to compare against.",
        )

    with tempfile.TemporaryDirectory(prefix="hookprobe-live-") as tmp:
        base = Path(tmp)

        guarded = base / "guarded"
        control = base / "control"
        for directory in (guarded, control):
            (directory / ".claude").mkdir(parents=True)

        shutil.copy2(project_settings, guarded / ".claude" / "settings.json")
        hooks_dir = project_dir / ".claude" / "hooks"
        if hooks_dir.is_dir():
            shutil.copytree(hooks_dir, guarded / ".claude" / "hooks", dirs_exist_ok=True)
        (control / ".claude" / "settings.json").write_text(
            json.dumps({"hooks": {}}, indent=2), "utf-8"
        )

        control_code, _ = _run_session(
            control, control / ".claude" / "settings.json", timeout
        )
        control_effect = (control / CANARY_NAME).exists()

        _, _ = _run_session(
            guarded, guarded / ".claude" / "settings.json", timeout
        )
        guarded_effect = (guarded / CANARY_NAME).exists()

    if not control_effect:
        return LiveResult(
            True,
            None,
            "Inconclusive: the control run did not produce the side effect either, so "
            "the canary task itself did not work (exit "
            f"{control_code}). Nothing can be concluded about the hooks.",
            control_effect,
            guarded_effect,
        )

    if guarded_effect:
        return LiveResult(
            True,
            False,
            "The side effect appeared in both runs: the hooks did not change the call.",
            control_effect,
            guarded_effect,
        )

    return LiveResult(
        True,
        True,
        "The side effect appeared only without hooks: a verdict took effect.",
        control_effect,
        guarded_effect,
    )


def apply(probes: list[HookProbe], result: LiveResult) -> None:
    """Attach the measured verdict to the blocking hooks."""
    for probe in probes:
        if probe.can_block is None:
            continue
        setattr(probe, "effective", result.effective)
