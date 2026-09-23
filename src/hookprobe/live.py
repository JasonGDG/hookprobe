"""The --live stage: does a deny verdict take effect in this channel?

Static checks can tell you that a hook starts and returns exit code 2. They
cannot tell you whether the harness *honours* that verdict here -- in this
version, on this platform, in headless mode. anthropics/claude-code#95726
reports exactly that gap: "ask" silently becomes "deny" in --print mode, and
PermissionRequest never fires.

What this stage does NOT do is ask whether your own hooks block the canary.
Your hooks are supposed to let a harmless command through, so a refusal to
block it would prove nothing. Instead hookprobe installs a known-good deny
hook of its own next to a disposable canary task and measures the difference:

    run A  with hookprobe's deny hook   -> the side effect must NOT appear
    run B  without any hook (control)   -> the side effect MUST appear

If the side effect appears in both runs, the hook mechanism itself is not
taking effect in this channel, and every verdict your own hooks return is
decoration. If it appears in neither, the canary task failed and nothing can
be concluded -- which is reported as inconclusive rather than as a pass.

Why side effects and not harness events: measured over 36 `claude -p` runs in
anthropics/claude-code#94275, `hook_started` and `hook_response` appear in the
stream only for SessionStart.
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
CANARY_MARKER = "hookprobe-canary"
CANARY_PROMPT = (
    "Run exactly this shell command and nothing else: "
    "printf hookprobe-canary > hookprobe-canary.txt"
)

# A deny hook hookprobe controls: exit code 2 is the only code that blocks.
DENY_HOOK = """#!/usr/bin/env python3
import json, sys
payload = sys.stdin.read()
if "hookprobe-canary" in payload:
    sys.stderr.write("blocked by hookprobe\\n")
    sys.exit(2)
print(json.dumps({"permissionDecision": "allow"}))
"""


@dataclass
class LiveResult:
    ran: bool
    effective: bool | None
    detail: str
    control_side_effect: bool | None = None
    guarded_side_effect: bool | None = None
    control_log: str = ""
    guarded_log: str = ""


def claude_available() -> bool:
    return shutil.which("claude") is not None


def _run_session(workdir: Path, settings: Path, timeout: float) -> tuple[int, str]:
    argv = [
        "claude",
        "-p",
        CANARY_PROMPT,
        "--output-format",
        "text",
        "--settings",
        str(settings),
        "--allowedTools",
        "Bash",
    ]
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
    return completed.returncode, ((completed.stdout or "") + (completed.stderr or ""))[:4000]


def _prepare(base: Path, name: str, with_hook: bool) -> tuple[Path, Path]:
    workdir = base / name
    (workdir / ".claude" / "hooks").mkdir(parents=True)
    settings_path = workdir / ".claude" / "settings.json"
    if with_hook:
        hook_path = workdir / ".claude" / "hooks" / "deny.py"
        hook_path.write_text(DENY_HOOK, "utf-8")
        hook_path.chmod(0o755)
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": str(hook_path)}],
                    }
                ]
            }
        }
    else:
        settings = {"hooks": {}}
    settings_path.write_text(json.dumps(settings, indent=2), "utf-8")
    return workdir, settings_path


def run(project_dir: Path, timeout: float = 180.0) -> LiveResult:
    """Two disposable sessions: one guarded by a known-good deny hook, one not.

    project_dir is only used for the report line -- the probe deliberately runs
    outside it so that nothing in the real project is touched.
    """
    if not claude_available():
        return LiveResult(False, None, "claude is not on PATH -- skipping the live stage.")

    with tempfile.TemporaryDirectory(prefix="hookprobe-live-") as tmp:
        base = Path(tmp)

        control_dir, control_settings = _prepare(base, "control", with_hook=False)
        control_code, control_log = _run_session(control_dir, control_settings, timeout)
        control_effect = (control_dir / CANARY_NAME).exists()

        guarded_dir, guarded_settings = _prepare(base, "guarded", with_hook=True)
        guarded_code, guarded_log = _run_session(guarded_dir, guarded_settings, timeout)
        guarded_effect = (guarded_dir / CANARY_NAME).exists()

    if guarded_code not in (0, None):
        return LiveResult(
            True,
            None,
            "Inconclusive: the guarded session itself failed (exit "
            f"{guarded_code}). A missing canary file proves nothing when the run "
            "that was supposed to create it did not finish.",
            control_effect,
            guarded_effect,
            control_log,
            guarded_log,
        )

    if not control_effect:
        return LiveResult(
            True,
            None,
            "Inconclusive: the control run did not create the canary file either "
            f"(exit {control_code}), so the task itself did not work. Nothing can be "
            "concluded about the hook mechanism.",
            control_effect,
            guarded_effect,
            control_log,
            guarded_log,
        )

    if guarded_effect:
        return LiveResult(
            True,
            False,
            "The canary was created in BOTH runs: a deny verdict did not take effect "
            "in this channel. Hooks are not enforcing anything here.",
            control_effect,
            guarded_effect,
            control_log,
            guarded_log,
        )

    return LiveResult(
        True,
        True,
        "The canary was created only without the hook: a deny verdict takes effect "
        f"in this channel (guarded run exit {guarded_code}). Checked outside "
        f"{project_dir}, in a disposable directory.",
        control_effect,
        guarded_effect,
        control_log,
        guarded_log,
    )


def apply(probes: list[HookProbe], result: LiveResult) -> None:
    """Attach the channel verdict to every handler that could block.

    The verdict is a property of the channel, not of the individual hook: it
    says whether a deny is honoured here at all.
    """
    for probe in probes:
        # Only a handler that demonstrably rejects something can inherit the
        # channel verdict. For the rest the column stays empty on purpose.
        if probe.can_block is not True:
            continue
        setattr(probe, "effective", result.effective)
