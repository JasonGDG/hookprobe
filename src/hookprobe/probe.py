"""Execution-based checks: does the hook start, answer, and could it block?

Static analysis cannot answer these questions. A hook is a separate program on
disk, and every step between "listed in settings.json" and "running" can fail
silently. Claude Code documents the consequence: "a mistyped path in
settings.json leaves the gate silently disabled" and "Claude Code treats exit
code 1 as a non-blocking error and proceeds with the action".

So we run each handler the way the harness would -- same shell split, same
working directory, a realistic payload on stdin -- and observe what happens.
Nothing here touches the network, and nothing is written outside a temporary
directory.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .checks import (
    Finding,
    RunResult,
    build_payload,
    default_timeout,
    run_handler,
)
from .config import HookEntry

# Documented cap for additionalContext, systemMessage, initialUserMessage and
# plain stdout. Above it Claude Code writes the value to a file and substitutes
# a 2,000 character preview -- and does not ask Claude to read that file.
OUTPUT_CAP = 10_000
NEAR_CAP = 8_000

# Events where plain-text stdout is legitimate: Claude Code adds it as context
# that Claude can see. For every other event stdout goes to the debug log, so a
# handler that means to steer anything must emit JSON.
CONTEXT_STDOUT_EVENTS = frozenset(
    {"UserPromptSubmit", "UserPromptExpansion", "SessionStart", "PostModelSwitch"}
)

# Events where a rejection payload is meaningful at all: only here does a probe
# with a dangerous-looking tool call tell us anything about blocking behaviour.
REJECTABLE_EVENTS = frozenset(
    {"PreToolUse", "PostToolUse", "PostToolBatch", "UserPromptSubmit"}
)

# Events whose handlers can block the action at all. A "can block" verdict is
# only meaningful for these; for the rest the column reads n/a.
BLOCKING_EVENTS = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PostToolBatch",
        "UserPromptSubmit",
        "Stop",
        "SubagentStop",
        "PreCompact",
        "SessionStart",
        "SessionEnd",
        "Notification",
        "TaskCreated",
        "TaskCompleted",
        "FileChanged",
        "CwdChanged",
        "WorktreeCreate",
        "WorktreeRemove",
    }
)


@dataclass
class HookProbe:
    """Everything observed about one handler.

    can_block carries three states on purpose: True (a rejection took effect in
    the probe), False (the handler cannot block -- wrong exit code, no answer,
    dead command) and None (not applicable, or nothing to reject in this probe).
    """

    hook: HookEntry
    starts: bool | None = None
    answers: bool | None = None
    can_block: bool | None = None
    findings: list[Finding] = field(default_factory=list)
    neutral: RunResult | None = None
    deny: RunResult | None = None

    @property
    def name(self) -> str:
        return self.hook.name

    @property
    def is_broken(self) -> bool:
        """True when this hook cannot deliver the protection it declares.

        A handler that simply had nothing to reject is not broken -- that case
        arrives as can_block None plus a warning, not as a verdict.
        """
        if self.starts is False:
            return True
        if self.answers is False:
            return True
        if self.can_block is False:
            return True
        return any(f.severity == "critical" for f in self.findings)


def _finding(code: str, hook: str | None, message: str, detail: str = "") -> Finding:
    from . import evidence

    entry = evidence.lookup(code)
    return Finding(
        code=code,
        hook=hook,
        severity=entry.severity,
        message=message or entry.title,
        detail=detail,
    )


INTERPRETERS = frozenset(
    {"sh", "bash", "zsh", "python", "python3", "node", "uv", "uvx", "deno", "ruby"}
)


def _expanded_command(hook: HookEntry, cwd: Path) -> str:
    """The command with ${CLAUDE_*} placeholders resolved, as the harness does."""
    from .checks import _placeholder_values, _substitute_placeholders

    command = hook.command
    if not isinstance(command, str):
        return ""
    try:
        values = _placeholder_values(hook, cwd)
    except Exception:
        return command
    return _substitute_placeholders(command, values)


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _script_path(hook: HookEntry, cwd: Path | None = None) -> Path | None:
    """Best effort: the script a command handler invokes directly."""
    command = _expanded_command(hook, cwd or Path.cwd()) if cwd else hook.command
    if not isinstance(command, str) or not command.strip():
        return None
    if "${" in command:
        # An unresolved placeholder means we cannot judge the path at all.
        return None
    first = _unquote(command.strip().split()[0])
    if first in INTERPRETERS:
        parts = [_unquote(part) for part in command.strip().split()]
        first = parts[1] if len(parts) > 1 else ""
    if not first or first.startswith("-"):
        return None
    candidate = Path(os.path.expanduser(first))
    return candidate if candidate.suffix or candidate.exists() else None


def check_startable(hook: HookEntry, cwd: Path) -> list[Finding]:
    """Static half of P01 -- the cheap reasons a hook never starts."""
    findings: list[Finding] = []
    command = hook.command
    if hook.type != "command" or not isinstance(command, str) or not command.strip():
        return findings

    path = _script_path(hook, cwd)
    if path is None:
        return findings
    command = _expanded_command(hook, cwd) or command

    resolved = path if path.is_absolute() else (cwd / path)
    if not path.is_absolute():
        findings.append(
            _finding(
                "P01.RELATIVE_PATH",
                hook.name,
                f"Relative command path {str(path)!r} depends on the working directory.",
                f"Resolved against {cwd} for this probe.",
            )
        )

    if " " in str(resolved) and not (command.strip().startswith('"') or "'" in command):
        findings.append(
            _finding(
                "P01.SPACE_IN_PATH",
                hook.name,
                "Command path contains a space and is not quoted.",
                f"/bin/sh splits {str(resolved)!r} into separate words (exit 127).",
            )
        )

    if not resolved.exists():
        findings.append(
            _finding(
                "P01.MISSING_FILE",
                hook.name,
                f"Command file does not exist: {resolved}",
                "Claude Code treats the failed launch as non-blocking and proceeds.",
            )
        )
        return findings

    mode = resolved.stat().st_mode
    directly_invoked = _unquote(command.strip().split()[0]) not in INTERPRETERS
    if directly_invoked and not mode & stat.S_IXUSR:
        findings.append(
            _finding(
                "P01.NOT_EXECUTABLE",
                hook.name,
                f"{resolved.name} has no execute bit -- the gate is silently disabled.",
                f"chmod +x {resolved}",
            )
        )

    if directly_invoked:
        try:
            head = resolved.read_bytes()[:256]
        except OSError:
            head = b""
        if head and not head.startswith(b"#!"):
            findings.append(
                _finding(
                    "P01.NO_SHEBANG",
                    hook.name,
                    f"{resolved.name} has no shebang line.",
                    "Without #! the kernel cannot pick an interpreter.",
                )
            )
        elif head.startswith(b"#!"):
            shebang = head.split(b"\n", 1)[0].decode("utf-8", "replace")[2:].strip()
            interpreter = shebang.split()[0] if shebang else ""
            if interpreter.endswith("env"):
                rest = shebang.split()[1:] if len(shebang.split()) > 1 else []
                interpreter = shutil.which(rest[0]) if rest else None
            elif interpreter:
                interpreter = interpreter if Path(interpreter).exists() else None
            if not interpreter:
                findings.append(
                    _finding(
                        "P01.MISSING_INTERPRETER",
                        hook.name,
                        f"Interpreter from the shebang of {resolved.name} was not found.",
                        shebang,
                    )
                )
    return findings


# A process can start and still never reach the hook's own logic: the shell
# refuses to execute the file, the interpreter cannot open the script, an import
# fails. Several of these exit with code 2 -- the very code that means "block" --
# so without this check a hook that never ran is reported as a working guard.
LAUNCH_FAILURE_EXITS = frozenset({126, 127, 49})
LAUNCH_FAILURE_STDERR = (
    "no such file or directory",
    "can't open file",
    "cannot open file",
    "command not found",
    "not found",
    "cannot execute",
    "bad interpreter",
    "permission denied",
    "is a directory",
    "modulenotfounderror",
    "importerror",
    "syntaxerror",
    "no module named",
)


def launch_failed(result: RunResult) -> str | None:
    """Return the reason when the process ran but the hook logic never did."""
    if not result.started or result.timed_out:
        return None
    if result.stdout.strip():
        return None
    stderr = (result.stderr or "").strip()
    if result.exit_code in LAUNCH_FAILURE_EXITS and stderr:
        return stderr.splitlines()[0][:200]
    lowered = stderr.lower()
    if stderr and any(marker in lowered for marker in LAUNCH_FAILURE_STDERR):
        return stderr.splitlines()[0][:200]
    return None


def _decode_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse hook stdout the way the harness does: exactly one JSON object."""
    stripped = text.strip()
    if not stripped:
        return None, "empty"
    if not stripped.startswith("{"):
        brace = stripped.find("{")
        if brace > 0:
            return None, "preamble"
        return None, "not-json"
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError as error:
        if stripped.count("{") > 1:
            return None, "multiple"
        return None, f"invalid: {error.msg}"
    if not isinstance(value, dict):
        return None, "not-object"
    return value, None


def _reads_stdin(hook: HookEntry) -> bool:
    path = _script_path(hook, Path.cwd())
    if path is None or not path.exists():
        return True
    try:
        body = path.read_text("utf-8", "replace")
    except OSError:
        return True
    markers = ("stdin", "read -r", "read ", "input()", "sys.stdin", "cat -")
    return any(marker in body for marker in markers)


def probe_hook(hook: HookEntry, cwd: Path, timeout: float | None = None) -> HookProbe:
    """Run one handler and derive starts / answers / can block."""
    result = HookProbe(hook=hook)
    result.findings.extend(check_startable(hook, cwd))

    if hook.type != "command":
        result.findings.append(
            _finding(
                "P01.NOT_TESTED",
                hook.name,
                f"Handler type {hook.type!r} is not executed by hookprobe.",
            )
        )
        return result

    limit = timeout or default_timeout(hook.event, "command")
    limit = min(float(limit), 20.0)

    neutral = run_handler(hook, build_payload(hook, "neutral"), limit, cwd)
    result.neutral = neutral
    result.starts = bool(neutral.started)

    if not neutral.started:
        result.answers = False
        result.can_block = False if hook.event in BLOCKING_EVENTS else None
        if not any(f.code.startswith("P01.") for f in result.findings):
            result.findings.append(
                _finding(
                    "P01.SPAWN_FAILED",
                    hook.name,
                    "The command could not be started -- the tool call proceeds unguarded.",
                    neutral.spawn_error or "",
                )
            )
        return result

    failure = launch_failed(neutral)
    if failure is not None:
        # The process spawned, but the hook never ran: the gate is open.
        result.starts = False
        result.answers = False
        result.can_block = False if hook.event in BLOCKING_EVENTS else None
        result.findings.append(
            _finding(
                "P01.SPAWN_FAILED",
                hook.name,
                "The command started but the hook itself never ran.",
                failure,
            )
        )
        return result

    if neutral.timed_out:
        result.answers = False
        result.can_block = False if hook.event in BLOCKING_EVENTS else None
        code = "P10.STDIN_BLOCK" if not _reads_stdin(hook) else "P10.PROBE_TIMEOUT"
        result.findings.append(
            _finding(
                code,
                hook.name,
                f"No answer within {limit:.0f}s.",
                "A PreToolUse hook that runs into its timeout does not block the action.",
            )
        )
        return result

    payload, problem = _decode_json(neutral.stdout)
    plain_text_allowed = hook.event in CONTEXT_STDOUT_EVENTS
    if neutral.stdout.strip() and problem and not plain_text_allowed:
        mapping = {
            "preamble": "P09.PREAMBLE",
            "multiple": "P09.MULTIPLE_OBJECTS",
            "not-json": "P09.NOT_JSON",
            "not-object": "P09.NOT_JSON",
            "empty": "P09.NOT_JSON",
        }
        code = mapping.get(problem, "P09.NOT_JSON")
        result.findings.append(
            _finding(
                code,
                hook.name,
                "Output on stdout is not a single JSON object.",
                (neutral.stdout[:120] or "").replace("\n", " "),
            )
        )

    if plain_text_allowed and problem and neutral.stdout.strip():
        result.findings.append(
            Finding(
                code="P09.PLAIN_TEXT",
                hook=hook.name,
                severity="info",
                message="Plain-text stdout is added to the context for this event.",
                detail=f"{len(neutral.stdout)} characters; JSON is only needed for structured control.",
            )
        )

    result.answers = bool(neutral.stdout.strip()) or neutral.exit_code == 0

    for label, value in _capped_strings(payload, neutral.stdout).items():
        if len(value) > OUTPUT_CAP:
            result.findings.append(
                _finding(
                    "P07.OVER_CAP",
                    hook.name,
                    f"{label} is {len(value):,} characters -- above the 10,000 cap.",
                    "Everything past the cap is written to a file that Claude is not asked to read.",
                )
            )
        elif len(value) > NEAR_CAP:
            result.findings.append(
                _finding(
                    "P07.NEAR_CAP",
                    hook.name,
                    f"{label} is {len(value):,} characters -- close to the 10,000 cap.",
                )
            )

    if hook.event in REJECTABLE_EVENTS:
        result.can_block = _probe_blocking(hook, cwd, limit, result)
    else:
        # The event can block, but nothing in a neutral probe would be rejected.
        result.can_block = None

    return result


def _capped_strings(payload: dict[str, Any] | None, stdout: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if payload is None:
        if stdout.strip():
            values["stdout"] = stdout
        return values
    for key in ("additionalContext", "systemMessage", "initialUserMessage"):
        value = payload.get(key)
        if isinstance(value, str):
            values[key] = value
        nested = payload.get("hookSpecificOutput")
        if isinstance(nested, dict) and isinstance(nested.get(key), str):
            values[key] = nested[key]
    return values


def _probe_blocking(
    hook: HookEntry, cwd: Path, limit: float, result: HookProbe
) -> bool | None:
    """Second run with a payload the hook is expected to reject."""
    neutral_blocked = result.neutral is not None and result.neutral.exit_code == 2
    if neutral_blocked:
        result.findings.append(
            _finding(
                "P08.BLOCKS_EVERYTHING",
                hook.name,
                "Rejects even an ordinary tool call -- this blocks the event outright.",
            )
        )
        return True

    deny = run_handler(hook, build_payload(hook, "deny"), limit, cwd)
    result.deny = deny
    if not deny.started or deny.timed_out or launch_failed(deny) is not None:
        return False

    payload, _ = _decode_json(deny.stdout)
    decision = None
    if payload:
        decision = payload.get("permissionDecision") or payload.get("decision")
        nested = payload.get("hookSpecificOutput")
        if decision is None and isinstance(nested, dict):
            decision = nested.get("permissionDecision") or nested.get("decision")

    if deny.exit_code == 2:
        result.findings.append(
            _finding(
                "P08.BLOCKED_AS_EXPECTED",
                hook.name,
                "Rejects with exit code 2 -- the only code that blocks.",
            )
        )
        return True

    if decision in {"deny", "block", "ask"}:
        return True

    if deny.exit_code == 1:
        result.findings.append(
            _finding(
                "P08.EXIT_ONE_ON_REJECT",
                hook.name,
                "Rejects with exit code 1, which Claude Code treats as a non-blocking error.",
                "Only exit code 2 blocks. The action proceeds.",
            )
        )
        return False

    result.findings.append(
        _finding(
            "P08.NO_BLOCK_OBSERVED",
            hook.name,
            "No rejection observed for a payload that should be refused.",
            "Either the hook allows it on purpose, or it never rejects anything.",
        )
    )
    return None
