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

import hashlib
import json
import os
import re
import shlex
import uuid
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
from .checks import OUTPUT_CAP  # noqa: E402

NEAR_CAP = int(OUTPUT_CAP * 0.8)

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

# One canonical table, imported rather than restated. The hand-written copy that
# used to live here listed PostToolUse and SessionStart as blocking, which the
# documented "exit code 2 behavior per event" table contradicts -- a tool that
# reports on other people's configuration cannot afford its own second opinion.
from .checks import BLOCKING_EVENTS  # noqa: E402

# Of those, the ones where a rejection payload is meaningful: a probe with a
# dangerous-looking tool call only tells us something where a tool call exists.
REJECTABLE_EVENTS = frozenset(
    {"PreToolUse", "UserPromptSubmit", "UserPromptExpansion", "PostToolBatch"}
) & BLOCKING_EVENTS


MAX_FINGERPRINT_BYTES = 64 * 1024 * 1024


@dataclass
class Identity:
    """What the configured entry actually points at, on disk, right now.

    Configuration says which command should run; it cannot say whether the file
    at that path is still the file you installed. Reported per entry so a
    swapped or stale artefact under an unchanged config becomes visible by
    comparing two runs (anthropics/claude-code#83952).
    """

    path: str | None = None
    exists: bool = False
    size: int | None = None
    mtime: float | None = None
    sha256: str | None = None
    symlink_to: str | None = None
    note: str = ""


def identify(hook: HookEntry, cwd: Path) -> Identity:
    """Resolve the entry's target and fingerprint it.

    Deliberately uses the same resolution the probe executes with, not a better
    one: a fingerprint found by a route the hook itself does not take would
    describe a file that never runs.
    """
    if hook.type != "command":
        return Identity(note=f"handler type {hook.type!r} has no command target")
    target = _script_path(hook, cwd)
    if target is None:
        command = _expanded_command(hook, cwd) or str(hook.command or "")
        if "${" in command or "$(" in command:
            reason = "command still contains an unresolved placeholder"
        elif any(symbol in command for symbol in ("|", ";", "&&", "||", ">", "<")):
            reason = "shell construct: no single target to fingerprint"
        else:
            reason = "target is a bare name resolved on PATH, not a path"
        return Identity(note=reason)

    resolved = target if target.is_absolute() else (cwd / target)
    identity = Identity(path=str(resolved))
    try:
        link = os.readlink(resolved) if os.path.islink(resolved) else None
    except OSError:
        link = None
    identity.symlink_to = link
    try:
        info = resolved.stat()  # follows symlinks, as execution does
    except OSError as error:
        identity.note = f"cannot stat the target: {type(error).__name__}"
        return identity
    identity.exists = True
    identity.size = info.st_size
    identity.mtime = info.st_mtime
    if info.st_size > MAX_FINGERPRINT_BYTES:
        identity.note = f"{info.st_size} bytes is above the {MAX_FINGERPRINT_BYTES} byte hashing limit"
        return identity
    digest = hashlib.sha256()
    try:
        with open(resolved, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as error:
        identity.note = f"cannot read the target: {type(error).__name__}"
        return identity
    identity.sha256 = digest.hexdigest()
    return identity


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
    identity: Identity | None = None

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
    {
        "sh", "bash", "zsh", "dash", "ksh", "fish",
        "python", "python2", "python3", "py",
        "node", "deno", "bun", "ruby", "perl", "php",
        "uv", "uvx", "npx", "npm", "pnpm", "yarn", "bunx", "poetry", "pipx", "pdm", "env",
        "pwsh", "powershell",
    }
)


# Runners whose first argument is a subcommand, not the script. disler's
# hooks-mastery repo (3.9k stars) configures every hook as `uv run x.py`; taking
# `run` for the script reported all 13 as "file does not exist".
RUNNER_SUBCOMMANDS = {
    "uv": {"run"},
    "deno": {"run"},
    "poetry": {"run"},
    "pipx": {"run"},
    "pdm": {"run"},
    "npm": {"run", "exec", "x"},
    "pnpm": {"run", "exec", "dlx"},
    "yarn": {"run", "exec", "dlx"},
    "bun": {"run", "x"},
}
# `pnpm run lint` names a package.json script, never a file on disk.
SCRIPT_NAME_RUNNERS = frozenset({"npm", "pnpm", "yarn"})
# `npx foo`, `uvx foo`, `pipx run foo`: a package or binary name, never a path.
RUNNER_ARGUMENT_IS_PACKAGE = frozenset({"npx", "uvx", "bunx", "pipx"})


def _basename(token: str) -> str:
    name = Path(token).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def _skip_options(tokens: list[str], index: int) -> int | None:
    """Step over options and NAME=value pairs; None when -m / -c means no file."""
    while index < len(tokens) and (
        tokens[index].startswith("-") or "=" in tokens[index].split("/")[0]
    ):
        if tokens[index] in {"-m", "-c"}:
            return None
        index += 1
    return index


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
    # The harness hands the command to a shell, where $HOME resolves. Without
    # this, "bash $HOME/.claude/hooks/x.sh" is judged as a relative path named
    # "$HOME/..." -- Continuous-Claude-v3 configures 36 hooks that way.
    return os.path.expandvars(_substitute_placeholders(command, values))


def _tokens(command: str) -> list[str]:
    """Split like a shell would, falling back to whitespace on malformed input."""
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _is_interpreter(token: str) -> bool:
    """Recognise interpreters by basename, so /usr/bin/env counts as one."""
    return _basename(token) in INTERPRETERS


def _script_path(hook: HookEntry, cwd: Path | None = None) -> Path | None:
    """Best effort: the script this handler actually runs.

    Walks past interpreters and their options -- `/usr/bin/env python3 -u h.py`
    is three tokens before the script. Returns None when the command is a
    pipeline, a placeholder or anything else we cannot judge honestly; a wrong
    guess here means condemning a healthy hook.
    """
    command = _expanded_command(hook, cwd) if cwd else hook.command
    if not isinstance(command, str) or not command.strip():
        return None
    if "${" in command or "$(" in command:
        return None
    if any(symbol in command for symbol in ("|", ";", "&&", "||", ">", "<")):
        return None

    tokens = _tokens(command)
    if not tokens:
        return None

    index = 0
    while index < len(tokens) and _is_interpreter(tokens[index]):
        runner = _basename(tokens[index])
        index += 1
        next_index = _skip_options(tokens, index)
        if next_index is None:
            return None  # module or inline code: there is no script file
        index = next_index
        if index < len(tokens) and tokens[index] in RUNNER_SUBCOMMANDS.get(runner, ()):
            if runner in SCRIPT_NAME_RUNNERS and tokens[index] == "run":
                return None  # a package.json script name, not a file
            index += 1
            next_index = _skip_options(tokens, index)
            if next_index is None:
                return None
            index = next_index
        if runner in RUNNER_ARGUMENT_IS_PACKAGE:
            return None
        if index < len(tokens) and _is_interpreter(tokens[index]):
            continue  # env python3 -> keep walking
        break

    if index >= len(tokens):
        return None
    candidate = tokens[index]
    if candidate.startswith("-"):
        return None
    if "/" not in candidate and not candidate.startswith("~"):
        # A bare word is looked up on PATH (or inside the runner's environment),
        # never in the working directory. There is no file here to judge; if it
        # is missing, the execution probe sees exit 127 and says so itself.
        return None
    return Path(os.path.expanduser(candidate))


def _interpreter_prefixed(hook: HookEntry, cwd: Path) -> bool:
    """True when the script is handed to an explicit interpreter."""
    command = _expanded_command(hook, cwd)
    tokens = _tokens(command)
    return bool(tokens) and _is_interpreter(tokens[0])


def check_startable(hook: HookEntry, cwd: Path) -> list[Finding]:
    """Static half of P01 -- the cheap reasons a hook never starts."""
    findings: list[Finding] = []
    command = hook.command
    if hook.type != "command" or not isinstance(command, str) or not command.strip():
        return findings

    command = _expanded_command(hook, cwd) or command
    path = _script_path(hook, cwd)
    if path is None:
        # Unresolvable placeholder, pipeline or inline code -- say so instead of
        # guessing. The execution probe still runs.
        if "${" in command:
            findings.append(
                _finding(
                    "P01.UNSET_PLACEHOLDER",
                    hook.name,
                    "Command still contains an unresolved placeholder.",
                    command[:160],
                )
            )
        elif any(sym in command for sym in ("|", ";", "&&", "||", ">", "<")):
            # A shell construct can hide its own failure -- `cmd 2>/dev/null ||
            # exit 0` exits cleanly whether or not cmd exists. From the outside
            # that is indistinguishable from a hook that ran and allowed, so the
            # honest answer is that startability was not verified.
            findings.append(
                _finding(
                    "P01.NOT_TESTED",
                    hook.name,
                    "Shell construct: whether the guard itself ran cannot be verified.",
                    f"{command[:120]} -- a swallowed error looks exactly like a pass.",
                )
            )
        return findings

    resolved = path if path.is_absolute() else (cwd / path)
    directly_invoked = not _interpreter_prefixed(hook, cwd)
    if not path.is_absolute():
        findings.append(
            _finding(
                "P01.RELATIVE_PATH",
                hook.name,
                f"Relative command path {str(path)!r} depends on the working directory.",
                f"Resolved against {cwd} for this probe.",
            )
        )

    # A space only breaks the launch when the shell was not given quotes.
    unquoted = str(path) not in _tokens(command) or (
        " " in str(path) and str(path) in command.split('"')[0].split("'")[0]
    )
    if " " in str(resolved) and unquoted:
        findings.append(
            _finding(
                "P01.SPACE_IN_PATH",
                hook.name,
                "Command path contains a space and is not quoted.",
                f"/bin/sh splits {str(resolved)!r} into separate words (exit 127).",
            )
        )

    if not resolved.exists():
        # A split path is the more useful diagnosis than "file missing".
        remainder = command.split(str(path), 1)[0] if str(path) in command else ""
        rest = command[len(remainder) :] if remainder or True else command
        joined = rest.strip().strip('"').strip("'")
        if " " in joined and (cwd / joined).exists() or Path(joined).exists():
            findings.append(
                _finding(
                    "P01.SPACE_IN_PATH",
                    hook.name,
                    "The command path contains an unquoted space.",
                    f"/bin/sh stops at {str(resolved)!r}; quote the path or escape the space.",
                )
            )
            return findings
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
# refuses to execute the file, the interpreter cannot open the script. Several
# of these exit with code 2 -- the very code that means "block" -- so without
# this check a hook that never ran is reported as a working guard.
#
# The rule has to be narrow. A correct deny hook writes its reason to stderr and
# exits 2, and those reasons legitimately contain words like "permission denied"
# or "not found". Matching on free text would condemn exactly the hooks this
# tool exists to protect. So: shell-level exit codes, or a message that names a
# path from the command itself.
LAUNCH_FAILURE_EXITS = frozenset({126, 127, 49})
_MISSING_SCRIPT = re.compile(
    r"(?:can't open file|cannot open file|No such file or directory|"
    r"Cannot find module|Failed to spawn)"
    r"[^'\"`]*['\"`]?([^'\"`\n]+)['\"`]?",
    re.IGNORECASE,
)
# "/bin/sh: ..." or "python3: ..." at the very start means the shell or the
# interpreter is complaining -- not the hook. A hook's own message does not
# carry that prefix, which is what keeps this apart from a policy refusal.
_SHELL_COMPLAINT = re.compile(
    r"^(?:/[\w./-]*/)?(?:ba|z|da|k|fi)?sh: ", re.IGNORECASE
)
_INTERPRETER_ERROR = re.compile(
    r"^(?:Traceback \(most recent call last\)|"
    r"node:internal/modules/[a-z_/]+:\d+|"
    r"(?:ModuleNotFoundError|ImportError|SyntaxError|IndentationError):)",
    re.MULTILINE,
)


def launch_failed(result: RunResult, command: str = "") -> str | None:
    """Return the reason when the process ran but the hook logic never did.

    Deliberately conservative: when in doubt the handler counts as having run,
    because calling a working guard broken is the worse error.
    """
    if not result.started or result.timed_out:
        return None
    if result.stdout.strip():
        return None
    stderr = (result.stderr or "").strip()
    if not stderr:
        return None

    first = stderr.splitlines()[0][:200]

    # Shell-level: cannot execute (126), not found (127), Windows stub (49).
    if result.exit_code in LAUNCH_FAILURE_EXITS:
        return first

    # The shell itself refused the command line -- a quote it could not match,
    # a syntax error. Exit code varies by shell, so the prefix is the signal.
    if result.exit_code not in (0, None) and _SHELL_COMPLAINT.match(first):
        return first

    # Interpreter could not open the script it was told to run. Only counts when
    # the path it complains about actually appears in the configured command --
    # otherwise it is the hook talking about some file of its own.
    match = _MISSING_SCRIPT.search(stderr)
    if match:
        mentioned = match.group(1).strip().rstrip(":")
        if mentioned and command and mentioned in command:
            return first

    # The interpreter failed before the hook's own code ran.
    if _INTERPRETER_ERROR.search(stderr):
        return first

    return None


def _camouflage(payload: dict[str, Any], cwd: Path) -> dict[str, Any]:
    """Strip the probe's fingerprints.

    The default payload announced itself -- session id "hookprobe-probe-session",
    paths under a hookprobe directory. Any handler could read that and behave
    differently while being measured, which is precisely the case a probe must
    not be blind to. So the ordinary run looks like ordinary work.
    """
    if not isinstance(payload, dict):
        return payload

    def scrub(value: Any) -> Any:
        # The tool name leaks through more than the obvious fields: the canary
        # command and the tool_use_id carried it too. Anything a handler could
        # grep for has to go, or the probe is only measuring handlers that do
        # not bother to look.
        if isinstance(value, str):
            return re.sub(r"hookprobe[-_]?probe|hookprobe", "check", value, flags=re.I)
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    disguised = {key: scrub(item) for key, item in payload.items()}
    disguised["session_id"] = str(uuid.uuid4())
    disguised["cwd"] = str(cwd)
    disguised["transcript_path"] = str(
        Path.home()
        / ".claude"
        / "projects"
        / str(cwd).replace("/", "-")
        / f"{uuid.uuid4()}.jsonl"
    )
    if "tool_use_id" in disguised:
        disguised["tool_use_id"] = "toolu_" + uuid.uuid4().hex[:16]
    return disguised


# What "dangerous" looks like differs per tool. A Write guard reads file_path
# and never sees a shell command, so sending it `rm -rf` proves nothing -- the
# probe would report "no rejection observed" for a guard that works.
DANGEROUS_INPUT: dict[str, dict[str, Any]] = {
    "Write": {"file_path": "~/.ssh/authorized_keys", "content": "ssh-rsa AAAA"},
    "Edit": {
        "file_path": "/etc/sudoers",
        "old_string": "root",
        "new_string": "everyone",
    },
    "NotebookEdit": {"notebook_path": "/etc/hosts", "new_source": "127.0.0.1 evil"},
    "Read": {"file_path": "~/.aws/credentials"},
    "WebFetch": {"url": "http://169.254.169.254/latest/meta-data/"},
    "Bash": {"command": "rm -rf /important/data"},
}


def _tool_shaped_deny(payload: dict[str, Any], matcher: str | None) -> dict[str, Any]:
    """Give the rejection probe a payload the matched tool would actually carry."""
    if not isinstance(payload, dict) or "tool_name" not in payload:
        return payload
    candidates = [
        part.strip()
        for part in re.split(r"[|,]", matcher or "")
        if part.strip() and part.strip() in DANGEROUS_INPUT
    ]
    tool = candidates[0] if candidates else payload.get("tool_name")
    if tool not in DANGEROUS_INPUT:
        return payload
    shaped = dict(payload)
    shaped["tool_name"] = tool
    shaped["tool_input"] = dict(DANGEROUS_INPUT[tool])
    return shaped


def _decoy(payload: dict[str, Any]) -> dict[str, Any]:
    """The opposite: a payload that loudly says 'you are being tested'."""
    if not isinstance(payload, dict):
        return payload
    obvious = dict(payload)
    obvious["session_id"] = "hookprobe-probe-session"
    obvious["transcript_path"] = "/tmp/hookprobe-probe/transcript.jsonl"
    obvious["cwd"] = "/tmp/hookprobe-probe"
    return obvious


def _resolves(word: str, cwd: Path) -> bool:
    """Is this command word something that can actually be executed?"""
    word = word.strip().strip('"').strip("'")
    if not word or word.startswith("-"):
        return True  # an option, not a program
    candidate = Path(os.path.expanduser(word))
    if candidate.is_absolute() or "/" in word:
        return (candidate if candidate.is_absolute() else cwd / candidate).exists()
    return shutil.which(word) is not None


def check_wrapped_commands(hook: HookEntry, cwd: Path) -> list[Finding]:
    """Look inside a shell construct: does the program it wraps exist?

    This is the answer to the hook that hides its own failure. `cmd 2>/dev/null
    || exit 0` exits cleanly whether or not cmd is there, so the run tells us
    nothing -- but resolving the words of the command line does.
    """
    findings: list[Finding] = []
    command = _expanded_command(hook, cwd)
    if not command or "${" in command:
        return findings
    if not any(symbol in command for symbol in ("|", ";", "&&", "||", ">", "<")):
        return findings

    # First word of each segment: that is where a program name sits.
    segments = re.split(r"\|\||&&|\||;|\n", command)
    seen: set[str] = set()
    for segment in segments:
        words = _tokens(segment.strip())
        if not words:
            continue
        program = words[0]
        if program in seen or program in {"exit", "true", "false", "return", "echo", "cd"}:
            continue
        seen.add(program)
        if _is_interpreter(program):
            continue
        if not _resolves(program, cwd):
            findings.append(
                _finding(
                    "P11.WRAPPED_COMMAND_MISSING",
                    hook.name,
                    f"{program!r} is neither on PATH nor on disk.",
                    f"In {command[:120]!r} -- the construct exits cleanly anyway.",
                )
            )
    return findings


DECISION_KEYS = ("permissionDecision", "decision", "continue", "stopReason")


def _verdict(result: RunResult) -> tuple[int | None, str]:
    """What Claude Code would act on: the exit code and the decision fields.

    Not the raw stdout. A Setup hook that quotes the session id and the working
    directory into its additionalContext answers differently every time in
    text and identically in effect; comparing bytes filed it as broken.
    """
    payload, _ = _decode_json(result.stdout)
    decision: dict[str, Any] = {}
    if isinstance(payload, dict):
        for key in DECISION_KEYS:
            if key in payload:
                decision[key] = payload[key]
        nested = payload.get("hookSpecificOutput")
        if isinstance(nested, dict):
            for key in DECISION_KEYS:
                if key in nested:
                    decision[f"hookSpecificOutput.{key}"] = nested[key]
    return result.exit_code, json.dumps(decision, sort_keys=True, default=str)


def _describe(verdict: tuple[int | None, str]) -> str:
    exit_code, decision = verdict
    return f"exit {exit_code}" + (f" {decision}" if decision != "{}" else "")


def check_determinism(hook: HookEntry, cwd: Path, limit: float, first: RunResult) -> list[Finding]:
    """Same payload, twice. A guard that answers differently is not a guard.

    This is what makes a stateful handler visible: we cannot reset someone's
    counter or lock file, but we can notice that it exists. Only the verdict is
    compared, and only where a verdict exists -- a hook that cannot block has
    nothing to be inconsistent about.
    """
    findings: list[Finding] = []
    if not first.started or first.timed_out or hook.event not in BLOCKING_EVENTS:
        return findings
    seen = [_verdict(first)]
    for _ in range(2):
        again = run_handler(
            hook, _camouflage(build_payload(hook, "neutral"), cwd), limit, cwd
        )
        if not again.started or again.timed_out:
            return findings
        seen.append(_verdict(again))
    if len(set(seen)) > 1:
        findings.append(
            _finding(
                "P11.NONDETERMINISTIC",
                hook.name,
                "Identical probes produced different verdicts.",
                " then ".join(_describe(v) for v in seen)
                + ". A verdict that changes on its own cannot be relied on for the run that matters.",
            )
        )
    return findings


def check_payload_sensitivity(
    hook: HookEntry, cwd: Path, limit: float, first: RunResult
) -> list[Finding]:
    """Run the same request once disguised and once obviously as a probe.

    A handler that answers differently is reading fields a decision must not
    depend on -- the session id, the working directory, or a marker that says
    'this is a test'. That covers the backdoor keyed to one session as well as
    the hook that behaves itself only while someone is watching.
    """
    findings: list[Finding] = []
    if not first.started or first.timed_out or hook.event not in BLOCKING_EVENTS:
        return findings
    payload = build_payload(hook, "neutral")
    if not isinstance(payload, dict):
        return findings
    other = run_handler(hook, _decoy(payload), limit, cwd)
    if not other.started or other.timed_out:
        return findings
    before, after = _verdict(first), _verdict(other)
    if before != after:
        findings.append(
            _finding(
                "P11.PAYLOAD_SENSITIVE",
                hook.name,
                "The verdict changed when only session id and cwd changed.",
                f"{_describe(before)} vs {_describe(after)}.",
            )
        )
    return findings


DECIDING_MARKERS = (
    "exit(2)", "exit 2", "sys.exit(2)", "permissiondecision",
    '"deny"', "'deny'", "blocked", "refuse", "reject", "not allowed", "forbidden",
)


def _intends_to_decide(hook: HookEntry, cwd: Path) -> bool:
    """Does this handler look like it wants to decide anything?

    A logging hook that rejects nothing is doing its job. Saying "rejected
    nothing" about it is noise, and noise in a report about silent failures is
    the one thing that gets a tool uninstalled.
    """
    path = _script_path(hook, cwd)
    if path is None:
        return True  # cannot read it, so do not assume it is harmless
    try:
        body = path.read_text("utf-8", "replace").lower()
    except OSError:
        return True
    return any(marker in body for marker in DECIDING_MARKERS)


def _looks_like_decision(text: str) -> bool:
    stripped = text.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return False
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    if not isinstance(value, dict):
        return False
    keys = set(value) | set(
        value.get("hookSpecificOutput", {}) if isinstance(value.get("hookSpecificOutput"), dict) else {}
    )
    return bool(keys & {"permissionDecision", "decision", "continue", "additionalContext"})


def _decision_on_stderr(result: RunResult) -> bool:
    return not result.stdout.strip() and _looks_like_decision(result.stderr)


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
    result.identity = identify(hook, cwd)
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

    # The handler's own timeout is what Claude Code enforces; a hook that
    # answers after its limit is discarded there, so crediting it with blocking
    # would be a false green on the one column that matters.
    declared = hook.timeout if isinstance(hook.timeout, (int, float)) else None
    limit = timeout or declared or default_timeout(hook.event, "command")
    limit = min(float(limit), 20.0)
    if declared and not timeout and float(declared) < limit:
        limit = float(declared)

    neutral = run_handler(hook, _camouflage(build_payload(hook, "neutral"), cwd), limit, cwd)
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

    failure = launch_failed(neutral, _expanded_command(hook, cwd) or str(hook.command or ""))
    if failure is not None:
        # The process spawned, but the hook never ran: the gate is open. The
        # static check may already have named the cause; this is the runtime
        # confirmation, kept as its own finding and folded into the static one
        # by the report.
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

    if neutral.flooded:
        result.findings.append(
            _finding(
                "P07.OUTPUT_FLOOD",
                hook.name,
                "Wrote more than 1 MB; the probe stopped reading and ended it.",
                "Claude Code caps hook output far below that. Whatever the handler "
                "meant to say is lost in the flood.",
            )
        )

    # The handler demonstrably ran. A static "file does not exist" was therefore
    # a wrong guess about which token is the script; keeping it would contradict
    # the table two lines further down. Measurement beats the guess.
    guessed = _script_path(hook, cwd)
    if guessed is not None:
        resolved_guess = guessed if guessed.is_absolute() else cwd / guessed
        if not resolved_guess.exists():
            result.findings = [
                f
                for f in result.findings
                if f.code not in {"P01.MISSING_FILE", "P01.RELATIVE_PATH", "P01.SPACE_IN_PATH"}
            ]

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

    result.findings.extend(check_wrapped_commands(hook, cwd))
    result.findings.extend(check_determinism(hook, cwd, limit, neutral))
    result.findings.extend(check_payload_sensitivity(hook, cwd, limit, neutral))

    if _decision_on_stderr(neutral):
        result.findings.append(
            _finding(
                "P09.DECISION_ON_STDERR",
                hook.name,
                "A decision-shaped object went to stderr; stdout stayed empty.",
                neutral.stderr.strip()[:120],
            )
        )

    payload, problem = _decode_json(neutral.stdout)
    plain_text_allowed = hook.event in CONTEXT_STDOUT_EVENTS
    if neutral.stdout.strip() and problem and not plain_text_allowed:
        mapping = {
            "preamble": "P09.PREAMBLE",
            "multiple": "P09.MULTIPLE_OBJECTS",  # treated as plain text, so the decision is lost
            "not-json": "P09.NOT_JSON",
            "not-object": "P09.NOT_JSON",
            "empty": "P09.NOT_JSON",
        }
        code = mapping.get(problem, "P09.NOT_JSON")
        result.findings.append(
            _finding(
                code,
                hook.name,
                "Output on stdout is not a single JSON object, so no decision reaches Claude."
                if hook.event in REJECTABLE_EVENTS
                else "Output on stdout is not a single JSON object.",
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

    # Exit 2 is the most definite answer a handler can give. Treating it as "no
    # answer" filed the strictest guard in the broken list.
    result.answers = (
        bool(neutral.stdout.strip())
        or neutral.exit_code == 0
        or neutral.exit_code == 2
    )

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

    if hook.async_ is True:
        # The handler may well exit 2 -- it just does not matter. The action it
        # would have controlled has already happened.
        result.can_block = False
        result.findings.append(
            _finding(
                "P08.ASYNC_CANNOT_BLOCK",
                hook.name,
                "Declared async, so its decision fields have no effect.",
                "Runs in the background; the action it would control is already done.",
            )
        )
    elif hook.event in REJECTABLE_EVENTS:
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

    deny_payload = _tool_shaped_deny(build_payload(hook, "deny"), hook.matcher)
    deny = run_handler(hook, _camouflage(deny_payload, cwd), limit, cwd)
    result.deny = deny
    if not deny.started or deny.timed_out:
        result.findings.append(
            _finding(
                "P08.NO_BLOCK_OBSERVED",
                hook.name,
                "The rejection probe did not complete, so blocking is unproven.",
                f"started={deny.started}, timed_out={deny.timed_out}",
            )
        )
        return False
    deny_failure = launch_failed(deny, _expanded_command(hook, cwd) or str(hook.command or ""))
    if deny_failure is not None:
        result.findings.append(
            _finding(
                "P01.SPAWN_FAILED",
                hook.name,
                "The rejection probe started but the hook itself never ran.",
                deny_failure,
            )
        )
        return False

    payload, _ = _decode_json(deny.stdout)
    decision = None
    if payload:
        decision = payload.get("permissionDecision") or payload.get("decision")
        nested = payload.get("hookSpecificOutput")
        if decision is None and isinstance(nested, dict):
            decision = nested.get("permissionDecision") or nested.get("decision")

    if deny.exit_code == 2:
        if decision in {"allow", "approve"}:
            result.findings.append(
                _finding(
                    "P08.CONTRADICTORY_DECISION",
                    hook.name,
                    "Exits 2 while its JSON says allow; the exit code wins.",
                )
            )
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

    if _intends_to_decide(hook, cwd):
        result.findings.append(
            _finding(
                "P08.NO_BLOCK_OBSERVED",
                hook.name,
                "Looks like a guard, but rejected nothing.",
                "Its source mentions a rejection path, yet the probe payload passed.",
            )
        )
    return None
