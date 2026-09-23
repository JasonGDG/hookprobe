"""Documented hook metadata and the Stage 1 static checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import get_close_matches
from enum import Enum
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Configuration, HookEntry, LoadIssue


EVENTS = frozenset(
    {
        "SessionStart",
        "Setup",
        "UserPromptSubmit",
        "UserPromptExpansion",
        "PreToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUse",
        "PostToolUseFailure",
        "PostToolBatch",
        "Notification",
        "MessageDisplay",
        "SubagentStart",
        "SubagentStop",
        "TaskCreated",
        "TaskCompleted",
        "Stop",
        "StopFailure",
        "TeammateIdle",
        "InstructionsLoaded",
        "ConfigChange",
        "CwdChanged",
        "DirectoryAdded",
        "FileChanged",
        "WorktreeCreate",
        "WorktreeRemove",
        "PreCompact",
        "PostCompact",
        "PreModelSwitch",
        "PostModelSwitch",
        "SessionEnd",
        "Elicitation",
        "ElicitationResult",
    }
)

NO_MATCHER_EVENTS = frozenset(
    {
        "UserPromptSubmit",
        "PostToolBatch",
        "Stop",
        "TeammateIdle",
        "TaskCreated",
        "TaskCompleted",
        "WorktreeCreate",
        "WorktreeRemove",
        "MessageDisplay",
        "CwdChanged",
    }
)

TOOL_EVENTS = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PermissionRequest",
        "PermissionDenied",
    }
)

BLOCKING_EVENTS = frozenset(
    {
        "PreToolUse",
        "UserPromptSubmit",
        "UserPromptExpansion",
        "Stop",
        "SubagentStop",
        "TeammateIdle",
        "TaskCreated",
        "TaskCompleted",
        "ConfigChange",
        "PostToolBatch",
        "PreCompact",
        "PreModelSwitch",
        "Elicitation",
        "ElicitationResult",
        "WorktreeCreate",
        "WorktreeRemove",
    }
)
# WorktreeCreate and WorktreeRemove block on every non-zero exit, not only exit 2.

NON_BLOCKING_EVENTS = EVENTS - BLOCKING_EVENTS

NON_BLOCKING_REASON = {
    "PermissionRequest": (
        "Exit code 2 isn't honored for this event; deny through the decision object"
    ),
    "PostToolUse": "Shows stderr to Claude; the tool already ran",
    "PostToolUseFailure": "Shows stderr to Claude; the tool already failed",
    "PermissionDenied": (
        "Exit code and stderr are ignored because the denial already occurred"
    ),
    "SessionStart": "Shows stderr to the user only; the session proceeds",
    "Setup": "Exit code and stderr are ignored",
    "SessionEnd": "Shows stderr to the user only; the session still ends",
    "Notification": "Exit code and stderr are ignored",
    "SubagentStart": "Shows stderr to the user only; the subagent proceeds",
    "CwdChanged": "Shows stderr to the user only; the directory already changed",
    "DirectoryAdded": "Sends stderr to the debug log; the directory is already added",
    "FileChanged": "Shows stderr to the user only",
    "PostCompact": "Shows stderr to the user only; compaction already completed",
    "PostModelSwitch": "Shows stderr to the user only; the model already switched",
    "StopFailure": "Output and exit code are ignored except for terminalSequence",
    "InstructionsLoaded": "Exit code is ignored",
    "MessageDisplay": "The original text is displayed",
}

MATCHER_VALUES = {
    "SessionStart": ("startup", "resume", "clear", "compact", "fork"),
    "Setup": ("init", "maintenance"),
    "SessionEnd": ("clear", "resume", "logout", "prompt_input_exit", "other"),
    "PreCompact": ("manual", "auto"),
    "PostCompact": ("manual", "auto"),
    "ConfigChange": (
        "user_settings",
        "project_settings",
        "local_settings",
        "policy_settings",
        "skills",
    ),
    "DirectoryAdded": ("slash_command", "register_repo_root"),
    "InstructionsLoaded": (
        "session_start",
        "nested_traversal",
        "path_glob_match",
        "include",
        "compact",
    ),
    "StopFailure": (
        "rate_limit",
        "overloaded",
        "authentication_failed",
        "oauth_org_not_allowed",
        "account_on_hold",
        "billing_error",
        "invalid_request",
        "model_not_found",
        "server_error",
        "max_output_tokens",
        "cloud_credential_error",
        "unknown",
    ),
    "Notification": (
        "permission_prompt",
        "idle_prompt",
        "auth_success",
        "elicitation_dialog",
        "elicitation_url_dialog",
        "elicitation_complete",
        "elicitation_response",
        "agent_needs_input",
        "agent_completed",
        "quota_auto_resume_fired",
        "quota_auto_resume_stale",
        "quota_auto_resume_disabled",
    ),
}

# TodoWrite, SlashCommand, KillShell, and BashOutput were omitted because those
# names do not occur in the authoritative hooks reference.
KNOWN_TOOLS = frozenset(
    {
        "Bash",
        "PowerShell",
        "Edit",
        "Write",
        "Read",
        "Glob",
        "Grep",
        "Agent",
        "Workflow",
        "WebFetch",
        "WebSearch",
        "AskUserQuestion",
        "ExitPlanMode",
        "NotebookEdit",
        "Task",
        "Skill",
    }
)

HANDLER_TYPES = ("command", "http", "mcp_tool", "prompt", "agent")

DEFAULT_TIMEOUTS = {
    "command": 600,
    "http": 600,
    "mcp_tool": 600,
    "prompt": 30,
    "agent": 60,
}

OUTPUT_CAP = 10_000
OUTPUT_PREVIEW = 2_000


class MatcherKind(str, Enum):
    """The evaluation path Claude Code selects for a matcher."""

    MATCH_ALL = "match_all"
    EXACT = "exact"
    REGEX = "regex"


@dataclass
class Finding:
    """A concrete problem or relevant fact found by a check."""

    code: str
    hook: str | None
    severity: str
    message: str
    detail: str = ""


_GENERAL_EXACT = re.compile(r"^[A-Za-z0-9_\- ,|]+$")
_NARROW_EXACT = re.compile(r"^[A-Za-z0-9_|]+$")
_NARROW_EVENTS = frozenset({"FileChanged", "StopFailure"})


def default_timeout(event: str, handler_type: str) -> float:
    """Return Claude Code's documented default timeout in seconds."""

    if event == "SessionEnd":
        return 1.5
    if handler_type in {"command", "http", "mcp_tool"}:
        if event in {"UserPromptSubmit", "PreModelSwitch", "PostModelSwitch"}:
            return 30.0
        if event == "MessageDisplay":
            return 10.0
    return float(DEFAULT_TIMEOUTS[handler_type])


def classify_matcher(event: str, matcher: str | None) -> MatcherKind:
    """Classify a matcher using Claude Code's character-set rule."""

    if matcher is None or matcher in {"", "*"}:
        return MatcherKind.MATCH_ALL
    exact_pattern = _NARROW_EXACT if event in _NARROW_EVENTS else _GENERAL_EXACT
    if exact_pattern.fullmatch(matcher):
        return MatcherKind.EXACT
    return MatcherKind.REGEX


def matcher_alternatives(event: str, matcher: str | None) -> list[str]:
    """Return the alternatives of an exact matcher, or an empty list otherwise."""

    if classify_matcher(event, matcher) is not MatcherKind.EXACT:
        return []
    assert matcher is not None
    separator = r"\|" if event in _NARROW_EVENTS else r"[|,]"
    return [part.strip() for part in re.split(separator, matcher)]


def _closest_event(event: str) -> str | None:
    matches = get_close_matches(event, sorted(EVENTS), n=1)
    return matches[0] if matches else None


def _unknown_event_finding(event: str, hook: str | None) -> Finding:
    closest = _closest_event(event)
    message = (
        f'Unknown hook event "{event}"; did you mean "{closest}"?'
        if closest
        else f'Unknown hook event "{event}".'
    )
    return Finding(
        code="P03.UNKNOWN_EVENT",
        hook=hook,
        severity="critical",
        message=message,
        detail=(
            "One schema-invalid matcher entry can silently disable every hook "
            "from the settings file (issue #75071)."
        ),
    )


def _schema_issue_finding(issue: LoadIssue) -> Finding | None:
    code_map = {
        "CONFIG.BAD_MATCHER_TYPE": "P03.BAD_MATCHER_TYPE",
        "CONFIG.BAD_GROUP": "P03.BAD_GROUP",
        "CONFIG.BAD_HANDLER_TYPE": "P03.BAD_HANDLER_TYPE",
        "CONFIG.MISSING_COMMAND": "P03.MISSING_COMMAND",
    }
    code = code_map.get(issue.code)
    if code is None:
        return None
    return Finding(
        code=code,
        hook=None,
        severity="critical",
        message=issue.message,
        detail=(
            "A schema-invalid matcher entry can silently disable every hook "
            "from this settings file (issue #75071)."
        ),
    )


def check_schema(config: Configuration) -> list[Finding]:
    """Run P03 schema checks over a loaded configuration."""

    findings: list[Finding] = []
    unknown_events_with_hooks: set[tuple[object, str]] = set()

    for hook in config.hooks:
        if hook.event not in EVENTS:
            findings.append(_unknown_event_finding(hook.event, hook.name))
            unknown_events_with_hooks.add((hook.source.path, hook.event))

        if hook.matcher is not None and not isinstance(hook.matcher, str):
            findings.append(
                Finding(
                    "P03.BAD_MATCHER_TYPE",
                    hook.name,
                    "critical",
                    f'Matcher for hook "{hook.name}" is not a string.',
                    "A schema-invalid matcher entry can silently disable every hook "
                    "from this settings file (issue #75071).",
                )
            )

        handler_type = hook.handler.get("type")
        if handler_type not in HANDLER_TYPES:
            rendered = "missing" if handler_type is None else repr(handler_type)
            findings.append(
                Finding(
                    "P03.BAD_HANDLER_TYPE",
                    hook.name,
                    "critical",
                    f'Hook "{hook.name}" has handler type {rendered}.',
                )
            )
        elif handler_type == "command" and "command" not in hook.handler:
            findings.append(
                Finding(
                    "P03.MISSING_COMMAND",
                    hook.name,
                    "critical",
                    f'Command hook "{hook.name}" has no command field.',
                )
            )

    for issue in config.issues:
        if issue.code == "CONFIG.UNKNOWN_EVENT":
            if (issue.source.path, issue.detail) not in unknown_events_with_hooks:
                findings.append(_unknown_event_finding(issue.detail, None))
            continue
        finding = _schema_issue_finding(issue)
        if finding is None:
            continue
        if issue.detail and any(hook.name == issue.detail for hook in config.hooks):
            continue
        findings.append(finding)

    for issue in config.sandbox_issues:
        findings.append(
            Finding(
                "P03.SANDBOX_NON_STRING",
                None,
                "critical",
                issue.message,
                "A non-string denyRead or denyWrite entry can silently disable "
                "permission enforcement (issue #92365).",
            )
        )

    if config.disable_all_hooks:
        findings.append(
            Finding(
                "P03.HOOKS_DISABLED",
                None,
                "critical",
                'The effective configuration contains "disableAllHooks": true, so every hook is off.',
            )
        )

    return findings


def _complete_mcp_tool_name(value: str) -> bool:
    if not value.startswith("mcp__"):
        return False
    server, separator, tool = value[5:].partition("__")
    return bool(server and separator and tool)


def check_matcher(hook: HookEntry) -> list[Finding]:
    """Run P04 matcher checks for one hook."""

    findings: list[Finding] = []
    matcher = hook.matcher

    if matcher is not None and hook.event in NO_MATCHER_EVENTS:
        findings.append(
            Finding(
                "P04.MATCHER_IGNORED",
                hook.name,
                "warning",
                f'Matcher {matcher!r} is silently ignored on {hook.event}; the hook fires on every occurrence.',
            )
        )

    if "if" in hook.handler:
        if hook.event not in TOOL_EVENTS:
            findings.append(
                Finding(
                    "P04.IF_ON_NON_TOOL_EVENT",
                    hook.name,
                    "critical",
                    f'Hook "{hook.name}" sets if on non-tool event {hook.event}, so it never runs.',
                )
            )
        findings.append(
            Finding(
                "P04.IF_BEST_EFFORT",
                hook.name,
                "info",
                f'Hook "{hook.name}" uses the best-effort if filter; do not rely on it for a hard allow or deny.',
                "The documented warning is supported by issues #95819 and #84632.",
            )
        )

    if not isinstance(matcher, str):
        return findings

    kind = classify_matcher(hook.event, matcher)
    alternatives = matcher_alternatives(hook.event, matcher)

    if hook.event in _NARROW_EVENTS and "," in matcher:
        findings.append(
            Finding(
                "P04.NARROW_EXACT_SET",
                hook.name,
                "warning",
                f'Matcher {matcher!r} contains a comma, but {hook.event} only separates exact alternatives with "|".',
                "A comma keeps this matcher on the unanchored regular-expression path.",
            )
        )

    compiled: re.Pattern[str] | None = None
    if kind is MatcherKind.REGEX:
        try:
            compiled = re.compile(matcher)
        except re.error as error:
            findings.append(
                Finding(
                    "P04.BAD_REGEX",
                    hook.name,
                    "critical",
                    f'Matcher {matcher!r} is not a valid regular expression: {error}.',
                    "Claude Code uses JavaScript regular expressions, so Python compilation "
                    "is an approximation of the runtime check.",
                )
            )

    if hook.event in TOOL_EVENTS and kind is MatcherKind.EXACT:
        useful = any(
            value in KNOWN_TOOLS or _complete_mcp_tool_name(value)
            for value in alternatives
        )
        if not useful:
            findings.append(
                Finding(
                    "P04.EXACT_NO_MATCH",
                    hook.name,
                    "critical",
                    f'Exact tool matcher {matcher!r} contains no documented tool name.',
                    "Tool names are case-sensitive, and an MCP server prefix such as "
                    '"mcp__memory" needs ".*" to match its tools.',
                )
            )

    if hook.event in TOOL_EVENTS and compiled is not None:
        extra_hits = sorted(
            tool
            for tool in KNOWN_TOOLS
            if compiled.search(tool) and compiled.fullmatch(tool) is None
        )
        if extra_hits:
            findings.append(
                Finding(
                    "P04.UNANCHORED_REGEX",
                    hook.name,
                    "warning",
                    f'Unanchored matcher {matcher!r} also matches longer tool names: {", ".join(extra_hits)}.',
                    "Claude Code tests regular expressions at any position; for example, "
                    'Edit.* also matches NotebookEdit, while ^Edit$ matches only Edit.',
                )
            )

    allowed_values = MATCHER_VALUES.get(hook.event)
    if allowed_values is not None:
        if kind is MatcherKind.EXACT:
            unknown_values = [value for value in alternatives if value not in allowed_values]
            if unknown_values:
                findings.append(
                    Finding(
                        "P04.UNKNOWN_MATCHER_VALUE",
                        hook.name,
                        "critical",
                        f'Matcher {matcher!r} contains undocumented {hook.event} value(s): {", ".join(repr(value) for value in unknown_values)}.',
                    )
                )
        elif compiled is not None and not any(
            compiled.search(value) for value in allowed_values
        ):
            findings.append(
                Finding(
                    "P04.UNKNOWN_MATCHER_VALUE",
                    hook.name,
                    "critical",
                    f'Matcher {matcher!r} matches no documented value for {hook.event}.',
                )
            )

    return findings


def check_location(hook: HookEntry) -> list[Finding]:
    """Run P05 source-location checks for one hook."""

    findings: list[Finding] = []
    source_kind = hook.source.kind

    if source_kind == "agent-frontmatter":
        findings.append(
            Finding(
                "P05.AGENT_FRONTMATTER",
                hook.name,
                "critical",
                f'Hook "{hook.name}" is declared in agent frontmatter, where PreToolUse hooks are reported not to fire.',
                "The identical hook in settings.json did fire in issue #95650; see also issue #39468.",
            )
        )

    if source_kind == "skill-frontmatter" and hook.once is True:
        findings.append(
            Finding(
                "P05.SKILL_ONCE",
                hook.name,
                "warning",
                f'Hook "{hook.name}" sets once in skill frontmatter, but once is reported to be ignored there.',
                "Issue #95280 observed the hook firing repeatedly after a successful run.",
            )
        )

    settings_kinds = {"managed", "user", "project", "local", "explicit"}
    if hook.once is True and source_kind in settings_kinds | {"agent-frontmatter"}:
        findings.append(
            Finding(
                "P05.ONCE_IGNORED",
                hook.name,
                "warning",
                f'Hook "{hook.name}" sets once in {source_kind}, where Claude Code ignores it.',
                "The hooks reference says once is ignored in settings files and agent frontmatter.",
            )
        )

    if source_kind == "plugin":
        findings.append(
            Finding(
                "P05.PLUGIN_SOURCE",
                hook.name,
                "info",
                f'Hook "{hook.name}" comes from a plugin, where enforcement has reported source-specific failures.',
                "Issue #92675 reports unenforced plugin-native PreToolUse hooks, and "
                "issue #20432 reports plugin installation dropping executable bits.",
            )
        )

    return findings


# These are data only: hookprobe passes them to a hook but never executes the
# described tool calls. Even a hook that mistakenly executes one runs in the
# empty probe directory; the removal target and .env file do not exist, the
# reserved .invalid host does not resolve, and hookprobe never creates either
# /etc target.
DENY_PROBES: tuple[dict[str, Any], ...] = (
    {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf ./hookprobe-canary-does-not-exist"},
    },
    {"tool_name": "Bash", "tool_input": {"command": "cat .env"}},
    {
        "tool_name": "Bash",
        "tool_input": {
            "command": "curl -s https://hookprobe.invalid/canary"
        },
    },
    {"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}},
    {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/etc/hookprobe-canary.conf",
            "content": "hookprobe deny probe",
        },
    },
)

_MATCHER_FIELD = {
    "SessionStart": "source",
    "Setup": "trigger",
    "SessionEnd": "reason",
    "Notification": "notification_type",
    "SubagentStart": "agent_type",
    "SubagentStop": "agent_type",
    "PreCompact": "trigger",
    "PostCompact": "trigger",
    "PreModelSwitch": "to_model",
    "PostModelSwitch": "to_model",
    "ConfigChange": "source",
    "DirectoryAdded": "source",
    "FileChanged": "file_path",
    "StopFailure": "error",
    "InstructionsLoaded": "load_reason",
    "UserPromptExpansion": "command_name",
    "Elicitation": "mcp_server_name",
    "ElicitationResult": "mcp_server_name",
}

_MATCHER_DEFAULT = {
    "SessionStart": "startup",
    "Setup": "init",
    "SessionEnd": "other",
    "Notification": "permission_prompt",
    "SubagentStart": "Explore",
    "SubagentStop": "Explore",
    "PreCompact": "manual",
    "PostCompact": "manual",
    "PreModelSwitch": "claude-opus-5",
    "PostModelSwitch": "claude-opus-5",
    "ConfigChange": "project_settings",
    "DirectoryAdded": "slash_command",
    "FileChanged": "hookprobe-probe.txt",
    "StopFailure": "unknown",
    "InstructionsLoaded": "session_start",
    "UserPromptExpansion": "hookprobe-probe",
    "Elicitation": "hookprobe-probe-server",
    "ElicitationResult": "hookprobe-probe-server",
}

_TOOL_SAMPLE_INPUTS: dict[str, dict[str, Any]] = {
    "Bash": {"command": "echo hookprobe"},
    "PowerShell": {"command": "Write-Output hookprobe"},
    "Edit": {
        "file_path": "/tmp/hookprobe-probe.txt",
        "old_string": "before",
        "new_string": "after",
        "replace_all": False,
    },
    "Write": {
        "file_path": "/tmp/hookprobe-probe.txt",
        "content": "hookprobe",
    },
    "Read": {"file_path": "/tmp/hookprobe-probe.txt"},
    "Glob": {"pattern": "hookprobe-*", "path": "/tmp"},
    "Grep": {"pattern": "hookprobe", "path": "/tmp"},
    "Agent": {
        "prompt": "Return without taking action.",
        "description": "hookprobe neutral probe",
        "subagent_type": "Explore",
    },
    "Workflow": {"name": "hookprobe-neutral"},
    "WebFetch": {
        "url": "https://hookprobe.invalid/neutral",
        "prompt": "Return without taking action.",
    },
    "WebSearch": {"query": "hookprobe neutral probe"},
    "AskUserQuestion": {"questions": []},
    "ExitPlanMode": {
        "plan": "No changes.",
        "planFilePath": "/tmp/hookprobe-plan.md",
    },
    "NotebookEdit": {
        "notebook_path": "/tmp/hookprobe-probe.ipynb",
        "new_source": "",
    },
    "Task": {"description": "hookprobe neutral probe"},
    "Skill": {"skill": "hookprobe-neutral"},
}


def _event_and_hook(event: Any) -> tuple[str, HookEntry | None]:
    if isinstance(event, str):
        return event, None
    return str(event.event), event


def _matcher_candidates(event: str) -> list[str]:
    if event in TOOL_EVENTS:
        return sorted(KNOWN_TOOLS)
    values = MATCHER_VALUES.get(event)
    if values is not None:
        return list(values)
    default = _MATCHER_DEFAULT.get(event)
    return [default] if default is not None else []


def _matching_value(hook: HookEntry) -> tuple[str, bool]:
    default = "Bash" if hook.event in TOOL_EVENTS else _MATCHER_DEFAULT.get(
        hook.event, "hookprobe-probe"
    )
    matcher = hook.matcher
    kind = classify_matcher(hook.event, matcher)
    if kind is MatcherKind.MATCH_ALL:
        return default, True
    if kind is MatcherKind.EXACT:
        alternatives = matcher_alternatives(hook.event, matcher)
        return (alternatives[0], True) if alternatives else (default, False)
    assert isinstance(matcher, str)
    try:
        compiled = re.compile(matcher)
    except re.error:
        return default, False
    for candidate in _matcher_candidates(hook.event):
        if compiled.search(candidate):
            return candidate, True
    return default, False


def _deny_probe(tool_name: str, hook: HookEntry | None) -> dict[str, Any]:
    candidates = [probe for probe in DENY_PROBES if probe["tool_name"] == tool_name]
    if tool_name == "Bash" and candidates:
        condition = str(hook.if_ if hook is not None else "").lower()
        if "cat" in condition:
            candidates = [candidates[1]]
        elif "curl" in condition:
            candidates = [candidates[2]]
    if candidates:
        selected = candidates[0]
        return {
            "tool_name": selected["tool_name"],
            "tool_input": dict(selected["tool_input"]),
        }
    return {
        "tool_name": tool_name,
        "tool_input": {
            "command": "rm -rf ./hookprobe-canary-does-not-exist"
        },
    }


def build_payload(event: str | HookEntry, variant: str = "neutral") -> dict[str, Any]:
    """Build a documented synthetic stdin object for one hook event."""

    if variant not in {"neutral", "deny"}:
        raise ValueError(f"unknown payload variant: {variant}")
    event_name, hook = _event_and_hook(event)
    probe_root = Path(tempfile.gettempdir()) / "hookprobe-probe"
    payload: dict[str, Any] = {
        "session_id": "hookprobe-probe-session",
        "transcript_path": os.fspath(probe_root / "transcript.jsonl"),
        "cwd": os.fspath(probe_root),
        "permission_mode": "default",
        "hook_event_name": event_name,
    }

    matched = (
        _matching_value(hook)[0]
        if hook is not None
        else ("Bash" if event_name in TOOL_EVENTS else _MATCHER_DEFAULT.get(event_name))
    )

    if event_name in TOOL_EVENTS:
        tool_name = matched or "Bash"
        if variant == "deny":
            payload.update(_deny_probe(tool_name, hook))
        else:
            payload["tool_name"] = tool_name
            payload["tool_input"] = dict(
                _TOOL_SAMPLE_INPUTS.get(tool_name, {"command": "echo hookprobe"})
            )
        payload["tool_use_id"] = "toolu_hookprobe_probe"
        if event_name == "PermissionRequest":
            payload["permission_suggestions"] = []
        elif event_name == "PermissionDenied":
            payload["reason"] = "[Hookprobe Probe]"
        elif event_name == "PostToolUse":
            payload["tool_response"] = {"status": "ok"}
            payload["duration_ms"] = 1
        elif event_name == "PostToolUseFailure":
            payload["error"] = "Exit code 1\nhookprobe synthetic failure"
            payload["is_interrupt"] = False
            payload["duration_ms"] = 1
        return payload

    if event_name == "SessionStart":
        payload.update(source=matched or "startup", model="claude-probe-model")
    elif event_name == "Setup":
        payload["trigger"] = matched or "init"
    elif event_name == "UserPromptSubmit":
        payload["prompt"] = "hookprobe neutral probe"
    elif event_name == "UserPromptExpansion":
        command_name = matched or "hookprobe-probe"
        payload.update(
            expansion_type="slash_command",
            command_name=command_name,
            command_args="",
            command_source="project",
            prompt=f"/{command_name}",
        )
    elif event_name == "MessageDisplay":
        payload.update(
            turn_id="hookprobe-turn",
            message_id="hookprobe-message",
            index=0,
            final=True,
            delta="hookprobe neutral message\n",
        )
    elif event_name == "PostToolBatch":
        payload["tool_calls"] = [
            {
                "tool_name": "Bash",
                "tool_input": {"command": "echo hookprobe"},
                "tool_use_id": "toolu_hookprobe_probe",
                "tool_response": "hookprobe",
            }
        ]
    elif event_name == "Notification":
        payload.update(
            message="Hookprobe notification probe",
            title="Hookprobe",
            notification_type=matched or "permission_prompt",
        )
    elif event_name in {"SubagentStart", "SubagentStop"}:
        payload.update(
            agent_id="agent-hookprobe-probe",
            agent_type=matched or "Explore",
        )
        if event_name == "SubagentStop":
            payload.update(
                stop_hook_active=False,
                agent_transcript_path=os.fspath(probe_root / "agent-transcript.jsonl"),
                last_assistant_message="Hookprobe synthetic response.",
                background_tasks=[],
                session_crons=[],
            )
    elif event_name in {"TaskCreated", "TaskCompleted"}:
        payload.update(
            task_id="task-hookprobe-probe",
            task_subject="Hookprobe synthetic task",
            task_description="A harmless synthetic task.",
            teammate_name="hookprobe",
            team_name="hookprobe-probe-team",
        )
    elif event_name == "Stop":
        payload.update(
            stop_hook_active=False,
            last_assistant_message="Hookprobe synthetic response.",
            background_tasks=[],
            session_crons=[],
        )
    elif event_name == "StopFailure":
        payload.update(
            error=matched or "unknown",
            error_details="Hookprobe synthetic API error.",
            last_assistant_message="API Error: hookprobe synthetic failure",
        )
    elif event_name == "TeammateIdle":
        payload.update(
            teammate_name="hookprobe", team_name="hookprobe-probe-team"
        )
    elif event_name == "InstructionsLoaded":
        payload.update(
            file_path=os.fspath(probe_root / "CLAUDE.md"),
            memory_type="Project",
            load_reason=matched or "session_start",
        )
    elif event_name == "ConfigChange":
        payload.update(
            source=matched or "project_settings",
            file_path=os.fspath(probe_root / ".claude" / "settings.json"),
        )
    elif event_name == "CwdChanged":
        payload.update(
            old_cwd=os.fspath(probe_root / "old"),
            new_cwd=os.fspath(probe_root),
        )
    elif event_name == "DirectoryAdded":
        payload.update(
            directory=os.fspath(probe_root / "added"),
            source=matched or "slash_command",
        )
    elif event_name == "FileChanged":
        filename = Path(str(matched or "hookprobe-probe.txt")).name
        payload.update(file_path=os.fspath(probe_root / filename), event="change")
    elif event_name == "WorktreeCreate":
        payload["name"] = "hookprobe-probe-worktree"
    elif event_name == "WorktreeRemove":
        payload["worktree_path"] = os.fspath(probe_root / "worktree")
    elif event_name == "PreCompact":
        payload.update(trigger=matched or "manual", custom_instructions=None)
    elif event_name == "PostCompact":
        payload.update(
            trigger=matched or "manual",
            compact_summary="Hookprobe synthetic compact summary.",
        )
    elif event_name in {"PreModelSwitch", "PostModelSwitch"}:
        payload.update(
            from_model="claude-sonnet-probe",
            to_model=matched or "claude-opus-5",
            requested_model="opus",
            source="command" if event_name == "PreModelSwitch" else "auto",
            context_tokens=0,
            prompt_cache_warm=False,
            cache_ttl="5m",
            estimated_cache_write_usd=0.0,
            pricing="catalog",
        )
    elif event_name == "SessionEnd":
        payload["reason"] = matched or "other"
    elif event_name == "Elicitation":
        payload.update(
            mcp_server_name=matched or "hookprobe-probe-server",
            message="Hookprobe synthetic elicitation.",
            mode="form",
            elicitation_id="elicit-hookprobe-probe",
            requested_schema={"type": "object", "properties": {}},
        )
    elif event_name == "ElicitationResult":
        payload.update(
            mcp_server_name=matched or "hookprobe-probe-server",
            action="accept",
            content={},
            mode="form",
            elicitation_id="elicit-hookprobe-probe",
        )
    return payload


@dataclass
class RunResult:
    """Captured result of one isolated hook command invocation."""

    started: bool
    exit_code: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool
    spawn_error: str | None
    argv: list[str] | str


_ACTIVE_PROJECT_DIR: Path | None = None
_ACTIVE_PROBE_DIR: Path | None = None
_PATH_PLACEHOLDERS = (
    "CLAUDE_PROJECT_DIR",
    "CLAUDE_PLUGIN_ROOT",
    "CLAUDE_PLUGIN_DATA",
)


def _inferred_project_dir(hook: HookEntry) -> Path:
    if _ACTIVE_PROJECT_DIR is not None:
        return _ACTIVE_PROJECT_DIR
    if hook.source.kind in {"project", "local"} and hook.source.path.parent.name == ".claude":
        return hook.source.path.parent.parent
    if hook.source.kind == "explicit":
        return hook.source.path.parent
    return Path.cwd()


def _placeholder_values(hook: HookEntry, cwd: Path) -> dict[str, str | None]:
    source = hook.source
    plugin_root: Path | None = None
    if source.kind == "plugin":
        plugin_root = source.path.parent.parent
    elif (
        source.kind == "explicit"
        and source.path.name == "hooks.json"
        and source.path.parent.name == "hooks"
    ):
        # `--settings some-plugin/hooks/hooks.json`: the plugin layout is fixed,
        # so the root is two levels up. Without this every plugin hook probed
        # by file fails on ${CLAUDE_PLUGIN_ROOT} and is called broken.
        plugin_root = source.path.parent.parent
    return {
        "CLAUDE_PROJECT_DIR": os.fspath(_inferred_project_dir(hook)),
        "CLAUDE_PLUGIN_ROOT": os.fspath(plugin_root) if plugin_root else None,
        "CLAUDE_PLUGIN_DATA": (
            os.fspath(cwd / "plugin-data") if plugin_root else None
        ),
    }


def _substitute_placeholders(text: str, values: dict[str, str | None]) -> str:
    result = text
    for name, value in values.items():
        if value is not None:
            result = result.replace("${" + name + "}", value)
    return result


def _shell_argv(shell: Any, command: str) -> tuple[list[str] | None, str | None]:
    if shell == "powershell":
        executable = shutil.which("pwsh") or shutil.which("powershell")
        if executable is None:
            return None, 'requested shell interpreter "powershell" was not found on PATH'
        return [executable, "-NoProfile", "-NonInteractive", "-Command", command], None
    if shell not in {None, "bash"}:
        return None, f"unsupported shell value: {shell!r}"
    if shell == "bash":
        executable = shutil.which("bash")
        if executable is None:
            return None, 'requested shell interpreter "bash" was not found on PATH'
        return [executable, "-c", command], None
    if sys.platform == "win32":
        executable = shutil.which("bash") or shutil.which("powershell")
        if executable is None:
            return None, "neither Git Bash nor PowerShell was found on PATH"
        if Path(executable).stem.lower().startswith("power"):
            return [executable, "-NoProfile", "-NonInteractive", "-Command", command], None
        return [executable, "-c", command], None
    return ["/bin/sh", "-c", command], None


def _not_run(argv: list[str] | str, error: str) -> RunResult:
    return RunResult(False, None, "", "", 0.0, False, error, argv)


def run_handler(
    hook: HookEntry,
    payload: dict[str, Any],
    timeout: float,
    cwd: Path,
    stdin_mode: str = "payload",
) -> RunResult:
    """Execute a command handler with the same shell/exec split as Claude Code."""

    started_at = time.monotonic()
    argv: list[str] | str = str(hook.command or "")
    process: subprocess.Popen[str] | None = None
    try:
        if hook.type != "command":
            return _not_run(argv, "not executed by hookprobe")
        if stdin_mode not in {"payload", "empty"}:
            return _not_run(argv, f"unsupported stdin mode: {stdin_mode!r}")
        if not isinstance(hook.command, str) or not hook.command:
            return _not_run(argv, "missing command")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            return _not_run(argv, f"invalid probe timeout: {timeout!r}")

        workdir = Path(cwd)
        values = _placeholder_values(hook, workdir)
        environment = os.environ.copy()
        for name, value in values.items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value

        command = _substitute_placeholders(hook.command, values)
        if "args" in hook.handler:
            if not isinstance(hook.args, list) or not all(
                isinstance(argument, str) for argument in hook.args
            ):
                return _not_run(command, "exec-form args must be a list of strings")
            executable = command
            if not os.path.isabs(executable) and not any(
                separator in executable for separator in (os.sep, os.altsep) if separator
            ):
                resolved = shutil.which(executable, path=environment.get("PATH"))
                if resolved is None:
                    return _not_run(command, f'executable "{executable}" was not found on PATH')
                executable = resolved
            argv = [executable] + [
                _substitute_placeholders(argument, values) for argument in hook.args
            ]
        else:
            shell_argv, shell_error = _shell_argv(hook.shell, command)
            if shell_argv is None:
                return _not_run(command, shell_error or "shell is unavailable")
            argv = shell_argv

        popen_options: dict[str, Any] = {
            "cwd": os.fspath(workdir),
            "env": environment,
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if sys.platform == "win32":
            popen_options["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_options["start_new_session"] = True

        process = subprocess.Popen(argv, **popen_options)
        stdin_text = json.dumps(payload, separators=(",", ":")) if stdin_mode == "payload" else ""
        try:
            stdout, stderr = process.communicate(input=stdin_text, timeout=float(timeout))
            return RunResult(
                True,
                process.returncode,
                stdout,
                stderr,
                time.monotonic() - started_at,
                False,
                None,
                argv,
            )
        except subprocess.TimeoutExpired:
            try:
                if sys.platform == "win32":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                stdout, stderr = process.communicate(timeout=1.0)
            except Exception:
                stdout, stderr = "", ""
            return RunResult(
                True,
                process.returncode,
                stdout,
                stderr,
                time.monotonic() - started_at,
                True,
                None,
                argv,
            )
    except Exception as error:
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.communicate(timeout=1.0)
            except Exception:
                pass
        return RunResult(
            process is not None,
            process.returncode if process is not None else None,
            "",
            "",
            time.monotonic() - started_at,
            False,
            f"{type(error).__name__}: {error}",
            argv,
        )
