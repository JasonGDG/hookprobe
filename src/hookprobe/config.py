"""Discover, parse, and merge Claude Code hook configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable


@dataclass(frozen=True)
class Source:
    """A configuration file and the scope from which it was loaded."""

    kind: str
    path: Path
    label: str


@dataclass
class HookEntry:
    """One handler inside one matcher group."""

    name: str
    event: str
    matcher: str | None
    group_index: int
    handler_index: int
    handler: dict[str, Any]
    source: Source

    @property
    def type(self) -> Any:
        return self.handler.get("type")

    @property
    def command(self) -> Any:
        return self.handler.get("command")

    @property
    def args(self) -> Any:
        return self.handler.get("args")

    @property
    def timeout(self) -> Any:
        return self.handler.get("timeout")

    @property
    def if_(self) -> Any:
        return self.handler.get("if")

    @property
    def once(self) -> Any:
        return self.handler.get("once")

    @property
    def async_(self) -> Any:
        return self.handler.get("async")

    @property
    def shell(self) -> Any:
        return self.handler.get("shell")


@dataclass
class LoadIssue:
    """A problem encountered while loading configuration."""

    code: str
    source: Source
    message: str
    detail: str = ""


@dataclass
class Configuration:
    """The merged hook configuration and all recoverable load problems."""

    hooks: list[HookEntry]
    sources: list[Source]
    issues: list[LoadIssue]
    disable_all_hooks: bool
    project_dir: Path
    sandbox_issues: list[LoadIssue] = field(default_factory=list)


class _FrontmatterError(ValueError):
    """Raised when the deliberately narrow frontmatter parser cannot proceed."""


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    content: str
    number: int


_YAML_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):(.*)$")
_INTEGER = re.compile(r"^[+-]?[0-9]+$")
_MATCHER_SLUG = re.compile(r"[^A-Za-z0-9_.-]")
_PLUGIN_MAX_DEPTH = 6
_PLUGIN_MAX_FILES = 200
_PLUGIN_MAX_DIRECTORIES = 200


def _mapping_parts(content: str, line_number: int) -> tuple[str, str]:
    match = _YAML_KEY.fullmatch(content)
    if match is None:
        raise _FrontmatterError(
            f"line {line_number} is not a supported mapping entry"
        )
    return match.group(1), match.group(2).strip()


def _looks_like_mapping(content: str) -> bool:
    return _YAML_KEY.fullmatch(content) is not None


def _yaml_lines(block: str) -> list[_YamlLine]:
    parsed: list[_YamlLine] = []
    for number, raw_line in enumerate(block.splitlines(), start=2):
        if "\t" in raw_line:
            raise _FrontmatterError(f"line {number} contains a tab")
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        content = raw_line[indent:].rstrip()
        if content.startswith("- ") and _looks_like_mapping(content[2:].strip()):
            parsed.append(_YamlLine(indent, "-", number))
            parsed.append(_YamlLine(indent + 2, content[2:].strip(), number))
        else:
            parsed.append(_YamlLine(indent, content, number))
    return parsed


def _single_quoted(value: str, line_number: int) -> str:
    body = value[1:-1]
    result: list[str] = []
    index = 0
    while index < len(body):
        if body[index] != "'":
            result.append(body[index])
            index += 1
            continue
        if index + 1 >= len(body) or body[index + 1] != "'":
            raise _FrontmatterError(
                f"line {line_number} contains an invalid single-quoted scalar"
            )
        result.append("'")
        index += 2
    return "".join(result)


def _scalar(value: str, line_number: int) -> Any:
    if not value:
        raise _FrontmatterError(f"line {line_number} contains an empty scalar")
    if value.startswith('"'):
        if not value.endswith('"'):
            raise _FrontmatterError(
                f"line {line_number} contains an unterminated double-quoted scalar"
            )
        try:
            result = json.loads(value)
        except json.JSONDecodeError as error:
            raise _FrontmatterError(
                f"line {line_number} contains an invalid double-quoted scalar"
            ) from error
        if not isinstance(result, str):
            raise _FrontmatterError(
                f"line {line_number} does not contain a string scalar"
            )
        return result
    if value.startswith("'"):
        if not value.endswith("'"):
            raise _FrontmatterError(
                f"line {line_number} contains an unterminated single-quoted scalar"
            )
        return _single_quoted(value, line_number)
    if value != "*" and value[0] in "[{&*!>|":
        raise _FrontmatterError(
            f"line {line_number} uses unsupported YAML syntax"
        )
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    if _INTEGER.fullmatch(value):
        return int(value)
    return value


def _parse_yaml_block(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[Any, int]:
    if index >= len(lines) or lines[index].indent != indent:
        raise _FrontmatterError("frontmatter indentation is inconsistent")
    if lines[index].content == "-" or lines[index].content.startswith("- "):
        return _parse_yaml_sequence(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise _FrontmatterError(
                f"line {line.number} has unexpected indentation"
            )
        if line.content == "-" or line.content.startswith("- "):
            break
        key, raw_value = _mapping_parts(line.content, line.number)
        if key in result:
            raise _FrontmatterError(
                f'line {line.number} repeats mapping key "{key}"'
            )
        index += 1
        if raw_value:
            result[key] = _scalar(raw_value, line.number)
        elif index < len(lines) and lines[index].indent > indent:
            result[key], index = _parse_yaml_block(
                lines, index, lines[index].indent
            )
        else:
            result[key] = None
    return result, index


def _parse_yaml_sequence(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise _FrontmatterError(
                f"line {line.number} has unexpected indentation"
            )
        if line.content == "-":
            index += 1
            if index >= len(lines) or lines[index].indent <= indent:
                raise _FrontmatterError(
                    f"line {line.number} has an empty sequence item"
                )
            item, index = _parse_yaml_block(lines, index, lines[index].indent)
            result.append(item)
            continue
        if line.content.startswith("- "):
            result.append(_scalar(line.content[2:].strip(), line.number))
            index += 1
            continue
        break
    return result, index


def _parse_frontmatter(text: str) -> dict[str, Any] | None:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    closing = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing is None:
        raise _FrontmatterError("the opening delimiter has no closing delimiter")
    block = "\n".join(lines[1:closing])
    yaml_lines = _yaml_lines(block)
    if not yaml_lines:
        return {}
    if yaml_lines[0].indent != 0:
        raise _FrontmatterError("the top-level mapping must start at column zero")
    parsed, index = _parse_yaml_block(yaml_lines, 0, 0)
    if index != len(yaml_lines):
        line = yaml_lines[index]
        raise _FrontmatterError(f"line {line.number} could not be parsed")
    if not isinstance(parsed, dict):
        raise _FrontmatterError("the frontmatter root is not a mapping")
    return parsed


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _managed_path() -> Path | None:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    if sys.platform.startswith("linux"):
        return Path("/etc/claude-code/managed-settings.json")
    if sys.platform == "win32":
        return Path(r"C:\ProgramData\ClaudeCode\managed-settings.json")
    return None


def _source(kind: str, path: Path, label: str) -> Source:
    return Source(kind=kind, path=_absolute(path), label=label)


def _plugin_paths(roots: Iterable[Path]) -> list[Path]:
    found: list[Path] = []
    files_seen = 0
    directories_seen = 0
    stop = False

    for root in roots:
        if stop or not root.exists():
            continue
        for current, directories, files in os.walk(root, followlinks=False):
            directories.sort()
            files.sort()
            current_path = Path(current)
            try:
                depth = len(current_path.relative_to(root).parts)
            except ValueError:
                directories.clear()
                continue
            directories_seen += 1
            if depth >= _PLUGIN_MAX_DEPTH:
                directories.clear()
            if directories_seen >= _PLUGIN_MAX_DIRECTORIES:
                directories.clear()
                stop = True
            for filename in files:
                files_seen += 1
                candidate = current_path / filename
                if filename == "hooks.json" and current_path.name == "hooks":
                    found.append(_absolute(candidate))
                if files_seen >= _PLUGIN_MAX_FILES:
                    stop = True
                    break
            if stop:
                break
    return sorted(dict.fromkeys(found), key=os.fspath)


def _glob_existing(directory: Path, pattern: str) -> list[Path]:
    if not directory.exists():
        return []
    try:
        return sorted(
            (_absolute(path) for path in directory.glob(pattern) if path.is_file()),
            key=os.fspath,
        )
    except OSError:
        return []


def _discover(project_dir: Path, include_home: bool) -> list[Source]:
    config_dir = _absolute(
        Path(os.environ.get("CLAUDE_CONFIG_DIR", os.fspath(Path.home() / ".claude")))
    )
    sources: list[Source] = []

    managed = _managed_path()
    if managed is not None and managed.exists():
        sources.append(_source("managed", managed, f"managed ({managed})"))

    if include_home:
        user = config_dir / "settings.json"
        if user.exists():
            sources.append(_source("user", user, "user (~/.claude/settings.json)"))

    project = project_dir / ".claude" / "settings.json"
    if project.exists():
        sources.append(
            _source("project", project, "project (.claude/settings.json)")
        )
    local = project_dir / ".claude" / "settings.local.json"
    if local.exists():
        sources.append(
            _source("local", local, "local (.claude/settings.local.json)")
        )

    plugin_roots = [project_dir / ".claude" / "plugins"]
    if include_home:
        plugin_roots.insert(0, config_dir / "plugins")
    for path in _plugin_paths(plugin_roots):
        sources.append(_source("plugin", path, f"plugin ({path})"))

    agent_dirs = [project_dir / ".claude" / "agents"]
    if include_home:
        agent_dirs.append(config_dir / "agents")
    for directory in agent_dirs:
        for path in _glob_existing(directory, "*.md"):
            sources.append(
                _source("agent-frontmatter", path, f"agent frontmatter ({path})")
            )

    skill_dirs = [project_dir / ".claude" / "skills"]
    if include_home:
        skill_dirs.append(config_dir / "skills")
    for directory in skill_dirs:
        for path in _glob_existing(directory, "*/SKILL.md"):
            sources.append(
                _source("skill-frontmatter", path, f"skill frontmatter ({path})")
            )

    unique: list[Source] = []
    seen: set[tuple[str, Path]] = set()
    for item in sources:
        key = (item.kind, item.path)
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return unique


def _matcher_slug(matcher: str | None) -> str:
    if matcher is None or matcher in {"", "*"}:
        return "all"
    return _MATCHER_SLUG.sub("_", matcher)


def _hook_name(
    event: str,
    matcher: str | None,
    counters: dict[tuple[str, str], int],
) -> str:
    slug = _matcher_slug(matcher)
    key = (event, slug)
    counters[key] = counters.get(key, 0) + 1
    return f"{event}.{slug}.{counters[key]}"


def _record_sandbox_issues(
    data: dict[str, Any], source: Source, issues: list[LoadIssue]
) -> None:
    sandbox = data.get("sandbox")
    if sandbox is None:
        return
    if not isinstance(sandbox, dict):
        return
    filesystem = sandbox.get("filesystem")
    if filesystem is None or not isinstance(filesystem, dict):
        return
    for setting in ("denyRead", "denyWrite"):
        values = filesystem.get(setting)
        if values is None or not isinstance(values, list):
            continue
        for index, value in enumerate(values):
            if isinstance(value, str):
                continue
            issues.append(
                LoadIssue(
                    "CONFIG.SANDBOX_NON_STRING",
                    source,
                    f"sandbox.filesystem.{setting}[{index}] is not a string: {value!r}.",
                    f"sandbox.filesystem.{setting}[{index}]",
                )
            )


def _load_hooks(
    data: dict[str, Any],
    source: Source,
    counters: dict[tuple[str, str], int],
    issues: list[LoadIssue],
) -> list[HookEntry]:
    from .checks import EVENTS, HANDLER_TYPES

    loaded: list[HookEntry] = []
    if "hooks" not in data:
        return loaded
    hooks = data["hooks"]
    if not isinstance(hooks, dict):
        issues.append(
            LoadIssue(
                "CONFIG.BAD_GROUP",
                source,
                'The top-level "hooks" value is not an object.',
                "hooks",
            )
        )
        return loaded

    for raw_event, groups in hooks.items():
        event = str(raw_event)
        effective_event = (
            "SubagentStop"
            if source.kind == "agent-frontmatter" and event == "Stop"
            else event
        )
        if event not in EVENTS:
            issues.append(
                LoadIssue(
                    "CONFIG.UNKNOWN_EVENT",
                    source,
                    f'Unknown hook event "{event}" appears in {source.label}.',
                    event,
                )
            )
        if not isinstance(groups, list):
            issues.append(
                LoadIssue(
                    "CONFIG.BAD_GROUP",
                    source,
                    f'Hook event "{event}" does not contain a list of matcher groups.',
                    event,
                )
            )
            continue

        for group_index, group in enumerate(groups):
            group_detail = f"{event} group {group_index}"
            if not isinstance(group, dict):
                issues.append(
                    LoadIssue(
                        "CONFIG.BAD_GROUP",
                        source,
                        f'{group_detail} is not an object.',
                        group_detail,
                    )
                )
                continue
            matcher_present = "matcher" in group
            matcher = group.get("matcher")
            if matcher_present and not isinstance(matcher, str):
                issues.append(
                    LoadIssue(
                        "CONFIG.BAD_MATCHER_TYPE",
                        source,
                        f'{group_detail} has a non-string matcher: {matcher!r}.',
                        group_detail,
                    )
                )
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                issues.append(
                    LoadIssue(
                        "CONFIG.BAD_GROUP",
                        source,
                        f'{group_detail} has no list-valued "hooks" field.',
                        group_detail,
                    )
                )
                continue

            for handler_index, raw_handler in enumerate(handlers):
                handler_detail = f"{group_detail} handler {handler_index}"
                if not isinstance(raw_handler, dict):
                    issues.append(
                        LoadIssue(
                            "CONFIG.BAD_HANDLER_TYPE",
                            source,
                            f'{handler_detail} is not an object.',
                            handler_detail,
                        )
                    )
                    continue
                handler = dict(raw_handler)
                if source.kind == "agent-frontmatter" and event == "Stop":
                    # Claude Code converts a subagent frontmatter Stop hook into
                    # SubagentStop before registering it.
                    handler["_hookprobe_note"] = (
                        "Claude Code converts agent-frontmatter Stop to SubagentStop."
                    )
                name = _hook_name(effective_event, matcher, counters)
                entry = HookEntry(
                    name=name,
                    event=effective_event,
                    matcher=matcher,
                    group_index=group_index,
                    handler_index=handler_index,
                    handler=handler,
                    source=source,
                )
                loaded.append(entry)

                handler_type = handler.get("type")
                if handler_type not in HANDLER_TYPES:
                    rendered = "missing" if handler_type is None else repr(handler_type)
                    issues.append(
                        LoadIssue(
                            "CONFIG.BAD_HANDLER_TYPE",
                            source,
                            f'Hook "{name}" has handler type {rendered}.',
                            name,
                        )
                    )
                elif handler_type == "command" and "command" not in handler:
                    issues.append(
                        LoadIssue(
                            "CONFIG.MISSING_COMMAND",
                            source,
                            f'Command hook "{name}" has no command field.',
                            name,
                        )
                    )
    return loaded


def _read_source(
    source: Source,
) -> tuple[dict[str, Any] | None, LoadIssue | None]:
    try:
        text = source.path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return None, LoadIssue(
            "CONFIG.UNREADABLE",
            source,
            f"Could not read {source.label}.",
            str(error),
        )

    if source.kind in {"agent-frontmatter", "skill-frontmatter"}:
        try:
            return _parse_frontmatter(text), None
        except _FrontmatterError as error:
            return None, LoadIssue(
                "CONFIG.FRONTMATTER_UNPARSED",
                source,
                f"Could not parse the YAML frontmatter in {source.label}.",
                str(error),
            )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        return None, LoadIssue(
            "CONFIG.BAD_JSON",
            source,
            f"Could not parse JSON in {source.label}.",
            f"line {error.lineno}, column {error.colno}: {error.msg}",
        )
    if not isinstance(parsed, dict):
        return None, LoadIssue(
            "CONFIG.BAD_JSON",
            source,
            f"The root value in {source.label} is not an object.",
        )
    return parsed, None


def load(
    project_dir: Path,
    explicit_settings: list[Path] | None = None,
    include_home: bool = True,
) -> Configuration:
    """Load hook configuration without allowing malformed input to escape."""

    project = _absolute(Path(project_dir))
    if explicit_settings is not None:
        sources = [
            _source("explicit", Path(path), f"explicit ({path})")
            for path in explicit_settings
        ]
    else:
        try:
            sources = _discover(project, include_home)
        except Exception as error:
            fallback = _source("project", project, f"project ({project})")
            return Configuration(
                hooks=[],
                sources=[],
                issues=[
                    LoadIssue(
                        "CONFIG.UNREADABLE",
                        fallback,
                        "Could not discover hook configuration files.",
                        str(error),
                    )
                ],
                disable_all_hooks=False,
                project_dir=project,
                sandbox_issues=[],
            )

    hooks: list[HookEntry] = []
    issues: list[LoadIssue] = []
    sandbox_issues: list[LoadIssue] = []
    counters: dict[tuple[str, str], int] = {}
    disable_all_hooks = False

    for source in sources:
        try:
            data, read_issue = _read_source(source)
            if read_issue is not None:
                issues.append(read_issue)
                continue
            if data is None:
                continue
            disable_value = data.get("disableAllHooks")
            if disable_value is True:
                disable_all_hooks = True
            elif "disableAllHooks" in data and not isinstance(disable_value, bool):
                issues.append(
                    LoadIssue(
                        "CONFIG.BAD_DISABLE_ALL_HOOKS",
                        source,
                        f'"disableAllHooks" is not a boolean in {source.label}.',
                        repr(disable_value),
                    )
                )
            _record_sandbox_issues(data, source, sandbox_issues)
            hooks.extend(_load_hooks(data, source, counters, issues))
        except Exception as error:
            # Loading user-controlled configuration must never abort the probe.
            issues.append(
                LoadIssue(
                    "CONFIG.UNREADABLE",
                    source,
                    f"Could not load {source.label}.",
                    str(error),
                )
            )

    return Configuration(
        hooks=hooks,
        sources=sources,
        issues=issues,
        disable_all_hooks=disable_all_hooks,
        project_dir=project,
        sandbox_issues=sandbox_issues,
    )
