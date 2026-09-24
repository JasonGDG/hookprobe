"""The checks that matter: every test mirrors a documented failure case."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tests.helpers import ProjectTestCase  # noqa: E402

ALLOW = """#!/bin/sh
read -r payload
echo '{"permissionDecision":"allow"}'
"""

DENY_EXIT_2 = """#!/usr/bin/env python3
import json, sys
data = json.load(sys.stdin)
if "rm " in json.dumps(data):
    sys.exit(2)
print(json.dumps({"permissionDecision": "allow"}))
"""

DENY_EXIT_1 = """#!/usr/bin/env python3
import json, sys
data = json.load(sys.stdin)
if "rm " in json.dumps(data):
    sys.stderr.write("refused\\n")
    sys.exit(1)
print(json.dumps({"permissionDecision": "allow"}))
"""


def codes(probe) -> set[str]:
    return {finding.code for finding in probe.findings}


class FailOpenTests(ProjectTestCase):
    """anthropics/claude-code#94362 -- the file mode is the only difference."""

    def test_missing_execute_bit_is_reported_as_critical(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertEqual(len(probes), 1)
        probe = probes[0]
        self.assertIn("P01.NOT_EXECUTABLE", codes(probe))
        self.assertTrue(probe.is_broken)

    def test_same_hook_with_execute_bit_is_healthy(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=True)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        probe = probes[0]
        self.assertNotIn("P01.NOT_EXECUTABLE", codes(probe))
        self.assertTrue(probe.starts)
        self.assertFalse(probe.is_broken)

    def test_missing_file_is_reported(self) -> None:
        self.simple_settings("PreToolUse", str(self.project / ".claude" / "gone.sh"))
        _, probes = self.probe_all()
        self.assertIn("P01.MISSING_FILE", codes(probes[0]))
        self.assertTrue(probes[0].is_broken)


class ExitCodeTests(ProjectTestCase):
    """Only exit code 2 blocks; exit 1 is a non-blocking error."""

    def test_exit_two_counts_as_blocking(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertTrue(probes[0].can_block)
        self.assertIn("P08.BLOCKED_AS_EXPECTED", codes(probes[0]))

    def test_exit_one_does_not_block(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_1)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertFalse(probes[0].can_block)
        self.assertIn("P08.EXIT_ONE_ON_REJECT", codes(probes[0]))
        self.assertTrue(probes[0].is_broken)


class OutputTests(ProjectTestCase):
    def test_preamble_before_json_is_flagged(self) -> None:
        path = self.write_hook(
            "noisy.sh",
            "#!/bin/sh\nread -r payload\necho 'welcome to my shell'\n"
            'echo \'{"permissionDecision":"allow"}\'\n',
        )
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertTrue(codes(probes[0]) & {"P09.PREAMBLE", "P09.NOT_JSON"})

    def test_plain_text_is_fine_for_context_events(self) -> None:
        path = self.write_hook("note.sh", "#!/bin/sh\nread -r payload\necho hello\n")
        self.simple_settings("UserPromptSubmit", str(path), matcher=None)
        _, probes = self.probe_all()
        probe = probes[0]
        self.assertNotIn("P09.NOT_JSON", codes(probe))
        self.assertFalse(probe.is_broken)

    def test_output_above_the_cap_is_flagged(self) -> None:
        path = self.write_hook(
            "big.py",
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "sys.stdin.read()\n"
            'print(json.dumps({"additionalContext": "x" * 12000}))\n',
        )
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertIn("P07.OVER_CAP", codes(probes[0]))


class TimeoutTests(ProjectTestCase):
    def test_hook_that_never_answers_is_not_protecting(self) -> None:
        path = self.write_hook("hang.sh", "#!/bin/sh\nsleep 30\n")
        self.simple_settings("PreToolUse", str(path))
        from hookprobe.probe import probe_hook

        config = self.load()
        probe = probe_hook(config.hooks[0], self.project, timeout=1.0)
        self.assertFalse(probe.answers)
        self.assertTrue(probe.is_broken)


class MatcherTests(ProjectTestCase):
    def test_matcher_on_event_without_matcher_support(self) -> None:
        path = self.write_hook("note.sh", "#!/bin/sh\nread -r p\necho hi\n")
        self.simple_settings("UserPromptSubmit", str(path), matcher="Bash")
        from hookprobe.checks import check_matcher

        config = self.load()
        found = {finding.code for finding in check_matcher(config.hooks[0])}
        self.assertIn("P04.MATCHER_IGNORED", found)


class ReportTests(ProjectTestCase):
    def test_exit_code_is_one_when_a_hook_is_broken(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        from hookprobe.cli import main

        code = main([str(self.project), "--no-home"])
        self.assertEqual(code, 1)

    def test_exit_code_is_zero_when_everything_works(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", str(path))
        from hookprobe.cli import main

        self.assertEqual(main([str(self.project), "--no-home"]), 0)

    def test_json_output_is_parsable(self) -> None:
        import json

        path = self.write_hook("deny.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", str(path))
        from hookprobe.config import load
        from hookprobe.checks import check_schema
        from hookprobe.probe import probe_hook
        from hookprobe.report import render_json

        config = load(self.project, include_home=False)
        probes = [probe_hook(hook, self.project) for hook in config.hooks]
        payload = json.loads(render_json(config, probes, check_schema(config)))
        self.assertEqual(payload["summary"]["hooks"], 1)
        self.assertIn("hooks", payload)


class EvidenceTests(unittest.TestCase):
    def test_every_code_used_in_the_probe_layer_resolves(self) -> None:
        from hookprobe import evidence, probe

        source = Path(probe.__file__).read_text("utf-8")
        # Only full codes: "P01." is a prefix used in a startswith() guard.
        used = set(re.findall(r'"(P\d{2}\.[A-Z_]{2,})"', source))
        self.assertTrue(used)
        for code in used:
            entry = evidence.lookup(code)
            self.assertNotEqual(entry.title, "Uncatalogued finding", code)




class LaunchFailureTests(ProjectTestCase):
    """A process can start while the hook logic never runs -- and several of
    those failures exit with code 2, the code that means "block"."""

    def test_missing_script_behind_an_interpreter_is_not_a_working_guard(self) -> None:
        missing = self.project / ".claude" / "hooks" / "gone.py"
        self.simple_settings("PreToolUse", f"python3 {missing}")
        _, probes = self.probe_all()
        probe = probes[0]
        self.assertFalse(probe.starts, "python3 exits 2 here -- that is not a block")
        self.assertFalse(probe.can_block)
        self.assertTrue(probe.is_broken)
        self.assertIn("P01.SPAWN_FAILED", codes(probe))

    def test_unusable_shebang_interpreter_is_reported_as_not_starting(self) -> None:
        path = self.write_hook("bad.sh", "#!/usr/bin/nonexistent-interp\necho x\n")
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertFalse(probes[0].starts)
        self.assertIn("P01.MISSING_INTERPRETER", codes(probes[0]))

    def test_unquoted_space_in_path_breaks_the_launch(self) -> None:
        directory = self.project / ".claude" / "hooks" / "with space"
        directory.mkdir()
        path = directory / "deny.sh"
        path.write_text("#!/bin/sh\nexit 2\n", "utf-8")
        path.chmod(0o755)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertFalse(probes[0].starts)

    def test_handler_that_rejects_everything_is_flagged(self) -> None:
        path = self.write_hook("always.sh", "#!/bin/sh\nread -r p\nexit 2\n")
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertTrue(probes[0].can_block)
        self.assertIn("P08.BLOCKS_EVERYTHING", codes(probes[0]))




class DenyWordingTests(ProjectTestCase):
    """Regression for the worst kind of bug this tool can have: calling a
    working guard broken. A correct deny hook writes its reason to stderr, and
    those reasons legitimately contain 'permission denied' or 'not found'."""

    WORDINGS = [
        "Permission denied by policy: destructive command",
        "command not found in the allowlist",
        "refused: policy file not found, failing closed",
        "refused by policy",
    ]

    def test_stderr_wording_does_not_change_the_verdict(self) -> None:
        for index, wording in enumerate(self.WORDINGS):
            with self.subTest(wording=wording):
                path = self.write_hook(
                    f"deny{index}.py",
                    "#!/usr/bin/env python3\n"
                    "import json, sys\n"
                    "data = json.load(sys.stdin)\n"
                    'if "rm " in json.dumps(data):\n'
                    f"    sys.stderr.write({wording!r})\n"
                    "    sys.exit(2)\n"
                    'print(json.dumps({"permissionDecision": "allow"}))\n',
                )
                self.simple_settings("PreToolUse", str(path))
                _, probes = self.probe_all()
                probe = probes[0]
                self.assertTrue(probe.can_block, f"{wording}: verdict lost")
                self.assertFalse(probe.is_broken, f"{wording}: healthy hook broken")


class InvocationFormTests(ProjectTestCase):
    """The common ways people invoke a hook must not be misread as the script."""

    HOOK = (
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "data = json.load(sys.stdin)\n"
        'if "rm " in json.dumps(data):\n'
        "    sys.exit(2)\n"
        'print(json.dumps({"permissionDecision": "allow"}))\n'
    )

    def test_interpreter_prefixes_are_not_mistaken_for_the_script(self) -> None:
        path = self.write_hook("h.py", self.HOOK)
        for command in (
            f"/usr/bin/env python3 {path}",
            f"python3 {path}",
            f"python3 -u {path}",
        ):
            with self.subTest(command=command):
                self.simple_settings("PreToolUse", command)
                _, probes = self.probe_all()
                probe = probes[0]
                self.assertNotIn("P01.NO_SHEBANG", codes(probe), command)
                self.assertFalse(probe.is_broken, command)

    def test_quoted_path_with_space_is_healthy(self) -> None:
        directory = self.project / ".claude" / "hooks" / "my hooks"
        directory.mkdir()
        path = directory / "guard.py"
        path.write_text(self.HOOK, "utf-8")
        path.chmod(0o755)
        self.simple_settings("PreToolUse", f'"{path}"')
        _, probes = self.probe_all()
        self.assertTrue(probes[0].starts)
        self.assertFalse(probes[0].is_broken)

    def test_unquoted_path_with_space_names_the_real_cause(self) -> None:
        directory = self.project / ".claude" / "hooks" / "my hooks"
        directory.mkdir()
        path = directory / "guard.py"
        path.write_text(self.HOOK, "utf-8")
        path.chmod(0o755)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertIn("P01.SPACE_IN_PATH", codes(probes[0]))


class ConfigurationFailureTests(ProjectTestCase):
    """A settings file that does not parse means none of its hooks are active."""

    def test_broken_json_is_reported_and_fails(self) -> None:
        path = self.project / ".claude" / "settings.json"
        path.write_text('{"hooks": {"PreToolUse": [ {"matcher": "Bash",', "utf-8")
        from hookprobe.cli import main

        self.assertEqual(main([str(self.project), "--no-home"]), 1)




class WatchTests(ProjectTestCase):
    """The heartbeat must be additive, removable, and must not raise a false
    alarm just because another project is busy."""

    def test_install_is_additive_and_uninstall_is_clean(self) -> None:
        from hookprobe import watch

        existing = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}
        local = self.project / ".claude" / "settings.local.json"
        local.write_text(json.dumps(existing), "utf-8")

        added = watch.install(self.project)
        self.assertTrue(added)
        self.assertTrue(watch.is_installed(self.project))
        after = json.loads(local.read_text("utf-8"))
        self.assertIn("PreToolUse", after["hooks"], "existing hooks must survive")

        watch.uninstall(self.project)
        self.assertFalse(watch.is_installed(self.project))
        restored = json.loads(local.read_text("utf-8"))
        self.assertIn("PreToolUse", restored["hooks"])

    def test_install_is_idempotent(self) -> None:
        from hookprobe import watch

        watch.install(self.project)
        self.assertEqual(watch.install(self.project), [])
        watch.uninstall(self.project)

    def test_quiet_project_is_not_an_alarm(self) -> None:
        from hookprobe import watch

        watch.install(self.project)
        state = watch.status(self.project, window=900.0)
        self.assertFalse(state.alarm, "no activity for this project means no verdict")
        watch.uninstall(self.project)

    def test_heartbeat_script_never_fails(self) -> None:
        import subprocess

        from hookprobe import watch

        watch.install(self.project)
        script = self.project / ".claude" / "hooks" / "hookprobe-heartbeat.py"
        for payload in ("", "not json", '{"hook_event_name":"Stop"}'):
            with self.subTest(payload=payload):
                result = subprocess.run(
                    [str(script)], input=payload, capture_output=True, text=True, timeout=10
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        watch.uninstall(self.project)




class RecorderTests(ProjectTestCase):
    """The recorder sits in the decision path. If it changes anything -- the
    exit code, stdout, even by a byte -- it has broken the thing it observes."""

    GUARD = (
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "data = json.load(sys.stdin)\n"
        'if "rm " in json.dumps(data):\n'
        '    sys.stderr.write("refused by policy\\n")\n'
        "    sys.exit(2)\n"
        "print('{\"permissionDecision\": \"allow\"}')\n"
    )

    def _run(self, command: list[str], payload: str, env: dict | None = None):
        import os
        import subprocess

        environment = dict(os.environ)
        environment.update(env or {})
        return subprocess.run(
            command,
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )

    def test_recorder_is_byte_for_byte_transparent(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        config = self.load()
        record.wrap(self.project, config.hooks)
        recorder = self.project / ".claude" / "hooks" / "hookprobe-recorder.py"

        for payload in (
            '{"tool_name":"Bash","tool_input":{"command":"ls"}}',
            '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}',
        ):
            with self.subTest(payload=payload):
                direct = self._run([str(path)], payload)
                through = self._run(
                    [str(recorder)],
                    payload,
                    {
                        "HOOKPROBE_LABEL": "test",
                        "HOOKPROBE_EVENT": "PreToolUse",
                        "HOOKPROBE_ORIGINAL": str(path),
                    },
                )
                self.assertEqual(direct.returncode, through.returncode)
                self.assertEqual(direct.stdout, through.stdout)
                self.assertEqual(direct.stderr, through.stderr)

    def test_recorder_never_becomes_stricter_than_the_original(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        record.wrap(self.project, self.load().hooks)
        recorder = self.project / ".claude" / "hooks" / "hookprobe-recorder.py"

        result = self._run(
            [str(recorder)],
            "{}",
            {
                "HOOKPROBE_LABEL": "test",
                "HOOKPROBE_EVENT": "PreToolUse",
                "HOOKPROBE_ORIGINAL": "/definitely/not/here",
            },
        )
        self.assertNotEqual(result.returncode, 2, "a broken recorder must not block")

    def test_wrap_is_reversible(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        local = self.project / ".claude" / "settings.local.json"
        local.write_text(json.dumps({"hooks": {"Stop": [{"hooks": []}]}}), "utf-8")

        record.wrap(self.project, self.load().hooks)
        self.assertTrue(record.is_wrapped(self.project))
        record.unwrap(self.project)
        self.assertFalse(record.is_wrapped(self.project))
        self.assertIn("Stop", json.loads(local.read_text("utf-8"))["hooks"])
        self.assertFalse((self.project / ".claude" / "hookprobe-record.json").exists())
        self.assertFalse(
            (self.project / ".claude" / "hooks" / "hookprobe-recorder.py").exists()
        )

    def test_report_names_handlers_that_never_ran(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        record.wrap(self.project, self.load().hooks)
        # --record reads the configuration *after* the install, so the reload is
        # part of the flow under test.
        text = record.render(self.project, self.load().hooks, 900.0)
        self.assertIn("guard.py", text)
        self.assertIn("never", text)

    def test_wrap_replaces_the_handler_instead_of_adding_a_second_one(self) -> None:
        """Measured against a real session: an appended entry made one PreToolUse
        hook fire twice for a single Bash call. Replacing in place keeps it at one."""
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        before = [hook.command for hook in self.load().hooks]

        record.wrap(self.project, self.load().hooks)
        after = [hook.command for hook in self.load().hooks]

        self.assertEqual(len(before), len(after), "wrapping must not add a handler")
        self.assertNotIn(str(path), after, "the unwrapped original must be gone")
        self.assertEqual(
            [record.original_of(command) for command in after],
            before,
            "each wrapper must carry exactly the command it replaced",
        )

    def test_unwrap_deletes_entries_an_older_version_appended(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        local = self.project / ".claude" / "settings.local.json"
        legacy = (
            "HOOKPROBE_LABEL=PreToolUse:guard.py HOOKPROBE_EVENT=PreToolUse "
            f"HOOKPROBE_ORIGINAL={path} "
            f"{self.project}/.claude/hooks/hookprobe-recorder.py"
        )
        local.write_text(
            json.dumps(
                {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": legacy}]}]}}
            ),
            "utf-8",
        )

        record.unwrap(self.project)

        commands = [hook.command for hook in self.load().hooks]
        self.assertEqual(
            commands,
            [str(path)],
            "a legacy entry must be deleted, not turned into a duplicate handler",
        )

    def _wrapper_of(self, event: str = "PreToolUse") -> str:
        settings = json.loads((self.project / ".claude" / "settings.json").read_text("utf-8"))
        return settings["hooks"][event][0]["hooks"][0]["command"]

    def _through_sh(self, wrapper: str, payload: str, env: dict | None = None):
        return self._run(["/bin/sh", "-c", wrapper], payload, env)

    def test_generated_wrapper_line_is_transparent_through_sh(self) -> None:
        """The earlier transparency test called the recorder script directly. This
        one runs the exact command line that lands in the settings file, the way
        Claude Code runs it, for a quoted path with spaces and a blocking payload."""
        from hookprobe import record

        (self.project / ".claude" / "my hooks").mkdir()
        path = self.project / ".claude" / "my hooks" / "guard.py"
        path.write_text(self.GUARD, "utf-8")
        path.chmod(0o755)
        self.simple_settings("PreToolUse", f'"{path}"')
        record.wrap(self.project, self.load().hooks)
        wrapper = self._wrapper_of()

        for payload in (
            '{"tool_name":"Bash","tool_input":{"command":"ls"}}',
            '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}',
        ):
            with self.subTest(payload=payload):
                direct = self._run(["/bin/sh", "-c", f'"{path}"'], payload)
                through = self._through_sh(wrapper, payload)
                self.assertEqual(direct.returncode, through.returncode)
                self.assertEqual(direct.stdout, through.stdout)
                self.assertEqual(direct.stderr, through.stderr)

    def test_unwrap_restores_the_exact_command_text(self) -> None:
        from hookprobe import record

        original = "sh -c 'echo \"it'\"'\"'s fine\" ; exit 0'"
        self.simple_settings("PreToolUse", original)
        record.wrap(self.project, self.load().hooks)
        self.assertNotEqual(self._wrapper_of(), original)
        record.unwrap(self.project)
        self.assertEqual(self._wrapper_of(), original)

    def test_bash_shell_handler_keeps_its_shell(self) -> None:
        """A bash-only guard run through /bin/sh blocks everything on macOS (syntax
        error -> exit 2) and nothing on dash. The recorder must keep bash."""
        from hookprobe import record

        handler = {
            "type": "command",
            "command": "if grep -q rm <(cat); then exit 2; fi; exit 0",
            "shell": "bash",
        }
        self.write_settings({"PreToolUse": [{"matcher": "Bash", "hooks": [handler]}]})
        record.wrap(self.project, self.load().hooks)
        wrapper = self._wrapper_of()

        self.assertIn("HOOKPROBE_SHELL=bash", wrapper)
        benign = self._through_sh(wrapper, '{"tool_input":{"command":"ls"}}')
        blocked = self._through_sh(wrapper, '{"tool_input":{"command":"rm -rf /"}}')
        self.assertEqual((benign.returncode, blocked.returncode), (0, 2))

    def test_exec_form_handler_is_named_not_wrapped(self) -> None:
        from hookprobe import record

        handler = {"type": "command", "command": "/usr/bin/printf", "args": ["OK"]}
        self.write_settings({"PreToolUse": [{"matcher": "Bash", "hooks": [handler]}]})
        result = record.wrap(self.project, self.load().hooks)

        self.assertEqual(result.wrapped, [])
        self.assertIn("args", result.skipped[0][1])
        self.assertEqual(self._wrapper_of(), "/usr/bin/printf")

    def test_recorder_hides_itself_from_the_handler(self) -> None:
        from hookprobe import record

        body = (
            "#!/bin/sh\n"
            "cat > /dev/null\n"
            'if [ -n "$HOOKPROBE_LABEL" ]; then exit 2; fi\n'
            "exit 0\n"
        )
        path = self.write_hook("spy.sh", body)
        self.simple_settings("PreToolUse", str(path))
        record.wrap(self.project, self.load().hooks)

        self.assertEqual(self._through_sh(self._wrapper_of(), "{}").returncode, 0)

    def test_install_over_a_legacy_entry_does_not_double_the_handler(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        local = self.project / ".claude" / "settings.local.json"
        legacy = (
            "HOOKPROBE_LABEL=PreToolUse:guard.py HOOKPROBE_EVENT=PreToolUse "
            f"HOOKPROBE_ORIGINAL={path} {self.project}/.claude/hooks/hookprobe-recorder.py"
        )
        local.write_text(
            json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": legacy}]}]}}),
            "utf-8",
        )

        record.wrap(self.project, self.load().hooks)

        commands = [h.command for h in self.load().hooks if h.event == "PreToolUse"]
        self.assertEqual(len(commands), 1, "exactly one handler must remain")
        self.assertEqual(record.original_of(commands[0]), str(path))

    def test_user_level_file_is_restored_through_the_manifest(self) -> None:
        """`--record-remove` used to hard-code ~/.claude; with CLAUDE_CONFIG_DIR set
        it restored the project file and left the user-level hook pointing at a
        recorder it had just deleted -- in every project on the machine."""
        import os
        import tempfile

        from hookprobe import record
        from hookprobe.config import load

        config_dir = Path(tempfile.mkdtemp(prefix="hookprobe-cfg-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(config_dir, ignore_errors=True))
        previous = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = str(config_dir)
        self.addCleanup(
            lambda: os.environ.__setitem__("CLAUDE_CONFIG_DIR", previous)
            if previous is not None
            else os.environ.pop("CLAUDE_CONFIG_DIR", None)
        )
        user_hook = self.write_hook("user.sh", "#!/bin/sh\ncat >/dev/null\nexit 0\n")
        (config_dir / "settings.json").write_text(
            json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": str(user_hook)}]}]}}),
            "utf-8",
        )
        project_hook = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(project_hook))

        result = record.wrap(self.project, load(self.project, include_home=True).hooks)
        self.assertEqual(len(result.wrapped), 2)
        self.assertIn(config_dir / "settings.json", result.files)

        restored = record.unwrap(self.project)

        self.assertEqual(restored, 2)
        user_settings = json.loads((config_dir / "settings.json").read_text("utf-8"))
        self.assertEqual(user_settings["hooks"]["Stop"][0]["hooks"][0]["command"], str(user_hook))
        self.assertFalse(record.is_wrapped(self.project))

    def test_same_basename_in_two_files_gets_two_keys(self) -> None:
        from hookprobe import record

        (self.project / "a").mkdir()
        (self.project / "b").mkdir()
        first = self.project / "a" / "guard.sh"
        second = self.project / "b" / "guard.sh"
        for path in (first, second):
            path.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n", "utf-8")
            path.chmod(0o755)
        self.write_settings(
            {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": str(first)}]},
                    {"matcher": "Write", "hooks": [{"type": "command", "command": str(second)}]},
                ]
            }
        )
        record.wrap(self.project, self.load().hooks)
        fields = [record.wrapper_fields(h.command) for h in self.load().hooks]

        self.assertEqual(fields[0]["label"], fields[1]["label"])
        self.assertNotEqual(fields[0]["key"], fields[1]["key"])

    def test_label_names_the_script_not_the_last_token(self) -> None:
        from hookprobe import record

        self.assertEqual(record.label_for("PreToolUse", "python3 guard.py --strict"), "PreToolUse:guard.py")
        self.assertEqual(record.label_for("PreToolUse", "foo.py 2>/dev/null"), "PreToolUse:foo.py")
        self.assertEqual(record.label_for("PreToolUse", "uv run /x/hooks/pre.py"), "PreToolUse:pre.py")
        self.assertEqual(record.label_for("Stop", "echo 'oops"), "Stop:echo")

    def test_plugin_hooks_are_named_rather_than_half_wrapped(self) -> None:
        """${CLAUDE_PLUGIN_ROOT} is only set when Claude Code calls a plugin hook,
        so copying such a command into project settings would break it."""
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        hooks = self.load().hooks
        plugin = hooks[0]
        plugin.source = type(plugin.source)(
            kind="plugin", path=plugin.source.path, label="plugin (test)"
        )

        result = record.wrap(self.project, [plugin])

        self.assertEqual(result.wrapped, [])
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("CLAUDE_PLUGIN_ROOT", result.skipped[0][1])


class ForeignSetupTests(ProjectTestCase):
    """Three popular public hook setups produced false alarms on 23.09.2026
    (disler/claude-code-hooks-mastery, parcadei/Continuous-Claude-v3,
    karanb192/claude-code-hooks). Each case is the smallest fixture that
    reproduced one of them, with the verdict that is actually right."""

    def _hook(self, command: str):
        self.simple_settings("PreToolUse", command)
        return self.load().hooks[0]

    def test_uv_run_resolves_to_the_script_not_the_subcommand(self) -> None:
        from hookprobe.probe import _script_path

        path = self.write_hook("guard.py", DENY_EXIT_2)
        self.assertEqual(_script_path(self._hook(f"uv run {path}"), self.project), path)

    def test_uv_run_guard_is_healthy_when_it_is(self) -> None:
        # 13 of 13 hooks were reported "not protecting anything" because `run`
        # was taken for the script and did not exist.
        import shutil

        if shutil.which("uv") is None:
            self.skipTest("uv not installed")
        path = self.write_hook("guard.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", f"uv run {path}")
        _, probes = self.probe_all()
        self.assertFalse(probes[0].is_broken)
        self.assertNotIn("P01.MISSING_FILE", codes(probes[0]))
        self.assertTrue(probes[0].can_block)

    def test_script_names_and_package_names_are_not_files(self) -> None:
        from hookprobe.probe import _script_path

        for command in (
            "pnpm run lint",
            "npm run check",
            "npx prettier --check .",
            "uvx ruff check",
            "uv run pytest",
            "my-hook --strict",
        ):
            with self.subTest(command=command):
                self.assertIsNone(_script_path(self._hook(command), self.project))

    def test_unbraced_project_dir_placeholder_is_the_documented_form(self) -> None:
        # Claude Code's docs write "$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh; only the
        # braced spelling was substituted, so the documented form was "missing".
        import os

        previous = os.environ.pop("CLAUDE_PROJECT_DIR", None)
        if previous is not None:
            self.addCleanup(os.environ.__setitem__, "CLAUDE_PROJECT_DIR", previous)
        self.write_hook("guard.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", '"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.py')
        _, probes = self.probe_all()
        self.assertFalse(probes[0].is_broken)
        self.assertNotIn("P01.MISSING_FILE", codes(probes[0]))
        self.assertTrue(probes[0].can_block)

    def test_home_variable_is_expanded_as_the_shell_would(self) -> None:
        from hookprobe.probe import _script_path

        resolved = _script_path(self._hook("bash $HOME/.claude/hooks/x.sh"), self.project)
        self.assertEqual(resolved, Path.home() / ".claude" / "hooks" / "x.sh")

    def test_node_missing_module_is_a_failed_launch_not_a_wrong_exit_code(self) -> None:
        # 12 hooks whose file did not exist were told to "return exit code 2".
        import shutil

        if shutil.which("node") is None:
            self.skipTest("node not installed")
        self.simple_settings("PreToolUse", f"node {self.project}/.claude/hooks/gone.mjs")
        _, probes = self.probe_all()
        self.assertFalse(probes[0].starts)
        self.assertIn("P01.MISSING_FILE", codes(probes[0]))
        self.assertNotIn("P08.EXIT_ONE_ON_REJECT", codes(probes[0]))

    def test_explicit_plugin_hooks_file_gets_its_plugin_root(self) -> None:
        from hookprobe.checks import _placeholder_values
        from hookprobe.config import load
        from hookprobe.probe import probe_hook

        plugin = self.project / "plugins" / "git-safety"
        (plugin / "hooks").mkdir(parents=True)
        script = plugin / "guard.py"
        script.write_text(DENY_EXIT_2, "utf-8")
        script.chmod(0o755)
        hooks_json = plugin / "hooks" / "hooks.json"
        hooks_json.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": 'python3 "${CLAUDE_PLUGIN_ROOT}/guard.py"',
                                    }
                                ],
                            }
                        ]
                    }
                }
            ),
            "utf-8",
        )
        config = load(self.project, explicit_settings=[hooks_json], include_home=False)
        hook = config.hooks[0]

        self.assertEqual(
            _placeholder_values(hook, self.project)["CLAUDE_PLUGIN_ROOT"], str(plugin)
        )
        probe = probe_hook(hook, self.project)
        self.assertNotIn("P01.UNSET_PLACEHOLDER", codes(probe))
        self.assertTrue(probe.can_block)

    def test_context_that_quotes_the_payload_is_not_nondeterministic(self) -> None:
        # disler's setup.py echoes session id and cwd into additionalContext;
        # comparing raw stdout filed it as "different answers".
        body = (
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "d = json.load(sys.stdin)\n"
            "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'SessionStart',"
            " 'additionalContext': 'Session: ' + d.get('session_id', '') + ' cwd: ' + d.get('cwd', '')}}))\n"
        )
        path = self.write_hook("ctx.py", body)
        self.simple_settings("SessionStart", str(path), matcher=None)
        _, probes = self.probe_all()
        self.assertFalse(probes[0].is_broken)
        self.assertNotIn("P11.NONDETERMINISTIC", codes(probes[0]))
        self.assertNotIn("P11.PAYLOAD_SENSITIVE", codes(probes[0]))

    def test_a_guard_whose_verdict_flips_is_still_caught(self) -> None:
        counter = self.project / "calls.txt"
        body = (
            "#!/usr/bin/env python3\n"
            "import sys, pathlib\n"
            f"p = pathlib.Path({str(counter)!r})\n"
            "n = int(p.read_text()) + 1 if p.exists() else 1\n"
            "p.write_text(str(n))\n"
            "sys.exit(2 if n % 2 else 0)\n"
        )
        path = self.write_hook("flip.py", body)
        self.simple_settings("PreToolUse", str(path))
        _, probes = self.probe_all()
        self.assertIn("P11.NONDETERMINISTIC", codes(probes[0]))

    def test_agent_frontmatter_flow_list_is_readable(self) -> None:
        agents = self.project / ".claude" / "agents"
        agents.mkdir()
        (agents / "aegis.md").write_text(
            "---\nname: aegis\ndescription: x\nmodel: opus\n"
            "tools: [Read, Bash, Grep, Glob]\n---\n\n# Aegis\n",
            "utf-8",
        )
        self.simple_settings("PreToolUse", str(self.write_hook("g.py", DENY_EXIT_2)))
        config = self.load()
        self.assertEqual(
            [i.code for i in config.issues if i.code == "CONFIG.FRONTMATTER_UNPARSED"], []
        )

    def test_unreadable_frontmatter_is_not_a_switched_off_hook(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hookprobe.cli import main

        agents = self.project / ".claude" / "agents"
        agents.mkdir()
        (agents / "odd.md").write_text("---\nname: odd\nx: !tag value\n---\n", "utf-8")
        self.simple_settings("PreToolUse", str(self.write_hook("g.py", DENY_EXIT_2)))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([str(self.project), "--no-home"])
        text = buffer.getvalue()

        self.assertEqual(code, 0)
        self.assertNotIn("switch hooks off", text)
        self.assertIn("CONFIG.FRONTMATTER_UNPARSED", text)


class IdentityTests(ProjectTestCase):
    """anthropics/claude-code#83952: configuration says which command should run,
    it cannot say whether the file at that path is the file you installed. The
    fingerprint makes a swap under an unchanged config visible."""

    def _identity(self, command: str):
        from hookprobe.probe import identify

        self.simple_settings("PreToolUse", command)
        return identify(self.load().hooks[0], self.project)

    def test_swapped_file_under_unchanged_config_changes_the_hash(self) -> None:
        path = self.write_hook("guard.py", DENY_EXIT_2)
        before = self._identity(str(path))
        self.assertTrue(before.exists)
        self.assertEqual(len(before.sha256), 64)

        path.write_text(DENY_EXIT_1, "utf-8")  # same path, same settings, other file
        after = self._identity(str(path))

        self.assertEqual(before.path, after.path)
        self.assertNotEqual(before.sha256, after.sha256)

    def test_identical_content_gives_an_identical_hash(self) -> None:
        first = self.write_hook("a.py", DENY_EXIT_2)
        second = self.write_hook("b.py", DENY_EXIT_2)
        self.assertEqual(self._identity(str(first)).sha256, self._identity(str(second)).sha256)

    def test_interpreter_prefix_fingerprints_the_script_not_the_interpreter(self) -> None:
        path = self.write_hook("guard.py", DENY_EXIT_2)
        identity = self._identity(f"python3 {path}")
        self.assertEqual(identity.path, str(path))
        self.assertIsNotNone(identity.sha256)

    def test_symlinked_target_is_named_and_hashed_by_content(self) -> None:
        real = self.write_hook("real.py", DENY_EXIT_2)
        link = self.project / ".claude" / "hooks" / "link.py"
        link.symlink_to(real)
        identity = self._identity(str(link))
        self.assertEqual(identity.symlink_to, str(real))
        self.assertEqual(identity.sha256, self._identity(str(real)).sha256)

    def test_missing_target_is_reported_without_a_hash(self) -> None:
        identity = self._identity(str(self.project / ".claude" / "gone.sh"))
        self.assertFalse(identity.exists)
        self.assertIsNone(identity.sha256)
        self.assertIn("gone.sh", identity.path)

    def test_no_single_target_says_why(self) -> None:
        for command, expect in (
            ('"${CLAUDE_PLUGIN_ROOT}/g.sh"', "placeholder"),
            ("guard 2>/dev/null || exit 0", "shell construct"),
            ("some-tool --strict", "PATH"),
        ):
            with self.subTest(command=command):
                identity = self._identity(command)
                self.assertIsNone(identity.path)
                self.assertIn(expect, identity.note)

    def test_static_only_json_carries_the_fingerprint(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hookprobe.cli import main

        path = self.write_hook("guard.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", str(path))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main([str(self.project), "--no-home", "--static-only", "--json"])

        identity = json.loads(buffer.getvalue())["hooks"][0]["identity"]
        self.assertEqual(identity["resolvedPath"], str(path))
        self.assertEqual(len(identity["sha256"]), 64)
        self.assertTrue(identity["exists"])

    def test_explain_shows_settings_file_and_hash(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hookprobe.cli import main

        path = self.write_hook("guard.py", DENY_EXIT_2)
        self.simple_settings("PreToolUse", str(path))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main([str(self.project), "--no-home", "--explain", "guard"])
        text = buffer.getvalue()

        self.assertIn("settings file", text)
        self.assertIn("resolves to", text)
        self.assertIn("sha256", text)


class SafetyTests(ProjectTestCase):
    """Two things a tool that runs other people's programs has to have before
    anyone else runs it: a ceiling on what a handler can do to the machine, and
    a way to look without running anything."""

    def test_output_flood_is_capped_and_reported(self) -> None:
        import time as clock

        body = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdin.read()\n"
            "line = 'y' * 1000 + '\\n'\n"
            "while True:\n"
            "    sys.stdout.write(line)\n"
        )
        path = self.write_hook("flood.py", body)
        self.simple_settings("PostToolUse", str(path))
        started = clock.monotonic()
        _, probes = self.probe_all()

        self.assertLess(clock.monotonic() - started, 30, "the flood must be cut, not waited out")
        self.assertIn("P07.OUTPUT_FLOOD", codes(probes[0]))
        self.assertLessEqual(len(probes[0].neutral.stdout), 1_000_000)
        self.assertTrue(probes[0].neutral.flooded)

    def test_static_only_never_runs_a_handler(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hookprobe.cli import main

        marker = self.project / "ran.txt"
        path = self.write_hook("touch.sh", f"#!/bin/sh\ncat >/dev/null\ntouch {marker}\nexit 0\n")
        self.simple_settings("PreToolUse", str(path))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([str(self.project), "--no-home", "--static-only"])

        self.assertFalse(marker.exists(), "--static-only must not execute anything")
        self.assertEqual(code, 0)

    def test_static_only_still_sees_what_disk_shows(self) -> None:
        import io
        from contextlib import redirect_stdout

        from hookprobe.cli import main

        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([str(self.project), "--no-home", "--static-only"])

        self.assertEqual(code, 1)
        self.assertIn("execute bit", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
