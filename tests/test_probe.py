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
        self.assertFalse(
            (self.project / ".claude" / "hooks" / "hookprobe-recorder.py").exists()
        )

    def test_report_names_handlers_that_never_ran(self) -> None:
        from hookprobe import record

        path = self.write_hook("guard.py", self.GUARD)
        self.simple_settings("PreToolUse", str(path))
        config = self.load()
        text = record.render(self.project, config.hooks, 900.0)
        self.assertIn("guard.py", text)
        self.assertIn("never", text)


if __name__ == "__main__":
    unittest.main()
