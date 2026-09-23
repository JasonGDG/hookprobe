"""--ask: hooks that are off, the reason, and whether that is intended.

The contract under test: an acceptance is tied to the exact problem, "no"
applies only the two safe repairs, "skip" changes nothing, and none of it runs
without a terminal.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tests.helpers import ProjectTestCase  # noqa: E402
from tests.test_probe import DENY_EXIT_2  # noqa: E402


def scripted(*answers: str):
    queue = list(answers)

    def answer(_prompt: str) -> str:
        return queue.pop(0) if queue else ""

    return answer


class AskTests(ProjectTestCase):
    def _walk(self, *answers: str):
        from hookprobe import ask

        config, probes = self.probe_all()
        said: list[str] = []
        outcome = ask.walk(self.project, config, probes, scripted(*answers), said.append)
        return outcome, "\n".join(said)

    def _main(self, *extra: str) -> tuple[int, str]:
        from hookprobe.cli import main

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([str(self.project), "--no-home", *extra])
        return code, buffer.getvalue()

    def _with_disable_all(self) -> Path:
        path = self.write_hook("deny.py", DENY_EXIT_2)
        settings = self.simple_settings("PreToolUse", str(path))
        data = json.loads(settings.read_text("utf-8"))
        data["disableAllHooks"] = True
        settings.write_text(json.dumps(data), "utf-8")
        return settings

    def test_accepted_hook_stops_counting_as_broken(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        self.assertEqual(self._main()[0], 1)

        outcome, said = self._walk("y", "being rewritten this week")

        self.assertEqual(len(outcome.accepted), 1)
        self.assertIn("P01.NOT_EXECUTABLE", said)
        self.assertIn("fix would be", said)
        code, text = self._main()
        self.assertEqual(code, 0)
        self.assertIn("Off on purpose", text)
        self.assertIn("being rewritten this week", text)
        self.assertNotIn("not protecting anything", text)

    def test_saying_no_restores_the_execute_bit(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))

        outcome, _ = self._walk("n")

        self.assertEqual(len(outcome.fixed), 1)
        self.assertTrue(path.stat().st_mode & 0o100, "execute bit must be back")
        self.assertEqual(self._main()[0], 0)

    def test_skip_changes_nothing(self) -> None:
        from hookprobe import ask

        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))

        outcome, _ = self._walk("s")

        self.assertEqual(outcome.skipped, [outcome.skipped[0]])
        self.assertFalse(ask.accepted_path(self.project).exists())
        self.assertFalse(path.stat().st_mode & 0o100)
        self.assertEqual(self._main()[0], 1)

    def test_new_problem_on_an_accepted_hook_is_asked_again(self) -> None:
        from hookprobe import ask

        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        self._walk("y", "")
        path.unlink()  # a different problem now: the file is gone

        _, probes = self.probe_all()
        self.assertIsNone(ask.is_accepted(probes[0], ask.load_accepted(self.project)))
        self.assertEqual(self._main()[0], 1)

    def test_changed_command_starts_from_zero(self) -> None:
        from hookprobe import ask

        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        self._walk("y", "")
        other = self.write_hook("other.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(other))

        _, probes = self.probe_all()
        self.assertIsNone(ask.is_accepted(probes[0], ask.load_accepted(self.project)))

    def test_disable_all_hooks_no_fixes_the_project_file(self) -> None:
        settings = self._with_disable_all()
        self.assertEqual(self._main()[0], 1)

        outcome, said = self._walk("n")

        self.assertTrue(outcome.settings_changed)
        self.assertIn("P03.HOOKS_DISABLED", said)
        self.assertIs(json.loads(settings.read_text("utf-8"))["disableAllHooks"], False)
        self.assertEqual(self._main()[0], 0)

    def test_disable_all_hooks_yes_is_reported_not_alarmed(self) -> None:
        self._with_disable_all()

        self._walk("y", "demo machine, hooks off on purpose")

        code, text = self._main()
        self.assertEqual(code, 0)
        self.assertIn("accepted on", text)
        self.assertIn("demo machine", text)
        self.assertNotIn("no hook in this project runs at all", text)

    def test_managed_settings_are_never_rewritten(self) -> None:
        from hookprobe import ask
        from hookprobe.config import Configuration, Source

        managed = self.project / "managed-settings.json"
        managed.write_text(json.dumps({"disableAllHooks": True}), "utf-8")
        config = Configuration(
            hooks=[],
            sources=[Source("managed", managed, "managed")],
            issues=[],
            disable_all_hooks=True,
            project_dir=self.project,
        )

        self.assertEqual(ask.fix_disable_all(config), [])
        self.assertIs(json.loads(managed.read_text("utf-8"))["disableAllHooks"], True)

    def test_unfixable_problem_gets_the_manual_step(self) -> None:
        self.simple_settings("PreToolUse", str(self.project / ".claude" / "gone.sh"))

        outcome, said = self._walk("n")

        self.assertEqual(len(outcome.manual), 1)
        self.assertEqual(outcome.fixed, [])
        self.assertIn("cannot fix this itself", said)

    def test_ask_needs_a_terminal(self) -> None:
        from hookprobe.cli import main

        previous = sys.stdin
        sys.stdin = io.StringIO("")
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([str(self.project), "--no-home", "--ask"])
        finally:
            sys.stdin = previous
        self.assertEqual(code, 2)

    def test_same_command_in_two_files_needs_two_answers(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        local = self.project / ".claude" / "settings.local.json"
        local.write_text(
            json.dumps({"hooks": {"PreToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": str(path)}]}]}}),
            "utf-8",
        )

        outcome, _ = self._walk("y", "only the Bash one is on purpose", "s")

        self.assertEqual((len(outcome.accepted), len(outcome.skipped)), (1, 1))
        self.assertEqual(self._main()[0], 1, "the skipped one must still count")

    def test_fix_from_a_foreign_cwd_uses_the_project_dir(self) -> None:
        import os
        import tempfile

        from hookprobe.cli import main

        path = self.write_hook("guard.sh", "#!/bin/sh\ncat >/dev/null\nexit 0\n", executable=False)
        self.simple_settings("PreToolUse", ".claude/hooks/guard.sh")
        elsewhere = tempfile.mkdtemp(prefix="hookprobe-elsewhere-")
        previous = os.getcwd()
        os.chdir(elsewhere)
        self.addCleanup(os.chdir, previous)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            main([str(self.project), "--no-home", "--fix"])

        self.assertTrue(path.stat().st_mode & 0o100, "the project's file must get the bit")

    def test_explain_honours_the_acceptance(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        self._walk("y", "known")

        code, text = self._main("--explain", "deny")

        self.assertEqual(code, 0)
        self.assertIn("deny.py", text)

    def test_json_output_carries_the_acceptance(self) -> None:
        path = self.write_hook("deny.py", DENY_EXIT_2, executable=False)
        self.simple_settings("PreToolUse", str(path))
        self._walk("y", "known")

        code, text = self._main("--json")

        payload = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(payload["summary"]["broken"], 0)
        self.assertEqual(payload["summary"]["acceptedAsOff"], 1)
        self.assertTrue(payload["hooks"][0]["acceptedAsOff"])
        self.assertEqual(payload["accepted"][0]["reason"], "known")


if __name__ == "__main__":
    unittest.main()
