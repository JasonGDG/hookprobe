"""Shared scaffolding: a throwaway project with real files on disk."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


class ProjectTestCase(unittest.TestCase):
    """Builds a real .claude directory; no filesystem mocks."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hookprobe-test-")
        self.project = Path(self._tmp.name)
        (self.project / ".claude" / "hooks").mkdir(parents=True)
        self.addCleanup(self._tmp.cleanup)

    def write_hook(self, name: str, body: str, executable: bool = True) -> Path:
        path = self.project / ".claude" / "hooks" / name
        path.write_text(body, "utf-8")
        mode = path.stat().st_mode
        if executable:
            path.chmod(mode | stat.S_IXUSR | stat.S_IRUSR)
        else:
            path.chmod(mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)
        return path

    def write_settings(self, hooks: dict) -> Path:
        path = self.project / ".claude" / "settings.json"
        path.write_text(json.dumps({"hooks": hooks}, indent=2), "utf-8")
        return path

    def simple_settings(self, event: str, command: str, matcher: str | None = "Bash") -> Path:
        group: dict = {"hooks": [{"type": "command", "command": command}]}
        if matcher is not None:
            group["matcher"] = matcher
        return self.write_settings({event: [group]})

    def load(self):
        from hookprobe.config import load

        return load(self.project, include_home=False)

    def probe_all(self):
        from hookprobe.probe import probe_hook

        config = self.load()
        return config, [probe_hook(hook, self.project) for hook in config.hooks]
