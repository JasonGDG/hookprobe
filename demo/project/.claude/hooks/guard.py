#!/usr/bin/env python3
"""Refuse destructive shell commands. Exit 2 is the only code that blocks."""
import json
import sys

data = json.load(sys.stdin)
command = data.get("tool_input", {}).get("command", "")
if "rm -rf" in command or "sudo" in command:
    print(f"refused by policy: {command}", file=sys.stderr)
    sys.exit(2)
print(json.dumps({"permissionDecision": "allow"}))
