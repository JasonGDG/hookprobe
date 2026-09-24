#!/bin/sh
# Append every tool call to a log. Never blocks.
cat >> "${CLAUDE_PROJECT_DIR:-.}/.claude/audit.log"
exit 0
