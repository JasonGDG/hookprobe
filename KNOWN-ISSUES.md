# Known issues

Found, verified, not fixed. A tool that reports on other people's silent failures does not get
to keep a quiet list of its own, so this one is public and ordered by how wrong the tool can be
because of it.

Every entry was reproduced. Codes in brackets refer to the code review of 22.09.2026.
Entries that have since been fixed are listed at the bottom, so the list can be trusted as a
record rather than quietly shrinking.

## Wrong verdicts are possible

**`--live` attributes its verdict to handlers it never tested.** [K14, partly]
The exit code now turns 1 when the channel ignores a deny, but the `effective` column is filled
from one measurement of hookprobe's own canary hook. A plugin handler that blocks when called
directly and never fires inside Claude still shows `effective: yes`.

**`--live` gives the model unrestricted Bash.** [K15]
`--allowedTools Bash` (live.py:81) permits any shell command, not just the canary, and the child
inherits the full environment via `os.environ.copy()`. The consent prompt sits behind
`sys.stdin.isatty()` (cli.py:260), so in CI or behind a pipe two real sessions start without a
question. The README discloses the terminal-only wording; the unrestricted tool grant it does
not mention.

## Missing limits and unfinished checks

**The default run is not isolated.** [K7, what remains]
Hooks run with `os.environ.copy()` in the real project directory: a handler can read the
environment, write into the project and reach the network. `--static-only` now exists and the
run says on stderr that it is about to execute handlers, but there is no sandbox and no
per-handler consent. Use `env -i` and `--static-only` on anything you do not trust.

**The stdin heuristic is inverted and weak.** [W4]
`P10.STDIN_BLOCK` is emitted when the handler does *not* appear to read stdin, and the markers
(`read `, `stdin`) match ordinary comments. `run_handler(..., stdin_mode="empty")` exists and is
never called, so the empty-stdin probe promised in the spec does not happen.

**The rejection payload is per tool, not per guard.** [K11 remainder]
Six tools have one (`Bash`, `Write`, `Edit`, `NotebookEdit`, `Read`, `WebFetch`); everything
else, MCP tools above all, receives the Bash-shaped payload. And even for Bash there is one
payload: a guard against `git push --force` (karanb192's git-safety.js) sees `rm -rf`, rejects
nothing, and is reported as untested. Correct, but a working guard stays unverified until the
probe can read what a guard is looking for.

**Not every blocking signal is recognised.** [W6]
`{"continue": false}` is not read as a stop signal, and `hookSpecificOutput` without
`hookEventName` is accepted although the schema requires it.

## Judgement calls that may be wrong

**`_intends_to_decide` reads the handler's source.** A guard whose rejection path contains none
of the expected words — a compiled binary, a non-English code base, a wrapper that delegates — is
treated as a logging hook: it gets no "rejected nothing" finding and is not counted when deciding
whether any working guard is left.

**Three inherited overreaches.** [W12] `disableAllHooks` is a sticky OR across sources instead of
following settings precedence; `P03` claims an unknown event disables every hook in the file
where the current documentation describes a skipped entry with a warning; matchers are validated
with Python `re` although Claude Code uses JavaScript regular expressions, so `(?<tool>Bash)` is
valid there and reported as broken here.

**The matcher does not steer the probe.** [W13] `_matching_value` computes whether a matcher can
match at all and the result is discarded; the handler is probed with Bash regardless, and
`P04.MATCH_NOT_CONSTRUCTED` is never emitted.

## Out of reach by construction

Not defects, but the same practical effect: a backdoor keyed to a single session id, a verdict
that depends on the clock, a handler that deletes itself after the first call, and races between
parallel sessions. `--watch` proves the hook mechanism is alive rather than that one particular
guard still fires; `--record` answers that per handler, at the price of routing each command
through a recorder.

## Process

There is no release on PyPI and the repository is private, so none of this is in anyone else's
hands yet. The three suites run in CI since 23.09.

A second code review (Codex, 23.09.2026, against ec5faa9) found fifteen problems in the recorder
and `--ask` after the first review's fixes had landed; fourteen are fixed below, one is
documented behaviour with a warning. Its verdict at the time -- "not yet trustworthy enough to
run against a real project" -- was right, and the specific reasons are the fixed list's last
entry. The recorder rewrites the shared project file while recording; that stays true, and the
install now says so.

## Fixed since this list was written

- The handler's configured `timeout` is now the probe's limit, so a handler Claude Code would
  discard is no longer credited with blocking. [K9]
- Exit 2 counts as an answer; the strictest guard is no longer filed as broken. [K6]
- Exceeding the output cap is a warning, not a protection failure. [W2]
- `--live` reports inconclusive when its own guarded run crashed, instead of reporting success,
  and a channel that ignores a deny now reaches the exit code. [K13, K14 in part]
- `--explain` returns the real status and `--timeout` reaches `--live`. [W9, W10]
- One hook that raises no longer takes the whole report with it. [W11]
- The two contradictory tables of blocking events were merged into the documented one. [K12]
- Each tool now receives a rejection payload it would actually carry. [K11 in part]
- `--record-install` ran every handler twice: it appended a recorder entry next to the
  original instead of replacing it. Measured in a real session (one PreToolUse hook, one Bash
  call: 1 invocation before, 2 after, 1 again after the fix). The recorder now rewrites the
  entry in its own settings file and `--record-remove` restores it; managed, plugin and
  agent-frontmatter handlers are named as not recordable instead of being copied. [found 23.09.]
- Six false alarms found by pointing the probe at three public repositories on 23.09.: `uv run
  x.py` read as a script named `run` (13 of 13 healthy hooks "not protecting anything"), `$HOME`
  left unexpanded and called a relative path, node's "Cannot find module" not recognised as a
  failed launch (12 missing hooks told to "return exit code 2"), `${CLAUDE_PLUGIN_ROOT}` unresolved
  for a `hooks/hooks.json` given via `--settings`, flow-style lists in agent frontmatter rejected
  (32 agents "switch hooks off"), and determinism judged by stdout bytes instead of verdict (a
  Setup hook quoting the session id was "nondeterministic"). Each is pinned by a test; the README
  section "Against other people's setups" has the table. [found 23.09.]
- Fourteen findings of the second review (23.09.): the recorder replayed every handler through
  `/bin/sh` and kept `args`, so a `"shell": "bash"` guard blocked everything or nothing (now
  replayed under bash; exec-form handlers named, not wrapped); `--record-remove` hard-coded
  `~/.claude` and ignored `CLAUDE_CONFIG_DIR`, leaving a user-level hook pointing at a deleted
  recorder in every project (a manifest of touched files now drives the restore); the documented
  unbraced `"$CLAUDE_PROJECT_DIR"/...` form was never substituted and came back "missing";
  `--record` keyed calls by `event:basename(last token)` so distinct handlers collided (a per-file
  key now, basename for display only); installing over an older appended wrapper brought the
  double run back (legacy entries are cleared first); the acceptance key ignored file and matcher;
  `--fix` and the `--ask` repair resolved relative paths against the process cwd; the recorder
  shebang assumed `python3` on Claude's PATH (the installing interpreter is used); the handler
  could see `HOOKPROBE_*` in its environment; `--explain` ignored acceptances; a malformed managed
  command crashed the install; marker recognition was substring-based; a timed-out recorder left
  the handler running. Each has a test that executes the generated wrapper line through `/bin/sh`
  or the CLI from a foreign directory. [found 23.09.]
- Hook output is capped at 1 MB per stream; a handler that writes more is ended and reported
  as `P07.OUTPUT_FLOOD` instead of taking 5 GB of memory. [K8]
- `--static-only` reads the configuration and runs nothing; the default run announces on
  stderr that it is about to execute handlers. [K7 in part]
- The package no longer claims `OS Independent`; it is POSIX (macOS, Linux). [W14]
- The three suites run in GitHub Actions on Ubuntu and macOS, Python 3.11 and 3.13.
- Every entry now carries an identity fingerprint (settings file, resolved target, SHA-256, size,
  mtime, symlink target), in `--explain` and in `--json`, and computed under `--static-only`.
  Asked for in anthropics/claude-code#83952; what remains out of reach is the other half of that
  request — only the runtime can say which file it is about to execute, and this still infers
  from disk. [24.09.]
