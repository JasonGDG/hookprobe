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

## Honesty of the tool's own description

**The default run is not isolated.** [K7]
Hooks run with `os.environ.copy()` in the real project directory: a handler can read the
environment, write into the project and reach the network. The README states this plainly now,
including that each handler is executed five times, but there is still no `--static-only` and no
confirmation before someone else's code is run.

**`Operating System :: OS Independent` is not true.** [W14]
POSIX execute bits, `/bin/sh`, Unix shebangs, process groups. The suite does not run on Windows,
and one test depends on CPython's English wording for a missing file.

## Missing limits and unfinished checks

**No limit on hook output.** [K8]
`communicate()` buffers everything. The reviewer measured 5.27 GB resident and 96 seconds against
a handler writing `yes` in a loop; the probe timeout bounds the first read, not the drain.

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

The stress suite and the scenario suite are run by hand, not in CI. There is no release on PyPI
and the repository is private, so none of this is in anyone else's hands yet.

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
