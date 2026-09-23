# Known issues

Found, verified, not fixed. A tool that reports on other people's silent failures does not get
to have a quiet list of its own, so this one is public and ordered by how wrong the tool can be
because of it.

Every entry was reproduced. Codes in brackets refer to the code review of 22.09.2026.

## Wrong verdicts are possible

**Fixed since this list was written:** the configured timeout is now respected, exit 2 counts as
an answer, the output cap is a warning rather than a protection failure, `--live` reports
inconclusive when its own guarded run crashed and now reaches the exit code, `--explain` returns
the real status, `--timeout` reaches `--live`, and one hook that explodes no longer takes the
report with it. What follows is what is still open.

**~~The configured timeout is ignored.~~** [K9] — fixed.
`hook.timeout` is never read. The probe uses the documented default, capped at 20 s. A handler
declared with `"timeout": 2` that answers after 8 s with exit 2 is reported as `can block: yes`,
while Claude Code discards it after 2 s and lets the call through. False green on the one column
that matters.

**~~A handler that rejects the neutral payload is called broken.~~** [K6] — fixed.
`answers` is derived from `stdout or exit_code == 0`. A strict allowlist guard refuses the
ordinary probe on purpose, exits 2 and writes its reason to stderr — and lands in the broken
list. The `P08.BLOCKS_EVERYTHING` finding explains it, but the verdict above it still reads
`answers: no`.

**~~Output over the cap counts as "not protecting anything".~~** [W2] — fixed.
`P07.OVER_CAP` is `critical`, so a working `SessionStart` context hook with 10 001 characters is
counted in the broken total. Context quality and protection are different questions and should
not share a counter.

**~~`--live` reports success when its own run crashed.~~** [K13] — fixed.
Only the presence of the canary file is evaluated. If the guarded session fails on auth, a rate
limit or a timeout, the file is absent for the wrong reason and the verdict is
`a deny verdict takes effect`. `guarded_code` is written into the message and never checked.

**`--live` still attributes the channel verdict to handlers it did not test.** [K14, partly]
The exit code now turns 1 when the channel ignores a deny, but the `effective` column is still
filled from a measurement of hookprobe's own canary hook rather than of each handler.
`effective=False` leaves `is_broken` untouched, so the run still exits 0 — against the README's
promise that the exit code turns 1 as soon as a hook is ineffective. The channel verdict is also
attributed to every handler that blocks, although only hookprobe's own canary hook was measured.

## Honesty of the tool's own description

**The default run executes each hook five times, not twice.**
Measured, not estimated: neutral probe, two repeats for the determinism check, one decoy, one
rejection probe. Every side effect a hook has — a log line, a lock file, an outbound request —
happens five times. The README still says "twice".

**The default run is not isolated.** [K7]
Hooks run with `os.environ.copy()` in the real project directory. A hook can read the
environment, write into the project and reach the network. The README says so now, but the tool
offers no `--static-only` and asks for no confirmation before running someone's code.

**`Operating System :: OS Independent` is not true.** [W14]
POSIX execute bits, `/bin/sh`, Unix shebangs, process groups. The suite does not run on Windows,
and one test depends on CPython's English wording for a missing file.

## Missing limits and unfinished checks

**No limit on hook output.** [K8]
`communicate()` buffers everything. The reviewer measured 5.27 GB RSS and 96 s against a hook
writing `yes` in a loop; the probe timeout only bounds the first read, not the drain.

**The stdin heuristic is inverted and weak.** [W4]
`P10.STDIN_BLOCK` is emitted when the handler does *not* appear to read stdin, and the markers
(`read `, `stdin`) match ordinary comments. `run_handler(..., stdin_mode="empty")` exists and is
never called, so the empty-stdin probe promised in the spec does not happen.

**Only six tools have a rejection payload.** [K11 remainder]
`Bash`, `Write`, `Edit`, `NotebookEdit`, `Read`, `WebFetch`. Everything else — MCP tools above
all — receives the Bash-shaped payload, so a guard for those tools can still come back as
"rejected nothing" while working correctly.

**Not every blocking signal is recognised.** [W6]
`{"continue": false}` is not read as a stop signal, and `hookSpecificOutput` without
`hookEventName` is accepted although the schema requires it.

**~~One exception ends the whole run.~~** [W11] — fixed: each hook is probed inside its own
boundary and an exception marks that hook unverifiable.

**~~`--explain` always exits 0~~** [W9] and **~~`--timeout` never reaches `--live`~~** [W10] — both fixed.

## Judgement calls that may be wrong

**`_intends_to_decide` reads the handler's source.** A guard whose rejection path does not
contain any of the expected words — a compiled binary, a non-English code base, a wrapper that
delegates — is treated as a logging hook: no "rejected nothing" finding, and it is not counted
when deciding whether any working guard is left.

**`disableAllHooks` is a sticky OR across sources** [W12] instead of following settings
precedence, `P03` claims an unknown event disables every hook in the file when the current
documentation describes a skipped entry with a warning, and matchers are validated with Python
`re` although Claude Code uses JavaScript regular expressions — `(?<tool>Bash)` is valid there
and reported as broken here.

**The matcher does not steer the probe.** [W13] `_matching_value` computes whether a matcher can
match at all and the result is discarded; the handler is probed with Bash regardless, and
`P04.MATCH_NOT_CONSTRUCTED` is never emitted.

## Out of reach by construction

Not defects, but the same practical effect — see the README for the full wording: a backdoor
keyed to a single session id, a verdict that depends on the clock, a handler that deletes itself
after the first call, races between parallel sessions, and the fact that `--watch` proves the
hook mechanism is alive rather than that one particular guard still fires.

## Process

The stress suite and the scenario suite are not wired into CI; they are run by hand. There is no
release on PyPI and the repository is private, so nothing here is in anyone else's hands yet.
