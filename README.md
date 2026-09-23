# hookprobe

**Your protective hooks all show green. Two of them stopped checking weeks ago.**

Claude Code hooks are the place where permissions are actually enforced — a language model
is not a permission system. But a hook is a separate program on disk, and every step between
"listed in `settings.json`" and "running" can fail without a word. When it does, Claude Code
does not stop:

> "Claude Code treats exit code 1 as a non-blocking error and proceeds with the action."
> — Claude Code hook documentation

> "a mistyped path in settings.json leaves the gate silently disabled."
> — Claude Code hook documentation

A broken guard is worse than no guard. Without one you know you are exposed; with a silent one
you believe you are covered. In [anthropics/claude-code#81458] a hook failed to start **6,865
times in a single session** and nobody noticed.

`hookprobe` answers three questions per hook, separately: **does it start**, **does it answer**,
and **could it block** — the three properties you cannot read off a config file.

## Example

```
$ hookprobe --no-home

Hook                       source   starts  answers  can block
--------------------------------------------------------------
PreToolUse · guard.sh      project  yes     yes      yes
PreToolUse · deny-rm.py    project  no      no       no
SessionStart · context.py  project  yes     yes      n/a

2 of 3 hooks are not protecting anything.

  deny-rm.py
      deny-rm.py has no execute bit -- the gate is silently disabled.
      fix: Run chmod +x <path> and preserve the executable bit in version control.
      evidence: anthropics/claude-code#94362, docs:hook-cannot-start

  context.py
      additionalContext is 14,208 characters -- above the 10,000 cap.
      Everything past the cap is written to a file that Claude is not asked to read.
      evidence: anthropics/claude-code#94358, docs:output-cap
```

With `--live` the channel itself is measured as well:

```
$ hookprobe --no-home --live

The canary was created only without the hook: a deny verdict takes effect in
this channel (guarded run exit 0).

Hook                       source   starts  answers  can block  effective
-------------------------------------------------------------------------
PreToolUse · guard.sh      project  yes     yes      yes        yes
PreToolUse · deny-rm.py    project  no      no       no         n/a
SessionStart · context.py  project  yes     yes      n/a        n/a

Channel check: a deny verdict does take effect here -- measured against two
disposable sessions.
```

Exit code is `1` as soon as one hook is ineffective, so you can put it in front of your session:

```sh
hookprobe --no-home && claude
```

## Install

```sh
uvx hookprobe            # no installation
pipx install hookprobe   # or keep it around
```

Python 3.11+, standard library only. No dependencies.

## What it checks

| Check | What goes wrong | Needs a session |
|---|---|---|
| **Startability** | no execute bit, wrong path, missing interpreter, space in the path that `/bin/sh` splits | no |
| **Exit-code semantics** | only exit 2 blocks — a rejection path using `exit 1` never blocks anything | no |
| **Schema guard** | one malformed matcher switches off *all* hooks in that file | no |
| **Matcher** | ten events accept no matcher at all; there it is silently ignored | no |
| **Output shape** | a greeting from your shell profile in front of the JSON breaks parsing | no |
| **Output cap** | above 10,000 characters the value is written to a file Claude is not asked to read | no |
| **Timeout** | a hook waiting on stdin runs into its timeout — and a timed-out `PreToolUse` hook does **not** block | no |
| **Placement** | hooks in agent frontmatter, `once: true` in skills, plugin sources | partly |
| **Still firing** | hooks that stop mid-session, long after any one-off check | `--watch` |
| **Which one died** | one handler stops while the others keep going | `--record` |
| **Determinism** | the same request answered differently on the second try | no |
| **Hidden inputs** | a verdict that changes with the session id, or only while it is watched | no |
| **Wrapped commands** | `guard 2>/dev/null \|\| exit 0` when `guard` is not installed | no |
| **Effectiveness** | the hook fires, but its verdict does not change the call | **yes** (`--live`) |
| **Channel** | whether a deny verdict is honoured in headless mode at all | **yes** (`--live`) |

The default run needs no network, no API key and no tokens **of its own** — but be clear about
what it does: it **executes every configured hook five times** (one neutral probe, two repeats
for the determinism check, one decoy, one rejection probe), each with a payload on stdin. Those are
your programs, and they run with your environment in your project directory, exactly as Claude
Code would run them. If a hook writes files or calls out to the network, it will do that here
too. Only `--live` spends two real sessions, and it asks first when run from a terminal.

## Off on purpose

A hook that is off is not always a defect. The execute bit may be missing while someone
rewrites the script; `disableAllHooks` may be set on a demo machine. The default run cannot
tell, so it reports and exits 1 every time. `--ask` is the opt-in middle ground:

```sh
hookprobe --ask
```

```
[1/2] PreToolUse · deny-rm.py  (project (.claude/settings.json))
  off because: The handler file is not executable.  [P01.NOT_EXECUTABLE]
  fix would be: chmod +x .claude/hooks/deny-rm.py
  Is this off on purpose?  [y]es, keep it   [n]o, fix it   [s]kip (Enter)  > y
  Why? (one line, optional) > being rewritten this week
  kept. It will be listed as off on purpose from now on.
```

*Yes* is remembered in `.claude/hookprobe-accepted.json` with the reason and the date. From
then on the report lists that hook under *Off on purpose* instead of counting it as broken, and
the exit code follows. The acceptance is tied to the event, the command and the exact problems
accepted: a new problem on the same hook is asked about again, a changed command starts from
zero. Delete the entry to be asked again.

*No* applies the repair when there is a safe one — the execute bit, or `disableAllHooks` in a
file hookprobe may write (never managed settings) — and otherwise prints the manual step.
*Skip* changes nothing.

`--ask` needs a terminal. Without one it stops with exit 2 rather than guessing.

## How `--live` works

Effectiveness cannot be read from a single run — you cannot tell "the hook blocked it" from
"the model never tried". And it makes no sense to ask whether *your* hooks block a harmless
canary: they are supposed to let it through. So `hookprobe --live` installs a known-good deny
hook of its own and runs a canary task twice in a throwaway directory:

```
run A  with hookprobe's deny hook   -> the side effect must NOT appear
run B  without any hook (control)   -> the side effect MUST appear
```

That measures the property you cannot see otherwise: **does a deny verdict take effect in this
channel at all?** If the canary appears in both runs, the mechanism is not enforcing anything
here and every verdict your own hooks return is decoration — the failure mode reported in
[#95726], where "ask" silently becomes "deny" in `--print` mode. If it appears in neither run,
the canary task itself failed and `hookprobe` says inconclusive instead of reporting a false
green.

It measures **side effects, not harness events** on purpose: measured over 36 `claude -p` runs
in [anthropics/claude-code#94275], `hook_started` and `hook_response` appear in the stream only
for `SessionStart`.

## What it cannot do

Some of this list used to be longer. `--watch` and the probe-hardening closed four of the
entries; what stands below is what genuinely remains, with the ones that only moved rather than
disappeared marked as such.

- **A backdoor keyed to one session id** — a handler that allows everything for exactly one
  `session_id` cannot be found by sampling. The decoy comparison finds handlers that react to
  *the shape* of the payload; it cannot guess a specific value.
- **A coin flip** — a verdict that depends on the clock is caught by three repeated probes
  roughly three times in four, not always.
- **A handler that removes itself** after its first call ([#32990]) — the probe sees the first
  answer, and the configuration that produced it is gone by the time anyone looks.
- **Concurrency** — parallel sessions overwriting each other's configuration ([#95474]) is a
  race that a sequential probe cannot reproduce.
- **Someone else's environment** — hookprobe measures the environment it runs in; where the
  configuration lives changes the result ([#85613]).

Moved rather than solved:

- **Time-dependent failures** ([#16047], [#76322]) and **intermittent outages** ([#90296]) are
  reachable with `--watch` for the mechanism as a whole, and with `--record` per handler —
  at the price of routing each command through a recorder.
- **State changes after the run** — a `cd` that ends a file watcher ([#95440]) shows up in
  `--watch` as a heartbeat gap only if it takes the heartbeat with it.

hookprobe is a thermometer, not medicine. Run it before each session, and leave `--watch`
running during it.

## How this differs from existing tools

| Tool | What it does | starts? | answers? | effective? |
|---|---|---|---|---|
| `kVadrum/hookprobe` | runs hooks with synthetic input | mock | yes | no |
| `drakeo338/hookprobe` | static config linter, no network | no | no | no |
| `Tomdachs/agent-hook-probe` | disposable workspaces against real runtimes | yes | yes | no |
| Anthropic `test-hook.sh` | "Tests a hook with sample input" — never evaluates the matcher | mock | yes | no |
| `/hooks` (built in) | "a read-only browser for your configured hooks" | no | no | no |
| **hookprobe** | executes like the harness, then measures the difference | yes | yes | yes |

The gap this fills is stated by an open issue in the tracker itself:

> "Configured and effective are different properties, and only the first is observable today."
> — [anthropics/claude-code#82323]

## Watching a running session

A probe proves the moment of the test. The failures it cannot see are the ones that happen
later: hooks that stop firing mid-session ([#76322]), a log that grows until the handler dies
([#16047]), a single `cd` that ends a watcher for the rest of the session ([#95440]).

So turn the question around and let the hooks report in themselves:

```sh
hookprobe --install-heartbeat   # adds a non-blocking handler, marked and removable
hookprobe --watch               # did anything call a hook while you worked?
hookprobe --watch --follow      # keep printing when the verdict changes
hookprobe --uninstall-heartbeat
```

```
Heartbeat installed : yes
Last hook report    : 22s ago
Last session write  : 14s ago

Events in the last 15 minutes:
  PostToolUse       31
  UserPromptSubmit   6
  Stop               5

Hooks reported in alongside session activity.
```

The alarm is one specific thing: **this project's session wrote to its transcript, but no hook
reported in.** A quiet heartbeat during a quiet session means nothing and is not reported as a
problem. The comparison is scoped to the project the heartbeat is installed in, so another busy
project cannot raise a false alarm.

### Per handler, during real work

The heartbeat proves that *some* hook fired. It cannot say which one, so a guard that quietly
dies while the logging hooks keep beating stays invisible. `--record` closes that:

```sh
hookprobe --record-install   # route each handler through a transparent recorder
# ... work as usual ...
hookprobe --record
hookprobe --record-remove
```

```
Handler                 calls  last result       took   last seen
-----------------------------------------------------------------
PreToolUse:deny-rm.py   34     exit 0, 2 blocked  41 ms  12s ago
PreToolUse:audit.sh     34     exit 0             8 ms   12s ago
PostToolUse:log.sh      0      -                  -      never

1 of 3 handlers never ran while the others did: PostToolUse:log.sh
```

The recorder runs the original and writes down what happened. It is transparent by
construction: stdin forwarded, stdout and stderr handed through byte for byte, exit code passed
along — stdout carries the decision and the exit code *is* the verdict. If the recorder cannot
start the original it says so and exits 0, the same thing Claude Code does with a handler it
cannot launch, so wrapping is never stricter than not wrapping. A test asserts exactly that, for
an allowing and a blocking payload.

The recorder **replaces** each handler's entry in the settings file it lives in; it does not add
a second entry beside it. That distinction was measured, not assumed: an added entry left the
original registered too, and one PreToolUse hook fired twice for a single Bash call. With the
in-place version it fires once, exactly as without the recorder. `--record-remove` reads the
original command back out of the wrapper, so an unrelated edit made in between is left alone.

Five kinds of handler are named as *not recorded* rather than half-wrapped: managed settings
(enterprise policy), plugin hooks (their `${CLAUDE_PLUGIN_ROOT}` is only set when Claude Code
calls them as plugin hooks), agent frontmatter (markdown, not a settings file), exec-form
handlers with `args` (there is no shell line to replay) and handlers with a shell the recorder
cannot run. A handler that says `"shell": "bash"` is replayed under bash, not `/bin/sh` — a
bash-only guard run through `/bin/sh` blocks everything on macOS and nothing on dash, which is
exactly the kind of change a recorder must not make. The handler does not see the recorder's
own variables.

Every file the recorder rewrites is listed in `.claude/hookprobe-record.json`, and
`--record-remove` restores from that list, including a user-level file under `CLAUDE_CONFIG_DIR`.
One caution the install prints: while recording, the shared `.claude/settings.json` points at
a script on your machine. Do not commit it in that state.

The closest existing tool, `clooks`, converts command hooks into HTTP hooks behind a daemon.
This leaves the handlers, the settings shape and the failure modes as they were and only adds a
witness.

## Repairing

```sh
hookprobe --fix
```

Restores missing execute bits — the one repair that is unambiguous. Nothing else is touched:
rewriting someone's settings file on their behalf is not a repair, it is a second opinion they
did not ask for. Everything else is reported with the exact command to run.

## Known issues

Verified and unfixed, including the ones that can produce a wrong verdict:
[KNOWN-ISSUES.md](KNOWN-ISSUES.md). The short version: the handler's configured `timeout` is
ignored, `--live` reports success when its own run crashed and does not affect the exit code,
hook output is buffered without a limit, and the probe is not isolated from the project.

## Known limits of this version

`--live` measures one channel (`claude -p`), not the difference between headless and
interactive, and it attributes the channel verdict to handlers it did not individually test.
A hook wrapped in a shell construct that swallows its own error (`cmd 2>/dev/null || exit 0`)
cannot be verified from outside — hookprobe says so instead of reporting a pass.

## Development

```sh
python -m unittest discover -v   # 68 unit tests
python tests/stress.py -v        # 49 fixtures with a written-down expected verdict
python tests/scenarios.py        # three whole configurations, end to end
```

Every test mirrors a documented failure case; the fixtures are real files on disk, not mocks.

### Against other people's setups

The fixtures above were written by the same hands that wrote the checks. On 23.09.2026 the
probe was pointed at three public repositories it had never seen, with the expected verdict
written down first:

| Repository | Expected | First run | After the fixes |
|---|---|---|---|
| disler/claude-code-hooks-mastery (3.9k stars, 13 hooks, all `uv run …`) | all healthy, PreToolUse can block | **13 of 13 "not protecting anything"** — `run` taken for the script | 13 start and answer, PreToolUse blocks, exit 0 |
| parcadei/Continuous-Claude-v3 (3.9k stars, 36 hooks under `$HOME/.claude/hooks/dist`) | not installed here, so every file missing | right verdict, wrong reasons: `$HOME/…` called a relative path, 12 missing files told to "return exit code 2", 32 agent files listed as switching hooks off | 36 missing files, nothing else |
| karanb192/claude-code-hooks (525 stars, plugin hooks via `--settings`) | two guards, both should run | both "unresolved placeholder" and "rejects with exit 1" | protect-secrets blocks; git-safety runs, but the Bash probe payload is not what it guards — reported as untested, not as broken |

Six false alarms came out of that, each fixed and pinned by a test: runner subcommands
(`uv run`, `deno run`, `pnpm run`), `$HOME` in a command, node's "Cannot find module" as a
failed launch, the plugin root for a `hooks/hooks.json` given by path, flow-style lists in
agent frontmatter, and determinism judged by stdout bytes instead of by verdict (a Setup hook
that quotes the session id into its context is not nondeterministic).

To repeat it, or to try a setup of your own:

```sh
git clone --depth 1 https://github.com/disler/claude-code-hooks-mastery
cd claude-code-hooks-mastery
env -i HOME="$HOME" PATH="$PATH" CLAUDE_PROJECT_DIR="$PWD" hookprobe . --no-home
```

`env -i` is deliberate: the default run executes the hooks with your environment, and some of
these call a TTS API when they find a key. Write down the verdict you expect before you look at
the one you get. The question is never whether the tool finds something; it is whether it finds
the right thing and stays quiet otherwise.

### Three configurations, end to end

Single fixtures test single judgements; `tests/scenarios.py` asks whether the report as a whole
tells the truth. Every guard healthy must produce nothing to report and exit 0. Every guard
broken, one way each, must produce every finding and exit 1. And the third case is the one that
matters: the guards dead while the logging hooks work — the exact shape of a false sense of
safety. "3 of 8 hooks are not protecting anything" is true there and useless, so the report
names it:

```
No working guard left: all 3 handlers that could block are broken.
The rest of this configuration only observes.
```

### Making the invisible visible

Four of the cases that used to come back as "cannot see that" now have an answer, and the
method is the same each time: stop asking the handler, and change what it is asked.

| Case | Why a single run says nothing | What makes it visible |
|---|---|---|
| Hook hides its failure behind `\|\| exit 0` | it exits 0 either way | resolve every command word against PATH and disk |
| Hook keeps state and blocks only sometimes | one run is one sample | run the identical payload three times and compare |
| Hook behaves while it is watched | the probe announced itself | scrub the tool name from the payload, then send a decoy that carries it |
| Hook writes its decision to stderr | stdout is empty, exit 0 | recognise decision-shaped JSON on the wrong stream |

The probe used to introduce itself: `session_id: "hookprobe-probe-session"`, a canary command
reading `echo hookprobe`, a tool id of `toolu_hookprobe_probe`. Any handler could grep for that
and behave differently exactly while being measured. The ordinary run now looks like ordinary
work, and the obvious payload is kept as a decoy — a handler that answers differently to the
two is telling you something.

Three cases remain honestly out of reach, and they stay in the suite as observations rather
than passes: a backdoor keyed to **one** session id (sampling cannot find it), a coin flip
(three probes catch it about 75% of the time), and a handler that deletes itself after the
first call.

`tests/stress.py` is the harder one: each fixture carries the verdict hookprobe is supposed to
reach, written down before the run. Three groups — **healthy** hooks that must never be called
broken, **broken** ones that must be caught with the right reason, and **adversarial** ones
built to fool the probe, where "unverifiable" counts as a pass and a confident wrong answer
counts as a failure. It found seven real defects the unit tests missed, including a shell syntax
error being read as a working guard, `async: true` handlers credited with blocking they cannot
do, and the probe announcing itself in three separate fields.

## License

MIT

[anthropics/claude-code#81458]: https://github.com/anthropics/claude-code/issues/81458
[anthropics/claude-code#82323]: https://github.com/anthropics/claude-code/issues/82323
[anthropics/claude-code#94275]: https://github.com/anthropics/claude-code/issues/94275
[#16047]: https://github.com/anthropics/claude-code/issues/16047
[#76322]: https://github.com/anthropics/claude-code/issues/76322
[#95440]: https://github.com/anthropics/claude-code/issues/95440
[#95474]: https://github.com/anthropics/claude-code/issues/95474
[#32990]: https://github.com/anthropics/claude-code/issues/32990
[#90296]: https://github.com/anthropics/claude-code/issues/90296
[#85613]: https://github.com/anthropics/claude-code/issues/85613
[#95726]: https://github.com/anthropics/claude-code/issues/95726
