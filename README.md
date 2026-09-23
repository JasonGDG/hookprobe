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
PreToolUse · deny-rm.py    project  yes     no       untested
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
PreToolUse · deny-rm.py    project  yes     no       untested   n/a
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
| **Placement** | hooks in agent frontmatter, `once: true` in skills, the Desktop tab | partly |
| **Effectiveness** | the hook fires, but its verdict does not change the call | **yes** (`--live`) |
| **Channel** | headless behaves differently from interactive | **yes** (`--live`) |

The default run is offline: no network, no API key, no tokens. Only `--live` spends two real
sessions, and it asks before it does.

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

A probe proves the moment of the test, not the future. These stay out of reach, and all of them
are documented failures:

- **Time-dependent failures** — a hook can run for hours and then stop, for example because its
  log grew to 48 GB ([#16047]) or for no visible reason ([#76322]).
- **State changes after the run** — a single `cd` ends the file watcher for the rest of the
  session ([#95440]).
- **Concurrency** — parallel sessions overwrite each other's configuration ([#95474]).
- **Self-removal** — the agent deletes the hook file meant to restrain it ([#32990]).
- **Intermittent outages** — hooks gone for 30 minutes, then back by themselves ([#90296]).
- **Someone else's environment** — hookprobe measures the environment it runs in; where the
  configuration lives changes the result ([#85613]).

hookprobe is a thermometer, not medicine. Run it before each session, not once a month.

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

## Development

```sh
python -m unittest discover -v
```

Every test mirrors a documented failure case; the fixtures are real files on disk, not mocks.

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
