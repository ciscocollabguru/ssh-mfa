# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Bash automation that enables TOTP two-factor SSH authentication on
AlmaLinux 8 (RHEL 8 family), for all named users, with `root` exempt.
No application code — it edits `/etc/pam.d/sshd` and `/etc/ssh/sshd_config.d/`
on the host it runs on.

## Commands

```bash
./tests/test-pam-stack.sh          # the only test suite; no root/PAM/AlmaLinux needed
bash -n <script>                   # syntax check
shellcheck -S warning install.sh scripts/*.sh scripts/lib/common.sh tests/*.sh

sudo ./install.sh --dry-run        # print every proposed change, apply nothing
sudo scripts/90-validate.sh        # read-only verification, non-zero on failure
```

Individual test cases are not separately addressable — `test-pam-stack.sh` is
a single flat script with its own `assert`. To run one section, comment out
the others or add an early `exit`.

Development happens on macOS; the scripts target AlmaLinux 8. Anything
touching `/etc`, `dnf`, `systemctl` or `runuser` cannot be exercised locally —
only `tests/test-pam-stack.sh` runs on the dev machine. Test real changes in
an AlmaLinux 8 VM. `MFA_ALLOW_ANY_OS=yes` bypasses the OS check.

## Architecture

`scripts/lib/common.sh` is sourced by everything and holds all shared logic:
logging, `load_config`, backup/manifest handling, sshd helpers, user
enumeration, **and the PAM stack generator**. The numbered scripts are thin
drivers over it. `install.sh` runs 00→30 then validates.

Scripts are numbered by execution order and are all idempotent:
00 preflight (read-only) → 10 packages → 20 PAM → 30 sshd → 40 enrol →
50 enforce strict → 90 validate → 99 rollback.

### The PAM generator is the load-bearing part

`pam_block()` / `pam_render()` in `common.sh` generate the
marker-delimited block written into `/etc/pam.d/sshd`. They live in the
library rather than inline in `20-configure-pam.sh` specifically so
`tests/test-pam-stack.sh` exercises the production code path.

The block uses PAM `[success=N default=ignore]` jumps to skip the TOTP module
for exempt accounts. **N is a count of modules to skip and depends on the
block's exact position and length in the file.** Changing a line in
`pam_block()` silently invalidates every jump count below it, and the failure
mode is a locked-out fleet. Read `docs/DESIGN.md#the-successn-jumps` and re-run
the tests after any edit there.

Two invariants the tests enforce, both security-relevant:

- Exempt branches jump to the pre-existing `auth substack password-auth`
  line, never to `pam_permit` or `success=done`. Exempt accounts must still
  meet a real credential check, so that removing root's sshd `Match` block
  cannot yield credential-free auth.
- In `pubkey+totp`, a `pam_permit` line jumps *over* the password substack, so
  a non-exempt user is not asked for a password after a valid code.

### Exclusion happens in two layers

sshd `Match` blocks decide which methods a connection needs (this is where
root is exempted); the PAM stack decides what a keyboard-interactive
conversation prompts for (defence in depth). Both are needed — see
`docs/DESIGN.md`. Exemption criteria: `EXEMPT_USERS`, membership of
`EXEMPT_GROUP`, or UID < `MIN_UID`.

### Configuration

`config/mfa.env` (gitignored, copied from `mfa.env.example`) is sourced by
`load_config`. `AUTH_MODE` is `pubkey+totp` or `password+totp`; a mixed mode
is impossible because sshd's `password` and `keyboard-interactive` methods
share one PAM auth stack. `MFA_NULLOK` / `MFA_AUTH_MODE` env vars override the
file, which is how `50-enforce-strict.sh` flips `nullok` without rewriting it.

## Conventions

- Every mutating script takes `--dry-run`; add it to any new one.
- Call `backup_file` before writing to anything under `/etc`. It records
  absent files as `ABSENT` in the manifest so `99-rollback.sh` deletes files
  we created rather than leaving them.
- Gate every sshd reload on `sshd_validate`, and use `systemctl reload`,
  never `restart` — the operator is usually applying this over SSH.
- Prefer bash builtins over `awk`/`sed` for multi-line text: `awk -v` cannot
  portably carry a newline-containing value (this bit once already), and
  sed's insert commands mangle the `[success=N]` brackets.
- `docs/` is written for the operator, not for contributors. Anything a human
  must do by hand belongs in `docs/MANUAL-STEPS.md`, as a numbered step with
  the reason it is not automated.
