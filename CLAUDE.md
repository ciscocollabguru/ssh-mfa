# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Bash automation that enables TOTP two-factor SSH authentication on any
dnf-based RPM distribution — RHEL 8+ and its rebuilds (AlmaLinux, Rocky,
CentOS Stream, Oracle Linux) and Fedora — for all named users, with `root`
exempt. No application code: it edits `/etc/pam.d/sshd`,
`/etc/ssh/sshd_config.d/`, SELinux policy and, optionally, installs helpers
under `/usr/local/sbin`.

Validated end to end on AlmaLinux 8.10 with SELinux enforcing. Other members
of the family are covered by detection and tests but have not been run on
real hardware — treat EL9/10 and Fedora as untested in practice.

`CHANGELOG.md` records the non-obvious failures found on a real host; read it
before changing enrolment or SELinux behaviour, because most of them
presented as something other than what they were.

## Commands

```bash
./tests/test-pam-stack.sh          # 70 assertions on the PAM generator
./tests/test-selfenroll-flags.sh   # 19 assertions that enrolment asks nothing
./tests/test-os-detect.sh          # 21 assertions on distribution detection
bash -n <script>                   # syntax check
shellcheck -S warning install.sh scripts/*.sh scripts/lib/common.sh helpers/* tests/*.sh

sudo ./install.sh --dry-run        # print every proposed change, apply nothing
sudo scripts/90-validate.sh        # read-only verification, non-zero on failure
```

All three suites run on macOS with no root, PAM or SELinux. Individual cases
are not separately addressable; each suite is a flat script with its own
`assert`. To run one section, add an early `exit`.

Anything touching `/etc`, `dnf`, `systemctl`, `runuser`, `semanage` or
`semodule` cannot be exercised locally — and SELinux policy **cannot be
compiled** on macOS. Test those in a VM of the target distribution.
`MFA_ALLOW_ANY_OS=yes` bypasses the OS check.

## Architecture

`scripts/lib/common.sh` is sourced by everything and holds all shared logic:
logging, `load_config`, backup/manifest handling, sshd helpers, user
enumeration, the PAM stack generator, and the secret-file helpers
(`secure_secret`, `apply_state_policy`, `pad_b32`, `check_user_code`). The
numbered scripts are thin drivers over it.

Run order, all idempotent: 00 preflight (read-only) → 10 packages →
15 SELinux labels → 16 SELinux policy module → 45 enrolment gate →
20 PAM → 30 sshd → 40 enrol → 50 enforce strict → 90 validate → 99 rollback.

`install.sh` runs 00→30 in that order. **SELinux must precede PAM and sshd**,
or the host is left demanding a code the module may not record. **The gate
must precede PAM and sshd**, because both generators emit a branch for its
group.

### The PAM generator is the load-bearing part

`pam_block()` / `pam_render()` in `common.sh` generate the marker-delimited
block written into `/etc/pam.d/sshd`. They live in the library, not inline in
`20-configure-pam.sh`, so the tests exercise the production code path.

The block uses `[success=N default=ignore]` jumps to route three outcomes:
exempt (no TOTP), enrolling (TOTP with `nullok`), everyone else (TOTP under
the global `NULLOK`). **N counts modules to skip and depends on the block's
exact length and position.** Adding a line silently invalidates every jump
above it and the failure mode is a locked-out fleet. Read
`docs/DESIGN.md#the-successn-jumps`, and re-run the tests: they assert each
jump's declared count *and* the line it lands on, for all four
mode × gate combinations.

Two invariants the tests enforce, both security-relevant:

- Exempt branches land on the pre-existing `auth substack password-auth`,
  never on `pam_permit` or `success=done`. Exempt accounts must still meet a
  real credential check, so removing root's sshd `Match` block cannot yield
  credential-free auth.
- The strict TOTP module is not `nullok` while the enrolling one is, and a
  failed strict TOTP dies rather than falling through to the password stack.

### Exclusion happens in two layers

sshd `Match` blocks decide which methods a connection needs (where root is
exempted); the PAM stack decides what a keyboard-interactive conversation
prompts for (defence in depth). Both are needed. Exemption criteria:
`EXEMPT_USERS`, membership of `EXEMPT_GROUP`, or UID < `MIN_UID`.

### The secret file is rewritten on every login

This is the source of most of this project's history.
`pam_google_authenticator` records used codes (`-d`) and rate-limit state
(`-r`/`-R`) by creating `.google_authenticator~XXXXXX` in the home directory
and renaming it. Consequences, each of which caused a silent
"correct code, login refused, no message":

- The secret must be `0600`, not `0400`.
- Under enforcing SELinux the create is denied. `fcontext` **cannot** fix it:
  it governs what `restorecon` applies, not creation-time labels, and the
  random suffix defeats named type transitions. That needs
  `selinux/ssh-mfa-gauth.te` via `16-selinux-policy.sh`.
- `TOTP_STATEFUL=no` sidesteps both by stripping the option lines
  (`apply_state_policy`), trading away replay protection and rate limiting.

### Configuration

`config/mfa.env` (gitignored, copied from `mfa.env.example`) is sourced by
`load_config`. `AUTH_MODE` is `pubkey+totp` or `password+totp`; a mixed mode
is impossible because sshd's `password` and `keyboard-interactive` methods
share one PAM auth stack. `MFA_NULLOK` / `MFA_AUTH_MODE` override the file,
which is how `50-enforce-strict.sh` flips `nullok` without rewriting it.

## Conventions

- Every mutating script takes `--dry-run`; add it to any new one.
- Do not hardcode a distribution or version. `detect_os` sets `OS_ID`,
  `OS_MAJOR`, `OS_FAMILY` (`el`/`fedora`) and `OS_NEEDS_EPEL`; branch on
  those. It takes an os-release path so tests drive the real function.
  Probe for sshd keywords with `sshd_supports_keyword` rather than inferring
  from a version number.
- Call `backup_file` before writing anything under `/etc`. It records absent
  files as `ABSENT` so `99-rollback.sh` deletes files we created. One backup
  set per run — `install.sh` calls `begin_backup_set` so a rollback undoes
  PAM and sshd together.
- Gate every sshd reload on `sshd_validate`, and use `systemctl reload`,
  never `restart` — the operator is usually applying this over SSH.
- **Never invoke `google-authenticator` with output captured and a prompt
  possible.** Omitting a flag does not accept a default; the tool stops and
  asks, and with stdout redirected the question is invisible while it
  consumes stdin. `tests/test-selfenroll-flags.sh` guards both call sites.
- Pad base32 before handing a secret to `oathtool`. A 128-bit key is 26
  unpadded chars, and a decode failure is indistinguishable from a wrong
  code.
- Prefer bash builtins over `awk`/`sed` for multi-line text: `awk -v` cannot
  portably carry a newline-containing value, and sed's insert commands mangle
  the `[success=N]` brackets.
- When adding a check to `90-validate.sh`, ask what would make it fail. A
  validator that encodes the same assumption as the code it checks confirms
  nothing — this one passed a broken host three times.
- `docs/` is written for the operator, not contributors. Anything a human
  must do by hand goes in `docs/MANUAL-STEPS.md` as a numbered step with the
  reason it is not automated.
