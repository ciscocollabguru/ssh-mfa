# Changelog

## 1.0.0

First version validated end to end on AlmaLinux 8.10 (`selinux-policy
3.14.3`, `openssh 8.0p1`, `google-authenticator 1.07`), in `password+totp`
mode with SELinux enforcing.

Everything below was found by running this on a real host. The install and
operating procedure changed as a result, so the sections are written as
**what to do differently**, not as a list of commits.

---

## Process changes

### The install sequence gained two SELinux steps and a gate step

`install.sh` now runs:

```
00-preflight → 10-install-packages → 15-selinux → 16-selinux-policy
             → 45-enrollment-gate (if ENROLL_GATE=yes)
             → 20-configure-pam → 30-configure-sshd → 90-validate
```

Two ordering constraints are deliberate:

- **SELinux before PAM and sshd.** Otherwise the host is left requiring a
  second factor that the PAM module is not permitted to record, and every
  correct code is refused.
- **The gate before PAM and sshd.** Both generators emit an extra branch for
  the enrolment group, so the group and its helpers must exist first.

If you previously ran the numbered scripts by hand, add `15` and `16`, and
re-run `20` and `30` afterwards.

### Two new packages are required

`qrencode` and `oathtool`, installed by `10-install-packages.sh`.

- Without `qrencode` no QR code can be drawn, because
  `google-authenticator` only draws one when its stdout is a terminal and
  `40-enroll-user.sh` captures it.
- Without `oathtool` the server cannot compute the code it expects, so
  `40-enroll-user.sh --check` cannot work and self-enrolment releases
  accounts without verifying the user's app.

### Stateful tokens need an SELinux policy module

`pam_google_authenticator` rewrites `~/.google_authenticator` on every login
to record used codes (`-d`) and rate-limit state (`-r`/`-R`). It does so by
creating `.google_authenticator~XXXXXX` in the home directory and renaming
it. Under enforcing SELinux that create is denied, and the failure is
**silent to the user**: the correct code is accepted and the login is still
refused.

Run `scripts/16-selinux-policy.sh` once per host. The alternative is
`TOTP_STATEFUL="no"` plus `40-enroll-user.sh --restate`, which removes the
need for a policy change at the cost of replay protection and per-user rate
limiting.

Labelling alone is **not** sufficient, and an earlier version of this repo
wrongly claimed it was. `fcontext` governs what `restorecon` applies, not the
label a newly created file receives.

### The secret file is 0600, not 0400

It must be writable, because the module rewrites it. At `0400` the rewrite
fails and the login is refused with no message. Existing tokens are repaired
without rotation:

```bash
sudo scripts/40-enroll-user.sh --fix-perms
```

### New accounts can enrol themselves

Set `ENROLL_GATE="yes"` and run `scripts/45-enrollment-gate.sh --install`.
New accounts are gated automatically and forced through self-enrolment on
first login, so no admin handles a secret. See
[`docs/SELF-ENROLLMENT.md`](docs/SELF-ENROLLMENT.md), including what
membership of that group grants while it lasts.

Without the gate, adding a user is a two-step job: create the account, then
`scripts/40-enroll-user.sh <user>`. Under `NULLOK=no` an unenrolled account
cannot log in at all.

### Enrolment asks the user nothing

Every `google-authenticator` prompt is answered by a flag. `-f` alone is not
enough — it only covers the file-update question. Omitting `-d` or `-r`/`-R`
does not quietly accept a default; the tool stops and asks. Both are now
always passed, so reuse is disallowed and rate limiting is on.

### `90-validate.sh` is stricter

It now fails hosts it previously passed. It checks that the module can
actually rewrite each secret (mode `0600`, home writable, correct label) and
that a host running stateful tokens under enforcing SELinux has the policy
module. Re-run it after any change to sshd, PAM or the
`google-authenticator` package.

---

## Migrating a host installed with an earlier version

```bash
git pull
sudo scripts/10-install-packages.sh          # qrencode, oathtool
sudo scripts/15-selinux.sh                   # corrects a wrong label
sudo scripts/16-selinux-policy.sh            # permits the secret rewrite
sudo scripts/40-enroll-user.sh --fix-perms   # 0400 -> 0600
sudo scripts/20-configure-pam.sh
sudo scripts/30-configure-sshd.sh --safety-timer 10
sudo scripts/90-validate.sh
```

None of these rotate a token; users keep the entry in their app. Test a
login from a second terminal before closing your session.

To adopt forced self-enrolment as well, set `ENROLL_GATE="yes"` and run
`scripts/45-enrollment-gate.sh --install`, then re-run `20` and `30`.

---

## Defects fixed, and why they were hard to see

Each of these presented as something other than what it was. They are
recorded because the failure modes recur.

| Symptom | Actual cause |
|---|---|
| Enrolment hung with no output | stdout captured to a file, so an interactive prompt was invisible while it blocked on stdin |
| "no `-e` flag" on a build that has it | probed for `-e ` with a trailing space; help lists `-e, --emergency-codes=N` |
| No QR code | `google-authenticator` only draws one when stdout is a TTY |
| `%3F` in the URI looked corrupt | correct encoding: the otpauth URI is a query-parameter value inside a `google.com/chart` URL |
| Correct code, login refused, no message | secret at `0400`; the module could not record used-code state |
| Still refused after `0600` | SELinux denied creating the rename tempfile; `fcontext` cannot fix creation-time labels |
| User quizzed about reuse and rate limiting | `-f` suppresses only the file-update question |
| Every code rejected during self-enrolment | 26-char base32 secret passed to `oathtool` unpadded |

Two general lessons are encoded in the tests now:

- **A validator that shares the code's assumptions confirms nothing.**
  `90-validate.sh` passed this host in three successively broken states
  because it asserted only what the enrolment script already believed.
- **PAM `[success=N]` counts are positional.** Adding one line to the block
  invalidates every jump above it, and the failure mode is a locked-out
  fleet. `tests/test-pam-stack.sh` asserts each jump's declared count *and*
  the line it lands on, for every mode and gate combination.
