# ssh-mfa — TOTP two-factor SSH for AlmaLinux 8

Requires a second factor (a TOTP code from an authenticator app) for every
named user logging in over SSH. **`root` is exempt by design**, as are system
accounts and anything in the `ssh-mfa-exempt` group.

Automated end to end except for the steps that genuinely need a human —
those are in [`docs/MANUAL-STEPS.md`](docs/MANUAL-STEPS.md).

## What it changes

| File | Change |
|---|---|
| `/etc/pam.d/sshd` | Adds a marker-delimited block that runs `pam_google_authenticator` for non-exempt users |
| `/etc/ssh/sshd_config.d/50-mfa.conf` | New. Sets `AuthenticationMethods`, plus `Match` blocks exempting root and `ssh-mfa-exempt` |
| `/etc/ssh/sshd_config` | Adds an `Include` line at the top **only if absent** (AlmaLinux 8 ships without one) |
| `~/.google_authenticator` | Per-user TOTP secret, mode `0600`, owned by the user (the module writes to it) |
| SELinux | A local module (`ssh-mfa-gauth`) permitting that write, and an `fcontext` rule for the secret |
| `/usr/local/sbin/`, `/etc/ssh-mfa/`, `/etc/sudoers.d/`, systemd units | Only with `ENROLL_GATE=yes` — see [`docs/SELF-ENROLLMENT.md`](docs/SELF-ENROLLMENT.md) |

`system-auth` and `password-auth` are **not** touched — authselect owns those,
and breaking them breaks `sudo`, `login` and `cron`, not just SSH.

## Quick start

```bash
git clone <this repo> && cd ssh-mfa
cp config/mfa.env.example config/mfa.env
$EDITOR config/mfa.env      # AUTH_MODE, exemptions, ENROLL_GATE, TOTP_STATEFUL

sudo ./install.sh --dry-run             # show every change, apply nothing
sudo ./install.sh --safety-timer 10     # apply, auto-rollback in 10 min

# --- in a SECOND terminal, before the timer expires ---
ssh you@host                            # expect a verification-code prompt
ssh root@host                           # expect NO code prompt
sudo systemctl stop ssh-mfa-autorollback.timer   # cancel the rollback

sudo scripts/40-enroll-user.sh --all    # or let users self-enrol (ENROLL_GATE)
sudo scripts/90-validate.sh
sudo scripts/50-enforce-strict.sh       # once everyone is enrolled
```

`install.sh` runs, in this order:

```
00-preflight → 10-install-packages → 15-selinux → 16-selinux-policy
             → 45-enrollment-gate (if ENROLL_GATE=yes)
             → 20-configure-pam → 30-configure-sshd → 90-validate
```

The SELinux steps come **before** PAM and sshd on purpose: otherwise the host
is left requiring a code that the PAM module is not permitted to record, and
every correct code is refused. See [`CHANGELOG.md`](CHANGELOG.md) if you are
upgrading a host installed with an earlier version.

Nothing is irreversible: `sudo scripts/99-rollback.sh` restores the previous
`/etc/pam.d/sshd` and sshd config from `/var/backups/ssh-mfa/`.

## Scripts

Run in order; each is idempotent and safe to re-run.

| Script | Does | Root needed |
|---|---|---|
| `install.sh` | Runs 00→30 plus the SELinux step, then validates | yes |
| `scripts/00-preflight.sh` | Read-only. OS, clock, break-glass access, who is affected | yes |
| `scripts/10-install-packages.sh` | EPEL, `google-authenticator`, `chronyd` | yes |
| `scripts/15-selinux.sh` | Labels secrets `auth_home_t`; `--diagnose`, `--collect` | yes |
| `scripts/16-selinux-policy.sh` | Installs the policy module that permits the secret rewrite; `--remove` | yes |
| `scripts/20-configure-pam.sh` | Writes the `/etc/pam.d/sshd` auth block | yes |
| `scripts/30-configure-sshd.sh` | Writes the drop-in, validates, reloads sshd | yes |
| `scripts/40-enroll-user.sh` | `<user>…` / `--all` / `--status` / `--show` / `--revoke` / `--fix-perms` / `--restate` | yes |
| `scripts/45-enrollment-gate.sh` | Forces new users to self-enrol on first login; `--install` / `--status` | yes |
| `scripts/50-enforce-strict.sh` | Drops `nullok`; refuses while anyone is unenrolled | yes |
| `scripts/90-validate.sh` | Read-only. 20+ checks, non-zero on failure | yes |
| `scripts/99-rollback.sh` | `--list` / `--set DIR` / `--yes` | yes |
| `tests/test-pam-stack.sh` | Unit tests for the PAM generator | **no** |
| `tests/test-selfenroll-flags.sh` | Asserts enrolment asks the user nothing | **no** |

## Auth modes

Set `AUTH_MODE` in `config/mfa.env`:

- **`pubkey+totp`** (default) — SSH key **and** code. `PasswordAuthentication no`.
  Strongest. Every affected user must already have an `authorized_keys` file;
  `30-configure-sshd.sh` refuses to run otherwise.
- **`password+totp`** — Unix password **and** code, in one prompt sequence.
  Use where key distribution is not in place.

There is intentionally no "key *or* password, plus TOTP" mode — see
[`docs/DESIGN.md`](docs/DESIGN.md#why-there-is-no-mixed-mode).

## Rollout safety

The design assumes you are applying this over the SSH connection it could
break:

- **`nullok` first.** Until `50-enforce-strict.sh` runs, an unenrolled user
  still gets in on one factor. Nobody is locked out mid-rollout.
- **`sshd -t` before every reload**, and `reload` rather than `restart`, so
  established sessions survive a bad config.
- **`--safety-timer N`** arms a transient systemd unit that rolls everything
  back in N minutes unless you cancel it.
- **root stays exempt**, so there is always an account that can repair a
  broken PAM stack remotely.
- **Timestamped backups** with a manifest under `/var/backups/ssh-mfa/`.

## Testing

```bash
./tests/test-pam-stack.sh        # no root, no AlmaLinux, no PAM required
./tests/test-selfenroll-flags.sh
```

Covers jump arithmetic for both modes, idempotency, `nullok` flips, and the
safety property that no exempt branch can reach `pam_permit` without a real
credential check. Run it after any change to `pam_block()`.

## Requirements

AlmaLinux 8 (or RHEL/Rocky 8). Packages are installed by
`10-install-packages.sh`: `epel-release`, `google-authenticator`, `chrony`,
`qrencode` (draws the enrolment QR code) and `oathtool` (lets the server
compute the code it expects, which `--check` and self-enrolment rely on).

An accurate clock is not optional: `chronyd` must be running and synchronised,
or every user's codes are rejected at once.

## Docs

- [`docs/DESIGN.md`](docs/DESIGN.md) — how the PAM jumps work and why
- [`docs/MANUAL-STEPS.md`](docs/MANUAL-STEPS.md) — everything not automated
- [`docs/ROLLOUT-PLAN.md`](docs/ROLLOUT-PLAN.md) — phased plan for a fleet
- [`docs/USER-ENROLLMENT.md`](docs/USER-ENROLLMENT.md) — hand this to users
- [`docs/SELF-ENROLLMENT.md`](docs/SELF-ENROLLMENT.md) — forcing new users to enrol on first login
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — including lockout recovery
- [`CHANGELOG.md`](CHANGELOG.md) — process changes, migration, and the
  non-obvious failures this was built against
