# Rollout plan

A phased sequence for going from no MFA to enforced MFA without locking
anyone out. Scale the timings to your environment; the ordering is what
matters.

## Phase 0 — one throwaway host

Do not rehearse on a host you care about.

```bash
sudo ./install.sh --dry-run      # read every proposed change
sudo ./install.sh --safety-timer 10
sudo scripts/40-enroll-user.sh testuser
sudo scripts/90-validate.sh
sudo scripts/50-enforce-strict.sh
sudo scripts/99-rollback.sh      # prove the escape hatch works
```

Confirm, by hand, from a second terminal:

- a named enrolled user is asked for a code
- root is **not** asked for a code
- an `ssh-mfa-exempt` member is **not** asked for a code
- an unenrolled user still gets in under `nullok`, and does **not** after
  `50-enforce-strict.sh`
- `99-rollback.sh` restores single-factor login

Only proceed once you have personally seen all six.

## Phase 1 — decide and announce (1 week ahead)

1. Run `00-preflight.sh` on every target host and collect the affected
   accounts.
2. Classify each: human (enrol) or automation (exempt). See
   `docs/MANUAL-STEPS.md` step 2 — this is where rollouts go wrong.
3. Verify console/IPMI access for every host.
4. Send `docs/USER-ENROLLMENT.md` with a firm enrolment deadline, and say
   what happens after it.

## Phase 2 — apply permissively

`NULLOK="yes"` in `config/mfa.env`, then per host:

```bash
sudo ./install.sh --safety-timer 15
# verify in a second terminal, then:
sudo systemctl stop ssh-mfa-autorollback.timer
```

MFA is now live for anyone enrolled and nobody is locked out. Start with a
small batch of hosts and your most responsive users.

Do not apply to your whole fleet in one pass. A batch at a time bounds the
damage from an environment-specific surprise — NFS homes, an exotic
`/etc/pam.d/sshd`, an automation account nobody remembered.

## Phase 3 — enrol

Preferred: users self-enrol (no secret passes through an admin).

```bash
sudo scripts/40-enroll-user.sh --status     # track coverage
```

Chase the stragglers. `--all` is available for users who cannot self-enrol,
but read `docs/MANUAL-STEPS.md` step 6 first — it puts secrets on disk that
you must then distribute and shred.

## Phase 4 — enforce

Once `--status` shows everyone enrolled and the deadline has passed:

```bash
sudo scripts/90-validate.sh
sudo scripts/50-enforce-strict.sh
```

It refuses to run while anyone would be locked out. If you override that with
`--force`, you are choosing to lock those accounts out — tell them first.

Then set `NULLOK="no"` in `config/mfa.env` so later runs stay strict.

## Phase 5 — after

- Re-run `90-validate.sh` after any change to sshd, PAM, or the
  `google-authenticator` package. A `dnf update` that replaces
  `/etc/pam.d/sshd` will silently drop the managed block — the validator
  catches it; nothing else will.
- Add enrolment to onboarding and revocation to offboarding
  (`docs/MANUAL-STEPS.md` has the commands). Under `NULLOK=no` a new
  unenrolled account cannot log in at all.
- Review `ssh-mfa-exempt` quarterly.
- Consider whether root SSH should be reachable from the network at all
  (`docs/DESIGN.md`).

## If it goes wrong

`sudo scripts/99-rollback.sh` from a session you kept open, or from the
console. See `docs/TROUBLESHOOTING.md` for recovery with no session at all.
