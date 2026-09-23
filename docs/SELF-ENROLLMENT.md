# Forced self-enrolment

How a new account is made to set up MFA on its first login, with no admin
handling the secret.

## The problem it solves

Under `NULLOK=no` a new account cannot log in at all, so it can never
self-enrol over SSH. Under `NULLOK=yes` it logs in with one factor
indefinitely and is never prompted. Neither is what you want for onboarding.

## The flow

1. A new account is added to `ENROLL_GROUP` (`ssh-mfa-enroll` by default),
   automatically by `ssh-mfa-reconcile.path`, which watches `/etc/passwd`.
2. sshd matches that group and applies `AuthenticationMethods
   keyboard-interactive:pam` plus
   `ForceCommand /usr/local/sbin/ssh-mfa-selfenroll`. The PAM stack gives
   `nullok` to **that group only**, so the user authenticates with their
   password even though they have no token.
3. Instead of a shell they get the enrolment script: it runs
   `google-authenticator` on a real TTY (so the QR code renders natively),
   makes them confirm they saved the scratch codes, and then asks them for a
   code from the app.
4. If the code checks out, `ssh-mfa-finalize` — root, via a narrow sudoers
   rule — applies the server's state policy to the file, sets `0600` and the
   SELinux label, and removes the user from the group.
5. The next login goes through the strict branch of the PAM stack, like
   everyone else.

If they disconnect or Ctrl-C at any point, nothing is lost: they are still in
the group and land back in enrolment next time. The account is never left in
a state where it has a shell but no token.

## Install

```bash
# in config/mfa.env
ENROLL_GATE="yes"

sudo scripts/45-enrollment-gate.sh --install
sudo scripts/20-configure-pam.sh
sudo scripts/30-configure-sshd.sh --safety-timer 10
```

Then prove it with a throwaway account, from a second terminal:

```bash
sudo useradd -m testmfa && sudo passwd testmfa
ssh testmfa@host          # expect the enrolment prompt, not a shell
sudo scripts/45-enrollment-gate.sh --status
sudo userdel -r testmfa
```

## Day to day

| Task | Command |
|---|---|
| Who is pending | `scripts/45-enrollment-gate.sh --status` |
| Force one account to re-enrol | `scripts/40-enroll-user.sh --revoke u` then `--require u` |
| Gate an account by hand | `scripts/45-enrollment-gate.sh --require u` |
| Ungate without enrolling | `scripts/45-enrollment-gate.sh --release u` |
| Sync membership now | `scripts/45-enrollment-gate.sh --reconcile` |
| Remove the whole gate | `scripts/45-enrollment-gate.sh --uninstall` |

Adding a user needs no action: the path unit gates them within seconds, and
a 15-minute timer is the safety net for accounts created while it was down.

## What the group grants, precisely

Be clear about this when reviewing it, because "a group that bypasses MFA"
is exactly the sort of thing that deserves suspicion:

- A member authenticates with **their password alone** — one factor.
- What they reach is **not a shell**. `ForceCommand` replaces it with the
  enrolment script, and TCP, agent, X11 and tunnel forwarding are all off in
  that `Match` block, so the session cannot be used as a jump host or to
  forward ports.
- Membership is self-limiting: the only way out of the group is to produce a
  working token, and `ssh-mfa-finalize` does that removal itself.
- `ssh-mfa-finalize` takes **no username**. It acts on `$SUDO_USER`, refuses
  to act on root, and refuses to act on anyone not currently in the group, so
  a member cannot aim it at another account.
- `--reconcile` removes anyone from the group who is enrolled or exempt, so a
  stale membership does not persist and quietly weaken an account.

The residual risk is real and worth naming: between account creation and
enrolment, that account is password-only. Keep the window short, and set a
password the user must change (`chage -d 0 <user>`) so a stale initial
password is not left usable.

## If it goes wrong

`scripts/45-enrollment-gate.sh --uninstall` removes the helpers, sudoers
file and systemd units, and empties the group. It touches no token. Then set
`ENROLL_GATE="no"` and re-run `20-configure-pam.sh` and
`30-configure-sshd.sh`.

A user stuck in a loop usually means `ssh-mfa-finalize` cannot release them:

```bash
sudo grep ssh-mfa /var/log/secure | tail
sudo -n /usr/local/sbin/ssh-mfa-finalize   # run as the affected user, expect an error
sudo visudo -c                             # confirm the sudoers file parses
```
