# Manual steps

Everything the automation deliberately leaves to a human, and why. Work
through this alongside `README.md`.

---

## Before you run anything

### 1. Secure a second way onto the box — *not automatable*

The scripts reload sshd rather than restarting it, validate with `sshd -t`
first, and can auto-roll-back on a timer. None of that helps if the host
becomes unreachable and you have no console.

Confirm **one** of these works before you start:

- Hypervisor/IPMI/iDRAC/cloud serial console
- A physical console
- A second, already-established root SSH session you will not close

`00-preflight.sh` warns if `/root/.ssh/authorized_keys` is empty, but it
cannot verify that your console actually works. Test it.

### 2. Decide the exemption policy — *a judgement call*

The default is: `root`, anything with UID < 1000, and members of
`ssh-mfa-exempt`. Before applying, list every account that authenticates
non-interactively and would break if prompted for a code:

```bash
sudo scripts/00-preflight.sh          # prints the affected accounts
getent passwd | awk -F: '$3>=1000 && $7!~/(nologin|false)$/ {print $1}'
```

Automation accounts (Ansible, backup agents, monitoring, CI, rsync targets,
Git deploy users) frequently sit at UID ≥ 1000 with a login shell. A TOTP
prompt will hang or fail their jobs. Add them explicitly:

```bash
sudo usermod -aG ssh-mfa-exempt ansible
sudo usermod -aG ssh-mfa-exempt backup-agent
```

> An account in `ssh-mfa-exempt` is single-factor. Keep the list short, keep
> its members key-only, and review it periodically — this is the group an
> attacker would most like to join.

### 3. Tell your users first — *not automatable*

Enrolment requires each person to scan a QR code with a phone. Send
`docs/USER-ENROLLMENT.md` and set a deadline **before** you run
`50-enforce-strict.sh`. See `docs/ROLLOUT-PLAN.md` for timing.

### 4. Confirm the clock is trustworthy

TOTP is time-derived. `10-install-packages.sh` enables `chronyd`, but it
cannot know whether your NTP sources are reachable through your firewall:

```bash
chronyc sources -v
chronyc tracking      # 'System time' offset should be well under a second
```

`TOTP_WINDOW=3` tolerates about ±90 s of skew. Sustained drift beyond that
rejects every code from every user at once.

---

## During the rollout

### 5. Verify both paths in a second terminal — *must be a human*

No script can prove that an interactive login works, because sshd will not
authenticate a local automated caller through the same path a real client
uses. After `30-configure-sshd.sh`, **keep your current session open** and
from a *different* terminal:

```bash
ssh you@host          # expect: "Verification code:"  (or password, then code)
ssh root@host         # expect: NO code prompt
ssh exemptacct@host   # expect: NO code prompt
```

Only then cancel the auto-rollback:

```bash
sudo systemctl stop ssh-mfa-autorollback.timer
```

If any of the three misbehaves, run `sudo scripts/99-rollback.sh` from the
session you kept open.

### 6. Distribute enrolment secrets — *deliberately not automated*

`40-enroll-user.sh` writes the secret, QR code and scratch codes to
`/root/ssh-mfa-enrolments/<user>-<timestamp>.txt`. The script will not
email, message or otherwise transmit it, because that would put a
second-factor seed into a channel protected only by the first factor.

Preferred: **users self-enrol** over an existing session — no secret ever
passes through your hands. See `docs/USER-ENROLLMENT.md`.

If you must enrol on their behalf:

1. Deliver the file out-of-band (in person, or a password manager share).
2. Have the user confirm a working code.
3. Shred it: `sudo shred -u /root/ssh-mfa-enrolments/<file>`

`90-validate.sh` fails while any of these files remain.

### 7. Have each user store their scratch codes — *not automatable*

Enrolment produces one-time emergency codes. They are the user's own
recovery path for a lost or wiped phone; without them, recovery means an
admin re-enrolling them. Confirm each user has saved them somewhere that is
not the phone holding the TOTP secret.

---

## Optional and situational

### 8. Break-glass network exemption

`BREAKGLASS_CIDR` in `config/mfa.env` adds a `Match Address` block that skips
MFA from a given source. It is empty by default and should usually stay that
way: it converts an IP address into an authentication factor, and source
addresses are spoofable on networks you do not fully control.

Only use it when the source is a bastion that is itself MFA-protected, and
document the decision. It is single-factor access by definition.

### 9. Extending MFA beyond SSH (sudo, console login, cockpit)

Out of scope here, and **not** something to do by editing `password-auth` or
`system-auth` directly — authselect will revert your changes on its next run.
The supported route is a custom authselect profile:

```bash
sudo authselect create-profile mfa-local -b sssd
# edit /etc/authselect/custom/mfa-local/{system,password}-auth
sudo authselect select custom/mfa-local --force
sudo authselect check
```

Test this on a throwaway host first. A mistake here locks out console login
and `sudo` as well as SSH, and `root` exemption does not protect you.

### 10. SELinux with relocated secrets

Under the default policy sshd can read `~/.google_authenticator` where it is.
If you move secrets to a central directory (for shared/NFS homes), sshd will
be denied until you label the new location:

```bash
sudo semanage fcontext -a -t ssh_home_t '/etc/ssh/authenticator(/.*)?'
sudo restorecon -Rv /etc/ssh/authenticator
```

Then set `secret=` on the `pam_google_authenticator` line. Check with
`sudo ausearch -m avc -ts recent`.

### 11. NFS or automounted home directories

`pam_google_authenticator` reads the secret at authentication time, which on
some setups is before the user's home is mounted — every login then fails as
if unenrolled. If homes are not local, relocate secrets as in step 10 and
test one account thoroughly before rolling out.

### 12. Applying the PAM block by hand

If `20-configure-pam.sh` reports it cannot find the
`auth substack password-auth` anchor, `/etc/pam.d/sshd` has been customised.
Print the intended block and place it yourself:

```bash
sudo MFA_CONFIG=config/mfa.env bash -c '
  . scripts/lib/common.sh; load_config; pam_block'
```

For `pubkey+totp`, the block goes **immediately before**
`auth substack password-auth`. For `password+totp`, **immediately after** it.
The `[success=N]` counts assume that placement — read
`docs/DESIGN.md` before adjusting them, and re-run
`tests/test-pam-stack.sh`.

---

## Recurring operational tasks

| Task | Command | Cadence |
|---|---|---|
| Re-verify configuration | `sudo scripts/90-validate.sh` | after any sshd/PAM change, and monthly |
| Review exemptions | `getent group ssh-mfa-exempt` | quarterly |
| Check enrolment coverage | `sudo scripts/40-enroll-user.sh --status` | when accounts are added |
| New user | `sudo scripts/40-enroll-user.sh <user>` | at onboarding |
| Departing user | `sudo scripts/40-enroll-user.sh --revoke <user>` | at offboarding |
| Lost phone | `sudo MFA_REENROLL=yes scripts/40-enroll-user.sh <user>` | as needed |
| Prune old backups | `sudo ls -1dt /var/backups/ssh-mfa/*/ \| tail -n +10` | yearly |

Adding a user account does **not** enrol them. Under `NULLOK=no` a new,
unenrolled user cannot log in at all — enrol them as part of onboarding.
