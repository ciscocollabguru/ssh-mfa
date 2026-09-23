# Troubleshooting

Start with `sudo scripts/90-validate.sh` — it checks most of what follows.

## Locked out entirely

### You still have an open session

```bash
sudo /path/to/ssh-mfa/scripts/99-rollback.sh
```

Restores `/etc/pam.d/sshd`, `sshd_config` and the drop-in from the most
recent backup set and reloads sshd. `--list` shows the sets; `--set DIR`
picks one.

### You have no session, but you have a console

From the console as root:

```bash
cd /path/to/ssh-mfa && sudo scripts/99-rollback.sh --yes
```

Or by hand, without the repo:

```bash
ls -1dt /var/backups/ssh-mfa/*/          # newest first
cat /var/backups/ssh-mfa/<set>/manifest.tsv
cp -a /var/backups/ssh-mfa/<set>/_etc_pam.d_sshd /etc/pam.d/sshd
rm -f /etc/ssh/sshd_config.d/50-mfa.conf
sshd -t && systemctl reload sshd
```

Minimum to restore single-factor login without any backup:

```bash
sed -i '/^# BEGIN ssh-mfa/,/^# END ssh-mfa/d' /etc/pam.d/sshd
rm -f /etc/ssh/sshd_config.d/50-mfa.conf
sshd -t && systemctl reload sshd
```

### No session and no console

You need the host's recovery path — hypervisor console, cloud provider
serial console, single-user mode, or mounting the disk from rescue media and
applying the `sed`/`rm` above to the offline filesystem. There is no remote
fix. This is why `docs/MANUAL-STEPS.md` step 1 comes first.

---

## Everyone's codes are rejected at once

Almost always the server clock.

```bash
chronyc tracking            # check the 'System time' offset
timedatectl
```

`TOTP_WINDOW=3` tolerates roughly ±90 s. Fix the clock rather than widening
the window — every extra step of tolerance enlarges the window in which a
captured code stays valid.

```bash
sudo systemctl enable --now chronyd
sudo chronyc makestep       # step the clock immediately
```

## One user's codes are rejected

1. **Their phone's clock.** Automatic time sync on the device.
2. **Code reuse.** `-d` blocks reusing a code. Wait for the next one.
3. **Rate limiting.** 3 attempts per 30 s; a flurry of wrong codes locks the
   rest out. Wait a minute, try once.
4. **Wrong entry in the app.** Multiple servers look alike; check the label.
5. **Secret unreadable:**
   ```bash
   sudo ls -l ~user/.google_authenticator     # want: -rw------- user user
   sudo -u user cat ~user/.google_authenticator >/dev/null && echo readable
   ```
6. **Enrolled at all?** `sudo scripts/40-enroll-user.sh --status`

Last resort — re-enrol, which invalidates their old token:

```bash
sudo MFA_REENROLL=yes scripts/40-enroll-user.sh alice
```

## No code prompt appears (MFA silently not enforced)

```bash
sudo sshd -T | grep -iE 'authenticationmethods|passwordauthentication|kbdinteractive'
```

- **`AuthenticationMethods` unset or single-valued** — the drop-in is not
  being read. Check `/etc/ssh/sshd_config` has
  `Include /etc/ssh/sshd_config.d/*.conf` **at the top**. sshd takes the
  first value for each keyword, so an `Include` below a conflicting
  directive has no effect.
- **`PasswordAuthentication yes`** — something sets it before the drop-in.
  `grep -n PasswordAuthentication /etc/ssh/sshd_config`
- **No managed block in PAM** —
  `grep -c '^# BEGIN ssh-mfa' /etc/pam.d/sshd`. A package update can replace
  `/etc/pam.d/sshd`; re-run `20-configure-pam.sh`.
- **The user is exempt** — `id -nG user`, and check UID ≥ `MIN_UID`.
- **`nullok` still set and the user is unenrolled** — expected behaviour
  until `50-enforce-strict.sh` runs.

## Both factors accepted, then a silent failure and re-prompt

The classic cause is a read-only secret file. `pam_google_authenticator`
writes back to `~/.google_authenticator` to record used codes (`-d`) and
attempt timestamps (`-r`/`-R`). If it cannot, it fails the authentication and
emits no message to the user, so the prompts simply repeat.

```bash
sudo ls -l ~user/.google_authenticator     # want: -rw------- user user
sudo scripts/40-enroll-user.sh --fix-perms # repairs all users, no rotation
```

Confirm from the server side:

```bash
sudo grep -i 'google_auth\|secret file' /var/log/secure | tail -20
```

Read the log carefully, because two different faults look alike:

```
Accepted google_authenticator for alice                  <- the CODE was correct
Failed to create tempfile ".../.google_authenticator~XXXXXX": Permission denied
Failed to update secret file ".../.google_authenticator": Permission denied
```

`Accepted ...` followed by `Failed to create tempfile` means the code was
right and the *rewrite* failed. The module updates the secret atomically by
creating a tempfile in the home directory and renaming it, so a correct
`0600` file is not enough — it must also create a file in that directory.
Under SELinux that needs the `ssh_home_t` label, because `sshd_t` may read
`user_home_t` but not create files in it:

```bash
sudo scripts/15-selinux.sh --diagnose   # says which of the causes it is
sudo scripts/15-selinux.sh              # adds the fcontext rule and relabels
```

Neither rotates a secret; existing tokens keep working.

If instead you see `Invalid verification code` with no preceding `Accepted`
line, the code itself was wrong — see the clock and code-reuse causes above.

Tokens enrolled before the 0600 fix were written `0400`.

Other causes of the same silent re-prompt:

- **SELinux** is denying the read or write:
  `sudo ausearch -m avc -ts recent | grep -E 'sshd|google_auth'`
- **The home directory is not writable** or is on a full filesystem:
  `df -h ~user; sudo -u user touch ~user/.probe`
- **NFS/automounted home** not mounted at authentication time
  (`docs/MANUAL-STEPS.md` step 11).

## Prompted for a password *and* a code, in pubkey+totp mode

The PAM jump counts no longer match the file, so control is falling through
to `auth substack password-auth`. Re-run `20-configure-pam.sh` to regenerate
the block, and `tests/test-pam-stack.sh` to confirm the generator is sound.
Do not hand-edit the `[success=N]` values — read `docs/DESIGN.md` first.

## `Permission denied (publickey,keyboard-interactive)`

Both factors were attempted and at least one failed. Find out which:

```bash
sudo journalctl -u sshd -n 80 --no-pager
sudo grep -iE 'pam_google|authentication failure' /var/log/secure | tail -20
```

`ssh -vv user@host` on the client shows which methods were offered and where
it stopped.

## `Permission denied (publickey)` after enabling pubkey+totp

`PasswordAuthentication no` is now set and that account has no usable key.
Install their key, or move them to `password+totp`.
`30-configure-sshd.sh` refuses to apply in this state unless `MFA_FORCE=yes`
was set.

## sshd will not start or reload

```bash
sudo sshd -t              # syntax errors, with line numbers
sudo systemctl status sshd
```

Nothing in this kit restarts sshd, and every reload is gated on `sshd -t`,
so a running sshd should survive. If it is already down, fix
`/etc/ssh/sshd_config` from the console and start it.

## SELinux denials

```bash
sudo ausearch -m avc -ts recent | grep -E 'sshd|google_authenticator'
```

The default policy allows sshd to *read* `~/.google_authenticator` in place,
but not to *rewrite* it — which the module does on every login. That is the
usual denial here, and `scripts/15-selinux.sh` fixes it by labelling the
secret and its tempfiles `ssh_home_t`.

Otherwise, a home directory may have an unexpected label:

```bash
sudo restorecon -Rv /home/user
```

For a deliberately relocated secret, see `docs/MANUAL-STEPS.md` step 10.

## Automation broke after rollout

An Ansible/backup/monitoring account is being prompted for a code. Confirm,
then exempt it:

```bash
id -nG svcacct
sudo usermod -aG ssh-mfa-exempt svcacct
sudo systemctl reload sshd      # Match Group is evaluated per connection
```

Keep exempt accounts key-only. Re-run `90-validate.sh` afterwards.

## `authselect check` reports drift

Something hand-edited `system-auth` or `password-auth`. This kit does not
touch them. Find out what did before "fixing" it — `authselect select ...
--force` will overwrite whatever was added there.

## Enrolment fails with "no such user" or a home directory error

`40-enroll-user.sh` needs an existing home it can write to as the user:

```bash
getent passwd alice          # check the home path in field 6
sudo ls -ld /home/alice
```

For NFS or automounted homes, read `docs/MANUAL-STEPS.md` step 11 — the home
may not be mounted at authentication time, which breaks logins even when
enrolment succeeded.

## Where to look

| What | Where |
|---|---|
| sshd decisions, PAM messages | `journalctl -u sshd`, `/var/log/secure` |
| Effective sshd policy | `sshd -T`, `sshd -T -C user=x,host=y,addr=z` |
| Effective PAM stack | `grep '^auth' /etc/pam.d/sshd` |
| Backups | `/var/backups/ssh-mfa/*/manifest.tsv` |
| Pre-change snapshot | `/var/backups/ssh-mfa/preflight-*.txt` |
| Undistributed secrets | `/root/ssh-mfa-enrolments/` |
