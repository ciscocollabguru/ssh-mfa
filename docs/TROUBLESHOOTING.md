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
   sudo ls -l ~user/.google_authenticator     # want: -r-------- user user
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

The default policy allows sshd to read `~/.google_authenticator` in place.
Denials usually mean the secret was relocated or a home directory has an
unexpected label:

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
