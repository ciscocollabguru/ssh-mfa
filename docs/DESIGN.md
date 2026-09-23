# Design notes

Why the configuration looks the way it does. Read this before changing
`pam_block()` in `scripts/lib/common.sh`.

## Two layers, two jobs

Excluding root correctly needs both layers, because each can only see part of
the picture.

**sshd** decides *which methods a connection must satisfy*. It can branch on
user, group and address (`Match`), so this is where root is exempted:

```
AuthenticationMethods publickey,keyboard-interactive:pam
Match User root
    AuthenticationMethods publickey
```

A comma means *and*: key **then** keyboard-interactive. Root's `Match` block
overrides that with a single method.

**PAM** decides *what a keyboard-interactive conversation asks for*. sshd
cannot express "prompt for a code but not a password", because both
`password` and `keyboard-interactive` route through the same
`/etc/pam.d/sshd` auth stack. So the stack itself carries the exemption logic
as a second line of defence: if someone later edits the sshd drop-in and
removes root's `Match` block, PAM still does not hand root a free pass.

## The `[success=N]` jumps

PAM has no `if`/`else`. `[success=N default=ignore]` means *on success, skip
the next N modules; on anything else, carry on to the next line*. Miscounting
is the classic way to lock out a fleet, so the generated stack is numbered in
comments and asserted in `tests/test-pam-stack.sh`.

`pubkey+totp` produces:

```
1  auth  [success=4 default=ignore]  pam_succeed_if.so quiet uid < 1000
2  auth  [success=3 default=ignore]  pam_succeed_if.so quiet user in root
3  auth  [success=2 default=ignore]  pam_succeed_if.so quiet user ingroup ssh-mfa-exempt
4  auth  requisite                   pam_google_authenticator.so nullok
5  auth  [success=1 default=die]     pam_permit.so
6  auth  substack                    password-auth      <- pre-existing
7  auth  include                     postlogin          <- pre-existing
```

A jump on line *n* lands on line *n + N + 1*:

| Line | Jump | Lands on | Meaning |
|---|---|---|---|
| 1 | 4 | 6 | system account → skip TOTP, use the normal stack |
| 2 | 3 | 6 | named exempt user → same |
| 3 | 2 | 6 | exempt group member → same |
| 5 | 1 | 7 | code accepted → skip the password stack |

Two properties matter:

- **Exempt branches land on line 6, not on success.** They still meet
  `password-auth`, i.e. a real credential check. Jumping them to
  `[success=done]` would make PAM auth succeed for root with *no* credential
  at all — fine while sshd's `Match User root` block holds, catastrophic the
  moment someone removes it. `tests/test-pam-stack.sh` asserts that no guard
  uses `success=done`.
- **Line 5 exists so ordinary users are not asked for a password** after a
  valid code. Without it, control would fall through to line 6.

`requisite` on line 4, not `required`: a wrong code fails immediately rather
than continuing through the stack and revealing, by timing, whether the other
factor was also wrong.

`password+totp` is the same idea with the password stack first and no
`pam_permit`; the guards jump straight to `include postlogin`.

## Why there is no mixed mode

"Either a key or a password, plus a code" looks reasonable and does not work.
sshd's `password` method and its `keyboard-interactive` method both invoke
the same PAM auth stack. The `password` method answers the first PAM prompt
with the password it already collected — so if the stack's first prompt is
for a TOTP code, sshd feeds the password into the code prompt and the login
fails. One stack cannot serve both conversations. Pick one mode per host.

## `nullok`

`nullok` makes `pam_google_authenticator` return success when the user has no
`~/.google_authenticator`. During rollout that is the point: MFA is live for
everyone enrolled, and nobody else is locked out. It also means MFA is
**not yet enforced** — an attacker with one factor for an unenrolled account
gets in. `50-enforce-strict.sh` removes it and refuses to run while any
target user is unenrolled. `90-validate.sh` reports permissive mode as `[--]`
rather than a pass.

## `AuthenticationMethods` and first-value-wins

sshd honours the **first** occurrence of a keyword. AlmaLinux 8 ships
`sshd_config` with `PasswordAuthentication yes` and without an `Include`
line, so a drop-in added at the bottom would be silently ignored. Hence
`30-configure-sshd.sh` inserts `Include /etc/ssh/sshd_config.d/*.conf` at the
very top, and warns about any conflicting directive left below it.

`Match` blocks must come last in the drop-in: every directive after a `Match`
belongs to that block until the next one.

## Why `~/.google_authenticator` and 0600

The secret is a bearer credential: anyone who reads it can generate valid
codes forever. Per-user home storage means the OS's existing ownership rules
protect it, and revocation is a single `rm`.

The mode is `0600`, owned by the user — **writable, not just readable**. This
is easy to get wrong, and getting it wrong produces a silent failure. The
module does not only read the secret; it writes back to the same file:

- `-d` (disallow code reuse) records each code as it is used, so it cannot be
  replayed within its window.
- `-r`/`-R` (rate limiting) records attempt timestamps.

At `0400` those writes fail. The module then returns an authentication error
**without any message to the user**, so sshd accepts both factors and
re-prompts, with nothing in the prompt to indicate why. `0600` is what
`google-authenticator` itself creates. `90-validate.sh` requires exactly
`0600` and names this cause when it finds `0400`;
`40-enroll-user.sh --fix-perms` repairs affected tokens without rotating
them.

### The rewrite is atomic, so the directory matters too

The module does not edit the secret in place. It creates
`.google_authenticator~XXXXXX` in the user's home directory and renames it
over the original. So a correct `0600` file is necessary but **not
sufficient** — the module also needs to create a file *in that directory*:

- The home directory must be writable by the user (it normally is).
- Under SELinux the secret must be labelled `ssh_home_t`. `sshd_t` may read
  `user_home_t`, which is why *reading* works out of the box, but it may not
  create files there. The result is the most confusing failure in this whole
  system: `Accepted google_authenticator for <user>` immediately followed by
  `Failed to create tempfile ...: Permission denied`, and a re-prompt.

`scripts/15-selinux.sh` adds the `fcontext` rule and relabels. The rule
pattern is `<home-parent>/[^/]+/\.google_authenticator.*` — the trailing
`.*` is load-bearing. A rule matching only the exact filename leaves the
tempfile as `user_home_t` and the denial persists, which makes it look as
though labelling did not help.

## Why root is exempt rather than enrolled

Root is the repair path. A wrong `[success=N]`, a missing PAM module after a
package change, or a clock that has drifted out of tolerance breaks TOTP for
every enrolled user simultaneously — and the account you need in order to fix
it must not depend on the mechanism that broke.

This is a deliberate trade: root SSH is single-factor. It is worth
constraining separately, none of which this kit changes for you:

- `PermitRootLogin prohibit-password` (key-only) — AlmaLinux 8's default
- Restrict root logins to a management network with `Match Address`
- Or `PermitRootLogin no` entirely, relying on console plus `sudo` from an
  MFA-protected account — the strongest option, and it keeps root off the
  network without making TOTP a single point of failure

## Reload, not restart

`systemctl reload sshd` re-reads the configuration without dropping
established connections. If the new policy is wrong, the session you are
applying it from survives and can run `99-rollback.sh`. A `restart` would
drop it. Nothing in this kit restarts sshd.
