# Security policy

This project changes how a machine authenticates SSH logins. A defect in it
can lock an administrator out of a host, or weaken a second factor without
any visible sign. Please treat findings accordingly.

## Reporting a vulnerability

Report privately, not as a public issue: use GitHub's **Report a
vulnerability** button under the Security tab, which opens a private
advisory.

Useful in a report: the distribution and version, `sshd -V`, the
`google-authenticator` package version, whether SELinux is enforcing, the
relevant `auth` lines from `/etc/pam.d/sshd`, and the generated
`sshd_config.d` drop-in. Redact hostnames, usernames and any TOTP secret
before sending — a secret is a bearer credential and pasting one anywhere
burns it.

## Scope

In scope: anything that grants SSH access without both factors, that lets
an unprivileged user obtain another user's token or escalate via the
enrolment gate, or that silently disables enforcement while appearing to
work.

Out of scope: the upstream `pam_google_authenticator` module and the
distribution's SELinux policy — report those to their own projects. TOTP's
inherent properties (phishable codes, a shared secret at rest) are design
characteristics of the scheme, not defects here.

## Things this project deliberately does not protect against

Stated plainly so nobody assumes otherwise:

- **`root` is exempt by design.** Root SSH is single factor. It is the
  repair path, because an operator locked out of root cannot fix a broken
  PAM stack remotely. Constrain it separately — see
  [`docs/DESIGN.md`](docs/DESIGN.md).
- **Members of the exempt group are single factor.** Intended for
  key-only automation accounts. Review the membership.
- **An account mid-enrolment is password-only** until it has a token,
  though it reaches a forced enrolment prompt rather than a shell. See
  [`docs/SELF-ENROLLMENT.md`](docs/SELF-ENROLLMENT.md).
- **`nullok` means MFA is not yet enforced.** It exists so a rollout does
  not lock anyone out. `50-enforce-strict.sh` ends it.
- **`TOTP_STATEFUL="no"` removes replay protection and per-user rate
  limiting**, so a code can be reused within its validity window.
- **`BREAKGLASS_CIDR` turns a source address into an authentication
  factor.** It is empty by default and should usually stay that way.

Run `scripts/90-validate.sh` to confirm which of these apply to a host.
