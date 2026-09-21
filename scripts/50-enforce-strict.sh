#!/usr/bin/env bash
# Remove 'nullok': from this point a user without a TOTP token cannot log in.
# Refuses to run while any target user is still unenrolled.
#
# Usage: 50-enforce-strict.sh [--force]

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

FORCE=no
[[ "${1:-}" == "--force" ]] && FORCE=yes

if [[ "$NULLOK" == "no" ]] && grep -q 'pam_google_authenticator.so$' /etc/pam.d/sshd 2>/dev/null; then
  ok "already in strict mode"
fi

mapfile -t unenrolled < <(while read -r u; do
  [[ -n "$u" ]] && ! user_enrolled "$u" && printf '%s\n' "$u"
done < <(mfa_target_users))

if (( ${#unenrolled[@]} )); then
  err "these accounts have no TOTP token and would lose SSH access:"
  printf '    %s\n' "${unenrolled[@]}" >&2
  echo >&2
  err "Enrol them (scripts/40-enroll-user.sh --all), add them to $EXEMPT_GROUP, or re-run with --force."
  [[ "$FORCE" == "yes" ]] || exit 1
  warn "proceeding with --force; the accounts above will be locked out"
else
  ok "all target users are enrolled"
fi

# Regenerate the PAM block with nullok off. Same script, same generator,
# same backup handling -- only the one setting differs.
MFA_NULLOK=no "$REPO_ROOT/scripts/20-configure-pam.sh"

sshd_validate || die "sshd config invalid; not reloading"
sshd_reload

echo
ok "strict mode active: a missing or invalid TOTP token is now a failed login"
warn "set NULLOK=\"no\" in config/mfa.env so later runs stay strict"
