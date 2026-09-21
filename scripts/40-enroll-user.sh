#!/usr/bin/env bash
# Generate a TOTP secret for one or more users.
#
#   40-enroll-user.sh alice bob     enrol named users
#   40-enroll-user.sh --all         enrol every not-yet-enrolled target user
#   40-enroll-user.sh --status      show who is enrolled
#   40-enroll-user.sh --revoke bob  delete a user's token
#
# Self-enrolment is preferable: a secret generated here passes through root's
# hands and through this terminal's scrollback. See docs/USER-ENROLLMENT.md
# for the instructions to give users instead.

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

command -v google-authenticator >/dev/null \
  || die "google-authenticator not installed; run 10-install-packages.sh"

show_status() {
  printf '%-20s %-10s %s\n' USER UID ENROLLED
  while read -r u; do
    [[ -z "$u" ]] && continue
    if user_enrolled "$u"; then s="${C_GRN}yes${C_OFF}"; else s="${C_YEL}NO${C_OFF}"; fi
    printf '%-20s %-10s %b\n' "$u" "$(id -u "$u")" "$s"
  done < <(mfa_target_users)
}

revoke() {
  local u="$1" home
  home="$(getent passwd "$u" | cut -d: -f6)" || die "no such user: $u"
  if [[ -f "$home/.google_authenticator" ]]; then
    backup_file "$home/.google_authenticator"
    rm -f "$home/.google_authenticator"
    ok "revoked token for $u (backup in $(backup_dir))"
    [[ "$NULLOK" == "no" ]] && warn "NULLOK=no: $u can no longer log in until re-enrolled"
  else
    log "$u has no token"
  fi
}

enroll_one() {
  local u="$1" home uid
  getent passwd "$u" >/dev/null || die "no such user: $u"
  uid="$(id -u "$u")"
  home="$(getent passwd "$u" | cut -d: -f6)"

  if (( uid < MIN_UID )); then
    warn "skipping $u: uid $uid is below MIN_UID=$MIN_UID (system account)"
    return 0
  fi
  if is_exempt_user "$u"; then
    warn "skipping $u: exempt from MFA"
    return 0
  fi
  [[ -d "$home" ]] || die "$u has no home directory at $home"

  if [[ -s "$home/.google_authenticator" ]]; then
    if [[ "${MFA_REENROLL:-no}" != "yes" ]]; then
      warn "$u is already enrolled. Re-enrol with MFA_REENROLL=yes (invalidates their current token)."
      return 0
    fi
    backup_file "$home/.google_authenticator"
  fi

  install -d -m 0700 "$ENROLL_OUT_DIR"
  local out="$ENROLL_OUT_DIR/$u-$(date +%Y%m%dT%H%M%S).txt"

  # -t TOTP  -d no code reuse  -f no prompts  -w skew window  -r/-R rate limit
  # -e emergency scratch codes  -i issuer  -l account label
  local args=(-t -d -f
    -w "$TOTP_WINDOW"
    -r "$TOTP_RATE_LIMIT_N" -R "$TOTP_RATE_LIMIT_S"
    -i "$TOTP_ISSUER" -l "$u@$TOTP_ISSUER"
    -s "$home/.google_authenticator")
  # -e is not in every build; fall back to the default code count.
  if google-authenticator --help 2>&1 | grep -q -- '-e '; then
    args+=(-e "$SCRATCH_CODES")
  else
    warn "this google-authenticator build has no -e flag; using its default number of scratch codes"
  fi

  ( umask 077; runuser -u "$u" -- google-authenticator "${args[@]}" > "$out" 2>&1 ) \
    || { err "enrolment failed for $u:"; sed 's/^/    /' "$out" >&2; return 1; }

  chown root:root "$out"; chmod 0600 "$out"
  chown "$u:$(id -gn "$u")" "$home/.google_authenticator"
  chmod 0400 "$home/.google_authenticator"
  command -v restorecon >/dev/null && restorecon -F "$home/.google_authenticator" 2>/dev/null || true

  ok "enrolled $u"
  log "secret, QR code and scratch codes: $out"
  log "deliver it out-of-band, have $u confirm a working code, then: shred -u $out"
}

case "${1:-}" in
  ''|-h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  --status) show_status; exit 0 ;;
  --revoke) shift; (( $# )) || die "--revoke needs a username"
            for u in "$@"; do revoke "$u"; done; exit 0 ;;
  --all)
    mapfile -t users < <(mfa_target_users)
    (( ${#users[@]} )) || die "no target users found"
    for u in "${users[@]}"; do user_enrolled "$u" || enroll_one "$u"; done
    ;;
  *) for u in "$@"; do enroll_one "$u"; done ;;
esac

echo
show_status
