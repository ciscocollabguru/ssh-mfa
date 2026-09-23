#!/usr/bin/env bash
# Generate a TOTP secret for one or more users.
#
#   40-enroll-user.sh alice bob     enrol named users
#   40-enroll-user.sh --all         enrol every not-yet-enrolled target user
#   40-enroll-user.sh --status      show who is enrolled
#   40-enroll-user.sh --show alice  re-display QR/secret for an enrolled user
#   40-enroll-user.sh --revoke bob  delete a user's token
#   40-enroll-user.sh --fix-perms   repair 0400 secrets (no token rotation)
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

  # -t TOTP  -d no code reuse  -f write the file without confirming
  # -w skew window  -r/-R rate limit  -e emergency scratch codes
  local args=(-t -d -f
    -w "$TOTP_WINDOW"
    -r "$TOTP_RATE_LIMIT_N" -R "$TOTP_RATE_LIMIT_S"
    -s "$home/.google_authenticator")

  # Match on the long option: help lists flags as "-e, --emergency-codes=N",
  # so grepping for "-e " (trailing space) never matches and silently drops
  # the flag on builds that do support it.
  if google-authenticator --help 2>&1 | grep -q -- '--emergency-codes'; then
    args+=(-e "$SCRATCH_CODES")
  else
    warn "this google-authenticator build has no --emergency-codes flag; using its default count"
  fi

  # -i/-l are off by default. Passing both makes some builds percent-encode
  # the '?' and '&' of the otpauth URI ("...alice@host%3Fsecret%3D..."),
  # collapsing it into a single path segment that many apps cannot parse.
  # The default label is already user@hostname, which is what we want.
  if [[ "${TOTP_LABEL_FLAGS:-no}" == "yes" ]]; then
    args+=(-i "$TOTP_ISSUER" -l "$u@$TOTP_ISSUER")
  fi

  log "generating token for $u (non-interactive)..."

  # Two things matter here:
  #  * stdin is fed '-1'. Some builds prompt "Enter code from app
  #    (-1 to skip)" even under -f, and -1 declines it.
  #  * stdout is captured, so any prompt would be INVISIBLE and the script
  #    would look hung while blocking on the terminal. timeout is the
  #    backstop for a build that prompts for something we did not anticipate.
  local rc=0 runner=()
  command -v timeout >/dev/null && runner=(timeout "${ENROLL_TIMEOUT:-60}")
  ( umask 077
    printf '%s\n' -1 \
      | ${runner[@]+"${runner[@]}"} runuser -u "$u" -- \
          google-authenticator "${args[@]}" > "$out" 2>&1
  ) || rc=$?

  if (( rc != 0 )); then
    err "enrolment failed for $u (exit $rc$( ((rc==124)) && printf ': timed out'))"
    sed 's/^/    /' "$out" >&2
    # Do not leave a half-written token: under NULLOK=no a partial or absent
    # secret is the difference between working MFA and a locked-out account.
    if [[ ! -s "$home/.google_authenticator" ]]; then
      rm -f "$home/.google_authenticator"
    fi
    shred -u "$out" 2>/dev/null || rm -f "$out"
    return 1
  fi

  [[ -s "$home/.google_authenticator" ]] \
    || { err "$u: google-authenticator reported success but wrote no secret"; return 1; }

  chown root:root "$out"; chmod 0600 "$out"
  secure_secret "$u"
  command -v restorecon >/dev/null && restorecon -F "$home/.google_authenticator" 2>/dev/null || true

  # Record the URI we will show, so the file matches what the user scanned.
  # (The '%3F' inside google-authenticator's own google.com/chart URL is
  # correct encoding -- the otpauth URI is a query-parameter value there --
  # so it is not a sign of anything wrong.)
  otpauth_uri "$u" >> "$out" 2>/dev/null || true

  ok "enrolled $u"
  show_enrollment "$u"
  log "scratch codes and full output: $out"
  log "deliver out-of-band, have $u confirm a working code, then: shred -u $out"
}

case "${1:-}" in
  ''|-h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  --status) show_status; exit 0 ;;
  --show) shift; (( $# )) || die "--show needs a username"
          for u in "$@"; do show_enrollment "$u"; done; exit 0 ;;
  --fix-perms)
    # Repairs tokens written by an earlier version that chmod'd them 0400,
    # which silently breaks authentication. Does not rotate any secret.
    shift
    if (( $# )); then targets=("$@"); else mapfile -t targets < <(mfa_target_users); fi
    for u in "${targets[@]}"; do
      [[ -z "$u" ]] && continue
      home="$(getent passwd "$u" | cut -d: -f6)"
      if [[ ! -e "$home/.google_authenticator" ]]; then
        log "$u: not enrolled, nothing to fix"; continue
      fi
      before="$(stat -c '%a %U' "$home/.google_authenticator")"
      secure_secret "$u"
      after="$(stat -c '%a %U' "$home/.google_authenticator")"
      if [[ "$before" == "$after" ]]; then ok "$u: already $after"
      else ok "$u: $before -> $after"; fi
    done
    exit 0 ;;
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
