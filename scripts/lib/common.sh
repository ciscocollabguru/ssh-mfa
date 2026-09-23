#!/usr/bin/env bash
# Shared helpers. Sourced, never executed directly.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

# --- output ----------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'
  C_DIM=$'\033[2m';  C_OFF=$'\033[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_DIM=''; C_OFF=''
fi

log()   { printf '%s[ssh-mfa]%s %s\n' "$C_DIM" "$C_OFF" "$*"; }
ok()    { printf '%s[ ok ]%s %s\n'    "$C_GRN" "$C_OFF" "$*"; }
warn()  { printf '%s[warn]%s %s\n'    "$C_YEL" "$C_OFF" "$*" >&2; }
err()   { printf '%s[fail]%s %s\n'    "$C_RED" "$C_OFF" "$*" >&2; }
die()   { err "$*"; exit 1; }

# --- guards ----------------------------------------------------------------
require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "must run as root (try: sudo $0 $*)"
}

require_almalinux8() {
  [[ -r /etc/os-release ]] || die "/etc/os-release missing; unsupported host"
  # shellcheck disable=SC1091
  . /etc/os-release
  local major="${VERSION_ID%%.*}"
  case "${ID}:${major}" in
    almalinux:8|rhel:8|rocky:8|centos:8) ok "host is ${PRETTY_NAME:-$ID $VERSION_ID}" ;;
    *)
      if [[ "${MFA_ALLOW_ANY_OS:-no}" == "yes" ]]; then
        warn "host is ${PRETTY_NAME:-$ID $VERSION_ID}; continuing (MFA_ALLOW_ANY_OS=yes)"
      else
        die "expected AlmaLinux 8 (RHEL 8 family), found ${PRETTY_NAME:-$ID $VERSION_ID}. Override with MFA_ALLOW_ANY_OS=yes."
      fi
      ;;
  esac
}

# --- config ----------------------------------------------------------------
load_config() {
  local cfg="${MFA_CONFIG:-$REPO_ROOT/config/mfa.env}"
  if [[ -r "$cfg" ]]; then
    # shellcheck disable=SC1090
    . "$cfg"
    log "config: $cfg"
  else
    # shellcheck disable=SC1091
    . "$REPO_ROOT/config/mfa.env.example"
    warn "config: using defaults from mfa.env.example (no $cfg)"
  fi

  : "${AUTH_MODE:=pubkey+totp}"
  : "${NULLOK:=yes}"
  : "${EXEMPT_USERS:=root}"
  : "${EXEMPT_GROUP:=ssh-mfa-exempt}"
  : "${MIN_UID:=1000}"
  : "${BREAKGLASS_CIDR:=}"
  : "${TOTP_WINDOW:=3}"
  : "${TOTP_RATE_LIMIT_N:=3}"
  : "${TOTP_RATE_LIMIT_S:=30}"
  : "${SCRATCH_CODES:=5}"
  # Prefer an FQDN; 'localhost' is useless as a label in an authenticator app
  # holding entries for several hosts.
  if [[ -z "${TOTP_ISSUER:-}" ]]; then
    TOTP_ISSUER="$(hostname -f 2>/dev/null || true)"
    [[ -z "$TOTP_ISSUER" || "$TOTP_ISSUER" == localhost* ]] && \
      TOTP_ISSUER="$(hostname -s 2>/dev/null || true)"
    [[ -z "$TOTP_ISSUER" || "$TOTP_ISSUER" == localhost* ]] && TOTP_ISSUER="ssh"
  fi
  : "${TOTP_LABEL_FLAGS:=no}"
  : "${TOTP_STATEFUL:=yes}"
  : "${ENROLL_GATE:=no}"
  : "${ENROLL_GROUP:=ssh-mfa-enroll}"
  case "$ENROLL_GATE" in yes|no) ;; *) die "ENROLL_GATE must be yes or no" ;; esac
  [[ "$ENROLL_GROUP" == "$EXEMPT_GROUP" ]] && \
    die "ENROLL_GROUP and EXEMPT_GROUP must differ (both are '$ENROLL_GROUP')"
  case "$TOTP_STATEFUL" in yes|no) ;; *) die "TOTP_STATEFUL must be yes or no" ;; esac
  : "${ENROLL_TIMEOUT:=60}"
  : "${SSHD_DROPIN:=/etc/ssh/sshd_config.d/50-mfa.conf}"
  : "${BACKUP_ROOT:=/var/backups/ssh-mfa}"
  : "${ENROLL_OUT_DIR:=/root/ssh-mfa-enrolments}"

  case "$AUTH_MODE" in
    pubkey+totp|password+totp) ;;
    *) die "AUTH_MODE must be pubkey+totp or password+totp (got '$AUTH_MODE')" ;;
  esac
  case "$NULLOK" in yes|no) ;; *) die "NULLOK must be yes or no (got '$NULLOK')" ;; esac

  # Env overrides, so a caller can flip one setting without rewriting the
  # config file. Used by 50-enforce-strict.sh.
  [[ -n "${MFA_NULLOK:-}" ]]    && NULLOK="$MFA_NULLOK"
  [[ -n "${MFA_AUTH_MODE:-}" ]] && AUTH_MODE="$MFA_AUTH_MODE"

  # root must never be required to use MFA: it is the lockout escape hatch.
  grep -qw root <<<"$EXEMPT_USERS" || die "EXEMPT_USERS must include root"
}

# --- backups ---------------------------------------------------------------
# One timestamped directory per RUN, not per script. install.sh exports
# MFA_BACKUP_DIR so the PAM and sshd changes land in a single set; otherwise
# 99-rollback.sh would restore only whichever script ran last, leaving the
# other half of the change in place.
backup_dir() {
  if [[ -z "${_MFA_BACKUP_DIR:-}" ]]; then
    _MFA_BACKUP_DIR="${MFA_BACKUP_DIR:-$BACKUP_ROOT/$(date +%Y%m%dT%H%M%S)}"
    install -d -m 0700 "$_MFA_BACKUP_DIR"
    printf '%s\n' "$_MFA_BACKUP_DIR" > "$BACKUP_ROOT/.latest"
  fi
  printf '%s\n' "$_MFA_BACKUP_DIR"
}

# Reserve the run's backup set up front and export it to child scripts.
begin_backup_set() {
  install -d -m 0700 "$BACKUP_ROOT"
  export MFA_BACKUP_DIR="${MFA_BACKUP_DIR:-$BACKUP_ROOT/$(date +%Y%m%dT%H%M%S)}"
}

backup_file() {
  local src="$1" dir
  dir="$(backup_dir)"
  if [[ -e "$src" ]]; then
    local dest="$dir/${src//\//_}"
    cp -a "$src" "$dest"
    printf '%s\t%s\n' "$src" "$dest" >> "$dir/manifest.tsv"
    log "backed up $src"
  else
    # Record absence so rollback deletes a file we created.
    printf '%s\t%s\n' "$src" "ABSENT" >> "$dir/manifest.tsv"
    log "noted $src did not exist"
  fi
}

# --- sshd ------------------------------------------------------------------
sshd_validate() {
  local out
  if out="$(/usr/sbin/sshd -t 2>&1)"; then
    ok "sshd config syntax valid"
    return 0
  fi
  err "sshd config is INVALID; not reloading:"
  printf '%s\n' "$out" >&2
  return 1
}

sshd_reload() {
  # reload, not restart: established sessions survive, so a bad change does
  # not drop the operator who is applying it.
  systemctl reload sshd && ok "sshd reloaded (existing sessions kept)"
}

sshd_effective() {
  /usr/sbin/sshd -T "$@" 2>/dev/null
}

# --- users -----------------------------------------------------------------
is_exempt_user() {
  local u="$1" g
  for g in $EXEMPT_USERS; do [[ "$u" == "$g" ]] && return 0; done
  if getent group "$EXEMPT_GROUP" >/dev/null 2>&1; then
    id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$EXEMPT_GROUP" && return 0
  fi
  return 1
}

# Named, login-capable, non-exempt accounts: the population that needs MFA.
mfa_target_users() {
  local name uid shell
  while IFS=: read -r name _ uid _ _ _ shell; do
    (( uid >= MIN_UID )) || continue
    (( uid == 65534 )) && continue          # nfsnobody
    case "$shell" in */nologin|*/false|'') continue ;; esac
    is_exempt_user "$name" && continue
    printf '%s\n' "$name"
  done < <(getent passwd) | sort -u
}

user_enrolled() {
  local home
  home="$(getent passwd "$1" | cut -d: -f6)"
  [[ -n "$home" && -s "$home/.google_authenticator" ]]
}

pam_module_path() {
  local p
  for p in /usr/lib64/security/pam_google_authenticator.so \
           /usr/lib/security/pam_google_authenticator.so; do
    [[ -e "$p" ]] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

# --- PAM stack generation --------------------------------------------------
# Kept here (not inline in 20-configure-pam.sh) so tests/test-pam-stack.sh
# exercises the same code that runs in production.

PAM_ANCHOR='^[[:space:]]*auth[[:space:]]+substack[[:space:]]+password-auth'

# pam_succeed_if takes a colon-separated list for 'user in'.
exempt_user_list() {
  tr ' ' ':' <<<"$EXEMPT_USERS" | sed 's/::*/:/g; s/^://; s/:$//'
}

# Emit the managed block for $AUTH_MODE. The [success=N] jumps skip the NEXT
# N modules; every exempt branch is aimed at the original
# 'auth substack password-auth' line so exempt accounts still face a real
# credential check and are never waved through by pam_permit.
pam_block() {
  local ga_args="" list
  [[ "$NULLOK" == "yes" ]] && ga_args=" nullok"
  list="$(exempt_user_list)"

  echo "# BEGIN ssh-mfa -- generated by ssh-mfa/scripts/20-configure-pam.sh. Do not edit by hand."
  echo "# Mode: $AUTH_MODE | nullok: $NULLOK | gate: $ENROLL_GATE | exempt: uid<$MIN_UID, [$EXEMPT_USERS], group $EXEMPT_GROUP"

  # Three outcomes are possible for a connection:
  #   exempt     -> no TOTP at all; falls through to the normal password stack
  #   enrolling  -> TOTP with nullok, so a member of $ENROLL_GROUP who has no
  #                 token yet can still authenticate and be forced through
  #                 self-enrolment by sshd's ForceCommand
  #   everyone   -> TOTP under the global $NULLOK setting
  #
  # Every [success=N] skips the NEXT N modules, so a jump on line n lands on
  # line n+N+1. The counts below depend on the exact length of this block;
  # tests/test-pam-stack.sh asserts each landing site.
  if [[ "$AUTH_MODE" == "pubkey+totp" ]]; then
    if [[ "$ENROLL_GATE" == "yes" ]]; then
      # 1 uid  2 user  3 exempt-grp  4 enrol-grp  5 totp  6 totp-nullok
      # 7 permit  8 substack password-auth  9 include postlogin
      echo "auth       [success=6 default=ignore] pam_succeed_if.so quiet uid < $MIN_UID"
      echo "auth       [success=5 default=ignore] pam_succeed_if.so quiet user in $list"
      echo "auth       [success=4 default=ignore] pam_succeed_if.so quiet user ingroup $EXEMPT_GROUP"
      echo "auth       [success=1 default=ignore] pam_succeed_if.so quiet user ingroup $ENROLL_GROUP"
      echo "auth       [success=3 default=die] pam_google_authenticator.so${ga_args}"
      echo "auth       requisite     pam_google_authenticator.so nullok"
      echo "auth       [success=1 default=die] pam_permit.so"
    else
      # 1 uid  2 user  3 exempt-grp  4 totp  5 permit
      # 6 substack password-auth  7 include postlogin
      echo "auth       [success=4 default=ignore] pam_succeed_if.so quiet uid < $MIN_UID"
      echo "auth       [success=3 default=ignore] pam_succeed_if.so quiet user in $list"
      echo "auth       [success=2 default=ignore] pam_succeed_if.so quiet user ingroup $EXEMPT_GROUP"
      echo "auth       requisite     pam_google_authenticator.so${ga_args}"
      echo "auth       [success=1 default=die] pam_permit.so"
    fi
  else
    if [[ "$ENROLL_GATE" == "yes" ]]; then
      # 1 substack password-auth  2 uid  3 user  4 exempt-grp  5 enrol-grp
      # 6 totp  7 totp-nullok  8 include postlogin
      echo "auth       [success=5 default=ignore] pam_succeed_if.so quiet uid < $MIN_UID"
      echo "auth       [success=4 default=ignore] pam_succeed_if.so quiet user in $list"
      echo "auth       [success=3 default=ignore] pam_succeed_if.so quiet user ingroup $EXEMPT_GROUP"
      echo "auth       [success=1 default=ignore] pam_succeed_if.so quiet user ingroup $ENROLL_GROUP"
      echo "auth       [success=1 default=die] pam_google_authenticator.so${ga_args}"
      echo "auth       requisite     pam_google_authenticator.so nullok"
    else
      # 1 substack password-auth  2 uid  3 user  4 exempt-grp
      # 5 totp  6 include postlogin
      echo "auth       [success=3 default=ignore] pam_succeed_if.so quiet uid < $MIN_UID"
      echo "auth       [success=2 default=ignore] pam_succeed_if.so quiet user in $list"
      echo "auth       [success=1 default=ignore] pam_succeed_if.so quiet user ingroup $EXEMPT_GROUP"
      echo "auth       requisite     pam_google_authenticator.so${ga_args}"
    fi
  fi
  echo "# END ssh-mfa"
}

pam_insert_where() {
  case "$AUTH_MODE" in
    pubkey+totp)   echo before ;;   # TOTP runs instead of the password stack
    password+totp) echo after  ;;   # TOTP runs after the password stack
  esac
}

# Read a pam.d file on stdin, emit it with any previous block replaced.
# Idempotent: strips a prior managed block before inserting, so repeated runs
# (and NULLOK flips by 50-enforce-strict.sh) never stack duplicates.
pam_render() {
  local block where line inserted=no in_block=no
  block="$(pam_block)"
  where="$(pam_insert_where)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "# BEGIN ssh-mfa"* ]]; then in_block=yes; continue; fi
    if [[ "$in_block" == yes ]]; then
      [[ "$line" == "# END ssh-mfa"* ]] && in_block=no
      continue
    fi
    if [[ "$inserted" == "no" && "$line" =~ $PAM_ANCHOR ]]; then
      if [[ "$where" == "before" ]]; then
        printf '%s\n' "$block" "$line"
      else
        printf '%s\n' "$line" "$block"
      fi
      inserted=yes
    else
      printf '%s\n' "$line"
    fi
  done
  [[ "$inserted" == "yes" ]] || return 1
}

# --- enrolment display ------------------------------------------------------
# google-authenticator only draws a QR code when its stdout is a TTY, and
# 40-enroll-user.sh captures stdout to a file. So we build the otpauth URI
# from the stored secret and render it ourselves, which also lets us state
# algorithm/digits/period explicitly instead of relying on app defaults.

urlencode() {
  local s="$1" i c out=""
  for (( i=0; i<${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9.~_-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s\n' "$out"
}

# First line of ~/.google_authenticator is the base32 secret; the rest are
# options (" RATE_LIMIT ...") and scratch codes.
user_secret() {
  local home
  home="$(getent passwd "$1" | cut -d: -f6)" || return 1
  [[ -s "$home/.google_authenticator" ]] || return 1
  head -1 "$home/.google_authenticator"
}

otpauth_uri() {
  local u="$1" secret label issuer
  secret="$(user_secret "$u")" || return 1
  issuer="$TOTP_ISSUER"
  label="$u@$issuer"
  printf 'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30\n' \
    "$(urlencode "$label")" "$secret" "$(urlencode "$issuer")"
}

# Print the QR code, the URI and the secret for one enrolled user.
show_enrollment() {
  local u="$1" uri secret
  secret="$(user_secret "$u")" || { err "$u is not enrolled"; return 1; }
  uri="$(otpauth_uri "$u")"

  local drew=no
  echo
  if command -v qrencode >/dev/null 2>&1; then
    if qrencode -t ANSIUTF8 -m 1 -- "$uri" 2>/dev/null \
       || qrencode -t ASCII -m 1 -- "$uri" 2>/dev/null; then
      drew=yes
    else
      warn "qrencode failed; use the manual entry below"
    fi
  else
    warn "qrencode is not installed, so no QR code can be drawn."
    warn "  dnf -y install qrencode   then: scripts/40-enroll-user.sh --show $u"
  fi

  # google-authenticator emits a 128-bit secret as 26 unpadded base32 chars.
  # Most apps accept that; some require the length to be a multiple of 8 and
  # report an unpadded key as invalid, so offer the padded form too.
  local pad="" need=$(( (8 - ${#secret} % 8) % 8 ))
  (( need )) && pad="$secret$(printf '=%.0s' $(seq 1 $need))"

  cat <<INFO

  $([[ "$drew" == yes ]] && echo "Scan the code above, or enter" || echo "Enter") this by hand in the app:

    Account     $u@$TOTP_ISSUER
    Key         $secret
    Type        Time based   (NOT counter/HOTP based)
    Digits      6      Period 30s      Algorithm SHA1
${pad:+"
    If the app rejects that key as invalid, enter the padded form instead:
      $pad
"}
  Full URI (paste into a password manager that accepts otpauth:// URIs):

    $uri

INFO
  if command -v oathtool >/dev/null 2>&1; then
    local padded="$secret" n
    n=$(( (8 - ${#secret} % 8) % 8 ))
    (( n )) && padded="$secret$(printf '=%.0s' $(seq 1 $n))"
    log "code the server expects right now: $(oathtool --totp -b "$padded" 2>/dev/null || echo '(oathtool could not decode the key)')"
    log "if your app shows a different code, the app entry is wrong, not the secret."
  else
    log "install oathtool to compare your app against the server: dnf -y install oathtool"
  fi
}

# The secret file must be USER-WRITABLE, not just readable. With -d
# (disallow code reuse) the module records each used code in the file, and
# with -r/-R it records attempt timestamps for rate limiting. At 0400 those
# writes fail, the module returns an auth error with no message to the user,
# and sshd simply re-prompts -- both factors look accepted, then nothing.
# 0600 owned by the user is what google-authenticator itself creates.
secure_secret() {
  local u="$1" home
  home="$(getent passwd "$u" | cut -d: -f6)" || return 1
  local f="$home/.google_authenticator"
  [[ -e "$f" ]] || return 1
  chown "$u:$(id -gn "$u")" "$f"
  chmod 0600 "$f"
  command -v restorecon >/dev/null && restorecon -F "$f" 2>/dev/null || true
}

# Warn if a secret lacks the label sshd needs in order to REWRITE it.
# Reading works under the default policy; the atomic rewrite does not.
selinux_warn_if_unlabelled() {
  local u="$1" home f ctx
  command -v getenforce >/dev/null 2>&1 || return 0
  [[ "$(getenforce)" == "Disabled" ]] && return 0
  home="$(getent passwd "$u" | cut -d: -f6)" || return 0
  f="$home/.google_authenticator"
  [[ -e "$f" ]] || return 0
  ctx="$(ls -Zd "$f" 2>/dev/null | awk '{print $1}')"
  case "$ctx" in
    *ssh_home_t*) return 0 ;;
    *) warn "$u: secret is labelled ${ctx:-unknown}, not ssh_home_t."
       warn "    sshd will accept the code and then fail to update the file."
       warn "    Fix: scripts/15-selinux.sh" ;;
  esac
}

# Rewrite a secret's OPTION lines to match TOTP_STATEFUL, leaving the key and
# scratch codes untouched. Used after enrolment and by --restate.
#
# google-authenticator is always invoked WITH -d and -r/-R, because omitting
# them makes it stop and ask the user about settings that are the server's
# decision. Stateless mode is therefore produced by removing the option lines
# afterwards rather than by declining the flags.
apply_state_policy() {
  local u="$1" home f tmp
  home="$(getent passwd "$u" | cut -d: -f6)" || return 1
  f="$home/.google_authenticator"
  [[ -s "$f" ]] || return 1
  tmp="$(mktemp)"
  if [[ "$TOTP_STATEFUL" == "yes" ]]; then
    awk -v n="$TOTP_RATE_LIMIT_N" -v w="$TOTP_RATE_LIMIT_S" '
      NR==1 { print; next }
      /^" RATE_LIMIT/ || /^" DISALLOW_REUSE/ { next }
      /^" / && !done { print "\" RATE_LIMIT " n " " w; print "\" DISALLOW_REUSE"; done=1 }
      { print }
      END { if (!done) { print "\" RATE_LIMIT " n " " w; print "\" DISALLOW_REUSE" } }
    ' "$f" > "$tmp"
  else
    grep -v -e '^" RATE_LIMIT' -e '^" DISALLOW_REUSE' "$f" > "$tmp"
  fi
  install -m 0600 -o "$u" -g "$(id -gn "$u")" "$tmp" "$f"
  rm -f "$tmp"
  command -v restorecon >/dev/null && restorecon -F "$f" 2>/dev/null || true
}

# Pad a base32 secret to a multiple of 8. google-authenticator emits 26
# unpadded chars for a 128-bit key, which some decoders reject outright --
# and a decode failure is indistinguishable from a wrong code, so every
# attempt gets refused with no clue why.
#
# NOTE: ssh-mfa-finalize carries its own copy of this, because it runs from
# /usr/local/sbin without the repo present. Change both together.
pad_b32() {
  local k n
  k="$(tr -d '[:space:]' <<<"$1" | tr 'a-z' 'A-Z')"
  k="${k%%=*}"
  n=$(( (8 - ${#k} % 8) % 8 ))
  if (( n )); then printf '%s%s\n' "$k" "$(printf '=%.0s' $(seq 1 $n))"
  else printf '%s\n' "$k"; fi
}

# Print what the server expects for a user, and optionally test one code.
# This is the diagnostic for "my app's code is rejected".
check_user_code() {
  local u="$1" code="${2:-}" key padded now stamp exp match=no
  key="$(user_secret "$u")" || { err "$u is not enrolled"; return 1; }
  padded="$(pad_b32 "$key")"

  echo "  user            $u"
  echo "  secret length   ${#key} chars (padded to ${#padded})"
  echo "  file            $(getent passwd "$u" | cut -d: -f6)/.google_authenticator"
  echo "  mode/owner      $(stat -c '%a %U:%G' "$(getent passwd "$u" | cut -d: -f6)/.google_authenticator" 2>/dev/null)"
  echo "  options in file $(grep -c '^" ' "$(getent passwd "$u" | cut -d: -f6)/.google_authenticator" 2>/dev/null) line(s)"
  echo "  server time     $(date '+%Y-%m-%d %H:%M:%S %Z')  (epoch $(date +%s))"
  if command -v chronyc >/dev/null 2>&1; then
    echo "  clock offset    $(chronyc tracking 2>/dev/null | awk -F': *' '/System time/{print $2}')"
  fi

  if ! command -v oathtool >/dev/null 2>&1; then
    warn "oathtool is not installed; cannot compute the expected code"
    warn "  dnf -y install oathtool"
    return 1
  fi

  if ! oathtool --totp -b "$padded" >/dev/null 2>&1; then
    err "oathtool cannot decode this secret even padded. That is the fault:"
    err "  every code would be rejected regardless of the app."
    oathtool --totp -b "$padded" 2>&1 | sed 's/^/    /' >&2
    return 1
  fi

  now="$(date +%s)"
  echo "  codes the server accepts:"
  for off in -30 0 30; do
    if (( off == 0 )); then
      exp="$(oathtool --totp -b "$padded" 2>/dev/null)"
    else
      stamp="$(date -u -d "@$((now + off))" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null)" || continue
      exp="$(oathtool --totp -b --now="$stamp" "$padded" 2>/dev/null)" || continue
    fi
    printf '    %+4ds  %s\n' "$off" "${exp:-(could not compute)}"
    [[ -n "$code" && "$code" == "$exp" ]] && match=yes
  done

  if [[ -n "$code" ]]; then
    echo
    if [[ "$match" == yes ]]; then ok "code $code MATCHES"
    else err "code $code does not match any accepted step"; fi
  fi
}
