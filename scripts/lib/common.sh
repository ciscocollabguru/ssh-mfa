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
  : "${TOTP_ISSUER:=$(hostname -s 2>/dev/null || echo ssh)}"
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
  echo "# Mode: $AUTH_MODE | nullok: $NULLOK | exempt: uid<$MIN_UID, [$EXEMPT_USERS], group $EXEMPT_GROUP"
  case "$AUTH_MODE" in
    pubkey+totp)
      # Final auth order: 1-3 succeed_if, 4 totp, 5 permit,
      #                   6 substack password-auth, 7 include postlogin.
      # 1->6, 2->6, 3->6 (exempt); 5 jumps over 6 so a non-exempt user is
      # never asked for a password after a valid code.
      echo "auth       [success=4 default=ignore] pam_succeed_if.so quiet uid < $MIN_UID"
      echo "auth       [success=3 default=ignore] pam_succeed_if.so quiet user in $list"
      echo "auth       [success=2 default=ignore] pam_succeed_if.so quiet user ingroup $EXEMPT_GROUP"
      echo "auth       requisite     pam_google_authenticator.so${ga_args}"
      echo "auth       [success=1 default=die] pam_permit.so"
      ;;
    password+totp)
      # Final auth order: 1 substack password-auth, 2-4 succeed_if,
      #                   5 totp, 6 include postlogin. 2->6, 3->6, 4->6.
      echo "auth       [success=3 default=ignore] pam_succeed_if.so quiet uid < $MIN_UID"
      echo "auth       [success=2 default=ignore] pam_succeed_if.so quiet user in $list"
      echo "auth       [success=1 default=ignore] pam_succeed_if.so quiet user ingroup $EXEMPT_GROUP"
      echo "auth       requisite     pam_google_authenticator.so${ga_args}"
      ;;
  esac
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
