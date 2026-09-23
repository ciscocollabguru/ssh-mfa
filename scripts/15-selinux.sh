#!/usr/bin/env bash
# Diagnose and fix write access to ~/.google_authenticator.
#
# pam_google_authenticator updates the secret file on every authentication
# (it records used codes for -d and attempt timestamps for -r/-R). It does so
# atomically: it creates ".google_authenticator~XXXXXX" in the user's home
# directory and renames it over the original. That needs write access to the
# DIRECTORY, not just the file, and under SELinux it needs a label sshd_t is
# allowed to create.
#
# Symptom when this is wrong -- correct code, login still rejected:
#   sshd(pam_google_authenticator): Accepted google_authenticator for <user>
#   sshd(pam_google_authenticator): Failed to create tempfile ".../..~XXXXXX": Permission denied
#   sshd(pam_google_authenticator): Failed to update secret file ...: Permission denied
#
# Usage: 15-selinux.sh [--dry-run] [--diagnose]

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

DRY=no; DIAGNOSE_ONLY=no
while (( $# )); do
  case "$1" in
    --dry-run)  DRY=yes; shift ;;
    --diagnose) DIAGNOSE_ONLY=yes; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

# --- 1. diagnose ----------------------------------------------------------
mode=Disabled
command -v getenforce >/dev/null 2>&1 && mode="$(getenforce)"
log "SELinux: $mode"

problems=0
note() { warn "$*"; problems=$((problems+1)); }

log "checking each enrolled user's home directory"
while read -r u; do
  [[ -z "$u" ]] && continue
  home="$(getent passwd "$u" | cut -d: -f6)"
  f="$home/.google_authenticator"
  [[ -e "$f" ]] || continue

  # Plain filesystem permissions: the user must be able to create a file
  # in their own home, or the atomic rewrite cannot work at all.
  if runuser -u "$u" -- test -w "$home" 2>/dev/null; then
    ok "$u: $home is writable by $u"
  else
    note "$u: $home is NOT writable by $u -- $(stat -c '%a %U:%G' "$home")"
  fi

  # Read-only mount or a full filesystem produces the same error.
  if findmnt -no OPTIONS --target "$home" 2>/dev/null | grep -qw ro; then
    note "$u: the filesystem holding $home is mounted read-only"
  fi
  avail="$(df -P "$home" 2>/dev/null | awk 'NR==2{print $4}')"
  [[ -n "$avail" && "$avail" == 0 ]] && note "$u: filesystem holding $home is full"

  # The immutable attribute also yields EACCES.
  if command -v lsattr >/dev/null 2>&1 && lsattr -d "$f" 2>/dev/null | grep -q 'i'; then
    note "$u: $f has the immutable attribute set (chattr -i to clear)"
  fi

  if [[ "$mode" != "Disabled" ]]; then
    ctx="$(ls -Zd "$f" 2>/dev/null | awk '{print $1}')"
    log "$u: label $ctx"
    case "$ctx" in
      *ssh_home_t*) ok "$u: secret is ssh_home_t (sshd may rewrite it)" ;;
      *) note "$u: secret is not ssh_home_t; sshd_t cannot create its tempfile beside it" ;;
    esac
  fi
done < <(mfa_target_users)

if [[ "$mode" != "Disabled" ]] && command -v ausearch >/dev/null 2>&1; then
  if ausearch -m avc -ts recent 2>/dev/null | grep -q 'google_authenticator'; then
    note "recent SELinux AVC denials mention google_authenticator:"
    ausearch -m avc -ts recent 2>/dev/null | grep 'google_authenticator' | tail -3 | sed 's/^/    /' >&2
  fi
fi

if (( problems == 0 )); then
  ok "nothing to fix: the module can rewrite every enrolled secret"
  exit 0
fi

if [[ "$DIAGNOSE_ONLY" == "yes" ]]; then
  err "$problems problem(s) found. Re-run without --diagnose to apply the SELinux fix."
  exit 1
fi

# --- 2. fix ---------------------------------------------------------------
if [[ "$mode" == "Disabled" ]]; then
  err "SELinux is disabled, so the failures above are plain filesystem permissions."
  err "Fix the home directory ownership/mode (or the mount) and re-run; there is nothing for this script to label."
  exit 1
fi

command -v semanage >/dev/null 2>&1 || {
  log "installing policycoreutils-python-utils (provides semanage)"
  [[ "$DRY" == "yes" ]] || dnf -y install policycoreutils-python-utils
}
command -v semanage >/dev/null 2>&1 || die "semanage still unavailable; cannot add an fcontext rule"

# Label the secret AND its tempfiles as ssh_home_t. The tempfile name is
# ".google_authenticator~XXXXXX", so the pattern must not anchor at the end
# of the basename -- a rule matching only the exact filename leaves the
# tempfile as user_home_t and the denial persists.
#
# The rule is added per parent directory of the affected homes, so accounts
# created later are covered without re-running this.
escape_re() { sed 's/[][\.^$*+?(){}|]/\\&/g' <<<"$1"; }

mapfile -t parents < <(
  while read -r u; do
    [[ -z "$u" ]] && continue
    h="$(getent passwd "$u" | cut -d: -f6)"
    [[ -n "$h" ]] && dirname "$h"
  done < <(mfa_target_users) | sort -u
)

for p in "${parents[@]}"; do
  pattern="$(escape_re "$p")/[^/]+/\\.google_authenticator.*"
  if semanage fcontext -l 2>/dev/null | grep -qF -- "$pattern"; then
    ok "fcontext rule already present for $p"
    continue
  fi
  if [[ "$DRY" == "yes" ]]; then
    log "--dry-run: semanage fcontext -a -t ssh_home_t '$pattern'"
    continue
  fi
  if semanage fcontext -a -t ssh_home_t "$pattern" 2>/dev/null; then
    ok "added fcontext: $pattern -> ssh_home_t"
  else
    # -a fails if an equivalent rule exists; -m modifies it instead.
    semanage fcontext -m -t ssh_home_t "$pattern" \
      && ok "updated fcontext: $pattern -> ssh_home_t" \
      || die "could not add an fcontext rule for $pattern"
  fi
done

[[ "$DRY" == "yes" ]] && { log "--dry-run: nothing was changed"; exit 0; }

log "relabelling existing secrets"
while read -r u; do
  [[ -z "$u" ]] && continue
  home="$(getent passwd "$u" | cut -d: -f6)"
  f="$home/.google_authenticator"
  [[ -e "$f" ]] || continue
  restorecon -Fv "$f" || warn "restorecon failed for $f"
  log "$u: now $(ls -Zd "$f" | awk '{print $1}')"
done < <(mfa_target_users)

echo
ok "SELinux fix applied. No secret was rotated; existing tokens still work."
warn "Test a login from a SECOND terminal before closing this session."
log  "If it still fails: scripts/15-selinux.sh --diagnose"
