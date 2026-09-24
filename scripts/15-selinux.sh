#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Scott Jones
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
# Usage: 15-selinux.sh [--dry-run] [--diagnose] [--collect]
#
#   --diagnose  report which cause applies, change nothing
#   --collect   dump full diagnostic output for pasting into a bug report
#               (describes the secret file but never prints its contents)

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

DRY=no; DIAGNOSE_ONLY=no; COLLECT=no
while (( $# )); do
  case "$1" in
    --dry-run)  DRY=yes; shift ;;
    --diagnose) DIAGNOSE_ONLY=yes; shift ;;
    --collect)  COLLECT=yes; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

# --- --collect: dump everything needed to identify the denial -------------
# Printed so it can be pasted verbatim. Contains no secrets: the secret file
# is described (label, mode, owner, size) but never read.
if [[ "$COLLECT" == "yes" ]]; then
  sec() { printf '\n===== %s =====\n' "$*"; }
  # Commands are passed as a single string for display, so eval the string
  # form rather than the array form (shellcheck SC2294).
  run() { printf '$ %s\n' "$*"; eval "$*" 2>&1 | sed 's/^/  /' || true; }

  sec "identity"
  run "uname -r"; run "cat /etc/os-release | head -3"
  run "rpm -q google-authenticator openssh-server selinux-policy 2>&1"

  sec "selinux mode"
  run "getenforce"; run "sestatus | head -8"

  sec "the secret and its directory"
  while read -r u; do
    [[ -z "$u" ]] && continue
    h="$(getent passwd "$u" | cut -d: -f6)"
    [[ -e "$h/.google_authenticator" ]] || continue
    run "ls -ldZ '$h'"
    run "ls -lZ '$h/.google_authenticator'"
    run "stat -c '%n mode=%a owner=%U:%G size=%s' '$h/.google_authenticator'"
    run "runuser -u '$u' -- test -w '$h' && echo 'home writable by $u' || echo 'home NOT writable by $u'"
    run "findmnt -no SOURCE,FSTYPE,OPTIONS --target '$h'"
    run "df -Ph '$h' | tail -1"
    run "lsattr -d '$h/.google_authenticator' 2>&1"
  done < <(mfa_target_users)

  sec "fcontext rules for the secret"
  run "semanage fcontext -l 2>/dev/null | grep -i google_authenticator || echo '(no matching fcontext rule)'"

  sec "AVC denials (today)"
  run "ausearch -m avc -ts today 2>/dev/null | grep -iE 'google_authenticator|sshd' | tail -25 || echo '(none found)'"

  sec "what the policy would allow instead"
  run "ausearch -m avc -ts today 2>/dev/null | grep -i google_authenticator | audit2allow 2>/dev/null || echo '(audit2allow produced nothing; install policycoreutils-devel)'"
  if command -v sesearch >/dev/null 2>&1; then
    run "sesearch -A -s sshd_t -t ssh_home_t   -c file -p create,write 2>&1 | head"
    run "sesearch -A -s sshd_t -t user_home_t  -c file -p create,write 2>&1 | head"
    run "sesearch -A -s sshd_t -t user_home_dir_t -c dir -p add_name,write 2>&1 | head"
  else
    printf '  (sesearch not installed: dnf -y install setools-console)\n'
  fi

  sec "recent pam messages"
  run "grep -i 'google_auth\|secret file' /var/log/secure | tail -15"

  sec "effective policy"
  run "sshd -T | grep -iE 'authenticationmethods|passwordauthentication|kbdinteractive|usepam'"
  run "grep -nE '^[[:space:]]*auth' /etc/pam.d/sshd"
  exit 0
fi

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
      *auth_home_t*|*ssh_home_t*) ok "$u: secret label is $ctx" ;;
      *) note "$u: secret label is $ctx, expected auth_home_t" ;;
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

# Label the secret auth_home_t, which is the type the distribution policy
# already assigns to .google_authenticator (see `semanage fcontext -l`).
#
# Note what this does NOT fix. fcontext governs what restorecon applies, not
# the label a NEWLY CREATED file receives. The module's tempfile
# ".google_authenticator~XXXXXX" has a random suffix, so no named file
# transition matches it and it inherits user_home_dir_t from the directory.
# sshd_t cannot create that, and no fcontext rule changes it. That needs the
# policy module in scripts/16-selinux-policy.sh.
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
  # An earlier version of this script set ssh_home_t here, which overrode the
  # distribution's auth_home_t rule. Retract it if present.
  semanage fcontext -d -t ssh_home_t "$pattern" 2>/dev/null \
    && warn "removed an incorrect ssh_home_t rule for $p" || true
  if semanage fcontext -l 2>/dev/null | grep -qF -- "$pattern"; then
    ok "fcontext rule already present for $p"
    continue
  fi
  if [[ "$DRY" == "yes" ]]; then
    log "--dry-run: semanage fcontext -a -t ssh_home_t '$pattern'"
    continue
  fi
  if semanage fcontext -a -t auth_home_t "$pattern" 2>/dev/null; then
    ok "added fcontext: $pattern -> auth_home_t"
  else
    # -a fails if an equivalent rule exists; -m modifies it instead.
    semanage fcontext -m -t auth_home_t "$pattern" \
      && ok "updated fcontext: $pattern -> auth_home_t" \
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
ok "labelling done. No secret was rotated; existing tokens still work."
warn "Labelling alone does NOT permit the atomic rewrite. If logins still fail"
warn "with 'Failed to create tempfile', install the policy module:"
warn "    sudo scripts/16-selinux-policy.sh"
warn "Test a login from a SECOND terminal before closing this session."
log  "If it still fails: scripts/15-selinux.sh --diagnose"
