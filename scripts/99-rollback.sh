#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Scott Jones
# Restore /etc/pam.d/sshd, /etc/ssh/sshd_config and the drop-in from a
# backup set, then reload sshd. Enrolled tokens are left in place.
#
#   99-rollback.sh              restore the most recent set (prompts)
#   99-rollback.sh --yes        no prompt (used by the auto-rollback timer)
#   99-rollback.sh --list       list available sets
#   99-rollback.sh --set DIR    restore a specific set

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

ASSUME_YES=no; SET=""
while (( $# )); do
  case "$1" in
    --yes|-y) ASSUME_YES=yes; shift ;;
    --list) ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null || echo "(no backups under $BACKUP_ROOT)"; exit 0 ;;
    --set) SET="${2:?directory required}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -z "$SET" ]]; then
  if [[ -r "$BACKUP_ROOT/.latest" ]]; then
    SET="$(cat "$BACKUP_ROOT/.latest")"
  else
    SET="$(ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -1)"
  fi
fi
[[ -n "$SET" && -d "$SET" ]] || die "no backup set found. Restore by hand using docs/TROUBLESHOOTING.md."
[[ -r "$SET/manifest.tsv" ]] || die "$SET has no manifest.tsv"

log "restoring from $SET"
sed 's/^/    /' "$SET/manifest.tsv"

if [[ "$ASSUME_YES" != "yes" ]]; then
  read -r -p "Restore these files and reload sshd? [y/N] " a
  [[ "$a" == y || "$a" == Y ]] || { log "aborted"; exit 0; }
fi

while IFS=$'\t' read -r target saved; do
  [[ -z "$target" ]] && continue
  if [[ "$saved" == "ABSENT" ]]; then
    if [[ -e "$target" ]]; then rm -f "$target"; ok "removed $target (did not exist before)"; fi
  elif [[ -e "$saved" ]]; then
    cp -a "$saved" "$target"; ok "restored $target"
  else
    warn "backup for $target is missing at $saved"
  fi
done < "$SET/manifest.tsv"

command -v restorecon >/dev/null && restorecon -F /etc/ssh/sshd_config /etc/pam.d/sshd 2>/dev/null || true

if sshd_validate; then
  sshd_reload
  ok "rollback complete"
else
  err "restored files still fail sshd -t. Fix /etc/ssh/sshd_config from the console before restarting sshd."
  exit 1
fi

log "note: TOTP secrets in user home directories were NOT removed."
log "      MFA is simply no longer requested. Re-apply with install.sh."
