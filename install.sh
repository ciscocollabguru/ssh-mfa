#!/usr/bin/env bash
# Orchestrator: preflight -> packages -> PAM -> sshd.
# Enrolment and strict enforcement are deliberately separate, manual steps.
#
# Usage: ./install.sh [--dry-run] [--safety-timer MINUTES] [--yes]

set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
. scripts/lib/common.sh
require_root
load_config

DRY=""; TIMER=(); YES=no
while (( $# )); do
  case "$1" in
    --dry-run) DRY="--dry-run"; shift ;;
    --safety-timer) TIMER=(--safety-timer "${2:?minutes required}"); shift 2 ;;
    --yes|-y) YES=yes; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

cat <<BANNER
ssh-mfa: about to require two factors for SSH on $(hostname -f 2>/dev/null || hostname)

  mode            $AUTH_MODE
  enforcement     $([[ "$NULLOK" == yes ]] && echo "permissive (unenrolled users still get in)" || echo "STRICT (unenrolled users are locked out)")
  exempt          users [$EXEMPT_USERS], group [$EXEMPT_GROUP], uid < $MIN_UID
  affected        $(mfa_target_users | tr '\n' ' ')

BANNER

if [[ -z "$DRY" && "$YES" != "yes" ]]; then
  warn "Keep a second root session or console open while this runs."
  read -r -p "Continue? [y/N] " a
  [[ "$a" == y || "$a" == Y ]] || { log "aborted"; exit 0; }
fi

# One backup set for the whole run, so a rollback undoes PAM and sshd
# together rather than half the change.
[[ -n "$DRY" ]] || begin_backup_set
[[ -n "$DRY" ]] || log "backup set for this run: $MFA_BACKUP_DIR"

scripts/00-preflight.sh
[[ -n "$DRY" ]] || scripts/10-install-packages.sh
scripts/20-configure-pam.sh $DRY
scripts/30-configure-sshd.sh $DRY "${TIMER[@]}"

[[ -n "$DRY" ]] && { log "--dry-run: nothing was changed"; exit 0; }
scripts/90-validate.sh || true
