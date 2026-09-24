#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Scott Jones
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
  token state     $([[ "$TOTP_STATEFUL" == yes ]] && echo "stateful (replay protection + rate limit)" || echo "stateless (no replay protection, no rate limit)")
  new users       $([[ "$ENROLL_GATE" == yes ]] && echo "forced to self-enrol on first login" || echo "enrolled by an admin")
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

# SELinux before PAM and sshd, so a host is never left requiring a second
# factor that the module is not permitted to record. Both steps are no-ops
# when SELinux is disabled.
scripts/15-selinux.sh $DRY \
  || warn "SELinux labelling reported problems; see scripts/15-selinux.sh --diagnose"
if [[ "$TOTP_STATEFUL" == "yes" ]]; then
  # Stateful tokens are rewritten on every login. Without this module that
  # rewrite is denied and every correct code is refused.
  scripts/16-selinux-policy.sh $DRY \
    || warn "policy module failed; either fix it or set TOTP_STATEFUL=no and run 40-enroll-user.sh --restate"
else
  log "TOTP_STATEFUL=no: skipping the policy module (nothing rewrites the secret)"
fi

# The gate must exist before PAM and sshd are generated, because both emit
# an extra branch for its group.
if [[ "$ENROLL_GATE" == "yes" ]]; then
  [[ -n "$DRY" ]] || scripts/45-enrollment-gate.sh --install
fi

scripts/20-configure-pam.sh $DRY
scripts/30-configure-sshd.sh $DRY "${TIMER[@]}"

[[ -n "$DRY" ]] && { log "--dry-run: nothing was changed"; exit 0; }
scripts/90-validate.sh || true
