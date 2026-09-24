#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Scott Jones
# Write the sshd drop-in that requires two factors, exempt root and the
# exempt group, validate, then reload sshd.
#
# Usage: 30-configure-sshd.sh [--dry-run] [--safety-timer MINUTES]
#
# --safety-timer arms a transient systemd timer that runs 99-rollback.sh
# after N minutes unless you cancel it. Use it whenever you are applying
# this over the very SSH connection you might break.

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

DRY=no; TIMER=0
while (( $# )); do
  case "$1" in
    --dry-run) DRY=yes; shift ;;
    --safety-timer) TIMER="${2:?minutes required}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

MAIN=/etc/ssh/sshd_config

# --- guard: in pubkey mode, everyone affected needs a key already ----------
if [[ "$AUTH_MODE" == "pubkey+totp" ]]; then
  missing=()
  while read -r u; do
    [[ -z "$u" ]] && continue
    # Accounts mid-enrolment authenticate by password through the gate's own
    # Match block, so a missing key is expected and not a lockout risk.
    if [[ "$ENROLL_GATE" == "yes" ]] \
       && id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$ENROLL_GROUP"; then
      continue
    fi
    home="$(getent passwd "$u" | cut -d: -f6)"
    if [[ ! -s "$home/.ssh/authorized_keys" ]]; then missing+=("$u"); fi
  done < <(mfa_target_users)
  if (( ${#missing[@]} )); then
    err "AUTH_MODE=pubkey+totp disables password login, but these accounts have no authorized_keys:"
    printf '    %s\n' "${missing[@]}" >&2
    err "They will be unable to log in. Install their keys first, add them to $EXEMPT_GROUP, or use AUTH_MODE=password+totp."
    [[ "${MFA_FORCE:-no}" == "yes" ]] || exit 1
    warn "continuing anyway (MFA_FORCE=yes)"
  else
    ok "every target user has an authorized_keys file"
  fi
fi

# --- build the drop-in -----------------------------------------------------
case "$AUTH_MODE" in
  pubkey+totp)   METHODS="publickey,keyboard-interactive:pam" ;;
  password+totp) METHODS="keyboard-interactive:pam" ;;
esac

# ChallengeResponseAuthentication is the pre-8.7 name for
# KbdInteractiveAuthentication. It is still accepted on EL8 (OpenSSH 8.0) and
# is what that release's stock sshd_config sets, so emit it there to win the
# first-value-wins race. Newer OpenSSH removed it, and emitting a keyword the
# local sshd rejects would fail sshd -t and block every reload.
CR_LINE=""
if sshd_supports_keyword ChallengeResponseAuthentication yes; then
  CR_LINE="ChallengeResponseAuthentication yes"$'\n'
  log "sshd accepts ChallengeResponseAuthentication; emitting it alongside KbdInteractiveAuthentication"
else
  log "sshd has dropped ChallengeResponseAuthentication; using KbdInteractiveAuthentication only"
fi

dropin_content() {
  cat <<CONF
# Managed by ssh-mfa/scripts/30-configure-sshd.sh. Do not edit by hand.
# Generated $(date -Is) | AUTH_MODE=$AUTH_MODE
#
# Global policy: every named user must present two factors.
# sshd applies the FIRST value it sees for a keyword, so this file must be
# Include-d before any conflicting directive in $MAIN.

UsePAM yes
KbdInteractiveAuthentication yes
${CR_LINE}PasswordAuthentication no
AuthenticationMethods $METHODS

# --- exemptions ---
# Match blocks must come last: every directive after a Match belongs to it.

# root is exempt by design. It is the break-glass account, and an operator
# locked out of root cannot repair a broken PAM stack remotely.
Match User root
    AuthenticationMethods publickey

# Service and automation accounts that authenticate with keys only.
Match Group $EXEMPT_GROUP
    AuthenticationMethods publickey
$(if [[ "$ENROLL_GATE" == "yes" ]]; then cat <<GATE

# Accounts that have not set up a token yet. They authenticate with their
# password alone (the PAM stack applies nullok to this group only) and are
# forced into self-enrolment instead of a shell. ssh-mfa-finalize removes
# them from this group once they have a working token, after which the
# strict branch of the PAM stack applies to them like everyone else.
Match Group $ENROLL_GROUP
    AuthenticationMethods keyboard-interactive:pam
    ForceCommand /usr/local/sbin/ssh-mfa-selfenroll
    PermitTTY yes
    X11Forwarding no
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTunnel no
    GatewayPorts no
GATE
fi)
$(if [[ -n "$BREAKGLASS_CIDR" ]]; then cat <<BG

# Break-glass network. Review docs/MANUAL-STEPS.md before relying on this.
Match Address $BREAKGLASS_CIDR
    AuthenticationMethods publickey
BG
fi)
CONF
}

if [[ "$DRY" == "yes" ]]; then
  log "--dry-run: proposed $SSHD_DROPIN"
  dropin_content | sed 's/^/    /'
  exit 0
fi

# --- exempt group must exist before sshd parses Match Group ----------------
for g in "$EXEMPT_GROUP" $([[ "$ENROLL_GATE" == "yes" ]] && echo "$ENROLL_GROUP"); do
  if ! getent group "$g" >/dev/null; then
    groupadd -r "$g"; ok "created group $g"
  else
    ok "group $g exists"
  fi
done

backup_file "$MAIN"
backup_file "$SSHD_DROPIN"

install -d -m 0755 "$(dirname "$SSHD_DROPIN")"
dropin_content > "$SSHD_DROPIN"
chmod 0600 "$SSHD_DROPIN"
ok "wrote $SSHD_DROPIN"

# --- make sure the drop-in is actually read, and read first ----------------
if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$MAIN"; then
  ok "$MAIN already includes sshd_config.d"
else
  # EL8 ships sshd_config without an Include; EL9+ and Fedora include
  # sshd_config.d already. Where it is missing it must go at the very top,
  # because sshd honours the first occurrence of each keyword.
  tmp="$(mktemp)"
  { echo "# Added by ssh-mfa: drop-ins must be read first (first value wins)."
    echo "Include /etc/ssh/sshd_config.d/*.conf"
    echo
    cat "$MAIN"
  } > "$tmp"
  install -m 0600 -o root -g root "$tmp" "$MAIN"
  rm -f "$tmp"
  ok "added Include directive at the top of $MAIN"
fi

# Flag directives in the main file that our drop-in now overrides, so the
# next person reading sshd_config is not misled.
for kw in PasswordAuthentication KbdInteractiveAuthentication ChallengeResponseAuthentication AuthenticationMethods; do
  if grep -qE "^\s*${kw}\b" "$MAIN"; then
    warn "$MAIN still sets $kw; the drop-in takes precedence (first value wins)"
  fi
done

# --- validate before reloading --------------------------------------------
sshd_validate || die "refusing to reload. $MAIN and $SSHD_DROPIN are backed up under $(backup_dir)"

log "effective policy after reload:"
sshd_effective | grep -iE '^(authenticationmethods|passwordauthentication|kbdinteractive|challengeresponse|usepam)' | sed 's/^/    /'
echo
log "root:"
sshd_effective -C "user=root,host=localhost,addr=127.0.0.1" \
  | grep -i '^authenticationmethods' | sed 's/^/    /' || warn "could not evaluate root Match block"

# --- arm the safety net ----------------------------------------------------
if (( TIMER > 0 )); then
  systemd-run --unit=ssh-mfa-autorollback --on-active="${TIMER}min" \
    "$REPO_ROOT/scripts/99-rollback.sh" --yes >/dev/null 2>&1 \
    && ok "auto-rollback armed: fires in ${TIMER} minute(s)" \
    || warn "could not arm auto-rollback timer"
fi

sshd_reload

echo
ok "sshd now requires: $METHODS (root and $EXEMPT_GROUP: publickey only)"
echo
warn "DO NOT CLOSE THIS SESSION YET."
cat <<NEXT
  1. From another terminal, log in as a named user and confirm the prompt.
  2. Log in as root with a key and confirm no code is requested.
NEXT
if (( TIMER > 0 )); then
  cat <<NEXT
  3. Once both work, cancel the auto-rollback:
       systemctl stop ssh-mfa-autorollback.timer
NEXT
fi
cat <<NEXT
  Then enrol users:      scripts/40-enroll-user.sh <username>
  Then verify:           scripts/90-validate.sh
  Then enforce strictly: scripts/50-enforce-strict.sh
NEXT
