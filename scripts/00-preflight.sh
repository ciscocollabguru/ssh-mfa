#!/usr/bin/env bash
# Verify the host can support SSH MFA and record the pre-change state.
# Read-only except for the state snapshot it writes under BACKUP_ROOT.

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

fail=0
note() { warn "$*"; fail=$((fail+1)); }

require_almalinux8

# --- 1. a working second path onto the box ---------------------------------
log "checking break-glass access"
if [[ -s /root/.ssh/authorized_keys ]]; then
  ok "root has $(grep -cve '^\s*$' -e '^\s*#' /root/.ssh/authorized_keys) authorized key(s) — root SSH stays MFA-exempt"
else
  note "root has no authorized_keys. Confirm you have console/IPMI/hypervisor access before applying, or you may have no way back in."
fi
if systemctl is-enabled --quiet serial-getty@ttyS0.service 2>/dev/null; then
  ok "serial console getty enabled"
fi

# --- 2. time sync (TOTP is clock-dependent) -------------------------------
log "checking time synchronisation"
if systemctl is-active --quiet chronyd; then
  if chronyc tracking >/dev/null 2>&1 && \
     [[ "$(chronyc -c tracking 2>/dev/null | cut -d, -f2)" != "0.0.0.0" ]]; then
    ok "chronyd active and synchronised to $(chronyc -c tracking | cut -d, -f2)"
  else
    note "chronyd is running but not synchronised to a source. TOTP codes will be rejected once drift exceeds ${TOTP_WINDOW} x 30s."
  fi
else
  note "chronyd is not active. Enable it: systemctl enable --now chronyd"
fi

# --- 3. packages ----------------------------------------------------------
log "checking packages"
if pam_module_path >/dev/null; then
  ok "pam_google_authenticator.so present at $(pam_module_path)"
else
  log "pam_google_authenticator.so not installed yet (10-install-packages.sh will add it)"
fi
rpm -q epel-release >/dev/null 2>&1 && ok "epel-release installed" \
  || log "epel-release not installed yet"

# --- 4. authselect: /etc/pam.d/sshd must be ours to edit ------------------
log "checking authselect"
if command -v authselect >/dev/null 2>&1; then
  ok "authselect profile: $(authselect current 2>/dev/null | head -1 || echo none)"
  log "note: this kit edits /etc/pam.d/sshd only, which authselect does not manage."
else
  log "authselect not present"
fi

# --- 5. SELinux -----------------------------------------------------------
log "checking SELinux"
if command -v getenforce >/dev/null 2>&1; then
  ok "SELinux: $(getenforce)"
  [[ "$(getenforce)" == "Enforcing" ]] && \
    log "secrets will live in each user's home as ~/.google_authenticator, which sshd can read under the default policy. Do not relocate them without adding an fcontext rule."
fi

# --- 6. current SSH policy ------------------------------------------------
log "recording current sshd policy"
install -d -m 0700 "$BACKUP_ROOT"
snap="$BACKUP_ROOT/preflight-$(date +%Y%m%dT%H%M%S).txt"
{
  echo "== os-release ==";        cat /etc/os-release
  echo; echo "== sshd -T ==";     sshd_effective || echo "(sshd -T failed)"
  echo; echo "== /etc/pam.d/sshd =="; cat /etc/pam.d/sshd
  echo; echo "== sshd_config (non-comment) ==";
  grep -vE '^\s*(#|$)' /etc/ssh/sshd_config || true
  echo; echo "== target users ==";  mfa_target_users
} > "$snap"
chmod 0600 "$snap"
ok "state snapshot: $snap"

if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
  ok "sshd_config already has an Include for sshd_config.d"
else
  log "sshd_config has no Include directive; 30-configure-sshd.sh will add one at the top"
fi

# --- 7. the population that will be affected ------------------------------
echo
log "accounts that will require MFA (uid >= $MIN_UID, login shell, not exempt):"
mapfile -t targets < <(mfa_target_users)
if (( ${#targets[@]} == 0 )); then
  note "no target users found. Check MIN_UID and EXEMPT_USERS before proceeding."
else
  for u in "${targets[@]}"; do
    if user_enrolled "$u"; then printf '    %s  %s(enrolled)%s\n' "$u" "$C_GRN" "$C_OFF"
    else printf '    %s  %s(not enrolled)%s\n' "$u" "$C_YEL" "$C_OFF"; fi
  done
fi
echo
log "exempt from MFA: users [$EXEMPT_USERS], group [$EXEMPT_GROUP], uid < $MIN_UID"

echo
if (( fail )); then
  err "$fail preflight warning(s). Resolve them or re-run with MFA_FORCE=yes."
  [[ "${MFA_FORCE:-no}" == "yes" ]] || exit 1
  warn "continuing anyway (MFA_FORCE=yes)"
fi
ok "preflight complete"
