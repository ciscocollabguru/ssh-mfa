#!/usr/bin/env bash
# Force new users through self-enrolment on first login.
#
# How it works: accounts that need a token go into $ENROLL_GROUP. sshd gives
# that group a ForceCommand, so they authenticate with their password (the
# PAM stack applies nullok to that group only) and are dropped straight into
# ssh-mfa-selfenroll instead of a shell. On success a narrow sudoers rule
# lets them call ssh-mfa-finalize, which secures the token and removes them
# from the group -- after which the strict branch of the PAM stack applies.
#
#   45-enrollment-gate.sh --install        set everything up
#   45-enrollment-gate.sh --reconcile      sync group membership now
#   45-enrollment-gate.sh --require USER   put one account into the group
#   45-enrollment-gate.sh --release USER   take one account out
#   45-enrollment-gate.sh --status         who is pending
#   45-enrollment-gate.sh --uninstall      remove the gate (keeps tokens)

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

QUIET=no
ACTION=""
ARGS=()
while (( $# )); do
  case "$1" in
    --install|--reconcile|--status|--uninstall) ACTION="${1#--}"; shift ;;
    --require|--release) ACTION="${1#--}"; shift; ARGS+=("$@"); break ;;
    --quiet) QUIET=yes; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -n "$ACTION" ]] || { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
[[ "$QUIET" == "yes" ]] && { log() { :; }; ok() { :; }; }

CONFDIR=/etc/ssh-mfa
SUDOERS=/etc/sudoers.d/ssh-mfa-selfenroll
SELFENROLL=/usr/local/sbin/ssh-mfa-selfenroll
FINALIZE=/usr/local/sbin/ssh-mfa-finalize
RECONCILE=/usr/local/sbin/ssh-mfa-reconcile

# Accounts that must never be gated: exempt ones, and anyone already enrolled.
needs_enrolment() {
  local u="$1"
  is_exempt_user "$u" && return 1
  user_enrolled "$u" && return 1
  return 0
}

case "$ACTION" in

status)
  getent group "$ENROLL_GROUP" >/dev/null 2>&1 \
    || { log "group $ENROLL_GROUP does not exist; gate is not installed"; exit 0; }
  printf '%-20s %-8s %-10s %s\n' USER UID ENROLLED "PENDING ($ENROLL_GROUP)"
  while read -r u; do
    [[ -z "$u" ]] && continue
    inq=no
    id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$ENROLL_GROUP" && inq=yes
    printf '%-20s %-8s %-10s %s\n' "$u" "$(id -u "$u")" \
      "$(user_enrolled "$u" && echo yes || echo NO)" "$inq"
  done < <(mfa_target_users)
  echo
  log "gate active in sshd: $(grep -qc "$ENROLL_GROUP" "$SSHD_DROPIN" 2>/dev/null && echo yes || echo no)"
  exit 0 ;;

require|release)
  (( ${#ARGS[@]} )) || die "--$ACTION needs at least one username"
  getent group "$ENROLL_GROUP" >/dev/null 2>&1 || groupadd -r "$ENROLL_GROUP"
  for u in "${ARGS[@]}"; do
    getent passwd "$u" >/dev/null || { warn "no such user: $u"; continue; }
    if [[ "$ACTION" == require ]]; then
      is_exempt_user "$u" && { warn "$u is exempt from MFA; not gating"; continue; }
      gpasswd -a "$u" "$ENROLL_GROUP" >/dev/null && ok "$u must now self-enrol on next login"
    else
      gpasswd -d "$u" "$ENROLL_GROUP" >/dev/null 2>&1 && ok "$u released from $ENROLL_GROUP" \
        || log "$u was not in $ENROLL_GROUP"
    fi
  done
  exit 0 ;;

reconcile)
  getent group "$ENROLL_GROUP" >/dev/null 2>&1 || groupadd -r "$ENROLL_GROUP"
  added=0; removed=0
  while read -r u; do
    [[ -z "$u" ]] && continue
    inq=no
    id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$ENROLL_GROUP" && inq=yes
    if needs_enrolment "$u"; then
      [[ "$inq" == no ]] && { gpasswd -a "$u" "$ENROLL_GROUP" >/dev/null && added=$((added+1)) \
        && log "gated $u (no token yet)"; }
    else
      # Enrolled or exempt: they must not stay in a group that grants nullok.
      [[ "$inq" == yes ]] && { gpasswd -d "$u" "$ENROLL_GROUP" >/dev/null 2>&1 \
        && removed=$((removed+1)) && log "released $u"; }
    fi
  done < <(mfa_target_users)
  # Members who are no longer target users at all (deleted, shell removed).
  for u in $(getent group "$ENROLL_GROUP" | cut -d: -f4 | tr ',' ' '); do
    [[ -z "$u" ]] && continue
    mfa_target_users | grep -qx "$u" && continue
    gpasswd -d "$u" "$ENROLL_GROUP" >/dev/null 2>&1 && removed=$((removed+1)) \
      && log "released $u (no longer a target account)"
  done
  [[ "$QUIET" == "yes" ]] || ok "reconciled: $added gated, $removed released"
  exit 0 ;;

uninstall)
  log "removing the enrolment gate"
  rm -f "$SUDOERS" "$SELFENROLL" "$FINALIZE" "$RECONCILE"
  systemctl disable --now ssh-mfa-reconcile.path ssh-mfa-reconcile.timer 2>/dev/null || true
  rm -f /etc/systemd/system/ssh-mfa-reconcile.{service,path,timer}
  systemctl daemon-reload
  if getent group "$ENROLL_GROUP" >/dev/null 2>&1; then
    for u in $(getent group "$ENROLL_GROUP" | cut -d: -f4 | tr ',' ' '); do
      [[ -n "$u" ]] && gpasswd -d "$u" "$ENROLL_GROUP" >/dev/null 2>&1 || true
    done
    warn "group $ENROLL_GROUP left in place; remove with: groupdel $ENROLL_GROUP"
  fi
  warn "set ENROLL_GATE=\"no\" in config/mfa.env and re-run 20-configure-pam.sh and 30-configure-sshd.sh"
  ok "gate removed. No token was touched."
  exit 0 ;;

install)
  [[ "$ENROLL_GATE" == "yes" ]] || die \
    "set ENROLL_GATE=\"yes\" in config/mfa.env first, so the PAM and sshd generators emit the enrolment branch"

  command -v oathtool >/dev/null 2>&1 \
    || warn "oathtool is missing: finalize cannot verify a user's code before releasing them (dnf -y install oathtool)"

  getent group "$ENROLL_GROUP" >/dev/null 2>&1 || { groupadd -r "$ENROLL_GROUP"; ok "created group $ENROLL_GROUP"; }

  install -d -m 0755 "$CONFDIR"
  printf '%s\n' "$ENROLL_GROUP"   > "$CONFDIR/enroll-group"
  printf '%s\n' "$TOTP_STATEFUL"  > "$CONFDIR/stateful"
  printf '%s %s\n' "$TOTP_RATE_LIMIT_N" "$TOTP_RATE_LIMIT_S" > "$CONFDIR/ratelimit"
  printf '%s\n' "$REPO_ROOT"      > "$CONFDIR/repo-path"
  chmod 0644 "$CONFDIR"/*
  ok "wrote $CONFDIR (group, state policy, repo path)"

  install -m 0755 -o root -g root "$REPO_ROOT/helpers/ssh-mfa-selfenroll" "$SELFENROLL"
  install -m 0755 -o root -g root "$REPO_ROOT/helpers/ssh-mfa-finalize"   "$FINALIZE"
  install -m 0755 -o root -g root "$REPO_ROOT/helpers/ssh-mfa-reconcile"  "$RECONCILE"
  ok "installed helpers into /usr/local/sbin"

  # Narrow sudoers rule. The group may run ONE command as root, and that
  # command takes no username -- it acts on $SUDO_USER only, so a member
  # cannot use it against another account.
  tmp="$(mktemp)"
  cat > "$tmp" <<SUDO
# Managed by ssh-mfa/scripts/45-enrollment-gate.sh. Do not edit by hand.
# Lets a user mid-enrolment secure their own new token and release their own
# account. ssh-mfa-finalize accepts no username: it acts on \$SUDO_USER.
Defaults:%$ENROLL_GROUP !requiretty
%$ENROLL_GROUP ALL=(root) NOPASSWD: $FINALIZE, $FINALIZE --verify [0-9]*
SUDO
  visudo -cqf "$tmp" || { rm -f "$tmp"; die "generated sudoers file is invalid; nothing installed"; }
  install -m 0440 -o root -g root "$tmp" "$SUDOERS"
  rm -f "$tmp"
  visudo -cqf /etc/sudoers >/dev/null || warn "system sudoers now reports a problem; check visudo -c"
  ok "installed $SUDOERS (validated with visudo)"

  for unit in service path timer; do
    install -m 0644 -o root -g root \
      "$REPO_ROOT/systemd/ssh-mfa-reconcile.$unit" \
      "/etc/systemd/system/ssh-mfa-reconcile.$unit"
  done
  systemctl daemon-reload
  systemctl enable --now ssh-mfa-reconcile.path ssh-mfa-reconcile.timer >/dev/null 2>&1 \
    && ok "enabled ssh-mfa-reconcile.path and .timer (new accounts are gated automatically)" \
    || warn "could not enable the reconcile units; run --reconcile by hand when adding users"

  "$0" --reconcile

  echo
  ok "enrolment gate installed"
  cat <<NEXT
  Now regenerate the PAM and sshd configuration so the gate takes effect:
    sudo scripts/20-configure-pam.sh
    sudo scripts/30-configure-sshd.sh --safety-timer 10
  Then, from a SECOND terminal, test with a throwaway account:
    sudo useradd -m testmfa && sudo passwd testmfa
    ssh testmfa@$(hostname -s)        # should land in enrolment, not a shell
NEXT
  exit 0 ;;
esac
