#!/usr/bin/env bash
# Build and install the local SELinux policy module that lets sshd rewrite
# ~/.google_authenticator. See selinux/ssh-mfa-gauth.te for the reasoning.
#
# Needed only when SELinux is enforcing AND the secret is stateful (enrolled
# with -d and/or -r/-R, which is the default). The alternative is to enrol
# without that state: set TOTP_STATEFUL="no" in config/mfa.env, which removes
# the need for any policy change at the cost of replay protection and
# per-user rate limiting.
#
# Usage: 16-selinux-policy.sh [--remove] [--dry-run] [--status]

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

MODNAME=ssh-mfa-gauth
TE="$REPO_ROOT/selinux/$MODNAME.te"

ACTION=install
while (( $# )); do
  case "$1" in
    --remove)  ACTION=remove; shift ;;
    --status)  ACTION=status; shift ;;
    --dry-run) ACTION=dryrun; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

module_installed() { semodule -l 2>/dev/null | grep -qx "$MODNAME\(\s.*\)\?"; }

case "$ACTION" in
  status)
    if module_installed; then
      ok "$MODNAME is installed"
      semodule -l 2>/dev/null | grep "$MODNAME" | sed 's/^/    /'
    else
      log "$MODNAME is not installed"
    fi
    exit 0 ;;
  remove)
    module_installed || { log "$MODNAME is not installed"; exit 0; }
    semodule -r "$MODNAME" && ok "removed $MODNAME"
    warn "sshd can no longer rewrite secrets; stateful tokens will fail again"
    exit 0 ;;
esac

[[ -r "$TE" ]] || die "policy source missing: $TE"

if ! command -v getenforce >/dev/null 2>&1 || [[ "$(getenforce)" == "Disabled" ]]; then
  ok "SELinux is disabled; no policy module needed"
  exit 0
fi

if module_installed; then
  ok "$MODNAME already installed"
  log "reinstalling to pick up any change to $TE"
fi

# checkmodule comes from checkpolicy; semodule_package from policycoreutils.
for c in checkmodule semodule_package semodule; do
  command -v "$c" >/dev/null 2>&1 && continue
  log "installing checkpolicy policycoreutils-python-utils"
  [[ "$ACTION" == "dryrun" ]] || dnf -y install checkpolicy policycoreutils-python-utils
  break
done
for c in checkmodule semodule_package semodule; do
  command -v "$c" >/dev/null 2>&1 || die "$c still unavailable; cannot build the policy module"
done

if [[ "$ACTION" == "dryrun" ]]; then
  log "--dry-run: would build and install $MODNAME from $TE"
  sed 's/^/    /' "$TE"
  exit 0
fi

build="$(mktemp -d)"; trap 'rm -rf "$build"' EXIT
cp "$TE" "$build/$MODNAME.te"

log "compiling $MODNAME"
if ! checkmodule -M -m -o "$build/$MODNAME.mod" "$build/$MODNAME.te"; then
  err "checkmodule failed. The type_transition may conflict with the loaded policy."
  err "Fall back to stateless tokens instead: set TOTP_STATEFUL=\"no\" in config/mfa.env,"
  err "then: scripts/40-enroll-user.sh --restate   (no token is rotated)"
  exit 1
fi
semodule_package -o "$build/$MODNAME.pp" -m "$build/$MODNAME.mod" \
  || die "semodule_package failed"

log "installing $MODNAME"
semodule -i "$build/$MODNAME.pp" || die "semodule -i failed"
ok "installed SELinux module $MODNAME"

# Relabel so existing secrets carry the type the module grants access to.
log "relabelling existing secrets"
while read -r u; do
  [[ -z "$u" ]] && continue
  home="$(getent passwd "$u" | cut -d: -f6)"
  f="$home/.google_authenticator"
  [[ -e "$f" ]] || continue
  restorecon -Fv "$f" 2>/dev/null || true
  log "$u: $(ls -Zd "$f" | awk '{print $1}')"
done < <(mfa_target_users)

echo
ok "sshd may now rewrite secrets. No token was rotated."
warn "Test a login from a SECOND terminal before closing this session."
cat <<NEXT
  If it still fails, capture the new denial:
    sudo ausearch -m avc -ts recent | grep -i google_authenticator | audit2allow
  To undo:
    sudo scripts/16-selinux-policy.sh --remove
NEXT
