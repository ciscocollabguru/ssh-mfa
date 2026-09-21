#!/usr/bin/env bash
# Install EPEL + google-authenticator and ensure time sync is running.

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config
require_almalinux8

if ! rpm -q epel-release >/dev/null 2>&1; then
  log "installing epel-release"
  dnf -y install epel-release
  ok "epel-release installed"
else
  ok "epel-release already installed"
fi

if ! pam_module_path >/dev/null; then
  log "installing google-authenticator"
  dnf -y install google-authenticator
else
  ok "google-authenticator already installed"
fi

pam_module_path >/dev/null \
  || die "pam_google_authenticator.so still missing after install. Check that the EPEL repo is reachable and enabled (dnf repolist epel)."
ok "PAM module: $(pam_module_path)"
ok "CLI: $(command -v google-authenticator) ($(google-authenticator --version 2>&1 | head -1))"

# TOTP is only as good as the clock.
if ! systemctl is-active --quiet chronyd; then
  log "enabling chronyd"
  dnf -y install chrony >/dev/null 2>&1 || true
  systemctl enable --now chronyd
fi
systemctl is-active --quiet chronyd \
  && ok "chronyd active" \
  || warn "chronyd is not active; TOTP validation will drift out of tolerance"

ok "package stage complete"
