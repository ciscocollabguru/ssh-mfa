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

# qrencode draws the enrolment QR code (google-authenticator only draws one
# when its stdout is a TTY, which it is not when we capture output).
# oathtool lets an operator compare the server's expected code against the
# user's app, which separates "bad secret" from "misconfigured app entry".
for pkg in qrencode oathtool; do
  if rpm -q "$pkg" >/dev/null 2>&1; then
    ok "$pkg already installed"
  elif dnf -y install "$pkg" >/dev/null 2>&1; then
    ok "installed $pkg"
  else
    warn "could not install $pkg (enrolment still works; QR/verification aids unavailable)"
  fi
done

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
