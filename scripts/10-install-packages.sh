#!/usr/bin/env bash
# Install the packages this project needs, on any dnf-based RPM distribution.
#
# EL (RHEL 8+ and rebuilds) needs EPEL: google-authenticator, qrencode and
# oathtool are not in the base repositories. Fedora carries all three
# already and must not have EPEL added.
#
# Usage: 10-install-packages.sh [--dry-run]

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config
require_dnf_os

DRY=no
[[ "${1:-}" == "--dry-run" ]] && DRY=yes
run() { if [[ "$DRY" == yes ]]; then log "--dry-run: $*"; else "$@"; fi; }

# --- EPEL, for the EL family only -----------------------------------------
enable_crb() {
  local repo; repo="$(crb_repo_name)" || return 0
  if [[ "$OS_ID" == "rhel" ]] && command -v subscription-manager >/dev/null 2>&1; then
    # On RHEL proper the equivalent repository is entitlement-gated.
    run subscription-manager repos \
      --enable "codeready-builder-for-rhel-${OS_MAJOR}-$(arch)-rpms" >/dev/null 2>&1 \
      && ok "enabled CodeReady Builder" \
      || log "could not enable CodeReady Builder (may already be on, or unentitled)"
    return 0
  fi
  if dnf repolist --all 2>/dev/null | grep -qi "^${repo}[[:space:]]"; then
    run dnf -y config-manager --set-enabled "$repo" >/dev/null 2>&1 \
      && ok "enabled $repo" \
      || log "could not enable $repo (continuing; it is only needed for some dependencies)"
  fi
}

install_epel() {
  if rpm -q epel-release >/dev/null 2>&1 || rpm -q oracle-epel-release-el"$OS_MAJOR" >/dev/null 2>&1; then
    ok "EPEL already installed"
    return 0
  fi
  log "installing EPEL for ${OS_NAME}"

  # Oracle Linux ships its own EPEL package rather than Fedora's.
  if [[ "$OS_ID" == "ol" || "$OS_ID" == "oracle" ]]; then
    run dnf -y install "oracle-epel-release-el${OS_MAJOR}" && { ok "EPEL installed"; return 0; }
  fi

  # Rebuilds carry epel-release in extras; RHEL proper does not, so fall
  # back to the Fedora-hosted package for this major version.
  if run dnf -y install epel-release >/dev/null 2>&1; then
    ok "EPEL installed from the distribution repositories"
    return 0
  fi
  log "epel-release not in the configured repositories; using the Fedora-hosted package"
  run dnf -y install \
    "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm" \
    && ok "EPEL installed" \
    || die "could not install EPEL. Add it manually, then re-run. On RHEL see https://docs.fedoraproject.org/en-US/epel/"
}

if [[ "$OS_NEEDS_EPEL" == "yes" ]]; then
  enable_crb
  install_epel
else
  ok "${OS_NAME} does not use EPEL; the packages are in its own repositories"
fi

# --- packages --------------------------------------------------------------
# google-authenticator is required. The rest degrade gracefully but each
# costs a real capability, so say which one is missing and why it matters.
if ! pam_module_path >/dev/null; then
  log "installing google-authenticator"
  run dnf -y install google-authenticator
else
  ok "google-authenticator already installed"
fi

[[ "$DRY" == yes ]] || pam_module_path >/dev/null || die \
  "pam_google_authenticator.so is still missing. Check the repository is reachable and enabled: dnf repolist"

# qrencode  draws the enrolment QR code; google-authenticator only draws one
#           when its stdout is a terminal, which it is not when captured.
# oathtool  lets the server compute the code it expects, which --check and
#           self-enrolment verification depend on.
declare -A why=(
  [qrencode]="no QR code can be drawn at enrolment"
  [oathtool]="the server cannot verify a user's code (--check, self-enrolment)"
)
for pkg in qrencode oathtool; do
  if rpm -q "$pkg" >/dev/null 2>&1; then
    ok "$pkg already installed"
  elif run dnf -y install "$pkg" >/dev/null 2>&1; then
    ok "installed $pkg"
  else
    warn "could not install $pkg: ${why[$pkg]}"
  fi
done

# SELinux tooling, only where SELinux is actually in use.
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
  for pkg in policycoreutils-python-utils checkpolicy; do
    rpm -q "$pkg" >/dev/null 2>&1 && { ok "$pkg already installed"; continue; }
    run dnf -y install "$pkg" >/dev/null 2>&1 \
      && ok "installed $pkg" \
      || warn "could not install $pkg; scripts/15-selinux.sh and 16-selinux-policy.sh need it"
  done
fi

# --- time sync -------------------------------------------------------------
# TOTP is only as good as the clock. chrony is the default across this
# family, but accept systemd-timesyncd where that is what the host uses.
if timesync_active; then
  ok "time synchronisation active ($(timesync_name))"
else
  log "enabling time synchronisation"
  if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd\.service'; then
    run systemctl enable --now systemd-timesyncd
  else
    rpm -q chrony >/dev/null 2>&1 || run dnf -y install chrony >/dev/null 2>&1 || true
    run systemctl enable --now chronyd
  fi
  timesync_active \
    && ok "time synchronisation active ($(timesync_name))" \
    || warn "no active time synchronisation; every user's codes will be rejected once the clock drifts"
fi

ok "package stage complete"
