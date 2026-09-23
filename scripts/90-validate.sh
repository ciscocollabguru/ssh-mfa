#!/usr/bin/env bash
# Verify the MFA configuration. Read-only; safe to run any time.
# Exit 0 = all checks pass.

. "$(dirname "$(readlink -f "$0")")/lib/common.sh"
require_root
load_config

pass=0; fail=0
check()  { printf '  %-58s' "$1"; }
yes_()   { printf '%s[PASS]%s\n' "$C_GRN" "$C_OFF"; pass=$((pass+1)); }
no_()    { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_OFF" "${1:-}"; fail=$((fail+1)); }
skip_()  { printf '%s[ -- ]%s %s\n' "$C_DIM" "$C_OFF" "${1:-}"; }

echo "== 1. components =="
check "pam_google_authenticator.so installed"
pam_module_path >/dev/null && yes_ || no_ "run 10-install-packages.sh"

check "google-authenticator CLI available"
command -v google-authenticator >/dev/null && yes_ || no_

check "chronyd active (TOTP needs an accurate clock)"
systemctl is-active --quiet chronyd && yes_ || no_ "systemctl enable --now chronyd"

echo
echo "== 2. sshd =="
check "sshd config syntax valid"
/usr/sbin/sshd -t >/dev/null 2>&1 && yes_ || no_ "sshd -t"

check "drop-in present ($SSHD_DROPIN)"
[[ -f "$SSHD_DROPIN" ]] && yes_ || no_ "run 30-configure-sshd.sh"

check "drop-in is actually included"
grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config && yes_ \
  || no_ "no Include directive in /etc/ssh/sshd_config"

eff_methods="$(sshd_effective | awk 'tolower($1)=="authenticationmethods"{print $2}')"
check "global AuthenticationMethods requires two factors"
case "$eff_methods" in
  *,*) yes_ ;;
  '')  no_ "unset" ;;
  *)   no_ "single factor: $eff_methods" ;;
esac

check "password-only login disabled"
[[ "$(sshd_effective | awk 'tolower($1)=="passwordauthentication"{print $2}')" == "no" ]] && yes_ \
  || no_ "PasswordAuthentication is yes"

check "keyboard-interactive enabled (carries the TOTP prompt)"
sshd_effective | grep -qiE '^kbdinteractiveauthentication yes' && yes_ || no_

echo
echo "== 3. exemptions =="
root_methods="$(sshd_effective -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \
  | awk 'tolower($1)=="authenticationmethods"{print $2}')"
check "root is exempt from MFA"
[[ "$root_methods" == "publickey" ]] && yes_ || no_ "root sees: ${root_methods:-unknown}"

check "root can still authenticate (has a key)"
[[ -s /root/.ssh/authorized_keys ]] && yes_ \
  || no_ "no /root/.ssh/authorized_keys — console access is your only fallback"

check "exempt group $EXEMPT_GROUP exists"
getent group "$EXEMPT_GROUP" >/dev/null && yes_ || no_ "referenced by a Match block but missing"

if members="$(getent group "$EXEMPT_GROUP" | cut -d: -f4)" && [[ -n "$members" ]]; then
  log "exempt group members: $members"
fi

echo
echo "== 4. PAM =="
check "/etc/pam.d/sshd carries the managed block"
grep -q '^# BEGIN ssh-mfa' /etc/pam.d/sshd && yes_ || no_ "run 20-configure-pam.sh"

check "pam_google_authenticator is in the sshd auth stack"
grep -qE '^\s*auth\s+.*pam_google_authenticator\.so' /etc/pam.d/sshd && yes_ || no_

check "no exempt branch jumps to pam_permit (would allow credential-free auth)"
if awk '/pam_succeed_if/ && /success=/ {print}' /etc/pam.d/sshd | grep -q 'success=done'; then
  no_ "a succeed_if line uses success=done"
else yes_; fi

check "authselect-managed files untouched"
if command -v authselect >/dev/null 2>&1; then
  authselect check >/dev/null 2>&1 && yes_ || no_ "authselect check reports drift; run: authselect check"
else skip_ "authselect not installed"; fi

nullok_state=absent
grep -qE 'pam_google_authenticator\.so.*\bnullok\b' /etc/pam.d/sshd && nullok_state=present
check "enforcement mode"
if [[ "$nullok_state" == "present" ]]; then
  skip_ "permissive (nullok): unenrolled users pass on one factor"
else
  yes_
fi

echo
echo "== 5. enrolment =="
unenrolled=()
while read -r u; do
  [[ -z "$u" ]] && continue
  if user_enrolled "$u"; then
    home="$(getent passwd "$u" | cut -d: -f6)"
    perms="$(stat -c '%a %U' "$home/.google_authenticator")"
    check "$u enrolled"
    case "$perms" in
      "600 $u") yes_ ;;
      "400 $u") no_ "secret is 0400 (read-only); -d/-r need to write to it. Fix: scripts/40-enroll-user.sh --fix-perms $u" ;;
      *)        no_ "secret has perms/owner '$perms', expected '600 $u'" ;;
    esac
  else
    unenrolled+=("$u")
  fi
done < <(mfa_target_users)

if (( ${#unenrolled[@]} )); then
  check "all target users enrolled"
  no_ "missing: ${unenrolled[*]}"
else
  check "all target users enrolled"; yes_
fi

echo
echo "== 6. SELinux =="
if command -v getenforce >/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
  check "no recent sshd/PAM AVC denials"
  if command -v ausearch >/dev/null 2>&1; then
    if ausearch -m avc -ts recent 2>/dev/null | grep -qE 'comm="sshd"|google_authenticator'; then
      no_ "check: ausearch -m avc -ts recent | grep sshd"
    else yes_; fi
  else skip_ "ausearch not installed (audit package)"; fi
else
  skip_ "SELinux disabled"
fi

echo
echo "== 7. leftover secrets on disk =="
check "no plaintext enrolment output left in $ENROLL_OUT_DIR"
if [[ -d "$ENROLL_OUT_DIR" ]] && compgen -G "$ENROLL_OUT_DIR/*.txt" >/dev/null; then
  no_ "$(ls -1 "$ENROLL_OUT_DIR"/*.txt | wc -l) file(s) still there; shred them once users confirm"
else yes_; fi

echo
printf '%s passed, %s failed\n' "$pass" "$fail"
if (( fail )); then
  echo
  warn "Do not close your session while checks are failing. See docs/TROUBLESHOOTING.md"
  exit 1
fi
ok "all checks passed"
