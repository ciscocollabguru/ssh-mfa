#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Scott Jones
# Regression tests for pam_block()/pam_render() in scripts/lib/common.sh.
# Runs anywhere (no root, no AlmaLinux, no PAM), so it is safe in CI.
#
#   ./tests/test-pam-stack.sh

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source only what we need: common.sh calls set -e, which we do not want
# inside a test runner that expects failures.
# shellcheck source=../scripts/lib/common.sh
. "$HERE/../scripts/lib/common.sh"
set +e

pass=0; fail=0
t_ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
t_no()   { printf '  \033[31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; fail=$((fail+1)); }
assert() { if [[ "$2" == "$3" ]]; then t_ok "$1"; else t_no "$1" "expected [$3] got [$2]"; fi; }
# Collapse runs of whitespace (the stock file mixes tabs and spaces) and trim.
norm()   { tr -s '[:space:]' ' ' <<<"$1" | sed 's/ *$//'; }

# A stock AlmaLinux 8 /etc/pam.d/sshd (auth section is what matters).
STOCK=$'#%PAM-1.0\nauth\t   substack     password-auth\nauth       include      postlogin\naccount    required     pam_sepermit.so\npassword   include      password-auth\nsession    include      postlogin'

# Defaults the generator reads.
AUTH_MODE=pubkey+totp; NULLOK=yes; EXEMPT_USERS="root"
EXEMPT_GROUP="ssh-mfa-exempt"; MIN_UID=1000
ENROLL_GATE=no; ENROLL_GROUP="ssh-mfa-enroll"

auth_lines() { grep -E '^[[:space:]]*auth' ; }
nth_auth()   { auth_lines <<<"$1" | sed -n "${2}p"; }
count()      { grep -c "$1" <<<"$2"; }

echo "== pubkey+totp =="
out="$(pam_render <<<"$STOCK")"
assert "auth stack has 7 lines" "$(auth_lines <<<"$out" | wc -l | tr -d ' ')" "7"
assert "1: uid guard jumps 4"    "$(nth_auth "$out" 1 | grep -o 'success=4')" "success=4"
assert "2: user guard jumps 3"   "$(nth_auth "$out" 2 | grep -o 'success=3')" "success=3"
assert "3: group guard jumps 2"  "$(nth_auth "$out" 3 | grep -o 'success=2')" "success=2"
assert "4: is the TOTP module"   "$(nth_auth "$out" 4 | grep -o 'pam_google_authenticator.so')" "pam_google_authenticator.so"
assert "5: pam_permit jumps 1"   "$(nth_auth "$out" 5 | grep -o 'success=1')" "success=1"
assert "6: original password substack survives" \
  "$(norm "$(nth_auth "$out" 6)")" "auth substack password-auth"
assert "nullok present" "$(nth_auth "$out" 4 | grep -o nullok)" "nullok"

# Jump targets: each guard must land exactly on the password substack (line 6),
# and pam_permit must land past it (line 7). n + jump + 1 == target.
for spec in "1 4 6" "2 3 6" "3 2 6" "5 1 7"; do
  read -r n jump target <<<"$spec"
  assert "line $n lands on line $target" "$(( n + jump + 1 ))" "$target"
done

echo
echo "== pubkey+totp, strict =="
NULLOK=no
out="$(pam_render <<<"$STOCK")"
assert "nullok removed" "$(nth_auth "$out" 4 | grep -c nullok)" "0"
assert "no stray nullok on any auth line" \
  "$(auth_lines <<<"$out" | grep -c nullok)" "0"
assert "module still requisite" "$(nth_auth "$out" 4 | grep -o requisite)" "requisite"
NULLOK=yes

echo
echo "== password+totp =="
AUTH_MODE=password+totp
out="$(pam_render <<<"$STOCK")"
assert "auth stack has 6 lines" "$(auth_lines <<<"$out" | wc -l | tr -d ' ')" "6"
assert "1: password substack runs first" \
  "$(norm "$(nth_auth "$out" 1)")" "auth substack password-auth"
assert "5: is the TOTP module" "$(nth_auth "$out" 5 | grep -o 'pam_google_authenticator.so')" "pam_google_authenticator.so"
assert "no pam_permit in this mode" "$(count pam_permit "$out")" "0"
for spec in "2 3 6" "3 2 6" "4 1 6"; do
  read -r n jump target <<<"$spec"
  assert "line $n lands on line $target" "$(( n + jump + 1 ))" "$target"
done
AUTH_MODE=pubkey+totp

echo
echo "== safety properties =="
out="$(pam_render <<<"$STOCK")"
assert "no guard uses success=done (would grant credential-free auth)" \
  "$(grep -c 'success=done' <<<"$out")" "0"
assert "root is named in the exempt guard" \
  "$(grep -c 'user in root' <<<"$out")" "1"
EXEMPT_USERS="root backup svc"
out="$(pam_render <<<"$STOCK")"
assert "multiple exempt users become a colon list" \
  "$(grep -o 'user in [^ ]*' <<<"$out")" "user in root:backup:svc"
EXEMPT_USERS="root"

echo
echo "== idempotency =="
once="$(pam_render <<<"$STOCK")"
twice="$(pam_render <<<"$once")"
assert "re-running is a no-op" "$twice" "$once"
thrice="$(pam_render <<<"$twice")"
assert "third run is still stable" "$thrice" "$once"
assert "exactly one managed block" "$(grep -c '^# BEGIN ssh-mfa' <<<"$twice")" "1"

echo
echo "== flipping nullok on an already-configured file =="
NULLOK=no
flipped="$(pam_render <<<"$once")"
assert "strict flip leaves 7 auth lines" "$(auth_lines <<<"$flipped" | wc -l | tr -d ' ')" "7"
assert "strict flip drops nullok from the module line" \
  "$(grep -c 'pam_google_authenticator.so.*nullok' <<<"$flipped")" "0"
assert "header records the new mode" \
  "$(grep -c 'nullok: no' <<<"$flipped")" "1"
NULLOK=yes

echo
echo "== customised file is rejected, not mangled =="
pam_render <<<$'#%PAM-1.0\nauth required pam_deny.so' >/dev/null 2>&1
assert "missing anchor returns non-zero" "$?" "1"

echo
echo "== enrolment gate: pubkey+totp =="
AUTH_MODE=pubkey+totp; ENROLL_GATE=yes; NULLOK=no
out="$(pam_render <<<"$STOCK")"
assert "auth stack has 9 lines" "$(auth_lines <<<"$out" | wc -l | tr -d ' ')" "9"
assert "4: enrolment-group guard" \
  "$(nth_auth "$out" 4 | grep -o "ingroup $ENROLL_GROUP")" "ingroup $ENROLL_GROUP"
assert "5: strict TOTP is NOT nullok" "$(nth_auth "$out" 5 | grep -c nullok)" "0"
assert "6: enrolling TOTP IS nullok"  "$(nth_auth "$out" 6 | grep -c nullok)" "1"
assert "8: password substack survives" \
  "$(norm "$(nth_auth "$out" 8)")" "auth substack password-auth"
# Landing sites: exempt guards -> the password substack (8);
# enrol guard -> the nullok module (6); strict TOTP and permit -> postlogin (9).
for spec in "1 6 8" "2 5 8" "3 4 8" "4 1 6" "5 3 9" "7 1 9"; do
  read -r n jump target <<<"$spec"
  got="$(nth_auth "$out" "$n" | grep -oE 'success=[0-9]+' | head -1 | cut -d= -f2)"
  assert "line $n declares success=$jump" "$got" "$jump"
  assert "line $n lands on line $target" "$(( n + jump + 1 ))" "$target"
done
assert "a failed strict TOTP dies rather than falling through" \
  "$(nth_auth "$out" 5 | grep -c 'default=die')" "1"

echo
echo "== enrolment gate: password+totp =="
AUTH_MODE=password+totp
out="$(pam_render <<<"$STOCK")"
assert "auth stack has 8 lines" "$(auth_lines <<<"$out" | wc -l | tr -d ' ')" "8"
assert "1: password first" "$(norm "$(nth_auth "$out" 1)")" "auth substack password-auth"
assert "6: strict TOTP is NOT nullok" "$(nth_auth "$out" 6 | grep -c nullok)" "0"
assert "7: enrolling TOTP IS nullok"  "$(nth_auth "$out" 7 | grep -c nullok)" "1"
for spec in "2 5 8" "3 4 8" "4 3 8" "5 1 7" "6 1 8"; do
  read -r n jump target <<<"$spec"
  got="$(nth_auth "$out" "$n" | grep -oE 'success=[0-9]+' | head -1 | cut -d= -f2)"
  assert "line $n declares success=$jump" "$got" "$jump"
  assert "line $n lands on line $target" "$(( n + jump + 1 ))" "$target"
done

echo
echo "== gate off reproduces the original stacks =="
ENROLL_GATE=no; NULLOK=yes
AUTH_MODE=pubkey+totp
assert "pubkey: 7 auth lines" "$(auth_lines <<<"$(pam_render <<<"$STOCK")" | wc -l | tr -d ' ')" "7"
AUTH_MODE=password+totp
assert "password: 6 auth lines" "$(auth_lines <<<"$(pam_render <<<"$STOCK")" | wc -l | tr -d ' ')" "6"
assert "no enrolment group referenced when gate is off" \
  "$(pam_render <<<"$STOCK" | grep -c "$ENROLL_GROUP")" "0"
AUTH_MODE=pubkey+totp

echo
echo "== gate stacks are idempotent =="
ENROLL_GATE=yes
once="$(pam_render <<<"$STOCK")"
assert "re-render is stable" "$(pam_render <<<"$once")" "$once"
assert "exactly one managed block" "$(grep -c '^# BEGIN ssh-mfa' <<<"$once")" "1"
assert "switching gate off shrinks the stack again" \
  "$(ENROLL_GATE=no; auth_lines <<<"$(pam_render <<<"$once")" | wc -l | tr -d ' ')" "7"
ENROLL_GATE=no

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
