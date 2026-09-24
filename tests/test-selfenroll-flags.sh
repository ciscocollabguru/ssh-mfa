#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Scott Jones
# Assert that the flags ssh-mfa-selfenroll passes leave google-authenticator
# with nothing to ask. Runs anywhere: it stubs google-authenticator with a
# model of 1.07's prompting logic, where each question is asked only when the
# corresponding flag is absent.
#
#   ./tests/test-selfenroll-flags.sh

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$HERE/../helpers/ssh-mfa-selfenroll"

pass=0; fail=0
t_ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
t_no() { printf '  \033[31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; fail=$((fail+1)); }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# Model of google-authenticator's interactive questions and the flag that
# suppresses each. Anything unsuppressed is printed as ASKED:<name>.
cat > "$W/google-authenticator" <<'FAKE'
#!/usr/bin/env bash
has() { for a in "${ARGS[@]}"; do [[ "$a" == "$1" ]] && return 0; done; return 1; }
ARGS=("$@")
secret=""
for ((i=0;i<${#ARGS[@]};i++)); do [[ "${ARGS[i]}" == "-s" ]] && secret="${ARGS[i+1]}"; done
has -t || has -c || echo "ASKED:time-based"
has -f             || echo "ASKED:update-file"
has -d || has -D   || echo "ASKED:disallow-reuse"
has -w || has -W   || echo "ASKED:window-size"
has -r || has -u   || echo "ASKED:rate-limit"
[[ -n "$secret" ]] && printf 'SECRETKEY23456789ABCDEFGHIJ\n" RATE_LIMIT 3 30\n" DISALLOW_REUSE\n" TOTP_AUTH\n11111111\n' > "$secret"
echo "QR-CODE-DRAWN"
exit 0
FAKE
chmod +x "$W/google-authenticator"

# Extract the real invocation from the helper and run it under the stub, so
# the test tracks the helper rather than a copy of its flags.
line="$(grep -A1 '^if ! google-authenticator' "$HELPER" | tr '\n' ' ' | sed 's/^if ! //; s/; then.*//')"
if [[ -z "$line" ]]; then
  t_no "could not locate the google-authenticator invocation in the helper"
else
  t_ok "found the invocation in the helper"
  RL_N=3; RL_S=30; ISSUER=testhost; USER=tester; SECRET="$W/.google_authenticator"
  export RL_N RL_S ISSUER USER SECRET
  out="$(PATH="$W:$PATH" bash -c "$line" 2>&1)"

  asked="$(grep -c '^ASKED:' <<<"$out" || true)"
  if [[ "$asked" == "0" ]]; then
    t_ok "no interactive questions remain"
  else
    t_no "$asked question(s) still asked" "$(grep '^ASKED:' <<<"$out" | tr '\n' ' ')"
  fi

  for q in time-based update-file disallow-reuse window-size rate-limit; do
    if grep -q "^ASKED:$q$" <<<"$out"; then t_no "'$q' is suppressed"; else t_ok "'$q' is suppressed"; fi
  done

  grep -q 'QR-CODE-DRAWN' <<<"$out" && t_ok "the QR code step is reached" \
    || t_no "the QR code step was not reached" "$out"
  [[ -s "$SECRET" ]] && t_ok "a secret file is written" || t_no "no secret written"

  # The reuse/rate-limit options must be present, so the two prompts are
  # suppressed by asserting the setting rather than by declining it.
  grep -qw -- '-d' <<<"$line" && t_ok "reuse is disallowed (-d), not merely unasked" \
    || t_no "-d absent: the prompt would be suppressed only by -D (allow reuse)"
  grep -qE -- '-r "\$RL_N"' <<<"$line" && t_ok "rate limit comes from the server's policy file" \
    || t_no "rate limit is not taken from /etc/ssh-mfa/ratelimit"
fi

echo
echo "== 40-enroll-user.sh passes the same suppressing flags =="
# It builds an args array rather than a single command line, so check the
# array contents. It captures stdout, which makes an unsuppressed prompt
# invisible AND lets it consume the stdin fed to it -- so a missing flag here
# is worse than in the interactive helper.
ADMIN="$HERE/../scripts/40-enroll-user.sh"
argblock="$(sed -n '/local args=(-t/,/-s "\$home/p' "$ADMIN")"
# Split into one token per line so each flag can be matched exactly, rather
# than with a regex that is easy to get subtly wrong.
tokens="$(tr -s ' (\n' '\n\n\n' <<<"$argblock")"
for flag in -t -f -d -w -r -R; do
  if grep -Fxq -- "$flag" <<<"$tokens"; then
    t_ok "40-enroll-user.sh passes $flag"
  else
    t_no "40-enroll-user.sh is missing $flag" "tokens: $(tr '\n' ' ' <<<"$tokens")"
  fi
done
if grep -q 'TOTP_STATEFUL.*==.*yes.*args+=' "$ADMIN"; then
  t_no "state flags are still conditional" "omitting -d/-r makes it prompt, invisibly"
else
  t_ok "state flags are unconditional (stateless applied afterwards)"
fi
grep -q 'apply_state_policy' "$ADMIN" \
  && t_ok "stateless mode is applied by stripping option lines" \
  || t_no "apply_state_policy is not called"

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
