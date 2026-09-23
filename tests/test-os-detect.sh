#!/usr/bin/env bash
# Verify detect_os against real /etc/os-release contents from each supported
# distribution. Runs anywhere: it feeds detect_os a synthetic file rather
# than reading the host's.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/lib/common.sh
. "$HERE/../scripts/lib/common.sh"
set +e

pass=0; fail=0
t_ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
t_no() { printf '  \033[31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; fail=$((fail+1)); }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

# Call the REAL detect_os against a synthetic os-release, rather than
# reimplementing its logic here -- a test that encodes the same assumptions
# as the code it checks confirms nothing.
detect_with() {
  printf '%s\n' "$1" > "$W/os-release"
  unset OS_ID OS_NAME OS_MAJOR OS_FAMILY OS_NEEDS_EPEL
  detect_os "$W/os-release"
  printf '%s %s %s\n' "$OS_FAMILY" "$OS_NEEDS_EPEL" "$OS_MAJOR"
}

expect() {
  local name="$1" body="$2" want="$3" got
  got="$(detect_with "$body")"
  if [[ "$got" == "$want" ]]; then t_ok "$name -> $got"
  else t_no "$name" "expected [$want] got [$got]"; fi
}

echo "== EL family (needs EPEL) =="
expect "AlmaLinux 8.10" 'ID="almalinux"
VERSION_ID="8.10"
ID_LIKE="rhel centos fedora"' "el yes 8"
expect "AlmaLinux 9.4" 'ID="almalinux"
VERSION_ID="9.4"
ID_LIKE="rhel centos fedora"' "el yes 9"
expect "Rocky 9.3" 'ID="rocky"
VERSION_ID="9.3"
ID_LIKE="rhel centos fedora"' "el yes 9"
expect "CentOS Stream 9" 'ID="centos"
VERSION_ID="9"
ID_LIKE="rhel fedora"' "el yes 9"
expect "CentOS Stream 10" 'ID="centos"
VERSION_ID="10"
ID_LIKE="rhel fedora"' "el yes 10"
expect "RHEL 8.9" 'ID="rhel"
VERSION_ID="8.9"
ID_LIKE="fedora"' "el yes 8"
expect "RHEL 9.4" 'ID="rhel"
VERSION_ID="9.4"
ID_LIKE="fedora"' "el yes 9"
expect "Oracle Linux 9" 'ID="ol"
VERSION_ID="9.3"
ID_LIKE="fedora"' "el yes 9"
expect "EuroLinux 8" 'ID="eurolinux"
VERSION_ID="8.9"' "el yes 8"

echo
echo "== Fedora family (no EPEL) =="
expect "Fedora 40" 'ID=fedora
VERSION_ID=40' "fedora no 40"
expect "Fedora 42" 'ID=fedora
VERSION_ID=42' "fedora no 42"
expect "Amazon Linux 2023" 'ID="amzn"
VERSION_ID="2023"
ID_LIKE="fedora"' "fedora no 2023"

echo
echo "== unknown rebuilds fall back to ID_LIKE =="
expect "unnamed EL9 rebuild" 'ID="newrebuild"
VERSION_ID="9.2"
ID_LIKE="rhel centos fedora"' "el yes 9"
expect "unnamed Fedora derivative" 'ID="somefedora"
VERSION_ID="41"
ID_LIKE="fedora"' "fedora no 41"

echo
echo "== not this family =="
expect "Debian 12" 'ID=debian
VERSION_ID="12"
ID_LIKE=""' "unknown no 12"
expect "Ubuntu 24.04" 'ID=ubuntu
VERSION_ID="24.04"
ID_LIKE=debian' "unknown no 24"
expect "SUSE 15" 'ID="sles"
VERSION_ID="15.5"' "unknown no 15"

echo
echo "== CRB repo name by major =="
for spec in "el 8 powertools" "el 9 crb" "el 10 crb"; do
  read -r fam maj want <<<"$spec"
  OS_FAMILY="$fam"; OS_MAJOR="$maj"
  got="$(crb_repo_name)"
  [[ "$got" == "$want" ]] && t_ok "$fam $maj -> $got" || t_no "$fam $maj" "expected $want got $got"
done
OS_FAMILY=fedora; OS_MAJOR=40
crb_repo_name >/dev/null 2>&1 && t_no "fedora should have no CRB repo" || t_ok "fedora has no CRB repo"

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
