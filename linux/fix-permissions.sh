#!/usr/bin/env bash
# fix-permissions.sh - makes every script of the Linux side of the Agantra PKI executable and removes CRLF / BOM.
# Run it after unzip (when a zip tool dropped the execute bits), after copying from Windows or a share, or on a fresh clone
# (git hooks do the same automatically once  pwsh ./Setup-GitRepo.ps1  or  git config core.hooksPath .githooks  was run).
# Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
# ---- Platform gate (5.0.0): Linux only (VM, bare metal or WSL). Accepted: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+,
#      SUSE Linux Enterprise (SLES / SLED) 15+, openSUSE Leap 15+ / Tumbleweed. Everything else: error, exit 5, nothing is done.  (-h / --help work everywhere.)
if [ -z "${PKI_GATE_DONE:-}" ]; then
  case "${1:-}" in -h|--help|-help|--Help|help) : ;; *)
    __osrel="${PKI_OS_RELEASE_FILE:-/etc/os-release}"; __id=""; __ver=""; __pretty=""
    if [ -r "$__osrel" ]; then __id="$(. "$__osrel"; echo "${ID:-}")"; __ver="$(. "$__osrel"; echo "${VERSION_ID:-}")"; __pretty="$(. "$__osrel"; echo "${PRETTY_NAME:-${NAME:-}}")"; fi
    __maj="${__ver%%.*}"; case "$__maj" in ''|*[!0-9]*) __maj=0 ;; esac
    __ok=0
    case "$__id" in
      ubuntu) [ "$__maj" -ge 24 ] && __ok=1 ;;
      centos|rhel|rocky|ol) [ "$__maj" -ge 10 ] && __ok=1 ;;
      sles|sles_sap|sled|opensuse-leap) [ "$__maj" -ge 15 ] && __ok=1 ;;
      opensuse-tumbleweed) __ok=1 ;;
    esac
    [ "$(uname -s 2>/dev/null)" = Linux ] || __ok=0
    if [ "$__ok" != 1 ]; then
      echo "[ERROR] This system is '${__pretty:-$(uname -s 2>/dev/null)}' (ID=${__id:-?} VERSION_ID=${__ver:-?}): NOT supported. Nothing was done." >&2
      echo "        Supported: Linux on a VM, bare metal or WSL - Ubuntu 24.04 / 26.04 or newer; CentOS Stream 10+; RHEL 10+; Rocky Linux 10+; Oracle Linux 10+;" >&2
      echo "        SUSE Linux Enterprise 15+ (15, 16 ...); openSUSE 15+ (Leap 15, 16 ..., Tumbleweed). Other distributions, older versions and macOS are refused." >&2
      exit 5
    fi
    PKI_TOOL_VERSION="5.2.6"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
set -u
case "${1:-}" in -h|--help)
cat <<'TXT'
fix-permissions.sh [FOLDER]
  Version 5.2.6
  Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
 Runs on: Linux only (VM, bare metal or WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+. Other systems: error, exit 5.
  Makes *.sh and *.py executable (chmod 755), converts CRLF to LF and removes a BOM in *.sh, *.py, *.txt, *.cnf, *.json, *.crt, *.pem,
  and removes a "Zone.Identifier" file left by Windows. Default FOLDER: the package / repository root (one level above this script's folder).
  --check   only report, change nothing (exit 1 when something would change)
TXT
exit 0;; esac
CHECK=0; [ "${1:-}" = "--check" ] && { CHECK=1; shift; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP="${1:-$(dirname "$HERE")}"
changed=0
while IFS= read -r -d '' f; do
  if grep -q $'\r' "$f" 2>/dev/null || [ "$(head -c3 "$f" | od -An -tx1 | tr -d ' ')" = efbbbf ]; then
    changed=$((changed+1)); echo "LF/BOM : ${f#$TOP/}"; [ "$CHECK" = 1 ] || { sed -i '1s/^\xEF\xBB\xBF//; s/\r$//' "$f"; }
  fi
done < <(find "$TOP" \( -name .git -o -name node_modules \) -prune -o -type f \( -name '*.sh' -o -name '*.py' -o -name '*.txt' -o -name '*.cnf' -o -name '*.json' -o -name '*.crt' -o -name '*.pem' -o -name '*.pub' -o -name '*.md' \) -print0)
while IFS= read -r -d '' f; do
  if [ ! -x "$f" ]; then changed=$((changed+1)); echo "chmod +x: ${f#$TOP/}"; [ "$CHECK" = 1 ] || chmod 755 "$f"; fi
done < <(find "$TOP" -name .git -prune -o -type f \( -name '*.sh' -o -name '*.py' \) -print0)
find "$TOP" -name '*:Zone.Identifier' -delete 2>/dev/null
[ "$changed" = 0 ] && echo "all scripts are executable and LF" || { [ "$CHECK" = 1 ] && { echo "$changed file(s) need fixing"; exit 1; } || echo "fixed $changed file(s)"; }
exit 0
