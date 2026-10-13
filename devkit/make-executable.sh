#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# make-executable.sh - DevKit, Linux: LF line endings + executable bit for every .sh of this folder.
# Run it with bash (it needs no executable bit itself):   bash make-executable.sh [folder]
# Windows developers: use Make-ShExecutable.ps1 (the Windows twin).
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
    PKI_TOOL_VERSION="5.1.0"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
case "${1:-}" in -h|--help)
cat <<'EOT'
make-executable.sh [folder]     folder = this script's folder by default
  Version 5.1.0
  Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
 Runs on: Linux only (VM, bare metal or WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+. Other systems: error, exit 5.
  1. CRLF -> LF in every *.sh, *.py, *.env (sed; a CRLF script fails with  $'\r': command not found)
  2. chmod +x on every *.sh
EOT
exit 0;; esac
DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
[ -d "$DIR" ] || { echo "[ERROR] not a folder: $DIR" >&2; exit 1; }
n=0; c=0
while IFS= read -r -d '' f; do
  if grep -q $'\r' "$f" 2>/dev/null; then sed -i 's/\r$//' "$f"; c=$((c+1)); fi
  case "$f" in *.sh) chmod +x "$f"; n=$((n+1)) ;; esac
done < <(find "$DIR" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.env' \) -print0)
echo "[OK] $n script(s) are executable now, $c file(s) converted from CRLF to LF. Folder: $DIR"
