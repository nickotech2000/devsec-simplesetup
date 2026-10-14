#!/usr/bin/env bash
# setup-git.sh - run ONCE after "git clone" on Linux / WSL: turns on the repository hooks and makes every .sh / .py executable.
# (git does not copy hooks with a clone, so this one step is needed. The execute bits themselves come with the clone when the
#  index holds mode 100755 - Setup-GitRepo.ps1 on Windows writes them there - and this script is the safety net.)
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
    PKI_TOOL_VERSION="5.3.6"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
case "${1:-}" in -h|--help) echo "Version 5.3.6"; echo "Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com"; echo "setup-git.sh   (no options) - git config core.hooksPath .githooks, chmod 755 *.sh *.py, LF check. Run inside the clone."; echo "Runs on: Linux only (VM, bare metal or WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+. Other systems: error, exit 5."; exit 0;; esac
top="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not inside a git clone"; exit 1; }
cd "$top" || exit 1
git config core.hooksPath .githooks && echo "hooks: .githooks enabled"
git config core.autocrlf false; git config core.eol lf
chmod +x .githooks/* 2>/dev/null
bash "$top/linux/fix-permissions.sh" "$top"
if [ -d Scripts ] && [ ! -d scripts ]; then echo "WARNING: the folder is 'Scripts' but the code uses 'scripts' (Linux is case sensitive). On Windows run: pwsh ./Setup-GitRepo.ps1 -FixCase"; fi
echo "done. Try:  ./linux/pki-server/pki-server.sh --help"
