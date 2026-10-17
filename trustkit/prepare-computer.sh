#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# prepare-computer.sh - get this Linux computer ready: OpenSSL (3.x / 4.x) + the latest Python 3 from the package manager, both on the PATH. STANDALONE.
# ---- Platform gate: Linux only (VM, bare metal or WSL). Accepted: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+,
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
    echo "[INFO] $(basename "$0") version 6.4.3" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
VERSION="6.4.3"

help_pager() {  # help text: one screen at a time on a terminal (Space = next page, q = quit); everything when piped
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -FRXK; elif [ -t 1 ] && command -v more >/dev/null 2>&1; then more; else cat; fi
}
show_help() {
cat <<'EOF'
============================================================
 prepare-computer.sh - get this Linux computer ready: OpenSSL + the latest Python 3, both on the
 PATH
 Version 6.4.3
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES   (run it once; sudo is used for the install)
  1. OpenSSL   looks for openssl; installs the package "openssl" (+ ca-certificates) of your
     distribution when it is missing or older than 3.0.
  2. Python    looks for python3 (3.10 or newer); installs the newest Python 3 your distribution
     offers (+ pip, venv) when it is missing or older.
  3. PATH      makes sure `openssl` and `python3` work in a new shell: when a newer OpenSSL sits in
     a folder that is not on the PATH (for example /opt/openssl4/bin),
               that folder is put in front of the PATH for all users (/etc/profile.d/pki-openssl.sh,
               as root) or for you (~/.profile).
  Package managers:   Ubuntu 24 / 26: apt     CentOS Stream 10, RHEL 10, Rocky 10, Oracle Linux 10: dnf     SLES 15 / 16, openSUSE Leap 15 / 16, Tumbleweed: zypper
  Whatever OpenSSL version the distribution ships (3.x or 4.x) is accepted. RSA / ECDSA need 3.0,
  ML-DSA (quantum) needs 3.5 or 4: if you have less, the script says so;
  OpenSSL 4 can be added with linux/Install-DevEnvironment.sh --openssl-source ppa|build (full
  project).

USAGE   ./prepare-computer.sh [options]
  --only all|openssl|python   what to prepare (default all)
  --check     only look: say what is there, what would be installed, what would be added to the
              PATH. Nothing is changed.
  --yes       do not ask before installing
  --force     install / update the packages even when a good version is already there
  --no-path   do not touch the PATH
  -h | --help

AFTER IT
  Open a NEW shell (or: . /etc/profile), then:   openssl version     python3 --version     ./new-pki-csr.sh
  If the PKI is already installed on this computer (ca-certificates, from install-pki-ca.sh),
  nothing changes: this script does not touch certificates.

WHERE IT RUNS
  Linux: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE
  15+ (VM, bare metal, WSL).
  Needs Internet access to the repositories of the distribution (RHEL: a registered subscription).
  On Windows use Prepare-Computer.ps1.
  EXIT CODES   0 ok   1 error   4 something is still missing (OpenSSL below 3.0, Python not found)   5 system not supported
============================================================
EOF
}

say() { local l="$1"; shift; local c=""; case "$l" in OK) c=$'\e[32m';; WARN) c=$'\e[33m';; ERROR) c=$'\e[31m';; INFO) c=$'\e[36m';; esac
        if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then printf '%s[%s] %s\e[0m\n' "$c" "$l" "$*"; else printf '[%s] %s\n' "$l" "$*"; fi; }
die() { say ERROR "$1"; exit "${2:-1}"; }

ONLY=all; CHECK=0; YES=0; FORCE=0; NOPATH=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help|-help|--Help|help) show_help | help_pager; exit 0 ;;
    --only) ONLY="$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')"; shift ;;
    --check) CHECK=1 ;; --yes|-y) YES=1 ;; --force) FORCE=1 ;; --no-path) NOPATH=1 ;;
    *) die "Unknown option: $1   (prepare-computer.sh --help)" ;;
  esac; shift
done
case "$ONLY" in all|openssl|python) : ;; *) die "--only is all, openssl or python." ;; esac

echo "============================================================"
echo " prepare-computer.sh - OpenSSL + the latest Python 3, both on the PATH"
echo " Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com"
echo "============================================================"

__osrel="${PKI_OS_RELEASE_FILE:-/etc/os-release}"; ID_=""; PRETTY_=""
[ -r "$__osrel" ] && { ID_="$(. "$__osrel"; echo "${ID:-}")"; PRETTY_="$(. "$__osrel"; echo "${PRETTY_NAME:-}")"; }
case "$ID_" in
  ubuntu) FAMILY=apt ;;
  centos|rhel|rocky|ol) FAMILY=dnf ;;
  sles|sles_sap|sled|opensuse-leap|opensuse-tumbleweed) FAMILY=zypper ;;
  *) FAMILY=apt ;;
esac
say INFO "System: ${PRETTY_:-$ID_}  (package manager: $FAMILY)"
MISSING=0

SUDO=""; if [ "$(id -u)" != 0 ]; then command -v sudo >/dev/null 2>&1 && SUDO=sudo; fi
run_pm() {   # run_pm "<command line>"
  local c="$1"; [ "$FAMILY" = apt ] && c="DEBIAN_FRONTEND=noninteractive $c"
  if [ "$(id -u)" = 0 ]; then bash -c "$c"; elif [ -n "$SUDO" ]; then $SUDO env bash -c "$c"; else say ERROR "Not root and no sudo: cannot install."; return 1; fi
}
confirm() { [ "$YES" = 1 ] && return 0; if [ -t 0 ]; then printf '%s [Y/n] ' "$1"; local a; read -r a || a=""; case "$a" in n|N|no|NO) return 1 ;; esac; fi; return 0; }

# ---------------------------------------------------------------- PATH helpers
on_path() { case ":$PATH:" in *":$1:"*) return 0 ;; esac; return 1; }
add_to_path() {   # add_to_path <dir>   (in front)
  local d="$1" file line
  if [ "$NOPATH" = 1 ]; then say INFO "--no-path: $d is not added to the PATH."; return 0; fi
  if [ "$(id -u)" = 0 ]; then file=/etc/profile.d/pki-openssl.sh; else file="$HOME/.profile"; fi
  line="export PATH=\"$d:\$PATH\"   # added by prepare-computer.sh"
  if [ "$CHECK" = 1 ]; then say INFO "--check: would add $d to the PATH in $file."; return 0; fi
  if [ -f "$file" ] && grep -qF "$d:" "$file" 2>/dev/null; then say INFO "$d is already in $file."
  else { [ "$(id -u)" = 0 ] && [ ! -f "$file" ] && echo "# PKI: OpenSSL 4 first (prepare-computer.sh)"; echo "$line"; } >> "$file" && say OK "Added to the PATH in $file: $d" || say WARN "Could not write $file: add  $line  yourself."; fi
  export PATH="$d:$PATH"; say INFO "Open a NEW shell (or: . $file) so that every program sees the new PATH."
}

# ================================================================ OPENSSL
ossl_best() {   # -> path|text|major|minor of the newest openssl found
  local best="" bm=-1 bn=-1 p v m n c
  for c in openssl4 openssl /opt/openssl4/bin/openssl /usr/local/openssl4/bin/openssl /usr/local/bin/openssl /usr/local/ssl/bin/openssl; do
    p="$(command -v "$c" 2>/dev/null || true)"; [ -n "$p" ] || continue
    v="$("$p" version 2>/dev/null | head -n1)"; case "$v" in OpenSSL\ [0-9]*) : ;; *) continue ;; esac
    m="$(printf '%s' "$v" | sed -E 's/^OpenSSL ([0-9]+)\..*/\1/')"; n="$(printf '%s' "$v" | sed -E 's/^OpenSSL [0-9]+\.([0-9]+).*/\1/')"
    if [ "$m" -gt "$bm" ] || { [ "$m" -eq "$bm" ] && [ "$n" -gt "$bn" ]; }; then best="$p|$v|$m|$n"; bm=$m; bn=$n; fi
  done
  printf '%s' "$best"
}
openssl_path_check() {   # <info>
  local P T M N d first fv fm; IFS='|' read -r P T M N <<< "$1"; d="$(dirname "$P")"
  say OK "OpenSSL: $T  ($P)"
  if [ "$M" -ge 4 ] || { [ "$M" -eq 3 ] && [ "$N" -ge 5 ]; }; then say INFO "Good for RSA, ECDSA and ML-DSA (quantum) requests."
  elif [ "$M" -ge 3 ]; then say INFO "Good for RSA and ECDSA requests. ML-DSA (quantum) needs OpenSSL 3.5 or 4 (linux/Install-DevEnvironment.sh --openssl-source ppa|build)."
  else say WARN "OpenSSL $M.$N is older than 3.0: not usable."; MISSING=1; fi
  first="$(command -v openssl 2>/dev/null || true)"
  if [ -z "$first" ]; then
    if [ "$(basename "$P")" = openssl ]; then say WARN "openssl is installed but not found on the PATH."; add_to_path "$d"
    else say WARN "Only '$(basename "$P")' exists, no command named openssl on the PATH. Use it by name, or link it:  sudo ln -s $P /usr/local/bin/openssl"; fi
  elif [ "$(basename "$P")" = openssl ] && [ "$first" != "$P" ]; then
    fv="$("$first" version 2>/dev/null | head -n1)"; fm="$(printf '%s' "$fv" | sed -E 's/^OpenSSL ([0-9]+)\..*/\1/')"
    if [ "${fm:-0}" -lt "$M" ]; then say WARN "The openssl first on the PATH is older ($fv: $first). The folder of the newer one is put in front."; add_to_path "$d"
    else say OK "openssl is on the PATH: $first"; fi
  else say OK "openssl is on the PATH: $first"; fi
}
do_openssl() {
  say INFO "--- OpenSSL ---"
  local info P T M N cmds
  info="$(ossl_best)"
  if [ -n "$info" ]; then IFS='|' read -r P T M N <<< "$info"; say INFO "OpenSSL found: $T  ($P)"; else say INFO "OpenSSL is not installed."; fi
  if [ -n "$info" ] && [ "$M" -ge 3 ] && [ "$FORCE" = 0 ]; then openssl_path_check "$info"; return 0; fi
  case "$FAMILY" in
    apt) cmds=("apt-get update -y" "apt-get install -y openssl ca-certificates") ;;
    dnf) cmds=("dnf install -y openssl ca-certificates") ;;
    zypper) cmds=("zypper --non-interactive install openssl-3 ca-certificates || zypper --non-interactive install openssl ca-certificates") ;;
  esac
  local c; for c in "${cmds[@]}"; do say INFO "Would run: $c"; done
  if [ "$CHECK" = 1 ]; then [ -n "$info" ] && openssl_path_check "$info"; return 0; fi
  confirm "Install OpenSSL now?" || { say INFO "Stopped by you."; return 0; }
  for c in "${cmds[@]}"; do run_pm "$c" || { [ "$FAMILY" = apt ] && [[ "$c" == *update* ]] && continue; say ERROR "The command failed: $c"; MISSING=1; return 0; }; done
  info="$(ossl_best)"; [ -n "$info" ] || { say ERROR "The package was installed but openssl was not found."; MISSING=1; return 0; }
  openssl_path_check "$info"
}

# ================================================================ PYTHON
py_best() {   # -> path|text|minor of the newest python3 found
  local best="" bn=-1 p v n c
  for c in python3 python3.15 python3.14 python3.13 python3.12 python3.11 python3.10 python; do
    p="$(command -v "$c" 2>/dev/null || true)"; [ -n "$p" ] || continue
    v="$("$p" --version 2>&1 | head -n1)"; case "$v" in Python\ 3.*) : ;; *) continue ;; esac
    n="$(printf '%s' "$v" | sed -E 's/^Python 3\.([0-9]+).*/\1/')"
    [ "$n" -gt "$bn" ] && { best="$p|$v|$n"; bn=$n; }
  done
  printf '%s' "$best"
}
do_python() {
  say INFO "--- Python ---"
  local info P T N cmds
  info="$(py_best)"
  if [ -n "$info" ]; then IFS='|' read -r P T N <<< "$info"; say INFO "Python found: $T  ($P)"; else say INFO "Python 3 is not installed."; fi
  if [ -n "$info" ] && [ "$N" -ge 10 ] && [ "$FORCE" = 0 ]; then
    say OK "Python 3.10 or newer is there. (--force installs / updates the packages anyway.)"
    command -v python3 >/dev/null 2>&1 || { say WARN "python3 is not on the PATH."; add_to_path "$(dirname "$P")"; }
    "$P" -m pip --version >/dev/null 2>&1 && say OK "pip: $("$P" -m pip --version 2>&1 | head -n1)" || say WARN "pip is missing: install the package python3-pip (this script does it with --force)."
    return 0
  fi
  case "$FAMILY" in
    apt) cmds=("apt-get update -y" "apt-get install -y python3 python3-pip python3-venv") ;;
    dnf) cmds=("dnf install -y python3 python3-pip") ;;
    zypper) cmds=("zypper --non-interactive install python313 python313-pip || zypper --non-interactive install python312 python312-pip || zypper --non-interactive install python311 python311-pip || zypper --non-interactive install python3 python3-pip") ;;
  esac
  local c; for c in "${cmds[@]}"; do say INFO "Would run: $c"; done
  if [ "$CHECK" = 1 ]; then return 0; fi
  confirm "Install Python now?" || { say INFO "Stopped by you."; return 0; }
  for c in "${cmds[@]}"; do run_pm "$c" || { [ "$FAMILY" = apt ] && [[ "$c" == *update* ]] && continue; say ERROR "The command failed: $c"; MISSING=1; return 0; }; done
  info="$(py_best)"; [ -n "$info" ] || { say ERROR "The package was installed but python3 was not found."; MISSING=1; return 0; }
  IFS='|' read -r P T N <<< "$info"; say OK "Python: $T  ($P)"
  command -v python3 >/dev/null 2>&1 || { say WARN "python3 is not on the PATH."; add_to_path "$(dirname "$P")"; }
  "$P" -m pip --version >/dev/null 2>&1 && say OK "pip: $("$P" -m pip --version 2>&1 | head -n1)" || say WARN "pip was not found."
  [ "$N" -ge 10 ] || { say WARN "The distribution gives Python 3.$N: older than 3.10."; MISSING=1; }
}

[ "$ONLY" = all ] || [ "$ONLY" = openssl ] && do_openssl
[ "$ONLY" = all ] || [ "$ONLY" = python ] && do_python
echo
[ "$CHECK" = 1 ] && say INFO "--check: nothing was changed."
[ "$MISSING" = 1 ] && { say WARN "Not everything is ready: read the lines above."; exit 4; }
say OK "Ready. Open a NEW shell, then: openssl version   python3 --version"
exit 0
