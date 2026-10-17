#!/usr/bin/env bash
# ============================================================
# Install-DevEnvironment.sh
#
# Linux and macOS Developer Environment Bootstrap - the sibling of Install-DevEnvironment.ps1 (Windows).
#
# Author  : Nicko Satria Utama
# Company : Agantra Inovatif OU (NextMantra)
# Email   : nicko@nextmantra.com
# ============================================================
# Prepares a machine for the Agantra PKI scripts and for development:
#   tools     curl, tar, gzip, unzip, ca-certificates, a compiler, make, perl
#   7zip      7-Zip (the archive tool of the .certpacked transport: AES-256 zip and 7z)
#   openssl   DEFAULT: the OpenSSL of the distribution (Ubuntu 26.04: 3.5.x; Ubuntu 24.04: 3.0.x), nothing is built or replaced.
#             --openssl-source ppa    OpenSSL 4 (nicko-su-openssl4) from YOUR PPA ppa:nickotech2000/nicko-su-prod
#             --openssl-source build  OpenSSL 4 as a FULL build from the official source release (checksum verified).
#             Proven afterwards: version, FIPS provider, ML-DSA sign / verify, ML-KEM, ML-DSA inside the FIPS provider.
#   nginx     YOUR nginx (nicko-su-nginx) from the PPA ppa:nickotech2000/nicko-su-prod (Ubuntu 24.04 / 26.04 only).
#   git, python, go, node, php, dotnet, pwsh      developer tools, installed from the distribution (pwsh: GitHub release)
#
# Platforms: Ubuntu / Debian, RHEL / CentOS Stream / Rocky / Oracle / Alma, SLES / openSUSE, macOS (Apple Silicon, Intel).
# Written for bash 3.2 (macOS) and newer. UNBLOCK / UNLOCK of its own folder at every start; --unblock does only that.
# Manual: docs/Install-DevEnvironment-MANUAL.txt        Help: ./Install-DevEnvironment.sh --help
# ============================================================
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
    PKI_TOOL_VERSION="6.4.7"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi

VERSION="6.4.7"
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
OSSL_MIN_MAJOR=3; OSSL_MIN_MINOR=0; OSSL_MIN_PATCH=0        # set again after the options: system 3.0.0, ppa / build 4.0.1
OSSL_SOURCE="system"                       # system | ppa | build
PPA="ppa:nickotech2000/nicko-su-prod"; PPA_OPENSSL_PKG="nicko-su-openssl4"; NGINX_PKG="nicko-su-nginx"
OSSL_VERSION="4.0.3"                       # what is built; --openssl-version changes it
ALL_COMPONENTS="tools 7zip openssl nginx git python go node php dotnet pwsh"

help_pager() {  # help text: one screen at a time on a terminal (Space = next page, q = quit); everything when piped
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -FRXK; elif [ -t 1 ] && command -v more >/dev/null 2>&1; then more; else cat; fi
}
usage() {
cat <<'EOF'
====================================================================================================
 Install-DevEnvironment.sh  -  install the developer tools on Linux, and prove OpenSSL
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, Q = quit.
 Manual : docs/Install-DevEnvironment-MANUAL.txt     Twin: Install-DevEnvironment.ps1 (Windows)
 Runs on: Linux (VM, bare metal, WSL): Ubuntu 24+, CentOS Stream / RHEL / Rocky / Oracle 10+,
          SLES / openSUSE 15+. Other systems: error, exit 5.
 Needs  : bash, Internet access, root or sudo (not for --check and --unblock).

WHAT IT IS
  A bootstrap for a Linux developer computer. It installs what is MISSING, checks each component
  and prints a summary. It never replaces or removes what is already there.
  For the PKI tools alone you need only OpenSSL and 7-Zip: use  --only openssl,7zip.

QUICK START
  1. Look first. Nothing is changed, no root needed:   ./Install-DevEnvironment.sh --check
  2. See the commands without running them:    ./Install-DevEnvironment.sh --dry-run --yes
  3. Install what the PKI tools need:
        sudo ./Install-DevEnvironment.sh --yes --only openssl,7zip
  4. Everything:                               sudo ./Install-DevEnvironment.sh --yes
  5. Open a NEW shell (the PATH is read when a shell starts).

COMPONENTS
  tools    curl, tar, gzip, unzip, ca-certificates, compiler, make, perl
  7zip     7-Zip: the archive tool of the .certpacked transport (AES-256 zip, 7z)
  openssl  Default = the OpenSSL of your distribution. Ubuntu 26.04 ships 3.5.x (ML-DSA, ML-KEM).
           Ubuntu 24.04 ships 3.0.x (Classic RSA and ECDSA only). Nothing is built, nothing is
           replaced, the PATH is not touched. Enough for the DevKit generators.
           --openssl-source ppa     OpenSSL 4 from your PPA (package nicko-su-openssl4,
                                    ppa:nickotech2000/nicko-su-prod). Ubuntu 24.04 / 26.04, amd64.
           --openssl-source build   OpenSSL 4.0.1+ as a FULL build from the official source
                                    (SHA-256 checked) into --openssl-prefix, and a link openssl4
                                    in /usr/local/bin. pki_setup.ps1 on a CA machine needs 4.x.
  nginx    nginx from your PPA (package nicko-su-nginx 1.31.x). Ubuntu 24.04 / 26.04 only; other
           systems skip it. For the CRL, OCSP and time stamp server.
  git, python, go, node, php, dotnet, pwsh    Developer tools. Distribution packages; pwsh from the
           PowerShell GitHub release (checksum verified) into /opt/microsoft/powershell, linked
           as /usr/local/bin/pwsh.
  Every component is checked after the install: the program must be found.

OPENSSL: WHAT "READY" MEANS
  The script proves, on the binary it will use: the version, the FIPS provider, ML-DSA, ML-KEM.
  What is "ready" depends on --openssl-source: system 3.0.0+, ppa and build 4.0.1+.
  What the chosen OpenSSL cannot do is shown as NOTE (not a failure).
  Exit 0 = ready, 4 = not ready.

OPTIONS
  --only LIST            Comma list of components. Default: all.
  --skip LIST            All except these.
  --check                Scan only. No root needed.
  --yes, -y              Do not ask. Needed when there is no terminal.
  --dry-run              Print the commands that change the system. Run nothing.
  --openssl-source S     system (default) | ppa | build.
  --ppa PPA              The PPA for nginx and OpenSSL 4. Default ppa:nickotech2000/nicko-su-prod.
  --nginx-package P      Default nicko-su-nginx.
  --openssl-prefix DIR   (build) Where OpenSSL goes. Default /opt/openssl-4.0.3.
  --openssl-version V    (build) Build this version instead of 4.0.3 (4.0.1 or newer).
  --openssl-no-docs      (build) Skip the manual pages. Shorter. The cryptography is still FULL.
  --openssl-jobs N       (build) Parallel compile jobs. Default: the number of CPU cores.
  --no-path              (ppa, build) Do not put the OpenSSL 4 bin folder on the PATH. Default: it
                         goes FIRST on the PATH of login shells: /etc/profile.d/openssl4.sh (sudo),
                         else a marked block in ~/.profile and ~/.bashrc.
  --unblock              Set write permission, make scripts executable and remove the immutable
                         flag where chattr exists, for this script's folder, then stop. The same is
                         done silently at every start.
  --version              Show the version.         --help, -h   This text.

BUILD TIME  (only with --openssl-source build; be warned)
  A full build compiles hundreds of files. About 5 minutes on 8 cores, 15 to 25 on 2 cores, and
  over an hour on ONE core. Use a machine with cores.

EXAMPLES
  ./Install-DevEnvironment.sh --check
  sudo ./Install-DevEnvironment.sh --yes --only openssl,7zip
  sudo ./Install-DevEnvironment.sh --yes --only openssl --openssl-source ppa
  sudo ./Install-DevEnvironment.sh --yes --only nginx
  sudo ./Install-DevEnvironment.sh --yes --skip php,dotnet
  ./Install-DevEnvironment.sh --dry-run --only openssl --openssl-source build

LIMITS
  Package names differ between distributions and versions. Each component is tried with the usual
  names and then checked, never assumed. dotnet, node, go and php are best effort: your
  distribution may not ship a current version. The PPA and the source build are not tested with
  the real packages (see the manual, section 17).

EXIT CODES
  0 ok    1 error    5 platform not supported    4 OpenSSL not ready
  6 a component could not be installed
====================================================================================================
EOF
}

# ------------------------------------------------------------------------------------------------ messages
if [ -t 1 ]; then C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m'); C_Y=$(printf '\033[33m'); C_C=$(printf '\033[36m'); C_0=$(printf '\033[0m'); else C_R=; C_G=; C_Y=; C_C=; C_0=; fi
info() { printf '%s[INFO]%s %s\n' "$C_C" "$C_0" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_Y" "$C_0" "$*"; }
err()  { printf '%s[ERROR]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
dry()  { printf '%s[DRY ]%s %s\n' "$C_C" "$C_0" "$*"; }
row()  { printf '%s[%s]%s %-14s %s\n' "$1" "$2" "$C_0" "$3" "$4"; }
die()  { err "$1"; exit "${2:-1}"; }

# ------------------------------------------------------------------------------------------------ UNBLOCK + UNLOCK
unblock_unlock() {   # $1 = folder ; children and recursive. Linux: write bit, immutable flag. macOS: quarantine, locked flags.
  local d="$1"
  [ -d "$d" ] || return 0
  chmod -R u+rw "$d" 2>/dev/null
  find "$d" -maxdepth 3 -type f \( -name '*.sh' \) -exec chmod u+x {} + 2>/dev/null
  case "${PKI_UNAME:-$(uname -s)}" in
    Darwin)
      command -v xattr >/dev/null 2>&1 && xattr -dr com.apple.quarantine "$d" 2>/dev/null
      command -v chflags >/dev/null 2>&1 && chflags -R nouchg,noschg "$d" 2>/dev/null ;;
    *)
      command -v chattr >/dev/null 2>&1 && chattr -R -i "$d" 2>/dev/null ;;
  esac
  return 0
}
unblock_unlock "$SCRIPT_DIR"

# ------------------------------------------------------------------------------------------------ options
OSSL_SOURCE_SET=0; ONLY=""; SKIP=""; CHECK=0; YES=0; DRYRUN=0; OSSL_PREFIX=""; OSSL_DOCS=1; OSSL_JOBS=""; UNBLOCK=0; ADDPATH=1
need_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "Option $1 needs a value. See --help." 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage | help_pager; exit 0 ;;
    --version) echo "Install-DevEnvironment.sh $VERSION"; exit 0 ;;
    --only) need_value "$@"; ONLY="$2"; shift 2 ;;            --only=*) ONLY="${1#*=}"; shift ;;
    --skip) need_value "$@"; SKIP="$2"; shift 2 ;;            --skip=*) SKIP="${1#*=}"; shift ;;
    --check) CHECK=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --dry-run) DRYRUN=1; shift ;;
    --openssl-source) need_value "$@"; OSSL_SOURCE="$2"; shift 2 ;; --openssl-source=*) OSSL_SOURCE="${1#*=}"; shift ;;
    --ppa) need_value "$@"; PPA="$2"; shift 2 ;; --ppa=*) PPA="${1#*=}"; shift ;;
    --nginx-package) need_value "$@"; NGINX_PKG="$2"; shift 2 ;; --nginx-package=*) NGINX_PKG="${1#*=}"; shift ;;
    --openssl-prefix) need_value "$@"; OSSL_PREFIX="$2"; shift 2 ;; --openssl-prefix=*) OSSL_PREFIX="${1#*=}"; shift ;;
    --openssl-version) need_value "$@"; OSSL_VERSION="$2"; shift 2 ;; --openssl-version=*) OSSL_VERSION="${1#*=}"; shift ;;
    --openssl-no-docs) OSSL_DOCS=0; shift ;;
    --no-path) ADDPATH=0; shift ;;
    --openssl-jobs) need_value "$@"; OSSL_JOBS="$2"; shift 2 ;; --openssl-jobs=*) OSSL_JOBS="${1#*=}"; shift ;;
    --unblock) UNBLOCK=1; shift ;;
    *) die "Unknown option $1. See ./Install-DevEnvironment.sh --help" 1 ;;
  esac
done

case "$OSSL_SOURCE" in system) OSSL_MIN_MAJOR=3; OSSL_MIN_MINOR=0; OSSL_MIN_PATCH=0 ;; ppa|build) OSSL_MIN_MAJOR=4; OSSL_MIN_MINOR=0; OSSL_MIN_PATCH=1 ;; *) die "--openssl-source is system, ppa or build (got '$OSSL_SOURCE')." 1 ;; esac

if [ "$UNBLOCK" = 1 ]; then
  info "UNBLOCK + UNLOCK (children and recursive): $SCRIPT_DIR"
  unblock_unlock "$SCRIPT_DIR"
  ok "Done: write permission set, scripts executable; $(case "${PKI_UNAME:-$(uname -s)}" in Darwin) echo 'quarantine mark and locked flags removed';; *) echo 'immutable flag removed where chattr exists';; esac)."
  exit 0
fi

# component selection
SELECT=""
if [ -n "$ONLY" ]; then SELECT="$(echo "$ONLY" | tr ',' ' ')"; else SELECT="$ALL_COMPONENTS"; fi
for s in $(echo "$SKIP" | tr ',' ' '); do SELECT="$(echo " $SELECT " | sed "s/ $s / /g")"; done
for s in $SELECT; do case " $ALL_COMPONENTS " in *" $s "*) ;; *) die "Unknown component '$s'. Components: $ALL_COMPONENTS" 1 ;; esac; done
want() { case " $SELECT " in *" $1 "*) return 0 ;; esac; return 1; }

# ------------------------------------------------------------------------------------------------ platform
UNAME="${PKI_UNAME:-$(uname -s)}"; ARCH="$(uname -m)"
PLATFORM=""; FAMILY=""; DIST_NAME=""
os_field() { grep -E "^$1=" "$2" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'; }
detect_platform() {
  case "$UNAME" in
    Linux)
      PLATFORM=linux
      local rel="${PKI_OS_RELEASE_FILE:-/etc/os-release}"; [ -r "$rel" ] || rel=/usr/lib/os-release
      local id like t; id="$(os_field ID "$rel")"; like="$(os_field ID_LIKE "$rel")"; DIST_NAME="$(os_field PRETTY_NAME "$rel")"
      FAMILY=unknown
      for t in $id $like; do
        case "$t" in
          ubuntu|debian|linuxmint|pop|raspbian) FAMILY=debian; break ;;
          rhel|centos|rocky|almalinux|ol|fedora|amzn) FAMILY=rhel; break ;;
          sles|sled|sles_sap|suse|opensuse|opensuse-leap|opensuse-tumbleweed|opensuse-slowroll) FAMILY=suse; break ;;
        esac
      done ;;
    Darwin) PLATFORM=macos; FAMILY=macos; DIST_NAME="macOS ${PKI_MACOS_VERSION:-$(sw_vers -productVersion 2>/dev/null)} ($ARCH)" ;;
    *) PLATFORM=other ;;
  esac
}
detect_platform
[ "$PLATFORM" != other ] || die "$UNAME is not supported (Linux and macOS). On Windows use Install-DevEnvironment.ps1." 2
[ "$FAMILY" != unknown ] || die "$DIST_NAME: not a known family (Debian / RHEL / SUSE). Install the components by hand." 2

SUDO=""
if [ "$DRYRUN" = 0 ] && [ "$CHECK" = 0 ] && [ "$(id -u)" != 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO=sudo; elif [ "$PLATFORM" != macos ]; then die "Not root and no sudo: cannot install. Run as root, or use --check." 1; fi
fi
priv() { if [ "$DRYRUN" = 1 ]; then dry "$*"; return 0; fi; if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi; }
confirm() { [ "$YES" = 1 ] && return 0; if [ -t 0 ]; then printf '%s [y/N] ' "$1"; local a; read -r a; case "$a" in y|Y|yes|YES) return 0 ;; esac; fi; return 1; }
APT_UPDATED=0
pkg_install() {
  case "$FAMILY" in
    debian) if [ "$APT_UPDATED" = 0 ]; then priv env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; APT_UPDATED=1; fi
            priv env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    rhel)   if command -v dnf >/dev/null 2>&1; then priv dnf install -y "$@"; else priv yum install -y "$@"; fi ;;
    suse)   priv zypper --non-interactive install "$@" ;;
    macos)  command -v brew >/dev/null 2>&1 && brew install "$@" ;;
  esac
}
pkg_any() {   # pkg_any "alt one pkgs" "alt two pkgs" ... : the first alternative that installs wins
  local alt
  for alt in "$@"; do
    # shellcheck disable=SC2086
    if [ "$DRYRUN" = 1 ]; then pkg_install $alt; return 0; fi
    # shellcheck disable=SC2086
    pkg_install $alt >/dev/null 2>&1 && return 0
  done
  return 1
}
have() { command -v "$1" >/dev/null 2>&1; }
sha256_of() { if have sha256sum; then sha256sum "$1" | cut -d' ' -f1; elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1; else openssl dgst -sha256 -r "$1" | cut -d' ' -f1; fi; }
ncpu() { getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1; }

# ------------------------------------------------------------------------------------------------ OpenSSL
OPENSSL=""; OSSL_TEXT=""
ver_parts() { echo "$1" | sed -n 's/^OpenSSL \([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\{0,1\}\([0-9]*\).*/\1 \2 \3/p'; }
ver_ok() { set -- $1; local a="$1" b="$2" c="${3:-0}"; [ -z "$c" ] && c=0
  [ "$a" -gt "$OSSL_MIN_MAJOR" ] && return 0; [ "$a" -lt "$OSSL_MIN_MAJOR" ] && return 1
  [ "$b" -gt "$OSSL_MIN_MINOR" ] && return 0; [ "$b" -lt "$OSSL_MIN_MINOR" ] && return 1
  [ "$c" -ge "$OSSL_MIN_PATCH" ]; }
find_openssl() {
  OPENSSL=""; OSSL_TEXT=""
  local c v p cands=""
  if [ "$OSSL_SOURCE" = system ]; then cands="$(command -v openssl 2>/dev/null) /usr/bin/openssl"
  elif [ "$OSSL_SOURCE" = ppa ]; then cands="$(dpkg -L "$PPA_OPENSSL_PKG" 2>/dev/null | grep -E '/bin/openssl$' | head -1)"; fi
  for c in $cands "$OSSL_PREFIX/bin/openssl" $(command -v openssl4 2>/dev/null) $(command -v openssl 2>/dev/null) \
           /opt/openssl-4*/bin/openssl /usr/local/openssl-4*/bin/openssl "$HOME"/.local/openssl-4*/bin/openssl \
           /opt/homebrew/opt/openssl@4/bin/openssl /usr/local/opt/openssl@4/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    v="$("$c" version 2>/dev/null | head -1)"; p="$(ver_parts "$v")"; [ -n "$p" ] || continue
    if ver_ok "$p"; then OPENSSL="$c"; OSSL_TEXT="$(echo "$v" | cut -d'(' -f1 | sed 's/ *$//')"; return 0; fi
  done
  return 1
}

# Finds fipsmodule.cnf for the OpenSSL binary $1 (prints the path). Looks next to the install, in OPENSSLDIR, in the files of the package that owns the binary,
# and in /etc/agantra-pki; when the package ships fips.so but no fipsmodule.cnf it makes one with "openssl fipsinstall" (own user: ~/.config/agantra-pki, root: /etc/agantra-pki).
find_fips_cnf() {
  local o="$1" prefix bin odir mdir c pkg fso d dest real
  real="$(readlink -f "$o" 2>/dev/null || echo "$o")"; bin="$(dirname "$o")"; prefix="$(cd "$bin/.." 2>/dev/null && pwd)"
  odir="$("$o" version -d 2>/dev/null | sed -n 's/^OPENSSLDIR: *"\(.*\)"/\1/p')"
  mdir="$("$o" version -m 2>/dev/null | sed -n 's/^MODULESDIR: *"\(.*\)"/\1/p')"
  for c in "$prefix/ssl/fipsmodule.cnf" "$prefix/etc/ssl/fipsmodule.cnf" "$bin/fipsmodule.cnf" "${odir:+$odir/fipsmodule.cnf}" "${odir:+$(dirname "$odir")/fipsmodule.cnf}" \
           /etc/agantra-pki/fipsmodule.cnf "${XDG_CONFIG_HOME:-$HOME/.config}/agantra-pki/fipsmodule.cnf" /etc/ssl/openssl4/fipsmodule.cnf /etc/openssl4/fipsmodule.cnf /etc/ssl/fipsmodule.cnf /usr/lib/ssl/fipsmodule.cnf /usr/local/ssl/fipsmodule.cnf; do
    [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return 0; }
  done
  if command -v dpkg >/dev/null 2>&1; then
    pkg="$(dpkg -S "$real" 2>/dev/null | head -1 | cut -d: -f1)"
    if [ -n "$pkg" ]; then
      c="$(dpkg -L "$pkg" 2>/dev/null | grep 'fipsmodule\.cnf$' | head -1)"; [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return 0; }
      fso="$(dpkg -L "$pkg" 2>/dev/null | grep '/fips\.so$' | head -1)"
    fi
  fi
  if [ -z "$fso" ]; then for d in "$mdir" "$prefix/lib/ossl-modules" "$prefix/lib64/ossl-modules" "$prefix/lib/x86_64-linux-gnu/ossl-modules" "$prefix/lib/aarch64-linux-gnu/ossl-modules"; do [ -n "$d" ] && [ -f "$d/fips.so" ] && { fso="$d/fips.so"; break; }; done; fi
  if [ -n "$fso" ] && [ -f "$fso" ]; then
    if [ "$(id -u)" = 0 ]; then dest=/etc/agantra-pki/fipsmodule.cnf; else dest="${XDG_CONFIG_HOME:-$HOME/.config}/agantra-pki/fipsmodule.cnf"; fi
    mkdir -p "$(dirname "$dest")" 2>/dev/null && "$o" fipsinstall -out "$dest" -module "$fso" >/dev/null 2>&1 && [ -s "$dest" ] && { echo "$dest"; return 0; }
  fi
  return 1
}

# The proof: version, FIPS provider active, ML-DSA sign + verify, ML-KEM key generation, ML-DSA inside the FIPS provider.
openssl_ready() {   # $1 = openssl binary; prints one line per check; returns 0 when ALL pass
  local o="$1" t fips ok_all=0 prefix cnf
  t="$(mktemp -d "${TMPDIR:-/tmp}/ossl-ready.XXXXXX")" || return 1
  local v; v="$("$o" version 2>/dev/null | head -1)"
  if ver_ok "$(ver_parts "$v")"; then row "$C_G" PASS "version" "$(echo "$v" | cut -d'(' -f1)"; else row "$C_R" FAIL "version" "${v:-not runnable} ($OSSL_MIN_MAJOR.$OSSL_MIN_MINOR.$OSSL_MIN_PATCH or newer is required for --openssl-source $OSSL_SOURCE)"; ok_all=1; fi
  prefix="$(cd "$(dirname "$o")/.." 2>/dev/null && pwd)"
  fips="$(find_fips_cnf "$o")"
  if [ -n "$fips" ]; then
    printf 'openssl_conf = openssl_init\n.include %s\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\nfips = fips_sect\nbase = base_sect\n[base_sect]\nactivate = 1\n' "$fips" > "$t/fips.cnf"
    if OPENSSL_CONF="$t/fips.cnf" "$o" list -providers -provider fips -provider base 2>&1 | grep -q 'fips'; then row "$C_G" PASS "FIPS provider" "active ($fips)"; else row "$C_R" FAIL "FIPS provider" "does not load with $fips"; ok_all=1; fips=""; fi
  elif [ "$OSSL_SOURCE" = system ]; then row "$C_Y" NOTE "FIPS provider" "no fipsmodule.cnf next to the distribution's OpenSSL: the FIPS quadrants (Q2 / Q4) need --openssl-source ppa or build"
  else row "$C_Y" WARN "FIPS provider" "no fipsmodule.cnf / fips.so found for this OpenSSL: the FIPS quadrants (Q2 / Q4) are not available with it; everything else works (trust install, signing, ML-DSA). Find it: sudo find / -name 'fipsmodule.cnf' -o -name fips.so 2>/dev/null"; fi
  echo hello > "$t/d.txt"
  if "$o" genpkey -algorithm ML-DSA-65 -out "$t/k.pem" >/dev/null 2>&1 && "$o" pkeyutl -sign -inkey "$t/k.pem" -rawin -in "$t/d.txt" -out "$t/s.bin" >/dev/null 2>&1 \
     && "$o" pkeyutl -verify -inkey "$t/k.pem" -rawin -in "$t/d.txt" -sigfile "$t/s.bin" >/dev/null 2>&1; then row "$C_G" PASS "ML-DSA" "ML-DSA-65 key, sign and verify (post-quantum signatures)"; else
    if [ "$OSSL_SOURCE" = system ]; then row "$C_Y" NOTE "ML-DSA" "not available in this OpenSSL (needs 3.5 or newer): Classic RSA / ECDSA certificates only; Quantum (ML-DSA) needs Ubuntu 26.04 or --openssl-source ppa"
    else row "$C_R" FAIL "ML-DSA" "ML-DSA-65 sign / verify failed"; ok_all=1; fi; fi
  if "$o" genpkey -algorithm ML-KEM-768 -out "$t/kem.pem" >/dev/null 2>&1 && [ -s "$t/kem.pem" ]; then row "$C_G" PASS "ML-KEM" "ML-KEM-768 key generation (post-quantum key exchange)"
  elif [ "$OSSL_SOURCE" = system ]; then row "$C_Y" NOTE "ML-KEM" "not available in this OpenSSL (needs 3.5 or newer)"
  else row "$C_R" FAIL "ML-KEM" "ML-KEM-768 key generation failed"; ok_all=1; fi
  if [ -n "$fips" ]; then
    if OPENSSL_CONF="$t/fips.cnf" "$o" genpkey -provider fips -propquery fips=yes -algorithm ML-DSA-65 -out "$t/kf.pem" >/dev/null 2>&1 && [ -s "$t/kf.pem" ]; then row "$C_G" PASS "ML-DSA in FIPS" "ML-DSA-65 key inside the FIPS provider"; else row "$C_Y" WARN "ML-DSA in FIPS" "not available inside the FIPS provider of this build"; fi
  fi
  rm -rf "$t"
  return $ok_all
}

build_openssl() {   # FULL build: FIPS, shared, headers, docs
  local v="$OSSL_VERSION" prefix base work jobs
  prefix="${OSSL_PREFIX:-$([ "$PLATFORM" = macos ] && echo /usr/local/openssl-$v || echo /opt/openssl-$v)}"
  base="https://github.com/openssl/openssl/releases/download/openssl-$v"
  jobs="${OSSL_JOBS:-$(ncpu)}"
  info "Building OpenSSL $v as a FULL build (FIPS provider, ML-DSA / ML-KEM, shared libraries, headers$([ "$OSSL_DOCS" = 1 ] && echo ', documentation')) into $prefix with $jobs job(s)."
  [ "$jobs" = 1 ] && warn "ONE CPU core: the compile can take over an hour."
  local missing=""
  have make || missing="make"; have perl || missing="$missing perl"; { have cc || have gcc; } || missing="$missing compiler"
  { have curl || have wget; } || missing="$missing curl"; have tar || missing="$missing tar"
  if [ -n "$missing" ]; then
    info "Build tools missing:$missing"
    case "$FAMILY" in
      debian) pkg_install build-essential perl curl ca-certificates tar gzip || return 1 ;;
      rhel)   pkg_install gcc make perl-core curl tar gzip >/dev/null 2>&1 || pkg_install gcc make perl perl-IPC-Cmd curl tar gzip || return 1 ;;
      suse)   pkg_install gcc make perl curl tar gzip || return 1 ;;
      macos)  warn "macOS: install the Xcode command line tools first:  xcode-select --install"; return 1 ;;
    esac
  fi
  if [ "$DRYRUN" = 1 ]; then
    dry "curl -fL -o openssl-$v.tar.gz $base/openssl-$v.tar.gz   (+ the .sha256 file, checked)"
    dry "./Configure --prefix=$prefix --openssldir=$prefix/ssl --libdir=lib enable-fips $([ "$OSSL_DOCS" = 0 ] && echo no-docs) -Wl,-rpath,$prefix/lib"
    dry "make -j$jobs && make install   (installs the FIPS module and writes fipsmodule.cnf)"
    dry "ln -sf $prefix/bin/openssl /usr/local/bin/openssl4"
    return 0
  fi
  work="$(mktemp -d "${TMPDIR:-/tmp}/pki-openssl.XXXXXX")" || return 1
  ( cd "$work" || exit 1
    if have curl; then curl -fL --retry 3 -o "openssl-$v.tar.gz" "$base/openssl-$v.tar.gz" && curl -fL --retry 3 -o "openssl-$v.tar.gz.sha256" "$base/openssl-$v.tar.gz.sha256"
    else wget -q -O "openssl-$v.tar.gz" "$base/openssl-$v.tar.gz" && wget -q -O "openssl-$v.tar.gz.sha256" "$base/openssl-$v.tar.gz.sha256"; fi ) \
    || { err "The download of OpenSSL $v failed (network, proxy, version?)."; rm -rf "$work"; return 1; }
  local want got
  want="$(awk '{print $1}' "$work/openssl-$v.tar.gz.sha256" | head -1 | tr 'A-F' 'a-f')"; got="$(sha256_of "$work/openssl-$v.tar.gz")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then err "SHA-256 of the tarball does not match the release page (wanted '$want', got '$got'). Nothing was built."; rm -rf "$work"; return 1; fi
  ok "OpenSSL $v tarball: SHA-256 matches the official release page."
  local doc_flag=""; [ "$OSSL_DOCS" = 0 ] && doc_flag="no-docs"
  ( cd "$work" && tar xzf "openssl-$v.tar.gz" && cd "openssl-$v" || exit 1
    # shellcheck disable=SC2086
    ./Configure --prefix="$prefix" --openssldir="$prefix/ssl" --libdir=lib enable-fips $doc_flag "-Wl,-rpath,$prefix/lib" > "$work/configure.log" 2>&1 || { tail -6 "$work/configure.log"; exit 1; }
    make -j"$jobs" > "$work/make.log" 2>&1 || { tail -8 "$work/make.log"; exit 1; }
    if [ -w "$(dirname "$prefix")" ] || [ "$(id -u)" = 0 ]; then make install > "$work/install.log" 2>&1 || { tail -8 "$work/install.log"; exit 1; }
    else sudo make install > "$work/install.log" 2>&1 || { tail -8 "$work/install.log"; exit 1; }; fi ) \
    || { err "Building OpenSSL $v failed."; rm -rf "$work"; return 1; }
  rm -rf "$work"
  OSSL_PREFIX="$prefix"
  ok "OpenSSL $v installed in $prefix (the system openssl is untouched)."
  mkdir -p /usr/local/bin 2>/dev/null; priv ln -sf "$prefix/bin/openssl" /usr/local/bin/openssl4 && info "Link: /usr/local/bin/openssl4 -> $prefix/bin/openssl"
  return 0
}

# PATH: the bin folder of the OpenSSL 4 found/built goes FIRST on the PATH of login shells, so that "openssl version" says 4.x in a NEW terminal.
add_openssl_path() {
  [ "$ADDPATH" = 1 ] || { info "PATH not changed (--no-path). Use the full path or  openssl4."; return 0; }
  local bin; bin="$(dirname "$OPENSSL")"
  case "$bin" in /usr/bin|/bin) return 0 ;; esac
  local line="export PATH=\"$bin:\$PATH\"   # added by Install-DevEnvironment.sh (OpenSSL 4)"
  if [ "$DRYRUN" = 1 ]; then dry "write /etc/profile.d/openssl4.sh: $line"; return 0; fi
  if [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; then
    printf '%s\n' "$line" | priv tee /etc/profile.d/openssl4.sh >/dev/null && { ok "PATH: $bin is first in /etc/profile.d/openssl4.sh (new terminals; or now: source /etc/profile.d/openssl4.sh)"; return 0; }
  fi
  local rc
  for rc in "$HOME/.profile" "$HOME/.bashrc"; do
    [ -f "$rc" ] || [ "$rc" = "$HOME/.profile" ] || continue
    grep -q 'Install-DevEnvironment.sh (OpenSSL 4)' "$rc" 2>/dev/null || printf '\n%s\n' "$line" >> "$rc"
  done
  ok "PATH: $bin is first in ~/.profile and ~/.bashrc (new terminals; or now: export PATH=\"$bin:\$PATH\")"
}

# the PPA of the author: nicko-su-nginx and nicko-su-openssl4 for Ubuntu 24.04 (noble) and 26.04 (resolute)
PPA_ADDED=0
add_ppa() {
  [ "$PPA_ADDED" = 1 ] && return 0
  [ "$FAMILY" = debian ] || { warn "The PPA is for Ubuntu (24.04 / 26.04) only; this system is $DIST_NAME."; return 1; }
  if [ -r /etc/os-release ] && ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then warn "$DIST_NAME is not Ubuntu: a Launchpad PPA is not supported here."; return 1; fi
  have add-apt-repository || pkg_install software-properties-common ca-certificates >/dev/null 2>&1
  info "Adding the PPA $PPA (nicko-su-nginx 1.31.6, nicko-su-openssl4 4.0.3 for noble and resolute)"
  priv add-apt-repository -y "$PPA" || { err "add-apt-repository $PPA failed (network? Launchpad?)."; return 1; }
  [ "$DRYRUN" = 1 ] || { priv env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; APT_UPDATED=1; }
  PPA_ADDED=1; return 0
}
install_openssl() {
  local what
  case "$OSSL_SOURCE" in
    system)
      if find_openssl; then ok "OpenSSL: $OSSL_TEXT already installed at $OPENSSL (the distribution's)"
      else
        info "Installing the OpenSSL of the distribution"
        case "$FAMILY" in debian) pkg_any "openssl libssl-dev" "openssl" ;; rhel) pkg_any "openssl openssl-devel" "openssl" ;; suse) pkg_any "openssl libopenssl-devel" "openssl" ;; macos) pkg_any "openssl@3" ;; esac
        [ "$DRYRUN" = 1 ] && return 0
        find_openssl || { err "No OpenSSL 3.0.0 or newer after the installation."; return 1; }
      fi ;;
    ppa)
      if find_openssl; then ok "OpenSSL: $OSSL_TEXT already installed at $OPENSSL"
      else
        add_ppa || return 1
        pkg_install "$PPA_OPENSSL_PKG" || { err "Package $PPA_OPENSSL_PKG could not be installed from $PPA."; return 1; }
        [ "$DRYRUN" = 1 ] && return 0
        find_openssl || { err "$PPA_OPENSSL_PKG is installed but no OpenSSL 4.0.1+ binary was found (dpkg -L $PPA_OPENSSL_PKG | grep bin/openssl)."; return 1; }
      fi ;;
    build)
      if find_openssl; then ok "OpenSSL: $OSSL_TEXT already installed at $OPENSSL"
      else
        warn "No OpenSSL 4.0.1 or newer found."
        if [ "$DRYRUN" = 1 ] || confirm "Build OpenSSL $OSSL_VERSION (full, FIPS + quantum-safe) from the official source release now?"; then
          build_openssl || return 1
          [ "$DRYRUN" = 1 ] && return 0
          find_openssl || { err "OpenSSL was built but cannot be found."; return 1; }
        else return 1; fi
      fi ;;
  esac
  [ "$OSSL_SOURCE" = system ] || add_openssl_path
  info "Proving $OPENSSL"
  openssl_ready "$OPENSSL"
}

install_nginx() {
  # YOUR nginx from YOUR PPA. Ubuntu only. The binary package name is checked with apt-cache; "nginx" from the PPA is the fallback.
  [ "$FAMILY" = debian ] || { warn "nginx from the PPA: Ubuntu 24.04 / 26.04 only (this is $DIST_NAME). Skipped."; return 2; }
  add_ppa || return 1
  local pkg="$NGINX_PKG"
  if [ "$DRYRUN" != 1 ] && ! apt-cache policy "$pkg" 2>/dev/null | grep -q 'Candidate: [^(]'; then
    if apt-cache policy nginx 2>/dev/null | grep -q "$(echo "${PPA#ppa:}" | cut -d/ -f1)"; then pkg="nginx"; info "package $NGINX_PKG not listed; the PPA offers nginx"
    else err "Neither $NGINX_PKG nor an nginx from $PPA is listed by apt (apt-cache policy). Use --nginx-package NAME."; return 1; fi
  fi
  info "Installing nginx: $pkg"
  pkg_install "$pkg" || return 1
  return 0
}

# ------------------------------------------------------------------------------------------------ the other components
comp_present() {   # 0 when the component is already there
  case "$1" in
    tools)   have curl && have tar && have gzip && have unzip && have perl && have make && { have cc || have gcc; } ;;
    7zip)    have 7zz || have 7z || have 7za ;;
    openssl) find_openssl ;;
    nginx)   have nginx || [ -x /usr/sbin/nginx ] ;;
    git) have git ;; python) have python3 ;; go) have go ;; node) have node ;; php) have php ;; dotnet) have dotnet ;; pwsh) have pwsh ;;
  esac
}
comp_version() {
  case "$1" in
    tools) echo "$(have curl && curl --version | head -1 | cut -d' ' -f1-2)" ;;
    7zip) echo "$( (7zz 2>/dev/null || 7z 2>/dev/null || 7za 2>/dev/null) </dev/null | sed -n '1,3p' | grep -m1 '7-Zip' | cut -c1-60)" ;;
    openssl) echo "$OSSL_TEXT $OPENSSL" ;;
    nginx) { (nginx -v 2>&1 || /usr/sbin/nginx -v 2>&1) | sed 's/.*: //'
             if dpkg -s "$NGINX_PKG" >/dev/null 2>&1; then echo "  [PPA package $NGINX_PKG]"; else echo "  [NOT from the PPA: $NGINX_PKG is not installed; a different nginx is left alone - remove it first to switch]"; fi; } | tr -d '\n'; echo ;;
    git) git --version ;; python) python3 --version ;; go) go version ;; node) node --version ;; php) php --version | head -1 ;;
    dotnet) dotnet --version ;; pwsh) pwsh --version ;;
  esac 2>/dev/null
}

install_tools() {
  case "$FAMILY" in
    debian) pkg_install curl tar gzip unzip ca-certificates build-essential perl ;;
    rhel)   pkg_install curl tar gzip unzip ca-certificates gcc make perl-core >/dev/null 2>&1 || pkg_install curl tar gzip unzip ca-certificates gcc make perl perl-IPC-Cmd ;;
    suse)   pkg_install curl tar gzip unzip ca-certificates gcc make perl ;;
    macos)  have brew || { warn "Homebrew is not installed (https://brew.sh): needed for the macOS tools."; return 1; }; pkg_install curl unzip perl ;;
  esac
}
install_7zip() {
  case "$FAMILY" in
    debian) pkg_any "7zip" "p7zip-full" ;;
    rhel)   pkg_any "7zip" "p7zip p7zip-plugins" || { pkg_install epel-release >/dev/null 2>&1; pkg_any "7zip" "p7zip p7zip-plugins"; } ;;
    suse)   pkg_any "7zip" "p7zip-full" "p7zip" ;;
    macos)  pkg_any "sevenzip" "p7zip" ;;
  esac
}
install_pwsh_release() {
  local arch os tag file url hashes want got dir
  case "$ARCH" in x86_64|amd64) arch=x64 ;; aarch64|arm64) arch=arm64 ;; *) warn "pwsh: architecture $ARCH not handled"; return 1 ;; esac
  os=linux; [ "$PLATFORM" = macos ] && os=osx
  have curl || return 1
  # the release redirect first (not rate limited), the API as a fallback
  tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/PowerShell/PowerShell/releases/latest 2>/dev/null | sed -n 's#.*/releases/tag/v\{0,1\}\([0-9][^/]*\)$#\1#p')"
  [ -n "$tag" ] || tag="$(curl -fsSL https://api.github.com/repos/PowerShell/PowerShell/releases/latest 2>/dev/null | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$tag" ] || { warn "pwsh: could not read the latest release (network, proxy, GitHub rate limit)."; return 1; }
  file="powershell-$tag-$os-$arch.tar.gz"; url="https://github.com/PowerShell/PowerShell/releases/download/v$tag/$file"
  if [ "$DRYRUN" = 1 ]; then dry "download $url, check it against hashes.sha256 of that release, unpack to /opt/microsoft/powershell/$tag, link /usr/local/bin/pwsh"; return 0; fi
  local w; w="$(mktemp -d "${TMPDIR:-/tmp}/pwsh.XXXXXX")"
  curl -fL --retry 3 -o "$w/$file" "$url" && curl -fsSL -o "$w/hashes.sha256" "https://github.com/PowerShell/PowerShell/releases/download/v$tag/hashes.sha256" || { rm -rf "$w"; return 1; }
  # hashes.sha256 of the release: the layout differs between releases ("<hash> *<file>", "<hash>  <file>", CR LF line ends, BSD style "SHA256 (<file>) = <hash>").
  # Take the line that names OUR file exactly (not a longer name such as <file>.sig) and read the first 64-hex-digit word in it.
  local fre; fre="$(printf '%s' "$file" | sed 's/[.]/\\./g')"
  want="$(tr -d '\r' < "$w/hashes.sha256" | grep -E "(^|[^A-Za-z0-9._-])${fre}([^A-Za-z0-9._-]|\$)" | grep -oiE '[0-9a-f]{64}' | head -1 | tr 'A-F' 'a-f')"
  got="$(sha256_of "$w/$file")"
  if [ -z "$want" ]; then
    err "pwsh: $file is not listed in hashes.sha256 of release v$tag (lines that mention linux-x64 follow)."; grep -i "linux-x64" "$w/hashes.sha256" | tr -d '\r' | head -5 >&2
    rm -rf "$w"; return 1
  fi
  if [ "$want" != "$got" ]; then
    err "pwsh: SHA-256 of the download does not match hashes.sha256 of the release (not installed)."; echo "  expected: $want" >&2; echo "  got     : $got" >&2; echo "  file    : $file ($(wc -c < "$w/$file") bytes)" >&2
    rm -rf "$w"; return 1
  fi
  dir="/opt/microsoft/powershell/$tag"; [ "$PLATFORM" = macos ] && dir="/usr/local/microsoft/powershell/$tag"
  priv mkdir -p "$dir" && priv tar xzf "$w/$file" -C "$dir" && priv chmod +x "$dir/pwsh" && priv ln -sf "$dir/pwsh" /usr/local/bin/pwsh
  rm -rf "$w"
  case "$FAMILY" in debian) pkg_any "libicu-dev" >/dev/null 2>&1 ;; rhel|suse) pkg_any "libicu" >/dev/null 2>&1 ;; esac
  have pwsh
}
install_pwsh() {
  # 1. the official release archive, checksum verified.  2. when that fails and the .NET SDK is installed: the official NuGet package "PowerShell" as a .NET tool
  #    (NuGet verifies the package itself).  No apt package called "pwsh" exists on Ubuntu.
  install_pwsh_release && return 0
  if [ "$DRYRUN" != 1 ] && have dotnet; then
    warn "pwsh: the release archive could not be used. Trying the .NET tool package (dotnet tool install PowerShell) ..."
    local td=/opt/microsoft/powershell-dotnet
    priv mkdir -p "$td" && { priv dotnet tool install --tool-path "$td" PowerShell || priv dotnet tool update --tool-path "$td" PowerShell; } \
      && priv ln -sf "$td/pwsh" /usr/local/bin/pwsh && have pwsh && return 0
  fi
  return 1
}
install_component() {
  case "$1" in
    tools) install_tools ;; 7zip) install_7zip ;; openssl) install_openssl ;; nginx) install_nginx ;; pwsh) install_pwsh ;;
    git)    pkg_any "git" ;;
    python) case "$FAMILY" in macos) pkg_any "python" ;; debian) pkg_any "python3 python3-pip python3-venv" "python3" ;; *) pkg_any "python3 python3-pip" "python3" ;; esac ;;
    go)     case "$FAMILY" in debian) pkg_any "golang-go" "golang" ;; suse|macos) pkg_any "go" "golang" ;; *) pkg_any "golang" "go" ;; esac ;;
    node)   case "$FAMILY" in suse) pkg_any "nodejs-default npm-default" "nodejs npm" ;; macos) pkg_any "node" ;; *) pkg_any "nodejs npm" "nodejs" ;; esac ;;
    php)    case "$FAMILY" in suse) pkg_any "php8-cli" "php-cli" "php" ;; macos) pkg_any "php" ;; *) pkg_any "php-cli" "php" ;; esac ;;
    dotnet) case "$FAMILY" in macos) have brew && brew install --cask dotnet-sdk ;; *) pkg_any "dotnet-sdk-10.0" "dotnet-sdk-9.0" "dotnet-sdk-8.0" ;; esac ;;
  esac
}

# ================================================================================================ main
echo "============================================================"
echo "Install-DevEnvironment.sh $VERSION   $DIST_NAME   family: $FAMILY"
echo "============================================================"
[ "$DRYRUN" = 1 ] && info "dry run: nothing is changed"
info "components: $SELECT"

if [ "$CHECK" = 1 ]; then
  echo "SCAN"
  for c in $SELECT; do
    if comp_present "$c"; then row "$C_G" PASS "$c" "$(comp_version "$c")"; else row "$C_Y" MISS "$c" "not found"; fi
  done
  echo
  if want openssl || [ -n "$OPENSSL" ]; then
    if find_openssl; then echo "OPENSSL READINESS  ($OPENSSL)"; openssl_ready "$OPENSSL"; rc=$?; echo; [ $rc -eq 0 ] && echo "READY: OpenSSL $OSSL_TEXT (source: $OSSL_SOURCE) passes every check that applies to it." || echo "NOT READY: see above."; exit $([ $rc -eq 0 ] && echo 0 || echo 4)
    else echo "NOT READY: no OpenSSL $OSSL_MIN_MAJOR.$OSSL_MIN_MINOR.$OSSL_MIN_PATCH or newer for --openssl-source $OSSL_SOURCE (run: ./Install-DevEnvironment.sh --yes --only openssl [--openssl-source ppa|build])."; exit 4; fi
  fi
  exit 0
fi

FAILED=""; DONE_LIST=""; SKIPPED=""
for c in $SELECT; do
  echo
  if [ "$c" != openssl ] && comp_present "$c"; then ok "$c: already installed ($(comp_version "$c"))"; DONE_LIST="$DONE_LIST $c"; continue; fi
  info "Installing: $c"
  install_component "$c"; irc=$?
  if [ "$irc" = 2 ]; then info "$c: skipped (not available on this system)"; SKIPPED="$SKIPPED $c"; continue; fi
  if [ "$irc" = 0 ]; then
    if [ "$DRYRUN" = 1 ]; then DONE_LIST="$DONE_LIST $c"; continue; fi
    if [ "$c" = openssl ] || comp_present "$c"; then ok "$c: installed and verified"; DONE_LIST="$DONE_LIST $c"; else warn "$c: the package manager finished but the program is still not on PATH"; FAILED="$FAILED $c"; fi
  else
    warn "$c: could not be installed"; FAILED="$FAILED $c"
  fi
done
echo; echo "SUMMARY"
for c in $SELECT; do case " $FAILED " in *" $c "*) row "$C_R" FAIL "$c" "not installed" ;; *) case " $SKIPPED " in *" $c "*) row "$C_Y" SKIP "$c" "not available on this system" ;; *) row "$C_G" PASS "$c" "ok" ;; esac ;; esac; done
if [ -n "$FAILED" ]; then
  echo; case " $FAILED " in *" openssl "*) err "OpenSSL 4 is not ready. See above."; exit 4 ;; esac
  err "Not installed:$FAILED"; exit 6
fi
echo; ok "Developer environment ready.$(want openssl && echo ' OpenSSL: '$OPENSSL)"
exit 0
