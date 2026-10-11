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
#   openssl   OpenSSL 4 as a FULL build: FIPS provider (fipsmodule.cnf), native ML-DSA / ML-KEM (post-quantum), shared
#             libraries, headers, documentation. Built from the official source release (checksum verified) when the
#             machine has no OpenSSL 4.0.1 or newer. Proven afterwards: FIPS provider active, ML-DSA sign / verify,
#             ML-KEM key generation, ML-DSA inside the FIPS provider.
#   git, python, go, node, php, dotnet, pwsh      developer tools, installed from the distribution (pwsh: GitHub release)
#
# Platforms: Ubuntu / Debian, RHEL / CentOS Stream / Rocky / Oracle / Alma, SLES / openSUSE, macOS (Apple Silicon, Intel).
# Written for bash 3.2 (macOS) and newer. UNBLOCK / UNLOCK of its own folder at every start; --unblock does only that.
# Manual: docs/Install-DevEnvironment-MANUAL.txt        Help: ./Install-DevEnvironment.sh --help
# ============================================================

VERSION="4.9.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
OSSL_MIN_MAJOR=4; OSSL_MIN_MINOR=0; OSSL_MIN_PATCH=1
OSSL_VERSION="4.0.3"                       # what is built; --openssl-version changes it
ALL_COMPONENTS="tools 7zip openssl git python go node php dotnet pwsh"

usage() {
cat <<'EOF'
============================================================
 Install-DevEnvironment.sh - Linux and macOS developer bootstrap
 Version 4.9.0
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs/Install-DevEnvironment-MANUAL.txt     Windows sibling: Install-DevEnvironment.ps1

WHAT IT DOES
  Installs what is MISSING, verifies each component, and prints a summary. Nothing that is already there is replaced.
    tools      curl, tar, gzip, unzip, ca-certificates, compiler, make, perl
    7zip       7-Zip: the archive tool of the .certpacked transport (AES-256 zip, 7z)
    openssl    OpenSSL 4.0.1 or newer as a FULL build, never a stripped one: FIPS provider with fipsmodule.cnf, native ML-DSA
               and ML-KEM (quantum-safe), shared libraries, headers, documentation. Built from the official source release
               (the tarball is checked against the SHA-256 of the same release page) into --openssl-prefix. The system openssl
               is NOT replaced; a link  openssl4  is put in /usr/local/bin. Then PROVEN: version, FIPS provider active,
               ML-DSA-65 sign + verify, ML-KEM-768 key generation, ML-DSA inside the FIPS provider.
    git python go node php dotnet pwsh     developer tools (distribution packages; pwsh from the PowerShell GitHub release)

USAGE
  ./Install-DevEnvironment.sh --check                      what is installed, OpenSSL readiness; changes nothing
  ./Install-DevEnvironment.sh --yes                        install everything that is missing
  ./Install-DevEnvironment.sh --yes --only openssl,7zip    only these (what the PKI scripts need)
  ./Install-DevEnvironment.sh --yes --skip php,dotnet      everything except these
  ./Install-DevEnvironment.sh --dry-run --only openssl     show the commands, run nothing
  ./Install-DevEnvironment.sh --unblock                    UNBLOCK + UNLOCK this folder, then stop

OPTIONS
  --only LIST            Comma-separated components (above). Default: all.      --skip LIST   All except these.
  --check                Scan only: components found, OpenSSL readiness. Exit 0 when OpenSSL is ready, 4 when not.
  --yes, -y              Do not ask. Needed when there is no terminal.         --dry-run   Print system-changing commands.
  --openssl-prefix DIR   Where OpenSSL is installed. Default /opt/openssl-4.0.3 (macOS: /usr/local/openssl-4.0.3).
  --openssl-version V    Build this version instead of 4.0.3 (4.0.1 or newer).
  --no-path              Do not put the OpenSSL 4 bin folder on the PATH (default: it is put FIRST on the PATH of every login shell:
                         /etc/profile.d/openssl4.sh with sudo, else a marked block in ~/.profile and ~/.bashrc).
  --openssl-no-docs      Skip the manual pages (shorter build). The cryptography is still the FULL build.
  --openssl-jobs N       Parallel compile jobs. Default: the number of CPU cores.
  --unblock              UNBLOCK (macOS quarantine mark) and UNLOCK (read-only, immutable, locked flags) this script's
                         folder, children and recursive, then stop. The same is done silently at every start.
  --version              Show the version.                                     --help, -h   This text.

OPENSSL BUILD TIME  (be warned)
  A full build compiles hundreds of files. About 5 minutes on 8 cores, 15 to 25 on 2 cores, and over an hour on ONE core
  (measured: more than 30 minutes without finishing on a 1-core VM). Use a machine with cores, or --openssl-no-docs.

PLATFORMS  (family: package manager)
  Ubuntu, Debian: apt     RHEL, CentOS Stream, Rocky, Oracle, Alma: dnf (yum)     SLES, openSUSE: zypper     macOS: Homebrew
  macOS needs the Xcode command line tools (xcode-select --install) for the OpenSSL build and Homebrew for the others.

EXIT CODES   0 ok   1 error   2 platform not supported   4 OpenSSL not ready   6 a component could not be installed

LIMITATIONS
  * Needs root (or sudo) to install packages and into /opt. Not needed for --check and --unblock.
  * Package names differ between distributions and versions; each component is tried with the usual names and then
    verified, never assumed. dotnet, node, go and php are best effort (your distribution may not ship a current version).
  * Tested on Ubuntu 24.04 (real apt). The other platforms are tested only by simulation (--dry-run). The OpenSSL source build
    was NOT completed here (a 1-core VM); the Configure step, the download, the checksum and the readiness checks were tested.
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
ONLY=""; SKIP=""; CHECK=0; YES=0; DRYRUN=0; OSSL_PREFIX=""; OSSL_DOCS=1; OSSL_JOBS=""; UNBLOCK=0; ADDPATH=1
need_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "Option $1 needs a value. See --help." 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --version) echo "Install-DevEnvironment.sh $VERSION"; exit 0 ;;
    --only) need_value "$@"; ONLY="$2"; shift 2 ;;            --only=*) ONLY="${1#*=}"; shift ;;
    --skip) need_value "$@"; SKIP="$2"; shift 2 ;;            --skip=*) SKIP="${1#*=}"; shift ;;
    --check) CHECK=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --dry-run) DRYRUN=1; shift ;;
    --openssl-prefix) need_value "$@"; OSSL_PREFIX="$2"; shift 2 ;; --openssl-prefix=*) OSSL_PREFIX="${1#*=}"; shift ;;
    --openssl-version) need_value "$@"; OSSL_VERSION="$2"; shift 2 ;; --openssl-version=*) OSSL_VERSION="${1#*=}"; shift ;;
    --openssl-no-docs) OSSL_DOCS=0; shift ;;
    --no-path) ADDPATH=0; shift ;;
    --openssl-jobs) need_value "$@"; OSSL_JOBS="$2"; shift 2 ;; --openssl-jobs=*) OSSL_JOBS="${1#*=}"; shift ;;
    --unblock) UNBLOCK=1; shift ;;
    *) die "Unknown option $1. See ./Install-DevEnvironment.sh --help" 1 ;;
  esac
done

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
  local c v p
  for c in "$OSSL_PREFIX/bin/openssl" $(command -v openssl4 2>/dev/null) $(command -v openssl 2>/dev/null) \
           /opt/openssl-4*/bin/openssl /usr/local/openssl-4*/bin/openssl "$HOME"/.local/openssl-4*/bin/openssl \
           /opt/homebrew/opt/openssl@4/bin/openssl /usr/local/opt/openssl@4/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    v="$("$c" version 2>/dev/null | head -1)"; p="$(ver_parts "$v")"; [ -n "$p" ] || continue
    if ver_ok "$p"; then OPENSSL="$c"; OSSL_TEXT="$(echo "$v" | cut -d'(' -f1 | sed 's/ *$//')"; return 0; fi
  done
  return 1
}

# The proof: version, FIPS provider active, ML-DSA sign + verify, ML-KEM key generation, ML-DSA inside the FIPS provider.
openssl_ready() {   # $1 = openssl binary; prints one line per check; returns 0 when ALL pass
  local o="$1" t fips ok_all=0 prefix cnf
  t="$(mktemp -d "${TMPDIR:-/tmp}/ossl-ready.XXXXXX")" || return 1
  local v; v="$("$o" version 2>/dev/null | head -1)"
  if ver_ok "$(ver_parts "$v")"; then row "$C_G" PASS "version" "$(echo "$v" | cut -d'(' -f1)"; else row "$C_R" FAIL "version" "${v:-not runnable} (4.0.1 or newer is required)"; ok_all=1; fi
  prefix="$(cd "$(dirname "$o")/.." 2>/dev/null && pwd)"
  fips=""; for cnf in "$prefix/ssl/fipsmodule.cnf" "$prefix/etc/ssl/fipsmodule.cnf" "$(dirname "$o")/fipsmodule.cnf"; do [ -f "$cnf" ] && { fips="$cnf"; break; }; done
  if [ -n "$fips" ]; then
    printf 'openssl_conf = openssl_init\n.include %s\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\nfips = fips_sect\nbase = base_sect\n[base_sect]\nactivate = 1\n' "$fips" > "$t/fips.cnf"
    if OPENSSL_CONF="$t/fips.cnf" "$o" list -providers -provider fips -provider base 2>&1 | grep -q 'fips'; then row "$C_G" PASS "FIPS provider" "active ($fips)"; else row "$C_R" FAIL "FIPS provider" "does not load with $fips"; ok_all=1; fips=""; fi
  else row "$C_R" FAIL "FIPS provider" "fipsmodule.cnf not found (the build needs enable-fips; Windows: Install-DevEnvironment.ps1)"; ok_all=1; fi
  echo hello > "$t/d.txt"
  if "$o" genpkey -algorithm ML-DSA-65 -out "$t/k.pem" >/dev/null 2>&1 && "$o" pkeyutl -sign -inkey "$t/k.pem" -rawin -in "$t/d.txt" -out "$t/s.bin" >/dev/null 2>&1 \
     && "$o" pkeyutl -verify -inkey "$t/k.pem" -rawin -in "$t/d.txt" -sigfile "$t/s.bin" >/dev/null 2>&1; then row "$C_G" PASS "ML-DSA" "ML-DSA-65 key, sign and verify (post-quantum signatures)"; else row "$C_R" FAIL "ML-DSA" "ML-DSA-65 sign / verify failed"; ok_all=1; fi
  if "$o" genpkey -algorithm ML-KEM-768 -out "$t/kem.pem" >/dev/null 2>&1 && [ -s "$t/kem.pem" ]; then row "$C_G" PASS "ML-KEM" "ML-KEM-768 key generation (post-quantum key exchange)"; else row "$C_R" FAIL "ML-KEM" "ML-KEM-768 key generation failed"; ok_all=1; fi
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

install_openssl() {
  if find_openssl; then ok "OpenSSL: $OSSL_TEXT already installed at $OPENSSL"
  else
    warn "No OpenSSL 4.0.1 or newer found."
    if [ "$DRYRUN" = 1 ] || confirm "Build OpenSSL $OSSL_VERSION (full, FIPS + quantum-safe) from the official source release now?"; then
      build_openssl || return 1
      [ "$DRYRUN" = 1 ] && return 0
      find_openssl || { err "OpenSSL was built but cannot be found."; return 1; }
    else return 1; fi
  fi
  add_openssl_path
  info "Proving $OPENSSL"
  openssl_ready "$OPENSSL"
}

# ------------------------------------------------------------------------------------------------ the other components
comp_present() {   # 0 when the component is already there
  case "$1" in
    tools)   have curl && have tar && have gzip && have unzip && have perl && have make && { have cc || have gcc; } ;;
    7zip)    have 7zz || have 7z || have 7za ;;
    openssl) find_openssl ;;
    git) have git ;; python) have python3 ;; go) have go ;; node) have node ;; php) have php ;; dotnet) have dotnet ;; pwsh) have pwsh ;;
  esac
}
comp_version() {
  case "$1" in
    tools) echo "$(have curl && curl --version | head -1 | cut -d' ' -f1-2)" ;;
    7zip) echo "$( (7zz 2>/dev/null || 7z 2>/dev/null || 7za 2>/dev/null) </dev/null | sed -n '1,3p' | grep -m1 '7-Zip' | cut -c1-60)" ;;
    openssl) echo "$OSSL_TEXT $OPENSSL" ;;
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
install_pwsh() {
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
  want="$(grep " $file\$" "$w/hashes.sha256" | awk '{print $1}' | tr 'A-F' 'a-f')"; got="$(sha256_of "$w/$file")"
  [ -n "$want" ] && [ "$want" = "$got" ] || { err "pwsh: SHA-256 does not match hashes.sha256 of the release."; rm -rf "$w"; return 1; }
  dir="/opt/microsoft/powershell/$tag"; [ "$PLATFORM" = macos ] && dir="/usr/local/microsoft/powershell/$tag"
  priv mkdir -p "$dir" && priv tar xzf "$w/$file" -C "$dir" && priv chmod +x "$dir/pwsh" && priv ln -sf "$dir/pwsh" /usr/local/bin/pwsh
  rm -rf "$w"
  case "$FAMILY" in debian) pkg_any "libicu-dev" >/dev/null 2>&1 ;; rhel|suse) pkg_any "libicu" >/dev/null 2>&1 ;; esac
  have pwsh
}
install_component() {
  case "$1" in
    tools) install_tools ;; 7zip) install_7zip ;; openssl) install_openssl ;; pwsh) install_pwsh ;;
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
    if find_openssl; then echo "OPENSSL READINESS  ($OPENSSL)"; openssl_ready "$OPENSSL"; rc=$?; echo; [ $rc -eq 0 ] && echo "READY: OpenSSL 4 with FIPS and quantum-safe algorithms." || echo "NOT READY: see above."; exit $([ $rc -eq 0 ] && echo 0 || echo 4)
    else echo "NOT READY: no OpenSSL 4.0.1 or newer on this machine (run: ./Install-DevEnvironment.sh --yes --only openssl)."; exit 4; fi
  fi
  exit 0
fi

FAILED=""; DONE_LIST=""
for c in $SELECT; do
  echo
  if [ "$c" != openssl ] && comp_present "$c"; then ok "$c: already installed ($(comp_version "$c"))"; DONE_LIST="$DONE_LIST $c"; continue; fi
  info "Installing: $c"
  if install_component "$c"; then
    if [ "$DRYRUN" = 1 ]; then DONE_LIST="$DONE_LIST $c"; continue; fi
    if [ "$c" = openssl ] || comp_present "$c"; then ok "$c: installed and verified"; DONE_LIST="$DONE_LIST $c"; else warn "$c: the package manager finished but the program is still not on PATH"; FAILED="$FAILED $c"; fi
  else
    warn "$c: could not be installed"; FAILED="$FAILED $c"
  fi
done
echo; echo "SUMMARY"
for c in $SELECT; do case " $FAILED " in *" $c "*) row "$C_R" FAIL "$c" "not installed" ;; *) row "$C_G" PASS "$c" "ok" ;; esac; done
if [ -n "$FAILED" ]; then
  echo; case " $FAILED " in *" openssl "*) err "OpenSSL 4 is not ready. See above."; exit 4 ;; esac
  err "Not installed:$FAILED"; exit 6
fi
echo; ok "Developer environment ready.$(want openssl && echo ' OpenSSL: '$OPENSSL' (use  openssl4  or the full path).')"
exit 0
