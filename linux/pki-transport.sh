#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# pki-transport.sh - DESTINATION script for Linux and macOS:
#   unpack a .certpacked (made by PkiTransport.ps1 -Pack) and install the CA certificates in the SYSTEM
#   certificate store. Nothing else: no PKI is built here.
#
# Written for bash 3.2 (the bash of macOS) and newer: no associative arrays, no ${var,,}, no mapfile.
# Platforms: Ubuntu / Debian, RHEL / CentOS Stream / Rocky / Oracle / Alma Linux, SLES / openSUSE (Leap, Tumbleweed),
#            macOS (Apple Silicon M2 / M4 and Intel). Other Linux: --store-dir and --update-cmd.
# Manual : docs/PkiTransport-MANUAL.txt        Help: ./pki-transport.sh --help
# ============================================================

VERSION="4.9.5-phaseC"
PREFIX_NAME="agantra-pki-"                 # every file this script puts in the system store starts with this
OSSL_MIN_MAJOR=4; OSSL_MIN_MINOR=0; OSSL_MIN_PATCH=1
OSSL_BUILD_VERSION="4.0.3"                 # the version --install-openssl builds
OSSL_TESTED="4.0.1 to 4.0.3"
TAB="$(printf '\t')"

usage() {
cat <<'EOF'
============================================================
 pki-transport.sh - DESTINATION script for Linux and macOS
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs/PkiTransport-MANUAL.txt     Help: ./pki-transport.sh --help

WHAT IT DOES  (and nothing else)
  1. SCAN         the platform, privileges, OpenSSL 4.0.1+, the certificate-store tools, an archive tool.
  2. PREPARE      installs what is missing: the certificate-store tooling of your Linux, 7-Zip (for AES-256 zip and
                  7z packages), and - with your consent - OpenSSL 4 built from the official source release.
  3. UNPACK       the .certpacked (a password-protected zip or 7z; the extension says nothing, the first bytes do),
                  checks the SHA-256 of every file, writes what you select to a folder.
  4. INSTALL      the CA certificates in the SYSTEM certificate store of this machine (Linux: the ca-certificates
                  store of your distribution; macOS: the System keychain), then proves with OpenSSL 4 that the
                  chains verify against it.

USAGE
  ./pki-transport.sh --package dev.certpacked                         unpack the CA certificates, install the roots
  ./pki-transport.sh --package dev.certpacked --no-trust              unpack only
  ./pki-transport.sh --package dev.certpacked --extract roots         only the roots
  ./pki-transport.sh --package dev.certpacked --extract intermediates only the DV / OV / EV CAs
  ./pki-transport.sh --package dev.certpacked --extract ca,leafcerts  CAs and the leaf certificates
  ./pki-transport.sh --package dev.certpacked --extract fullchain     everything the package holds
  ./pki-transport.sh --package dev.certpacked --extract leafcerts --leaf 'www*' --no-trust
  ./pki-transport.sh --package dev.certpacked --list                  what is inside; nothing written
  ./pki-transport.sh --check                                          the scan only
  ./pki-transport.sh --package dev.certpacked --remove-trust          take the package's CAs out of the store

OPTIONS
  --package FILE        The .certpacked.                                          (also: the first plain argument)
  --password TEXT       Package password. Visible in a process list: prefer --password-file, the environment variable
  --password-file FILE  PKI_TRANSPORT_PASSWORD, or the prompt (not echoed).
  --dest DIR            Where to write the files. Default ./certpacked-received/<package name>.
  --extract LIST        Comma-separated:
                          roots          ca/roots/*.crt (Enterprise, Track and Quadrant roots) + ca-bundle-roots.crt
                          intermediates  ca/intermediates/*.crt (DV, OV and EV CAs)
                          chains         ca/chains/*-fullchain.crt (each intermediate + its parents) and the bundles
                          ca             roots + intermediates + chains + bundles + CRLs   (default)
                          leafcerts      the leafcerts folders (leaf certificates AND their private keys), if packed
                          pki            the PKI folder with the CA private keys (a DevKit: only the issuing CAs' keys), if packed
                          all            everything in the package;  fullchain is the same
  --leaf WILDCARD       With leafcerts: only these leaf sets (top-level folder names), e.g. 'www*'. Several: comma.
  --trust MODE          Which CAs go into the system store:
                          roots (default)  every root: Enterprise, Track and Quadrant roots (a Linux store has one
                                           kind of anchor; this follows the Windows layout where all roots are trusted)
                          enterprise       only the Enterprise Root (servers must send the whole chain)
                          all-ca           roots AND intermediates (macOS: intermediates without trust settings)
                          none             install nothing (same as --no-trust)
  --no-trust            Unpack only.            --remove-trust   Remove this package's CAs (or every ${PREFIX_NAME}* file).
  --list                Show scope, CAs, leaves, files; write nothing.      --check   The scan only.
  --force               Overwrite files in --dest that exist and differ.    --no-verify  Skip the OpenSSL chain proof.

PREPARATION
  --yes, -y             Do not ask: install what is missing (packages, 7-Zip). Needed when there is no terminal.
  --dry-run             Print every system-changing command instead of running it. Unpacking into --dest still happens.
  --install-openssl     Install OpenSSL 4 as a FULL build (FIPS provider, ML-DSA / ML-KEM, shared libraries, headers, docs) from the
                        official source release into --openssl-prefix (default /opt/openssl-4.0.3), through Install-DevEnvironment.sh
                        when it sits next to this script. Without the option the script asks (exit code 4 when there is no terminal).
                        An OpenSSL 4 that lacks the FIPS module or ML-DSA is NOT accepted (a stripped build). The build takes
                        minutes on several cores and over an hour on ONE core.
  --openssl-prefix DIR  Where --install-openssl installs. Default /opt/openssl-4.0.3.
  --openssl FILE        Use this openssl binary (4.0.1 or newer).
  --skip-openssl-check  Continue without OpenSSL 4 (the chain proof is skipped). Not recommended.
  --7z FILE             Use this 7-Zip program (7zz, 7z, 7za).
  --store-dir DIR       Linux, unknown distribution: the directory of trust anchors.
  --update-cmd CMD      Linux, unknown distribution: the command that rebuilds the store (run as root).
  --destdir DIR         Prefix for the store directory (image builds, tests): nothing is run to update the store.
  --unblock             UNBLOCK (macOS quarantine mark) and UNLOCK (read-only, locked, immutable flags) this script's folder and
                        --dest, children and recursive, then stop. The same is done silently at every start.
  --version             Show the version.          --help, -h   This text.

PLATFORMS  (family -> store directory -> command)
  Ubuntu, Debian                     /usr/local/share/ca-certificates   update-ca-certificates
  RHEL, CentOS Stream, Rocky, Oracle, Alma   /etc/pki/ca-trust/source/anchors   update-ca-trust extract
  SLES, openSUSE (Leap, Tumbleweed)  /etc/pki/trust/anchors             update-ca-certificates
  macOS (M2, M4, Intel)              /Library/Keychains/System.keychain security add-trusted-cert
  If the certificate-store tooling is not installed, the package ca-certificates is installed first.

EXIT CODES   0 ok   1 error   2 platform not supported   4 OpenSSL 4.0.1+ missing   5 wrong password
             6 a prerequisite could not be installed

LIMITATIONS
  * Needs root (or sudo) to install into the system store and to install packages. Not needed for --list or --no-trust.
  * 7-Zip packages for your distribution are tried in this order (best effort; EPEL is needed on the RHEL family):
    7zip, p7zip + p7zip-plugins, p7zip-full. A ZipCrypto zip needs only unzip. Use --7z when you have 7-Zip elsewhere.
  * --install-openssl compiles OpenSSL: it needs a compiler, make and perl (installed when you agree). 5 minutes on 8 cores, over an
    hour on one core. The checksum of the tarball is taken from the same official release page. The result is proven (FIPS provider,
    ML-DSA, ML-KEM) before the script goes on.
  * macOS: ML-DSA (post-quantum) certificates may be refused by the macOS keychain; classic CAs install.
  * Tested on Ubuntu 24.04 (real store, real packages). The other platforms are tested only by simulation (--dry-run):
    the commands are the documented ones of each distribution, but never ran on them. macOS never ran.
EOF
}

# ------------------------------------------------------------------------------------------------ UNBLOCK + UNLOCK
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
unblock_unlock() {   # $1 = folder ; children and recursive. Linux: write bit, immutable flag. macOS: quarantine mark, locked flags.
  local d="$1"
  [ -d "$d" ] || return 0
  chmod -R u+rw "$d" 2>/dev/null
  find "$d" -maxdepth 3 -type f -name '*.sh' -exec chmod u+x {} + 2>/dev/null
  case "${PKI_UNAME:-$(uname -s)}" in
    Darwin) command -v xattr >/dev/null 2>&1 && xattr -dr com.apple.quarantine "$d" 2>/dev/null
            command -v chflags >/dev/null 2>&1 && chflags -R nouchg,noschg "$d" 2>/dev/null ;;
    *)      command -v chattr >/dev/null 2>&1 && chattr -R -i "$d" 2>/dev/null ;;
  esac
  return 0
}
unblock_unlock "$SCRIPT_DIR"

# ------------------------------------------------------------------------------------------------ messages
if [ -t 1 ]; then C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m'); C_Y=$(printf '\033[33m'); C_C=$(printf '\033[36m'); C_0=$(printf '\033[0m'); else C_R=; C_G=; C_Y=; C_C=; C_0=; fi
info()  { printf '%s[INFO]%s %s\n' "$C_C" "$C_0" "$*"; }
ok()    { printf '%s[ OK ]%s %s\n' "$C_G" "$C_0" "$*"; }
warn()  { printf '%s[WARN]%s %s\n' "$C_Y" "$C_0" "$*"; }
err()   { printf '%s[ERROR]%s %s\n' "$C_R" "$C_0" "$*" >&2; }
scan()  { printf '%s[%s]%s %-28s %s\n' "$1" "$2" "$C_0" "$3" "$4"; }   # colour, status, name, text
pass()  { scan "$C_G" PASS "$1" "$2"; }
failx() { scan "$C_R" FAIL "$1" "$2"; }
warnx() { scan "$C_Y" WARN "$1" "$2"; }
infox() { scan "$C_0" INFO "$1" "$2"; }
die()   { err "$1"; exit "${2:-1}"; }
dry()   { printf '%s[DRY ]%s %s\n' "$C_C" "$C_0" "$*"; }

# ------------------------------------------------------------------------------------------------ options
PACKAGE=""; PASS=""; PASSFILE=""; DEST=""; EXTRACT=""; LEAF=""; TRUST="roots"; DO_TRUST=1; REMOVE=0; LIST=0; CHECK=0
FORCE=0; NOVERIFY=0; YES=0; DRYRUN=0; INSTALL_OSSL=0; OSSL_PREFIX=""; OSSL_BIN=""; SKIP_OSSL=0; SEVENZ=""
STORE_DIR_OVERRIDE=""; UPDATE_CMD_OVERRIDE=""; DESTDIR=""; UNBLOCK=0

need_value() { [ $# -ge 2 ] && [ -n "$2" ] || die "Option $1 needs a value. See --help." 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --version) echo "pki-transport.sh $VERSION"; exit 0 ;;
    --package) need_value "$@"; PACKAGE="$2"; shift 2 ;;       --package=*) PACKAGE="${1#*=}"; shift ;;
    --password) need_value "$@"; PASS="$2"; shift 2 ;;         --password=*) PASS="${1#*=}"; shift ;;
    --password-file) need_value "$@"; PASSFILE="$2"; shift 2 ;; --password-file=*) PASSFILE="${1#*=}"; shift ;;
    --dest) need_value "$@"; DEST="$2"; shift 2 ;;             --dest=*) DEST="${1#*=}"; shift ;;
    --extract) need_value "$@"; EXTRACT="$2"; shift 2 ;;       --extract=*) EXTRACT="${1#*=}"; shift ;;
    --leaf) need_value "$@"; LEAF="$2"; shift 2 ;;             --leaf=*) LEAF="${1#*=}"; shift ;;
    --trust) need_value "$@"; TRUST="$2"; shift 2 ;;           --trust=*) TRUST="${1#*=}"; shift ;;
    --no-trust) DO_TRUST=0; shift ;;
    --remove-trust) REMOVE=1; shift ;;
    --list) LIST=1; shift ;;
    --check) CHECK=1; shift ;;
    --force) FORCE=1; shift ;;
    --no-verify) NOVERIFY=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --dry-run) DRYRUN=1; shift ;;
    --install-openssl) INSTALL_OSSL=1; shift ;;
    --openssl-prefix) need_value "$@"; OSSL_PREFIX="$2"; shift 2 ;; --openssl-prefix=*) OSSL_PREFIX="${1#*=}"; shift ;;
    --openssl) need_value "$@"; OSSL_BIN="$2"; shift 2 ;;       --openssl=*) OSSL_BIN="${1#*=}"; shift ;;
    --skip-openssl-check) SKIP_OSSL=1; shift ;;
    --7z) need_value "$@"; SEVENZ="$2"; shift 2 ;;              --7z=*) SEVENZ="${1#*=}"; shift ;;
    --store-dir) need_value "$@"; STORE_DIR_OVERRIDE="$2"; shift 2 ;; --store-dir=*) STORE_DIR_OVERRIDE="${1#*=}"; shift ;;
    --update-cmd) need_value "$@"; UPDATE_CMD_OVERRIDE="$2"; shift 2 ;; --update-cmd=*) UPDATE_CMD_OVERRIDE="${1#*=}"; shift ;;
    --unblock) UNBLOCK=1; shift ;;
    --destdir) need_value "$@"; DESTDIR="$2"; shift 2 ;;        --destdir=*) DESTDIR="${1#*=}"; shift ;;
    -*) die "Unknown option $1. See ./pki-transport.sh --help" 1 ;;
    *) if [ -z "$PACKAGE" ]; then PACKAGE="$1"; shift; else die "Unexpected argument $1. See --help." 1; fi ;;
  esac
done
if [ "$UNBLOCK" = 1 ]; then
  echo "UNBLOCK + UNLOCK (children and recursive): $SCRIPT_DIR"; unblock_unlock "$SCRIPT_DIR"
  [ -n "$DEST" ] && unblock_unlock "$DEST"
  echo "Done: write permission set, scripts executable; quarantine / locked / immutable flags removed where the system has them."; exit 0
fi
case "$TRUST" in roots|enterprise|all-ca) ;; none) DO_TRUST=0 ;; *) die "--trust must be roots, enterprise, all-ca or none (got '$TRUST')." 1 ;; esac

# ------------------------------------------------------------------------------------------------ platform
UNAME="${PKI_UNAME:-$(uname -s)}"          # PKI_UNAME, PKI_OS_RELEASE_FILE, PKI_MACOS_VERSION: test hooks (simulate a platform)
ARCH="$(uname -m)"
PLATFORM=""; FAMILY=""; DIST_ID=""; DIST_LIKE=""; DIST_VER=""; DIST_NAME=""; STORE_DIR=""; UPDATE_CMD=""; SYSTEM_BUNDLE=""; STORE_TOOL=""

os_field() { grep -E "^$1=" "$2" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' ; }

detect_platform() {
  case "$UNAME" in
    Linux)
      PLATFORM=linux
      local rel="${PKI_OS_RELEASE_FILE:-/etc/os-release}"
      [ -r "$rel" ] || rel=/usr/lib/os-release
      DIST_ID="$(os_field ID "$rel")"; DIST_LIKE="$(os_field ID_LIKE "$rel")"; DIST_VER="$(os_field VERSION_ID "$rel")"; DIST_NAME="$(os_field PRETTY_NAME "$rel")"
      FAMILY=unknown
      local t
      for t in $DIST_ID $DIST_LIKE; do
        case "$t" in
          ubuntu|debian|linuxmint|pop|raspbian) FAMILY=debian; break ;;
          rhel|centos|rocky|almalinux|ol|fedora|amzn) FAMILY=rhel; break ;;
          sles|sled|sles_sap|suse|opensuse|opensuse-leap|opensuse-tumbleweed|opensuse-slowroll) FAMILY=suse; break ;;
        esac
      done
      case "$FAMILY" in
        debian) STORE_DIR=/usr/local/share/ca-certificates; UPDATE_CMD="update-ca-certificates"; STORE_TOOL=update-ca-certificates; SYSTEM_BUNDLE=/etc/ssl/certs/ca-certificates.crt ;;
        rhel)   STORE_DIR=/etc/pki/ca-trust/source/anchors; UPDATE_CMD="update-ca-trust extract"; STORE_TOOL=update-ca-trust; SYSTEM_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt ;;
        suse)   STORE_DIR=/etc/pki/trust/anchors; UPDATE_CMD="update-ca-certificates"; STORE_TOOL=update-ca-certificates; SYSTEM_BUNDLE=/var/lib/ca-certificates/ca-bundle.pem ;;
      esac
      [ -n "$STORE_DIR_OVERRIDE" ] && STORE_DIR="$STORE_DIR_OVERRIDE"
      [ -n "$UPDATE_CMD_OVERRIDE" ] && UPDATE_CMD="$UPDATE_CMD_OVERRIDE"
      ;;
    Darwin)
      PLATFORM=macos; FAMILY=macos; DIST_ID=macos
      DIST_VER="${PKI_MACOS_VERSION:-$(sw_vers -productVersion 2>/dev/null)}"; DIST_NAME="macOS $DIST_VER ($ARCH)"
      STORE_DIR=/Library/Keychains/System.keychain; UPDATE_CMD="(security)"; STORE_TOOL=security; SYSTEM_BUNDLE=""
      ;;
    *) PLATFORM=other ;;
  esac
}

# ------------------------------------------------------------------------------------------------ privileges, packages
SUDO=""
setup_privilege() {
  if [ -n "$DESTDIR" ] || [ "$DRYRUN" = 1 ]; then return 0; fi
  if [ "$(id -u)" != "0" ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO="__none__"; fi
  fi
}
have_privilege() { [ "$(id -u)" = "0" ] || [ "$SUDO" = "sudo" ] || [ "$DRYRUN" = 1 ] || [ -n "$DESTDIR" ]; }
priv() {
  if [ "$DRYRUN" = 1 ]; then dry "$*"; return 0; fi
  if [ -n "$SUDO" ] && [ "$SUDO" != "__none__" ]; then sudo "$@"; else "$@"; fi
}
confirm() {
  [ "$YES" = 1 ] && return 0
  if [ -t 0 ]; then printf '%s [y/N] ' "$1"; local a; read -r a; case "$a" in y|Y|yes|YES) return 0 ;; esac; fi
  return 1
}
APT_UPDATED=0
pkg_install() {   # package names for the current family; returns the package manager's status
  case "$FAMILY" in
    debian) if [ "$APT_UPDATED" = 0 ]; then priv env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; APT_UPDATED=1; fi
            priv env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    rhel)   if command -v dnf >/dev/null 2>&1; then priv dnf install -y "$@"; else priv yum install -y "$@"; fi ;;
    suse)   priv zypper --non-interactive install "$@" ;;
    macos)  if command -v brew >/dev/null 2>&1; then brew install "$@"; else return 1; fi ;;
    *) return 1 ;;
  esac
}

# ------------------------------------------------------------------------------------------------ hashing, versions
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  elif [ -n "$OPENSSL" ]; then "$OPENSSL" dgst -sha256 -r "$1" | cut -d' ' -f1
  else openssl dgst -sha256 -r "$1" | cut -d' ' -f1; fi
}
ver_parts() {   # "OpenSSL 4.0.3 29 Sep 2026" -> "4 0 3"
  echo "$1" | sed -n 's/^OpenSSL \([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\{0,1\}\([0-9]*\).*/\1 \2 \3/p'
}
ver_ok() {      # "maj min pat" >= minimum ?
  set -- $1
  local a="$1" b="$2" c="${3:-0}"; [ -z "$c" ] && c=0
  [ "$a" -gt "$OSSL_MIN_MAJOR" ] && return 0
  [ "$a" -lt "$OSSL_MIN_MAJOR" ] && return 1
  [ "$b" -gt "$OSSL_MIN_MINOR" ] && return 0
  [ "$b" -lt "$OSSL_MIN_MINOR" ] && return 1
  [ "$c" -ge "$OSSL_MIN_PATCH" ]
}

# ------------------------------------------------------------------------------------------------ OpenSSL 4
# The proof: version, FIPS provider active, ML-DSA sign + verify, ML-KEM key generation, ML-DSA inside the FIPS provider.
openssl_ready() {   # $1 = openssl binary, $2 = quiet ; returns 0 when ALL checks pass
  local o="$1" q="$2" t fips="" ok_all=0 prefix cnf v
  t="$(mktemp -d "${TMPDIR:-/tmp}/ossl-ready.XXXXXX")" || return 1
  row() { [ "$q" = quiet ] || scan "$1" "$2" "$3" "$4"; }
  v="$("$o" version 2>/dev/null | head -1)"
  if ver_ok "$(ver_parts "$v")"; then row "$C_G" PASS "version" "$(echo "$v" | cut -d'(' -f1)"; else row "$C_R" FAIL "version" "${v:-not runnable}"; ok_all=1; fi
  prefix="$(cd "$(dirname "$o")/.." 2>/dev/null && pwd)"
  for cnf in "$prefix/ssl/fipsmodule.cnf" "$prefix/etc/ssl/fipsmodule.cnf" "$(dirname "$o")/fipsmodule.cnf"; do [ -f "$cnf" ] && { fips="$cnf"; break; }; done
  if [ -n "$fips" ]; then
    printf 'openssl_conf = openssl_init\n.include %s\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\nfips = fips_sect\nbase = base_sect\n[base_sect]\nactivate = 1\n' "$fips" > "$t/fips.cnf"
    if OPENSSL_CONF="$t/fips.cnf" "$o" list -providers -provider fips -provider base 2>&1 | grep -q 'fips'; then row "$C_G" PASS "FIPS provider" "active ($fips)"; else row "$C_R" FAIL "FIPS provider" "does not load"; ok_all=1; fips=""; fi
  else row "$C_R" FAIL "FIPS provider" "no fipsmodule.cnf: a stripped build"; ok_all=1; fi
  echo hello > "$t/d.txt"
  if "$o" genpkey -algorithm ML-DSA-65 -out "$t/k.pem" >/dev/null 2>&1 && "$o" pkeyutl -sign -inkey "$t/k.pem" -rawin -in "$t/d.txt" -out "$t/s.bin" >/dev/null 2>&1 \
     && "$o" pkeyutl -verify -inkey "$t/k.pem" -rawin -in "$t/d.txt" -sigfile "$t/s.bin" >/dev/null 2>&1; then row "$C_G" PASS "ML-DSA" "ML-DSA-65 sign and verify"; else row "$C_R" FAIL "ML-DSA" "ML-DSA-65 failed"; ok_all=1; fi
  if "$o" genpkey -algorithm ML-KEM-768 -out "$t/kem.pem" >/dev/null 2>&1 && [ -s "$t/kem.pem" ]; then row "$C_G" PASS "ML-KEM" "ML-KEM-768 key generation"; else row "$C_R" FAIL "ML-KEM" "ML-KEM-768 failed"; ok_all=1; fi
  if [ -n "$fips" ]; then
    if OPENSSL_CONF="$t/fips.cnf" "$o" genpkey -provider fips -propquery fips=yes -algorithm ML-DSA-65 -out "$t/kf.pem" >/dev/null 2>&1 && [ -s "$t/kf.pem" ]; then row "$C_G" PASS "ML-DSA in FIPS" "inside the FIPS provider"; else row "$C_Y" WARN "ML-DSA in FIPS" "not available inside the FIPS provider"; fi
  fi
  rm -rf "$t"
  return $ok_all
}

OPENSSL=""; OSSL_TEXT=""; OSSL_OLD=""
find_openssl() {
  OPENSSL=""; OSSL_TEXT=""; OSSL_OLD=""
  local c v p
  for c in "$OSSL_BIN" $(command -v openssl 2>/dev/null) "$OSSL_PREFIX/bin/openssl" \
           /opt/openssl-4*/bin/openssl /usr/local/openssl-4*/bin/openssl "$HOME"/.local/openssl-4*/bin/openssl \
           /opt/homebrew/opt/openssl@4/bin/openssl /usr/local/opt/openssl@4/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl \
           /opt/openssl/bin/openssl; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    v="$("$c" version 2>/dev/null | head -1)"
    p="$(ver_parts "$v")"
    [ -n "$p" ] || continue
    if ver_ok "$p"; then
      if openssl_ready "$c" quiet; then OPENSSL="$c"; OSSL_TEXT="$(echo "$v" | cut -d'(' -f1 | sed 's/ *$//')"; return 0; fi
      [ -z "$OSSL_OLD" ] && OSSL_OLD="$(echo "$v" | cut -d'(' -f1 | sed 's/ *$//') at $c (a STRIPPED build: no FIPS module or no ML-DSA / ML-KEM)"
      continue
    fi
    [ -z "$OSSL_OLD" ] && OSSL_OLD="$(echo "$v" | cut -d'(' -f1 | sed 's/ *$//') at $c"
  done
  return 1
}

build_openssl() {
  local prefix="${OSSL_PREFIX:-/opt/openssl-$OSSL_BUILD_VERSION}" v="$OSSL_BUILD_VERSION" work base ncpu
  base="https://github.com/openssl/openssl/releases/download/openssl-$v"
  info "Building OpenSSL $v as a FULL build (FIPS provider, ML-DSA / ML-KEM, shared libraries, headers, docs) into $prefix. Minutes on several cores, over an hour on one."
  # build tools
  local missing=""
  command -v make >/dev/null 2>&1 || missing="make"
  command -v perl >/dev/null 2>&1 || missing="$missing perl"
  { command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; } || missing="$missing compiler"
  { command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; } || missing="$missing curl"
  command -v tar >/dev/null 2>&1 || missing="$missing tar"
  if [ -n "$missing" ]; then
    info "Build tools missing:$missing"
    case "$FAMILY" in
      debian) pkg_install build-essential perl curl ca-certificates tar gzip ;;
      rhel)   pkg_install gcc make perl-core curl tar gzip || pkg_install gcc make perl perl-IPC-Cmd curl tar gzip ;;
      suse)   pkg_install gcc make perl curl tar gzip ;;
      macos)  warn "macOS: install the Xcode command line tools first:  xcode-select --install"; return 1 ;;
      *) return 1 ;;
    esac || { err "The build tools could not be installed."; return 1; }
  fi
  if [ "$DRYRUN" = 1 ]; then
    dry "curl -fL -o openssl-$v.tar.gz $base/openssl-$v.tar.gz   (+ the .sha256 file, checked)"
    dry "./Configure --prefix=$prefix --openssldir=$prefix/ssl --libdir=lib enable-fips -Wl,-rpath,$prefix/lib   (full build)"
    dry "make -j && make install   (installs the FIPS module, writes fipsmodule.cnf)"
    return 0
  fi
  work="$(mktemp -d "${TMPDIR:-/tmp}/pki-openssl.XXXXXX")" || return 1
  ( cd "$work" || exit 1
    if command -v curl >/dev/null 2>&1; then
      curl -fL --retry 3 -o "openssl-$v.tar.gz" "$base/openssl-$v.tar.gz" && curl -fL --retry 3 -o "openssl-$v.tar.gz.sha256" "$base/openssl-$v.tar.gz.sha256"
    else
      wget -q -O "openssl-$v.tar.gz" "$base/openssl-$v.tar.gz" && wget -q -O "openssl-$v.tar.gz.sha256" "$base/openssl-$v.tar.gz.sha256"
    fi ) || { err "The download of OpenSSL $v failed (network, proxy?)."; rm -rf "$work"; return 1; }
  local want got
  want="$(awk '{print $1}' "$work/openssl-$v.tar.gz.sha256" | head -1 | tr 'A-F' 'a-f')"
  got="$(sha256_of "$work/openssl-$v.tar.gz")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then err "The SHA-256 of the OpenSSL tarball does not match the release page (wanted '$want', got '$got'). Nothing was built."; rm -rf "$work"; return 1; fi
  ok "OpenSSL $v tarball: SHA-256 matches the official release page."
  ncpu="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
  ( cd "$work" && tar xzf "openssl-$v.tar.gz" && cd "openssl-$v" || exit 1
    ./Configure --prefix="$prefix" --openssldir="$prefix/ssl" --libdir=lib enable-fips "-Wl,-rpath,$prefix/lib" > "$work/configure.log" 2>&1 || { tail -5 "$work/configure.log"; exit 1; }
    make -j"$ncpu" > "$work/make.log" 2>&1 || { tail -8 "$work/make.log"; exit 1; }
    if [ -w "$(dirname "$prefix")" ] || [ "$(id -u)" = 0 ]; then make install > "$work/install.log" 2>&1 || { tail -8 "$work/install.log"; exit 1; }
    else sudo make install > "$work/install.log" 2>&1 || { tail -8 "$work/install.log"; exit 1; }; fi ) || { err "Building OpenSSL $v failed."; rm -rf "$work"; return 1; }
  rm -rf "$work"
  OSSL_PREFIX="$prefix"
  ok "OpenSSL $v installed in $prefix (the system openssl is untouched; use $prefix/bin/openssl)."
  mkdir -p /usr/local/bin 2>/dev/null; priv ln -sf "$prefix/bin/openssl" /usr/local/bin/openssl4 2>/dev/null
  return 0
}

ensure_openssl() {
  if [ "$SKIP_OSSL" = 1 ]; then find_openssl; warnx "OpenSSL" "check skipped (--skip-openssl-check)"; return 0; fi
  if find_openssl; then pass "OpenSSL" "$OSSL_TEXT  [$OPENSSL]  (required: 4.0.1 or newer; tested $OSSL_TESTED)"; return 0; fi
  failx "OpenSSL" "$([ -n "$OSSL_OLD" ] && echo "too old: $OSSL_OLD" || echo "not found")  (required: 4.0.1 or newer; tested $OSSL_TESTED)"
  [ "$CHECK" = 1 ] && return 4
  local go=0
  [ "$INSTALL_OSSL" = 1 ] && go=1
  if [ "$go" = 0 ]; then
    if [ -t 0 ] && [ "$DRYRUN" = 0 ]; then confirm "Build OpenSSL $OSSL_BUILD_VERSION from the official source release now?" && go=1
    elif [ "$YES" = 1 ] && [ "$DRYRUN" = 0 ]; then go=1; fi
  fi
  if [ "$go" = 1 ] || [ "$DRYRUN" = 1 ]; then
    if [ -x "$SCRIPT_DIR/Install-DevEnvironment.sh" ] || [ -f "$SCRIPT_DIR/Install-DevEnvironment.sh" ]; then
      info "Using Install-DevEnvironment.sh for the OpenSSL installation."
      bash "$SCRIPT_DIR/Install-DevEnvironment.sh" --yes --only openssl --openssl-source build ${OSSL_PREFIX:+--openssl-prefix "$OSSL_PREFIX"} $([ "$DRYRUN" = 1 ] && echo --dry-run) || return 4
    else
      build_openssl || return 4
    fi
    [ "$DRYRUN" = 1 ] && return 0
    if find_openssl; then pass "OpenSSL" "$OSSL_TEXT  [$OPENSSL]"; openssl_ready "$OPENSSL"; return 0; fi
  fi
  err "OpenSSL 4.0.1 or newer is required on this machine."
  echo "  Install it with this script:   ./pki-transport.sh --install-openssl --package <file>      (a FULL build of $OSSL_BUILD_VERSION: FIPS + ML-DSA / ML-KEM)"
  echo "  Or with the bootstrap:          ./Install-DevEnvironment.sh --yes --only openssl --openssl-source ppa   (or build)"
  echo "  Or use your own build:         --openssl /path/to/openssl      Or skip the check (not recommended): --skip-openssl-check"
  return 4
}

# ------------------------------------------------------------------------------------------------ archive tools
SEVENZ_BIN=""
find_7z() {
  SEVENZ_BIN=""
  local c
  for c in "$SEVENZ" $(command -v 7zz 2>/dev/null) $(command -v 7z 2>/dev/null) $(command -v 7za 2>/dev/null) /opt/homebrew/bin/7zz /usr/local/bin/7zz /usr/bin/7z /usr/bin/7za; do
    [ -n "$c" ] && [ -x "$c" ] && { SEVENZ_BIN="$c"; return 0; }
  done
  return 1
}
install_7z() {
  info "Installing 7-Zip (needed for AES-256 zip and 7z packages)"
  local n
  case "$FAMILY" in
    debian) for n in "7zip" "p7zip-full"; do pkg_install $n >/dev/null 2>&1 && break; done ;;
    rhel)   for n in "7zip" "p7zip p7zip-plugins"; do pkg_install $n >/dev/null 2>&1 && break; done
            if ! find_7z; then info "7-Zip is in EPEL on this family: trying epel-release"; pkg_install epel-release >/dev/null 2>&1; for n in "7zip" "p7zip p7zip-plugins"; do pkg_install $n >/dev/null 2>&1 && break; done; fi ;;
    suse)   for n in "7zip" "p7zip-full" "p7zip"; do pkg_install $n >/dev/null 2>&1 && break; done ;;
    macos)  for n in sevenzip p7zip; do pkg_install $n >/dev/null 2>&1 && break; done ;;
  esac
  [ "$DRYRUN" = 1 ] && return 0
  find_7z
}

archive_type() {   # zip | 7z | unknown (the first bytes, never the extension)
  local h; h="$(od -An -tx1 -N6 "$1" 2>/dev/null | tr -d ' \n')"
  case "$h" in 504b0304*|504b0506*) echo zip ;; 377abcaf271c) echo 7z ;; *) echo unknown ;; esac
}

TMP=""
cleanup() { [ -n "$TMP" ] && [ -d "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT

get_password() {
  if [ -n "$PASS" ]; then warn "--password is visible in a process list; prefer --password-file or the prompt."; return 0; fi
  if [ -n "$PASSFILE" ]; then [ -r "$PASSFILE" ] || die "Password file not readable: $PASSFILE" 1; PASS="$(head -1 "$PASSFILE" | tr -d '\r\n')"; return 0; fi
  if [ -n "${PKI_TRANSPORT_PASSWORD:-}" ]; then PASS="$PKI_TRANSPORT_PASSWORD"; return 0; fi
  [ -t 0 ] || die "No password: use --password-file, PKI_TRANSPORT_PASSWORD, or run in a terminal." 1
  printf 'Package password: '; read -r -s PASS; echo
  [ -n "$PASS" ] || die "Empty password." 1
}

extract_package() {   # -> extracted into $TMP
  local type; type="$(archive_type "$PACKAGE")"
  [ "$type" != unknown ] || die "$PACKAGE is not a zip or 7z archive (first bytes not recognised): not a .certpacked, or damaged." 1
  TMP="$(mktemp -d "${TMPDIR:-/tmp}/certpacked.XXXXXX")" || die "Cannot create a temporary folder." 1
  chmod 700 "$TMP"
  local log="$TMP.log" rc=1
  info "Opening $PACKAGE ($type)"
  find_7z
  if [ "$type" = zip ] && [ -z "$SEVENZ_BIN" ] && command -v unzip >/dev/null 2>&1; then
    unzip -q -o -P "$PASS" -d "$TMP" "$PACKAGE" > "$log" 2>&1; rc=$?
    if [ $rc -ne 0 ] && grep -qiE 'unsupported compression method 99|compression method 99' "$log"; then rc=99; fi
    if [ $rc -eq 0 ]; then rm -f "$log"; return 0; fi
    if [ $rc -ne 99 ]; then if grep -qiE 'incorrect password|bad password|checkdir error' "$log"; then rm -f "$log"; die "WRONG_PASSWORD: the password is wrong (or the file is damaged)." 5; fi; fi
    rm -rf "$TMP"; TMP="$(mktemp -d "${TMPDIR:-/tmp}/certpacked.XXXXXX")"; chmod 700 "$TMP"
  fi
  if [ -z "$SEVENZ_BIN" ]; then
    warn "This package needs 7-Zip (AES-256 or 7z) and none was found."
    if confirm "Install 7-Zip now?" || [ "$DRYRUN" = 1 ]; then
      have_privilege || die "No root and no sudo: cannot install 7-Zip. Install it yourself or use --7z." 6
      install_7z || true
    fi
    find_7z || die "7-Zip is not available. Install it (Ubuntu: apt install 7zip; RHEL family: dnf install p7zip p7zip-plugins from EPEL; SUSE: zypper install 7zip; macOS: brew install sevenzip) or use --7z FILE." 6
  fi
  "$SEVENZ_BIN" x -p"$PASS" -y -bd -o"$TMP" "$PACKAGE" > "$log" 2>&1 < /dev/null; rc=$?
  if [ $rc -ne 0 ]; then
    if grep -qiE 'wrong password|can not open encrypted|data error in encrypted|cannot open encrypted' "$log"; then rm -f "$log"; die "WRONG_PASSWORD: the password is wrong (or the file is damaged)." 5; fi
    err "7-Zip failed:"; tail -4 "$log" >&2; rm -f "$log"; exit 1
  fi
  rm -f "$log"
}

# ------------------------------------------------------------------------------------------------ the package list
FILES_TSV=""
read_manifest() {
  FILES_TSV="$TMP/certpack.tsv"
  [ -f "$FILES_TSV" ] && [ -f "$TMP/certpack.json" ] || die "This archive has no certpack.tsv / certpack.json: it is not a .certpacked made by PkiTransport.ps1." 1
  # every file against its SHA-256
  local bad=0 n=0 role path sha size sha1 store ext kind name
  while IFS="$TAB" read -r role path sha size sha1 store ext kind name; do
    case "$role" in '#'*|'') continue ;; esac
    n=$((n+1))
    if [ ! -f "$TMP/$path" ]; then err "missing in the package: $path"; bad=$((bad+1)); continue; fi
    if [ "$(sha256_of "$TMP/$path")" != "$sha" ]; then err "SHA-256 differs: $path"; bad=$((bad+1)); fi
  done < "$FILES_TSV"
  [ "$bad" -eq 0 ] || die "The package does not match its own list of files ($bad problem(s))." 1
  ok "Package opened: $n file(s), every SHA-256 matches."
  local created; created="$(grep -m1 '"createdUtc"' "$TMP/certpack.json" | sed 's/.*: *"\(.*\)".*/\1/')"
  local scope_leaf scope_keys scope_issuing
  scope_leaf="$(grep -A4 '"scope"' "$TMP/certpack.json" | grep '"leafcerts"' | grep -c true)"; scope_keys="$(grep -A4 '"scope"' "$TMP/certpack.json" | grep '"caPrivateKeys"' | grep -c true)"
  scope_issuing="$(grep -A5 '"scope"' "$TMP/certpack.json" | grep '"issuingKeysOnly"' | grep -c true)"
  info "Made $created. Scope: CA certificates$([ "$scope_leaf" = 1 ] && echo ' + leaf certificates (private keys)')$([ "$scope_keys" = 1 ] && { [ "$scope_issuing" = 1 ] && echo ' + the PKI folder with the keys of the ISSUING (intermediate) CAs only (no root key)' || echo ' + the whole PKI (CA private keys)'; })."
}

want_role() {   # is this role selected by --extract ?  uses $SELECT_LIST (comma separated)
  local role="$1" s
  for s in $(echo "$SELECT_LIST" | tr ',' ' '); do
    case "$s" in
      roots)         case "$role" in root|bundle-roots) return 0 ;; esac ;;
      intermediates) case "$role" in intermediate) return 0 ;; esac ;;
      chains)        case "$role" in chain|bundle|bundle-roots) return 0 ;; esac ;;
      ca)            case "$role" in root|intermediate|chain|bundle|bundle-roots|publish|external|cross) return 0 ;; esac ;;
      leafcerts)     case "$role" in leaf|leaf-index) return 0 ;; esac ;;
      pki)           case "$role" in pki) return 0 ;; esac ;;
      all|fullchain) return 0 ;;
      *) die "Unknown --extract value '$s'. Use roots, intermediates, chains, ca, leafcerts, pki, all (fullchain)." 1 ;;
    esac
  done
  return 1
}

leaf_ok() {   # leaf filter on the top-level folder of leafcerts/<top>/...
  [ -z "$LEAF" ] && return 0
  local path="$1" top s
  top="$(echo "${path#leafcerts/}" | cut -d/ -f1)"
  for s in $(echo "$LEAF" | tr ',' ' '); do case "$top" in $s) return 0 ;; esac; done
  return 1
}

do_list() {
  echo; printf '%-14s %-12s %s\n' KIND ROLE "COMMON NAME / FILE"
  local role path sha size sha1 store ext kind name n=0
  while IFS="$TAB" read -r role path sha size sha1 store ext kind name; do
    case "$role" in '#'*|'') continue ;; esac
    n=$((n+1))
    case "$role" in root|intermediate) printf '%-14s %-12s %s\n' "$kind" "$role" "$name" ;; esac
  done < "$FILES_TSV"
  echo; local leaves; leaves="$(grep -c "^leaf${TAB}" "$FILES_TSV")"
  info "$n file(s); roles: $(grep -v '^#' "$FILES_TSV" | cut -f1 | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')"
  [ "$leaves" -gt 0 ] && info "leaf files: $leaves (folders: $(grep "^leaf${TAB}" "$FILES_TSV" | cut -f2 | cut -d/ -f2 | sort -u | tr '\n' ' '))"
}

do_export() {
  mkdir -p "$DEST" || die "Cannot create $DEST" 1
  local role path sha size sha1 store ext kind name written=0 skipped=0 dst
  while IFS="$TAB" read -r role path sha size sha1 store ext kind name; do
    case "$role" in '#'*|'') continue ;; esac
    want_role "$role" || continue
    case "$role" in leaf|leaf-index) leaf_ok "$path" || continue ;; esac
    dst="$DEST/$path"
    if [ -e "$dst" ]; then
      if [ "$(sha256_of "$dst")" = "$sha" ]; then skipped=$((skipped+1)); continue; fi
      [ "$FORCE" = 1 ] || die "$dst exists and differs. Use --force, or another --dest." 1
    fi
    mkdir -p "$(dirname "$dst")"; cp "$TMP/$path" "$dst"; written=$((written+1))
    case "$path" in leafcerts/*|pki/*) case "$dst" in *.key|*.pfx) chmod 600 "$dst" 2>/dev/null ;; esac ;; esac
  done < "$FILES_TSV"
  [ "$written" -gt 0 ] || [ "$skipped" -gt 0 ] || die "Nothing in this package matches --extract '$SELECT_LIST'." 1
  cp "$TMP/certpack.json" "$TMP/certpack.tsv" "$TMP/README.txt" "$DEST/" 2>/dev/null
  ok "$written file(s) written to $DEST ($skipped identical file(s) left alone)."
}

# ------------------------------------------------------------------------------------------------ trust
trust_candidates() {   # prints the files (relative to $DEST) to install, by --trust
  local role path sha size sha1 store ext kind name
  while IFS="$TAB" read -r role path sha size sha1 store ext kind name; do
    case "$role" in '#'*|'') continue ;; esac
    case "$TRUST" in
      roots)      [ "$role" = root ] && [ "$ext" != 1 ] && echo "$path" ;;
      enterprise) [ "$role" = root ] && [ "$kind" = root ] && [ "$ext" != 1 ] && echo "$path" ;;
      all-ca)     { [ "$role" = root ] && [ "$ext" != 1 ]; } || [ "$role" = intermediate ] && echo "$path" ;;
    esac
  done < "$FILES_TSV"
}

store_target() { echo "${DESTDIR}${STORE_DIR}"; }

ensure_store_tooling() {   # Linux: the certificate-store tooling of this distribution
  [ "$PLATFORM" = linux ] || return 0
  if [ "$FAMILY" = unknown ] && [ -z "$STORE_DIR_OVERRIDE" ]; then return 0; fi
  local tool="$STORE_TOOL"
  [ -n "$UPDATE_CMD_OVERRIDE" ] && tool="$(echo "$UPDATE_CMD_OVERRIDE" | awk '{print $1}')"
  if command -v "$tool" >/dev/null 2>&1 || [ -n "$DESTDIR" ]; then pass "Certificate store" "$tool found; trust anchors go to $(store_target)"; return 0; fi
  warnx "Certificate store" "$tool not found: the certificate-store tooling of this Linux is not installed"
  [ "$CHECK" = 1 ] && return 0
  if confirm "Install the certificate store package (ca-certificates) now?" || [ "$DRYRUN" = 1 ]; then
    have_privilege || die "No root and no sudo: cannot install ca-certificates." 6
    info "Installing the certificate store ($FAMILY: ca-certificates)"
    pkg_install ca-certificates || die "The package ca-certificates could not be installed." 6
    [ "$DRYRUN" = 1 ] && return 0
    command -v "$tool" >/dev/null 2>&1 || die "$tool is still missing after installing ca-certificates." 6
    ok "Certificate store installed."
  else
    die "The certificate store tooling is missing and was not installed. Install ca-certificates, then run again." 6
  fi
}

update_store() {
  if [ -n "$DESTDIR" ]; then info "--destdir: the store is NOT rebuilt (run '$UPDATE_CMD' on the target system)."; return 0; fi
  info "Rebuilding the system store: $UPDATE_CMD"
  # shellcheck disable=SC2086
  priv $UPDATE_CMD > /tmp/pki-transport-update.$$ 2>&1 || { err "The store update failed:"; tail -5 /tmp/pki-transport-update.$$ >&2; rm -f /tmp/pki-transport-update.$$; return 1; }
  [ "$DRYRUN" = 1 ] || tail -2 /tmp/pki-transport-update.$$ | sed 's/^/        /'
  rm -f /tmp/pki-transport-update.$$
}

install_trust_linux() {
  local target; target="$(store_target)"
  have_privilege || die "Installing into $target needs root (or sudo). Run with sudo, or use --no-trust." 1
  priv mkdir -p "$target"
  local n=0 f base
  for f in $(trust_candidates); do
    base="$PREFIX_NAME$(basename "$f")"
    case "$base" in *.crt|*.pem) ;; *) base="$base.crt" ;; esac
    if [ "$DRYRUN" = 1 ]; then dry "install -m 0644 $DEST/$f $target/$base"; else priv install -m 0644 "$DEST/$f" "$target/$base" || { err "Cannot write $target/$base"; return 1; }; fi
    n=$((n+1))
  done
  [ "$n" -gt 0 ] || die "No CA certificate selected for the store (--trust $TRUST). Extract the CAs: --extract ca." 1
  ok "$n certificate(s) placed in $target (files named ${PREFIX_NAME}*)."
  update_store || return 1
  INSTALLED_COUNT=$n
}

install_trust_macos() {
  have_privilege || die "Installing into the System keychain needs an administrator (sudo)." 1
  local n=0 bad=0 f role
  for f in $(trust_candidates); do
    role=root; case "$f" in ca/intermediates/*) role=intermediate ;; esac
    if [ "$role" = root ]; then
      if [ "$DRYRUN" = 1 ]; then dry "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $DEST/$f"
      else priv security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$DEST/$f" >/dev/null 2>&1 && n=$((n+1)) || { warn "macOS refused $f (post-quantum certificates may not be supported by this macOS)"; bad=$((bad+1)); }; fi
    else
      if [ "$DRYRUN" = 1 ]; then dry "security add-certificates -k /Library/Keychains/System.keychain $DEST/$f"
      else priv security add-certificates -k /Library/Keychains/System.keychain "$DEST/$f" >/dev/null 2>&1 && n=$((n+1)) || { warn "macOS refused $f"; bad=$((bad+1)); }; fi
    fi
  done
  [ "$DRYRUN" = 1 ] || { [ "$n" -gt 0 ] || die "macOS accepted no certificate." 1; ok "$n certificate(s) added to the System keychain ($bad refused)."; }
  INSTALLED_COUNT=$n
}

verify_chains() {
  [ "$NOVERIFY" = 1 ] && return 0
  [ "$DRYRUN" = 1 ] && return 0
  if [ -z "$OPENSSL" ]; then warn "No OpenSSL 4: the chain proof is skipped."; return 0; fi
  local roots="$DEST/ca/ca-bundle-roots.crt" all="$DEST/ca/ca-bundle-all.crt" ok_n=0 bad_n=0 f bundle
  if [ "$PLATFORM" = linux ] && [ -z "$DESTDIR" ] && [ -r "$SYSTEM_BUNDLE" ]; then bundle="$SYSTEM_BUNDLE"; else bundle="$roots"; fi
  [ -r "$bundle" ] || { warn "No bundle to verify against."; return 0; }
  [ -r "$all" ] || all="$bundle"
  for f in $(trust_candidates) $(grep "^intermediate${TAB}" "$FILES_TSV" | cut -f2); do
    [ -f "$DEST/$f" ] || continue
    if "$OPENSSL" verify -CAfile "$bundle" -untrusted "$all" "$DEST/$f" >/dev/null 2>&1; then ok_n=$((ok_n+1)); else bad_n=$((bad_n+1)); warn "does not verify against $( [ "$bundle" = "$roots" ] && echo 'the package roots' || echo 'the SYSTEM store' ): $f"; fi
  done
  if [ "$bad_n" -eq 0 ]; then ok "$OSSL_TEXT: all $ok_n CA certificate(s) verify against $( [ "$bundle" = "$roots" ] && echo 'the package roots' || echo "the system store ($bundle)")."
  else warn "$bad_n of $((ok_n+bad_n)) CA certificate(s) did not verify."; fi
}

remove_trust() {
  have_privilege || die "Removing from the store needs root (or sudo)." 1
  local n=0 f base target
  if [ "$PLATFORM" = macos ]; then
    local role path sha size sha1 store ext kind name
    [ -f "$FILES_TSV" ] || die "--remove-trust on macOS needs --package (or --dest with certpack.tsv)." 1
    while IFS="$TAB" read -r role path sha size sha1 store ext kind name; do
      case "$role" in root|intermediate) ;; *) continue ;; esac
      if [ "$DRYRUN" = 1 ]; then dry "security delete-certificate -Z $sha1 -t /Library/Keychains/System.keychain"; else priv security remove-trusted-cert -d "$TMP/$path" >/dev/null 2>&1; priv security delete-certificate -Z "$sha1" /Library/Keychains/System.keychain >/dev/null 2>&1 && n=$((n+1)); fi
    done < "$FILES_TSV"
    ok "$n certificate(s) removed from the System keychain."; return 0
  fi
  target="$(store_target)"
  if [ -f "${FILES_TSV:-/nonexistent}" ]; then
    for f in $(grep -E "^(root|intermediate)${TAB}" "$FILES_TSV" | cut -f2); do
      base="$PREFIX_NAME$(basename "$f")"; [ -e "$target/$base" ] && { if [ "$DRYRUN" = 1 ]; then dry "rm -f $target/$base"; else priv rm -f "$target/$base"; fi; n=$((n+1)); }
    done
  else
    for f in "$target"/${PREFIX_NAME}*; do [ -e "$f" ] || continue; if [ "$DRYRUN" = 1 ]; then dry "rm -f $f"; else priv rm -f "$f"; fi; n=$((n+1)); done
  fi
  ok "$n file(s) ${PREFIX_NAME}* removed from $target."
  if [ -n "$DESTDIR" ]; then return 0; fi
  info "Rebuilding the system store: $UPDATE_CMD$([ "$FAMILY" = debian ] || [ "$FAMILY" = suse ] && echo ' --fresh')"
  if [ "$FAMILY" = debian ] || [ "$FAMILY" = suse ]; then priv $UPDATE_CMD --fresh >/dev/null 2>&1 || priv $UPDATE_CMD >/dev/null 2>&1; else priv $UPDATE_CMD >/dev/null 2>&1; fi
  ok "Store rebuilt."
}

# ================================================================================================ main
detect_platform
echo "============================================================"
echo "pki-transport.sh $VERSION   Agantra Inovatif OU (NextMantra)   Nicko Satria Utama <nicko@nextmantra.com>"
echo "============================================================"
SELECT_LIST="${EXTRACT:-ca}"
setup_privilege

# ---------------- the SCAN
echo "SCAN OF THIS MACHINE"
case "$PLATFORM" in
  linux)
    if [ "$FAMILY" = unknown ] && [ -z "$STORE_DIR_OVERRIDE" ]; then
      failx "Platform" "$DIST_NAME (id=$DIST_ID like=$DIST_LIKE): not a known family"; echo "      Known: Ubuntu / Debian, RHEL / CentOS / Rocky / Oracle / Alma, SLES / openSUSE. Use --store-dir DIR --update-cmd CMD for another Linux."; exit 2
    fi
    pass "Platform" "$DIST_NAME  [family: $FAMILY, $ARCH]" ;;
  macos) pass "Platform" "$DIST_NAME  [System keychain]" ;;
  *) failx "Platform" "$UNAME is not supported (Linux and macOS only; on Windows use PkiTransport.ps1 -Install)"; exit 2 ;;
esac
if [ "$DRYRUN" = 1 ]; then infox "Privileges" "dry run: nothing is changed"
elif [ -n "$DESTDIR" ]; then infox "Privileges" "--destdir $DESTDIR: no root needed"
elif [ "$(id -u)" = 0 ]; then pass "Privileges" "root"
elif [ "$SUDO" = "sudo" ]; then pass "Privileges" "sudo is available"
else warnx "Privileges" "not root and no sudo: only --list, --no-trust and --check will work"; fi
ensure_openssl; OSSL_RC=$?
if find_7z; then infox "7-Zip" "$SEVENZ_BIN"; else infox "7-Zip" "not found (installed on demand; a ZipCrypto zip needs only unzip)"; fi
command -v unzip >/dev/null 2>&1 && infox "unzip" "$(command -v unzip)"
[ "$PLATFORM" = linux ] && { ensure_store_tooling || exit $?; }
[ "$PLATFORM" = macos ] && { command -v security >/dev/null 2>&1 && pass "Certificate store" "security found; System keychain" || failx "Certificate store" "security not found"; }
echo
if [ "$CHECK" = 1 ]; then
  [ "$OSSL_RC" -eq 0 ] || { echo "NOT READY: OpenSSL 4.0.1+ is missing."; exit 4; }
  echo "READY: this machine can install the package."; exit 0
fi
[ "$OSSL_RC" -eq 0 ] || exit "$OSSL_RC"

# ---------------- package
if [ -z "$PACKAGE" ] && [ "$REMOVE" = 1 ] && [ "$PLATFORM" = linux ]; then
  FILES_TSV=""; remove_trust; exit 0
fi
[ -n "$PACKAGE" ] || die "--package FILE is needed. See ./pki-transport.sh --help" 1
[ -f "$PACKAGE" ] || die "Package not found: $PACKAGE" 1
get_password
extract_package
read_manifest

if [ "$LIST" = 1 ]; then do_list; exit 0; fi
if [ "$REMOVE" = 1 ]; then remove_trust; exit 0; fi

base="$(basename "$PACKAGE")"; base="${base%.certpacked}"
[ -n "$DEST" ] || DEST="./certpacked-received/$base"
# the CAs are needed for the trust: add them to the selection when the user asked for something else
if [ "$DO_TRUST" = 1 ]; then
  case ",$SELECT_LIST," in *,ca,*|*,roots,*|*,all,*|*,fullchain,*) ;; *) SELECT_LIST="$SELECT_LIST,roots" ;; esac
  [ "$TRUST" = all-ca ] && case ",$SELECT_LIST," in *,ca,*|*,all,*|*,fullchain,*|*,intermediates,*) ;; *) SELECT_LIST="$SELECT_LIST,intermediates" ;; esac
fi
info "Unpacking ($SELECT_LIST) to $DEST"
do_export

INSTALLED_COUNT=0
if [ "$DO_TRUST" = 1 ]; then
  echo
  case "$PLATFORM" in linux) install_trust_linux || exit 1 ;; macos) install_trust_macos || exit 1 ;; esac
  verify_chains
else
  info "--no-trust: nothing was installed in the system store."
fi
echo
ok "Done.$([ "$DO_TRUST" = 1 ] && echo " $INSTALLED_COUNT CA certificate(s) handled by the system store.") Files: $DEST"
exit 0
