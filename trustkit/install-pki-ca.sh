#!/usr/bin/env bash
# ============================================================
# PKI Script - install-pki-ca.sh  (STANDALONE: needs no other script)
# Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
# ============================================================
# Installs the CA certificates of the PKI (roots only go to the system trust; NO private keys) on Ubuntu / Debian, RHEL family
# (RHEL, CentOS Stream, Rocky, Alma, Oracle, Fedora) and SUSE family (SLES, openSUSE).  Run:  ./install-pki-ca.sh --help
PKI_PREFIX="__PKI_PREFIX__"      # written by New-PkiTrustKit.ps1; the files in the system store start with it
PKI_TARGET="__PKI_TARGET__"      # ubuntu | redhat | suse  (auto = found from this machine)
set -u
VERSION="5.1.0"

usage() {
cat <<'EOF'
install-pki-ca.sh  -  install the CA certificates of the PKI on this Linux machine (Ubuntu / Debian, RHEL family, SUSE family)
Version 5.1.0
Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com

WHAT IT DOES
  (5.1.0) ONE .certpacked can hold the PKIs of SEVERAL companies (for example agantra and raksaka) and several releases of each: all are installed in one run.
  What was installed is written to /var/lib/pki-trust-kit/installed.tsv; take PKIs away again with  remove-pki-ca.sh --list | --pki NAME | --all  (same zip).
  Opens the .certpacked file that came in the same zip (it asks for the password) into the folder  pki/  next to this script, and
  puts every ROOT CA (top root, track roots, quadrant roots) into the system certificate store (the "ca-certificates" of this distribution).
  The intermediate CA certificates are kept in  pki/ca/intermediates  (and the chains in pki/ca/chains): a client needs only the roots.
  The package holds NO private key. An older version of the same PKI is replaced: its files in the system store are removed first.
  The zip and the pki folder stay.

HOW TO RUN (copy the zip to the machine, unzip it, open a terminal in that folder)
    bash install-pki-ca.sh
  The password comes from the person who sent you the zip (by another way than the zip). sudo is used for the system store (you may be asked for YOUR password).

OPTIONS
  --password TEXT      the password (else the variable PKI_PACKAGE_PASSWORD, else --password-file, else you are asked)
  --password-file F    read the password from the first line of this file
  --package FILE       a .certpacked (repeat it for several; default: every .certpacked next to this script - a kit of ALL releases has one per release)
  --target T           ubuntu | redhat | suse | auto   (default: this script's own target, checked against the machine)
  --firefox            also make Firefox trust the PKI (user profiles of the user who runs this: policy "use the system certificates"
                       and, when certutil is installed, the roots are imported into the profile databases). Close Firefox first.
  --check              show what would be done, change nothing
  --help

WHERE THE ROOTS GO
  ubuntu   /usr/local/share/ca-certificates/   then  update-ca-certificates       (Ubuntu, Debian, Mint)
  redhat   /etc/pki/ca-trust/source/anchors/   then  update-ca-trust extract       (RHEL, CentOS Stream, Rocky, Alma, Oracle, Fedora)
  suse     /etc/pki/trust/anchors/             then  update-ca-certificates       (SLES, openSUSE)

SUPPORTED  Ubuntu 24.04 / 26.04 or newer, CentOS Stream 10+, RHEL 10+, Rocky Linux 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+ (15, 16 ...),
           openSUSE 15+ (Leap 15, 16 ..., Tumbleweed). Any other distribution or older version is REFUSED with an error (exit 5), nothing is changed.

NEEDS    bash, and one of: python3 or unzip (or 7z) to open the package; sudo (unless you are root); ca-certificates tools of the distribution.
EXIT     0 done   1 error   3 wrong password   5 this Linux distribution / version is not supported
EOF
}

C_OK=""; C_W=""; C_E=""; C_I=""; C_0=""
[ -t 1 ] && { C_OK=$'\033[32m'; C_W=$'\033[33m'; C_E=$'\033[31m'; C_I=$'\033[36m'; C_0=$'\033[0m'; }
info() { printf '%s[INFO]%s %s\n' "$C_I" "$C_0" "$*"; }
ok()   { printf '%s[OK]%s   %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_W" "$C_0" "$*" >&2; }
die()  { printf '%s[ERROR]%s %s\n' "$C_E" "$C_0" "$1" >&2; exit "${2:-1}"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in -h|--help) : ;; *) echo "[INFO] install-pki-ca.sh version $VERSION" >&2 ;; esac
PASS="${PKI_PACKAGE_PASSWORD:-}"; PKG=""; PKGS=(); TARGET="$PKI_TARGET"; FIREFOX=0; CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --password) [ $# -ge 2 ] || die "--password needs a value"; PASS="$2"; shift 2 ;;
    --password-file) [ $# -ge 2 ] && [ -f "$2" ] || die "--password-file needs a file"; PASS="$(head -n1 "$2" | tr -d '\r')"; shift 2 ;;
    --package) [ $# -ge 2 ] || die "--package needs a file"; PKGS+=("$2"); shift 2 ;;
    --target) [ $# -ge 2 ] || die "--target needs a value"; TARGET="$2"; shift 2 ;;
    --firefox) FIREFOX=1; shift ;;
    --check) CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
done

echo "============================================================"
echo " install-pki-ca.sh - CA certificates of the PKI (no keys)"
echo " Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com"
echo "============================================================"
[ "$(uname -s)" = Linux ] || die "This script is for Linux. On Windows use Install-PkiCa.ps1." 1
[ "$CHECK" = 1 ] && info "CHECK mode: nothing is changed."

# ---- 0. which Linux? Only these are accepted, everything else is refused with an error (exit 5, nothing is changed):
#   Ubuntu 24.04 / 26.04 or newer | CentOS Stream 10 or newer | RHEL 10 or newer | Rocky Linux 10 or newer | Oracle Linux 10 or newer
#   SUSE Linux Enterprise (SLES / SLED) 15 or newer (15, 16 ...) | openSUSE Leap 15 or newer (15, 16 ...) | openSUSE Tumbleweed
OSREL="${PKI_OS_RELEASE_FILE:-/etc/os-release}"
OS_ID=""; OS_VER=""; OS_PRETTY=""
if [ -r "$OSREL" ]; then
  OS_ID="$(. "$OSREL"; echo "${ID:-}")"; OS_VER="$(. "$OSREL"; echo "${VERSION_ID:-}")"; OS_PRETTY="$(. "$OSREL"; echo "${PRETTY_NAME:-$NAME}")"
fi
OS_MAJOR="${OS_VER%%.*}"; case "$OS_MAJOR" in ''|*[!0-9]*) OS_MAJOR=0 ;; esac
OS_OK=0
case "$OS_ID" in
  ubuntu)                  [ "$OS_MAJOR" -ge 24 ] && OS_OK=1 ;;
  centos|rhel|rocky|ol)    [ "$OS_MAJOR" -ge 10 ] && OS_OK=1 ;;
  sles|sles_sap|sled)      [ "$OS_MAJOR" -ge 15 ] && OS_OK=1 ;;
  opensuse-leap)           [ "$OS_MAJOR" -ge 15 ] && OS_OK=1 ;;
  opensuse-tumbleweed)     OS_OK=1 ;;
esac
if [ "$OS_OK" != 1 ]; then
  die "This system is '${OS_PRETTY:-unknown}' (ID=${OS_ID:-?} VERSION_ID=${OS_VER:-?}): NOT supported. Nothing was changed.
        Supported: Ubuntu 24.04 / 26.04 or newer; CentOS Stream 10 or newer; RHEL 10 or newer; Rocky Linux 10 or newer; Oracle Linux 10 or newer;
        SUSE Linux Enterprise 15 or newer (SLES 15, 16 ...); openSUSE 15 or newer (Leap 15, 16 ..., Tumbleweed). Other distributions and older versions are refused." 5
fi
info "System: $OS_PRETTY - supported."

# ---- 1. this machine: which trust store
OSID=""; OSLIKE=""
[ -r /etc/os-release ] && { OSID="$(. /etc/os-release; echo "${ID:-}")"; OSLIKE="$(. /etc/os-release; echo "${ID_LIKE:-}")"; }
detect() {
  case " $OSID $OSLIKE " in *" ubuntu "*|*" debian "*) echo ubuntu; return;; esac
  case " $OSID $OSLIKE " in *" rhel "*|*" fedora "*|*" centos "*) echo redhat; return;; esac
  case " $OSID $OSLIKE " in *" suse "*|*" sles "*|*" opensuse "*) echo suse; return;; esac
  command -v update-ca-trust >/dev/null 2>&1 && { echo redhat; return; }
  command -v update-ca-certificates >/dev/null 2>&1 && { [ -d /etc/pki/trust/anchors ] && echo suse || echo ubuntu; return; }
  echo unknown
}
FOUND="$(detect)"
[ "$TARGET" = auto ] || [ -z "$TARGET" ] && TARGET="$FOUND"
[ "$FOUND" != unknown ] && [ "$TARGET" != "$FOUND" ] && warn "this package is for '$TARGET' but this machine looks like '$FOUND': using '$FOUND'." && TARGET="$FOUND"
case "$TARGET" in
  ubuntu) ANCHOR="/usr/local/share/ca-certificates"; UPDATE="update-ca-certificates"; BUNDLE="/etc/ssl/certs/ca-certificates.crt" ;;
  redhat) ANCHOR="/etc/pki/ca-trust/source/anchors"; UPDATE="update-ca-trust extract"; BUNDLE="/etc/pki/tls/certs/ca-bundle.crt" ;;
  suse)   ANCHOR="/etc/pki/trust/anchors"; UPDATE="update-ca-certificates"; BUNDLE="/etc/ssl/ca-bundle.pem" ;;
  *) die "this machine is not Ubuntu / Debian, RHEL family or SUSE family (ID=$OSID). Nothing was changed." ;;
esac
# for tests only: another folder / command / bundle
ANCHOR="${PKI_ANCHOR_DIR:-$ANCHOR}"; UPDATE="${PKI_UPDATE_CMD:-$UPDATE}"; BUNDLE="${PKI_BUNDLE_FILE:-$BUNDLE}"
UPD_BIN="${UPDATE%% *}"
command -v "$UPD_BIN" >/dev/null 2>&1 || die "'$UPD_BIN' not found: install the ca-certificates package of your distribution, then run this again."
info "System: ${OSID:-linux} -> target $TARGET. Roots go to $ANCHOR, then: $UPDATE"

SUDO=""
if [ "$(id -u)" != 0 ] && [ -z "${PKI_ANCHOR_DIR:-}" ]; then command -v sudo >/dev/null 2>&1 && SUDO="sudo" || die "root or sudo is needed for the system certificate store."; fi

# ---- 2. the package and the password
if [ "${#PKGS[@]}" -eq 0 ]; then
  for f in "$HERE"/*.certpacked; do [ -f "$f" ] && PKGS+=("$f"); done
  [ "${#PKGS[@]}" -ge 1 ] || die "No .certpacked file next to this script ($HERE). Unzip the whole zip first, or use --package FILE."
fi
for f in "${PKGS[@]}"; do [ -f "$f" ] || die "Package not found: $f"; done
if [ -z "$PASS" ]; then
  [ -t 0 ] || die "No password: use --password, --password-file or the variable PKI_PACKAGE_PASSWORD."
  read -r -s -p "Password of the package (from the person who sent you the zip): " PASS; echo
fi
[ -n "$PASS" ] || die "No password." 3

# ---- 3. open it into ./pki (kept). One package: ./pki ; several (a kit of ALL releases): ./pki/<package name>/
OUT="$HERE/pki"
[ "$CHECK" = 1 ] && OUT="$(mktemp -d "${TMPDIR:-/tmp}/pki-ca.XXXXXX")"
mkdir -p "$OUT" || die "cannot create $OUT"
extract_py() { python3 - "$PKG" "$DEST" "$PASS" <<'PY'
import sys, zipfile, os
pkg, out, pw = sys.argv[1], sys.argv[2], sys.argv[3].encode()
try:
    z = zipfile.ZipFile(pkg)
    for i in z.infolist():
        if i.flag_bits & 0x1 and i.compress_type == 99: sys.exit(5)     # AES: python cannot
    n = os.path.realpath(out)
    for i in z.infolist():
        t = os.path.realpath(os.path.join(out, i.filename))
        if not (t == n or t.startswith(n + os.sep)): sys.exit(6)
    z.extractall(out, pwd=pw)
except RuntimeError as e:
    sys.exit(3 if 'password' in str(e).lower() or 'Bad' in str(e) else 4)
except zipfile.BadZipFile:
    sys.exit(4)
PY
}
extract() {
  local rc=1 s
  if command -v python3 >/dev/null 2>&1; then extract_py; rc=$?; [ $rc = 0 ] && return 0; [ $rc = 3 ] && return 3; fi
  if command -v unzip >/dev/null 2>&1; then unzip -o -q -P "$PASS" "$PKG" -d "$DEST" >/dev/null 2>&1; rc=$?; [ $rc = 0 ] && return 0; [ $rc = 82 ] && return 3; fi
  for s in 7zz 7z 7za; do command -v $s >/dev/null 2>&1 && { $s x -y -bd -p"$PASS" -o"$DEST" "$PKG" >/dev/null 2>&1; rc=$?; [ $rc = 0 ] && return 0; [ $rc = 2 ] && return 3; }; done
  return "$rc"
}
DESTS=()
for PKG in "${PKGS[@]}"; do
  DEST="$OUT"
  if [ "${#PKGS[@]}" -gt 1 ]; then DEST="$OUT/$(basename "${PKG%.certpacked}")"; mkdir -p "$DEST" || die "cannot create $DEST"; fi
  extract; rc=$?
  if [ $rc != 0 ]; then [ -z "$(ls -A "$DEST" 2>/dev/null)" ] && rmdir "$DEST" 2>/dev/null; [ -z "$(ls -A "$OUT" 2>/dev/null)" ] && rmdir "$OUT" 2>/dev/null; fi
  if [ $rc = 3 ]; then die "The password is wrong." 3; fi
  if [ $rc != 0 ]; then die "The package could not be opened ($(basename "$PKG")). Install python3 or unzip (for example:  sudo apt install unzip  /  sudo dnf install unzip  /  sudo zypper install unzip) and run this again."; fi
  [ -f "$DEST/certpack.tsv" ] || die "This is not a PKI package (certpack.tsv is missing): $(basename "$PKG")"
  DESTS+=("$DEST")
done
ok "${#PKGS[@]} package(s) opened into $OUT"

# ---- 4. check every file against its SHA-256, collect the roots.  One package can hold SEVERAL PKIs (several companies, several releases):
#         certpack.tsv has the company (pki) and the PKI folder (release) of every certificate in its last two columns.
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$1" | cut -d' ' -f1; }
ROOTS=(); INTERS=(); ROOTNAMES=(); ROOTPKI=(); ROOTREL=(); INTERPKI=(); INTERREL=()
DEFPKI="${PKI_PREFIX#pki-}"
for DEST in "${DESTS[@]}"; do
  TAG=""
  if [ "${#DESTS[@]}" -gt 1 ]; then          # an older kit with one package per PKI: pki-<name>-<release tag>-<unique>  ->  <release tag>-
    TAG="$(basename "$DEST")"; TAG="${TAG#pki-}"; TAG="${TAG#"${PKI_PREFIX#pki-}"-}"; TAG="${TAG%-*}-"
  fi
  while IFS=$'\t' read -r role path hash _size _sha1 _store _ext _kind _name pkiname relname _rest; do
    case "$role" in root|intermediate) ;; *) continue ;; esac
    f="$DEST/$path"; [ -f "$f" ] || die "Missing in the package: $path"
    [ "$(sha "$f")" = "$hash" ] || die "Checksum mismatch (the package was changed or damaged): $path"
    [ -n "${pkiname:-}" ] || pkiname="$DEFPKI"
    if [ "$role" = root ]; then ROOTS+=("$f"); ROOTNAMES+=("$TAG$(basename "${f%.*}")"); ROOTPKI+=("$pkiname"); ROOTREL+=("${relname:-}"); else INTERS+=("$f"); INTERPKI+=("$pkiname"); INTERREL+=("${relname:-}"); fi
  done < <(grep -v '^#' "$DEST/certpack.tsv" | tr -d '\r')
done
[ "${#ROOTS[@]}" -gt 0 ] || die "No root certificate in the package."
ok "${#ROOTS[@]} root and ${#INTERS[@]} intermediate certificate(s), checksums fine."
PKILIST="$(printf '%s\n' "${ROOTPKI[@]}" "${INTERPKI[@]}" | sort -u)"
for pk in $PKILIST; do
  n=0; for x in "${ROOTPKI[@]}" "${INTERPKI[@]}"; do [ "$x" = "$pk" ] && n=$((n+1)); done
  info "  PKI $pk: $n CA certificate(s)"
done

# the name of a root in the system store:  pki-<company>-<...>.crt   (the company name first: Remove removes by it)
anchor_name() { local pk="$1" base="$2"; case "$base" in "pki-$pk-"*) echo "$base.crt" ;; pki-*) echo "pki-$pk-${base#pki-}.crt" ;; *) echo "pki-$pk-$base.crt" ;; esac; }

# ---- 5. replace the old version of each company in the package, install the roots
OLD=()
for pk in $PKILIST; do
  for f in "$ANCHOR/pki-$pk"-*.crt; do [ -f "$f" ] && OLD+=("$f"); done
  [ "$pk" = "$DEFPKI" ] && for f in "$ANCHOR/$PKI_PREFIX"-*.crt; do [ -f "$f" ] && OLD+=("$f"); done
  [ "$pk" = agantra ] && for f in "$ANCHOR"/agantra-pki-*.crt; do [ -f "$f" ] && OLD+=("$f"); done
done
info "${#OLD[@]} file(s) of an older version in $ANCHOR will be replaced."
STATE_DIR="${PKI_KIT_STATE_DIR:-/var/lib/pki-trust-kit}"
if [ "$CHECK" = 1 ]; then
  for i in "${!ROOTS[@]}"; do info "would install: ${ROOTPKI[$i]} / $(basename "${ROOTS[$i]}")"; done
else
  [ "${#OLD[@]}" -gt 0 ] && $SUDO rm -f "${OLD[@]}"
  $SUDO mkdir -p "$ANCHOR"
  ANCHORS=()
  for i in "${!ROOTS[@]}"; do
    an="$(anchor_name "${ROOTPKI[$i]}" "${ROOTNAMES[$i]}")"; ANCHORS+=("$ANCHOR/$an")
    $SUDO cp -f "${ROOTS[$i]}" "$ANCHOR/$an" || die "cannot copy to $ANCHOR"
    $SUDO chmod 644 "$ANCHOR/$an" 2>/dev/null
  done
  info "Running: $UPDATE"
  $SUDO $UPDATE 2>&1 | sed 's/^/        /'
  # read back: every root must be inside the system bundle
  miss=0
  if [ -r "$BUNDLE" ]; then
    for f in "${ROOTS[@]}"; do line="$(sed -n '2p' "$f" | tr -d '\r')"; grep -qF -- "$line" "$BUNDLE" || { miss=$((miss+1)); warn "not in $BUNDLE: $(basename "$f")"; }; done
    [ "$miss" = 0 ] && ok "Checked: all ${#ROOTS[@]} root(s) are in the system store ($BUNDLE)." || die "$miss root(s) are NOT in the system store."
  else warn "cannot read $BUNDLE to check the result."; fi
  # remember what was installed: remove-pki-ca.sh reads this list (pki, release, kind, path, name)
  REG="$STATE_DIR/installed.tsv"
  tmpreg="$(mktemp "${TMPDIR:-/tmp}/pki-reg.XXXXXX")"
  {
    printf '#update\t%s\t%s\n' "$UPDATE" "$ANCHOR"
    printf '# pki\trelease\tkind\tpath\tname\tinstalledUtc\n'
    # earlier lines stay, except those of a file that was just written again
    if [ -f "$REG" ]; then grep -v '^#' "$REG" | tr -d '\r' | while IFS=$'\t' read -r a b c d e g; do
      keep=1; for x in "${ANCHORS[@]}" "${ROOTS[@]}" "${INTERS[@]}"; do [ "$d" = "$x" ] && keep=0; done
      [ "$keep" = 1 ] && printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$a" "$b" "$c" "$d" "$e" "$g"; done; fi
    now="$(date -u '+%Y-%m-%d %H:%M')"
    for i in "${!ROOTS[@]}"; do printf '%s\t%s\tanchor\t%s\t%s\t%s\n' "${ROOTPKI[$i]}" "${ROOTREL[$i]}" "${ANCHORS[$i]}" "$(basename "${ROOTS[$i]}")" "$now"; done
    for i in "${!ROOTS[@]}"; do printf '%s\t%s\tfile\t%s\t%s\t%s\n' "${ROOTPKI[$i]}" "${ROOTREL[$i]}" "${ROOTS[$i]}" "$(basename "${ROOTS[$i]}")" "$now"; done
    for i in "${!INTERS[@]}"; do printf '%s\t%s\tfile\t%s\t%s\t%s\n' "${INTERPKI[$i]}" "${INTERREL[$i]}" "${INTERS[$i]}" "$(basename "${INTERS[$i]}")" "$now"; done
  } > "$tmpreg"
  $SUDO mkdir -p "$STATE_DIR" && $SUDO cp -f "$tmpreg" "$REG" && $SUDO chmod 644 "$REG" && info "Remembered in $REG (remove-pki-ca.sh --list shows it; --pki NAME or --all removes)." || warn "could not write $REG: remove-pki-ca.sh --org TEXT still works."
  rm -f "$tmpreg"
fi

# ---- 6. Firefox (optional)
if [ "$FIREFOX" = 1 ]; then
  H="${HOME:-}"; [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" = 0 ] && H="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  nprof=0
  for base in "$H/.mozilla/firefox" "$H/snap/firefox/common/.mozilla/firefox" "$H/.var/app/org.mozilla.firefox/.mozilla/firefox"; do
    [ -d "$base" ] || continue
    for p in "$base"/*/; do
      [ -f "$p/prefs.js" ] || continue; nprof=$((nprof+1))
      if [ "$CHECK" = 1 ]; then info "Firefox profile $(basename "$p"): would be set."; continue; fi
      grep -qs 'security.enterprise_roots.enabled' "$p/user.js" || echo 'user_pref("security.enterprise_roots.enabled", true);' >> "$p/user.js"
      if command -v certutil >/dev/null 2>&1; then
        for i in "${!ROOTS[@]}"; do nick="pki-${ROOTPKI[$i]} ${ROOTNAMES[$i]}"; certutil -A -d "sql:$p" -n "$nick" -t "CT,C,C" -i "${ROOTS[$i]}" >/dev/null 2>&1 && printf '%s\t%s\tfirefox\t%s\t%s\t%s\n' "${ROOTPKI[$i]}" "${ROOTREL[$i]}" "$p" "$nick" "$(date -u '+%Y-%m-%d %H:%M')" | $SUDO tee -a "$STATE_DIR/installed.tsv" >/dev/null; done
        ok "Firefox profile $(basename "$p"): enterprise roots on, ${#ROOTS[@]} root(s) imported."
      else ok "Firefox profile $(basename "$p"): enterprise roots on (certutil is not installed: that is enough for Firefox 120 and newer)."; fi
    done
  done
  [ "$nprof" = 0 ] && warn "Firefox: no profile found (start Firefox once, then run this again with --firefox)."
  pgrep -x firefox >/dev/null 2>&1 && warn "Firefox is running: close it and start it again."
fi

if [ "$CHECK" = 1 ]; then rm -rf "$OUT"; ok "Check finished: nothing was changed."; else ok "Done. The zip and the folder $OUT stay. Restart browsers / tools so they read the new certificates."; fi
exit 0
