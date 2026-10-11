#!/usr/bin/env bash
# pki-server.sh - Agantra Inovatif private PKI SERVER KIT for Ubuntu 24.04 / 26.04
# Publishes the CRLs and CA certificates, answers OCSP and RFC 3161 time stamp requests, all through YOUR nginx (PPA) and OpenSSL 4.
# Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
KIT_VERSION="1.1.0"
set -u
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------- locations (environment overrides exist for tests)
OPT_DIR="${PKI_SRV_OPT:-/opt/agantra-pki-server}"          # helper programs
ETC_DIR="${PKI_SRV_ETC:-/etc/agantra-pki-server}"          # configuration, responder and TSA keys
LIB_DIR="${PKI_SRV_LIB:-/var/lib/agantra-pki-server}"      # OCSP indexes, TSA serial
WWW_DIR="${PKI_SRV_WWW:-/srv/agantra-pki/www}"             # what the CRL / CA host serves
UNIT_DIR="${PKI_SRV_UNITS:-/etc/systemd/system}"
NGINX_ETC="${PKI_SRV_NGINX:-/etc/nginx}"
SVC_USER="pki-server"
PPA="ppa:nickotech2000/nicko-su-prod"
# what the PPA publishes (Launchpad API, amd64, Ubuntu 24.04 noble and 26.04 resolute): nicko-su-nginx 1.31.6, nicko-su-openssl4 4.0.3
NGINX_PKG="nicko-su-nginx"; OPENSSL_PKG="nicko-su-openssl4"; OPENSSL_BIN=""
NGINX_BIN=""; NGINX_SVC="nginx"
SOURCE=""; CNF=""; SERVER_IP=""; TSA_POLICY="1.3.6.1.4.1.67096.1.4"; TSA_POLICY_SET=0
OCSP_LEAVES=(); TSA_LEAF=""; CERTS=(); OUTDIR=""; KEYALGO="rsa"; TSA_CA=""
DRY=0; YES=0; NO_PPA=0; NO_SYSTEMD=0; NO_PACKAGES=0; BUILD_OPENSSL=0; PURGE=0
OCSP_BASE_PORT=25001; DISPATCH_PORT=2559; TSA_PORT=2560
CMD=""

# ---------------------------------------------------------------- output
if [ -t 1 ]; then C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_INF=$'\033[36m'; C_0=$'\033[0m'; else C_OK=""; C_WARN=""; C_ERR=""; C_INF=""; C_0=""; fi
info() { printf '%s[INFO]%s %s\n' "$C_INF" "$C_0" "$*"; }
ok()   { printf '%s[OK]%s   %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_0" "$*" >&2; }
die()  { printf '%s[ERROR]%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit "${2:-1}"; }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { if [ "$DRY" = 1 ]; then printf '  (dry-run) %s\n' "$*"; return 0; fi; "$@"; }
priv() { if [ "$(id -u)" = 0 ]; then "$@"; elif have sudo; then sudo "$@"; else die "root is needed: $*"; fi; }

usage() {
cat <<'EOF'
pki-server.sh  -  Agantra Inovatif PKI SERVER KIT  (Ubuntu 24.04 / 26.04)

WHAT IT DOES
  Turns one Ubuntu VM into the servers of your private PKI, on plain HTTP port 80 through nginx:
    CRL + CA certificates   http://crl-01.nextmantra.com/<ca>.crl   (host names are read from agantra_pki.cnf)
    OCSP                    http://ocsp.nextmantra.internal           one URL for ALL your CAs (one openssl responder per CA)
    Time stamping RFC 3161  http://tsa.nextmantra.internal            openssl ts, signed with your TimeStamping certificate
  nginx comes from YOUR PPA (default ppa:nickotech2000/nicko-su-prod), OpenSSL must be 4.0 or newer (PPA package, an existing
  install, or built by ../Install-DevEnvironment.sh (linux/ folder) with --build-openssl).

USAGE
  sudo ./pki-server.sh install --source <pki folder> --ocsp-leaf <leafcerts folder> --tsa-leaf <leafcerts folder> [options]
  sudo ./pki-server.sh update  --source <pki folder> ...        new CRLs / certificates / index.txt, keeps everything else
  ./pki-server.sh status | info | test | dns | crl-check | run | uninstall [--purge] | check

  KEYS STAY ON THE SERVER (recommended; the package from New-PkiServerPackage.ps1 has no private keys at all):
  1. sudo ./pki-server.sh csr --source <pki folder> --out ./csr        the server makes its OCSP / TSA keys + one CSR each
  2. (CA machine)  .\PkiRevocation.ps1 -Action SignCsr -Csr ocsp-q1-ev.csr -For Ocsp -Ca q1-ev     (and -For Tsa for the time stamp CSR)
  3. sudo ./pki-server.sh import-cert --cert ./signed/ocsp-q1-ev.crt --cert ./signed/tsa-q1-ev.crt
  4. sudo ./pki-server.sh install --source <pki folder>                 (finds the imported certificates by itself)

COMMANDS
  install      packages (PPA, nginx, python3, OpenSSL 4), service user, files, nginx site, systemd units, start, self-test
  update       the same without packages: copies the new PKI data, restarts the responders, reloads nginx
  status       services, ports, CRL expiry, the OCSP responders and the time stamp certificate
  test         end-to-end self-test: CRL download, one OCSP query per responder, one time stamp (create + verify)
  dns          the host names and the IP to put in your router (DNS records)
  crl-check    warns when a CRL expires soon (also run daily by a systemd timer)
  run          starts the responders, the dispatcher and the TSA in the FOREGROUND (containers, WSL, no systemd)
  check        read-only: what is installed, OpenSSL readiness
  csr          makes the keys + CSRs of the OCSP responders (one per issuing CA) and of the time stamp server, on THIS server (--out DIR)
  import-cert  installs the certificates signed from those CSRs (--cert FILE, repeat) and matches each to its key
  info         status + the DNS names
  uninstall    removes services, nginx site, helpers (--purge also keys, indexes and published files)

OPTIONS
  --source DIR         the PKI folder made by pki_setup.ps1 (the one that holds publish\ and the CA folders). Required.
  --ocsp-leaf DIR      a folder with OCSP-signing certificate(s) + .key (a leafcerts set, e.g. leafcerts\nextmantra.com).
                       Repeat for more CAs. Optional: <source>/ocsp, <source>/tsa and the imported certificates are found by themselves. Every certificate with the OCSP Signing purpose is matched to its issuing CA.
  --key-algo A         csr: rsa (2048, default) or ecdsa (P-256).   --tsa-ca ID   csr: the CA that signs the time stamp certificate (default: first -ev CA)
  --cert FILE          import-cert: a signed certificate (repeat)   --out DIR   csr: where the .csr files are written (default ./pki-server-csr)
  --tsa-leaf DIR       a folder with the TimeStamping certificate + .key (a leafcerts set or its timestamping folder).
  --cnf FILE           agantra_pki.cnf: the CRL / OCSP / CA-issuer URLs give the host names. Default: found next to the pki folder or in the package root.
  --server-ip IP       the IP shown by the dns command (default: the first address of this VM).
  --ppa PPA            default ppa:nickotech2000/nicko-su-prod        --no-ppa   do not add a PPA
  --nginx-package P    package name for nginx (default nicko-su-nginx; "nginx" for the Ubuntu one)
  --openssl-package P  package name of OpenSSL 4 in the PPA (default nicko-su-openssl4)
  --openssl PATH       use this openssl 4 binary
  --build-openssl      when no OpenSSL 4 exists: build it with ../Install-DevEnvironment.sh (linux/ folder) (FIPS + ML-DSA, long)
  --tsa-policy OID     time stamp policy OID (default: the policy found in the TSA certificate, else 1.3.6.1.4.1.67096.1.4)
  --no-packages        do not install anything with apt        --no-systemd   write the files, start nothing (use "run")
  --dry-run            show what would run                      --yes   no questions
  -h, --help           this text

NOTES
  * The CA private keys are NOT needed and NOT copied. Only public files, the index.txt of each CA, and the keys of the OCSP / TSA certificates.
  * WSL / testing: add the host names to C:\Windows\System32\drivers\etc\hosts (see "dns" and docs/PKI-SERVER-MANUAL.txt); run "run" when systemd is off.
  * CRLs are made on the machine that holds the CA keys (pki_setup.ps1). After a new CRL or after issuing / revoking certificates:
    copy the pki folder again and run "update". OCSP answers come from index.txt, so they follow the same update.
  * Certificates must carry the matching URLs: OCSP http://ocsp.nextmantra.internal, CRL http://crl-01.nextmantra.com/{ca}.crl ...
  * Details: docs/PKI-SERVER-MANUAL.txt and docs/PKI-Server-Design.txt (package root)
EOF
}

# ---------------------------------------------------------------- arguments
need() { [ $# -ge 2 ] && [ -n "$2" ] || die "option $1 needs a value"; }
[ $# -ge 1 ] || { usage; exit 0; }
CMD="$1"; shift
case "$CMD" in -h|--help|help) usage; exit 0 ;; esac
while [ $# -gt 0 ]; do
  case "$1" in
    --source) need "$@"; SOURCE="$2"; shift 2 ;;
    --ocsp-leaf) need "$@"; OCSP_LEAVES+=("$2"); shift 2 ;;
    --tsa-leaf) need "$@"; TSA_LEAF="$2"; shift 2 ;;
    --cnf) need "$@"; CNF="$2"; shift 2 ;;
    --server-ip) need "$@"; SERVER_IP="$2"; shift 2 ;;
    --ppa) need "$@"; PPA="$2"; shift 2 ;;
    --no-ppa) NO_PPA=1; shift ;;
    --nginx-package) need "$@"; NGINX_PKG="$2"; shift 2 ;;
    --openssl-package) need "$@"; OPENSSL_PKG="$2"; shift 2 ;;
    --openssl) need "$@"; OPENSSL_BIN="$2"; shift 2 ;;
    --build-openssl) BUILD_OPENSSL=1; shift ;;
    --tsa-policy) need "$@"; TSA_POLICY="$2"; TSA_POLICY_SET=1; shift 2 ;;
    --cert) need "$@"; CERTS+=("$2"); shift 2 ;;
    --out) need "$@"; OUTDIR="$2"; shift 2 ;;
    --key-algo) need "$@"; KEYALGO="$2"; shift 2 ;;
    --tsa-ca) need "$@"; TSA_CA="$2"; shift 2 ;;
    --no-packages) NO_PACKAGES=1; shift ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    --purge) PURGE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
done

# ---------------------------------------------------------------- helpers
SAVED="$ETC_DIR/kit.conf"
load_saved() { [ -f "$SAVED" ] && . "$SAVED"; return 0; }
cert_fp() {  # sha256 of the DER of a certificate file (PEM or DER)
  local f="$1" o="${OPENSSL_BIN:-openssl}"
  { "$o" x509 -in "$f" -outform DER 2>/dev/null || "$o" x509 -inform DER -in "$f" -outform DER 2>/dev/null; } | sha256sum | cut -d' ' -f1
}
lf() { sed -i 's/\r$//' "$@"; }
ver_ok() { local v; v="$("$1" version 2>/dev/null)"; [[ "$v" =~ ^OpenSSL\ ([0-9]+)\. ]] && [ "${BASH_REMATCH[1]}" -ge 4 ]; }

find_openssl() {
  local c
  local pk; pk="$(dpkg -L "$OPENSSL_PKG" 2>/dev/null | grep -E '/bin/openssl$' | head -1)"
  for c in "$OPENSSL_BIN" "$pk" "$(command -v openssl4 2>/dev/null)" /opt/openssl-4*/bin/openssl /usr/local/openssl-4*/bin/openssl /opt/openssl4/bin/openssl "$(command -v openssl 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && ver_ok "$c" && { OPENSSL_BIN="$c"; return 0; }
  done
  return 1
}
openssl_libdir() {   # a private lib folder of the OpenSSL package (empty when it uses the system library path)
  local p d l; p="$(dirname "$(dirname "$OPENSSL_BIN")")"
  for d in "$p/lib64" "$p/lib" "$p/lib/x86_64-linux-gnu"; do [ -e "$d/libssl.so.4" ] && { echo "$d"; return; }; done
  l="$(dpkg -L "$OPENSSL_PKG" 2>/dev/null | grep -E '/libssl\.so\.4$' | head -1)"; [ -n "$l" ] && case "$(dirname "$l")" in /lib/*|/usr/lib/*) ;; *) dirname "$l";; esac
}

ppa_packages() {   # binary packages published by the PPA (works with compressed apt lists)
  have apt-get || return 0
  local f
  while read -r f; do [ -n "$f" ] && /usr/lib/apt/apt-helper cat-file "$f" 2>/dev/null | sed -n 's/^Package: //p'; done \
    < <(apt-get indextargets --format '$(FILENAME) $(SITE)/$(RELEASE)' 'Created-By: Packages' 2>/dev/null | grep -i "${PPA#ppa:}\|$(echo "${PPA#ppa:}" | tr / ' ' | awk '{print $1}')" | awk '{print $1}')
}

# ---------------------------------------------------------------- hosts from agantra_pki.cnf
uri_hosts() {  # $1 = section name
  [ -f "$CNF" ] || return 0
  awk -v sec="[ $1 ]" 'BEGIN{on=0} /^\[/{on=($0==sec)} on && /^[A-Za-z;]*URI\.[0-9]+[ \t]*=/{sub(/^[^=]*=[ \t]*/,""); print}' "$CNF" \
   | sed -n 's#^[a-zA-Z]*://\([^/:]*\).*#\1#p' | sort -u
}
compute_hosts() {
  if [ -z "$CNF" ]; then for c in "$SOURCE/../agantra_pki.cnf" "$SOURCE/../../agantra_pki.cnf" "$KIT_DIR/../../agantra_pki.cnf" "$SAVED_CNF"; do [ -n "$c" ] && [ -f "$c" ] && { CNF="$c"; break; }; done; fi
  HOSTS_CRL="$(uri_hosts crl_urls; uri_hosts ca_issuer_urls)"; HOSTS_OCSP="$(uri_hosts ocsp_urls)"
  HOSTS_CRL="$(echo "$HOSTS_CRL" | sort -u | grep -v '^$')"; HOSTS_OCSP="$(echo "$HOSTS_OCSP" | sort -u | grep -v '^$')"
  [ -n "$HOSTS_CRL" ] || HOSTS_CRL=$'crl-01.nextmantra.com\ncrl-02.nextmantra.com\ncrl-dev.nextmantra.internal\npki.nextmantra.internal'
  [ -n "$HOSTS_OCSP" ] || HOSTS_OCSP=$'ocsp.nextmantra.internal\nocsp.nextmantra.com'
  HOSTS_TSA=$'tsa.nextmantra.internal\ntimestamp.nextmantra.internal'
}
SAVED_CNF=""

# nginx from the PPA: find its binary, service and configuration folder from the package file list (dpkg -L), not from guesses
detect_nginx() {
  local f
  if [ -n "$NGINX_PKG" ] && dpkg -s "$NGINX_PKG" >/dev/null 2>&1; then
    f="$(dpkg -L "$NGINX_PKG" 2>/dev/null | grep -E '/s?bin/nginx$' | head -1)"; [ -x "$f" ] && NGINX_BIN="$f"
    f="$(dpkg -L "$NGINX_PKG" 2>/dev/null | grep -E '/nginx\.conf$' | head -1)"; [ -n "$f" ] && [ -z "${PKI_SRV_NGINX:-}" ] && NGINX_ETC="$(dirname "$f")"
    f="$(dpkg -L "$NGINX_PKG" 2>/dev/null | grep -E '\.service$' | grep -i nginx | head -1)"; [ -n "$f" ] && NGINX_SVC="$(basename "$f" .service)"
  fi
  [ -n "$NGINX_BIN" ] && [ -x "$NGINX_BIN" ] || NGINX_BIN="$(command -v nginx 2>/dev/null)"
  [ -n "$NGINX_BIN" ] && info "nginx: $("$NGINX_BIN" -v 2>&1 | sed 's/.*: //')  [$NGINX_BIN]  service $NGINX_SVC  config $NGINX_ETC"
  return 0
}

# ---------------------------------------------------------------- packages
install_packages() {
  [ "$NO_PACKAGES" = 1 ] && { info "packages: skipped (--no-packages)"; return 0; }
  have apt-get || die "apt-get not found: this kit is for Ubuntu / Debian." 2
  export DEBIAN_FRONTEND=noninteractive
  priv apt-get update -y >/dev/null 2>&1 || warn "apt-get update reported errors"
  priv apt-get install -y ca-certificates curl python3 software-properties-common gnupg || die "base packages failed" 6
  if [ "$NO_PPA" = 0 ]; then
    local vid arch; vid="$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")"; arch="$(dpkg --print-architecture 2>/dev/null)"
    case "$vid" in 24.04|26.04) ;; *) warn "Ubuntu $vid: the PPA publishes for 24.04 (noble) and 26.04 (resolute) only";; esac
    [ "$arch" = amd64 ] || warn "architecture $arch: the PPA publishes amd64 only"
    info "adding $PPA"
    run priv add-apt-repository -y "$PPA" || die "cannot add $PPA (is the name right? use --ppa ppa:<owner>/<name>, or --no-ppa)" 6
    run priv apt-get update -y >/dev/null 2>&1
    local pk; pk="$(ppa_packages | sort -u | tr '\n' ' ')"
    if [ -n "$pk" ]; then ok "packages published by the PPA: $pk"; else warn "could not list the PPA packages (series not published yet?)"; fi
    case " $pk " in *" $NGINX_PKG "*) ;; *) [ -n "$pk" ] && warn "the PPA does not list $NGINX_PKG (it lists: $pk). Use --nginx-package." ;; esac
    case " $pk " in *" $OPENSSL_PKG "*) ;; *) [ -n "$pk" ] && warn "the PPA does not list $OPENSSL_PKG. Use --openssl-package or --openssl." ;; esac
  fi
  info "nginx package: $NGINX_PKG"
  run priv apt-get install -y "$NGINX_PKG" || die "cannot install $NGINX_PKG" 6
  if ! find_openssl && [ -n "$OPENSSL_PKG" ]; then
    info "OpenSSL 4 package: $OPENSSL_PKG"; run priv apt-get install -y "$OPENSSL_PKG" || warn "cannot install $OPENSSL_PKG"
  fi
  detect_nginx
  if ! find_openssl && [ "$BUILD_OPENSSL" = 1 ]; then
    [ -x "$KIT_DIR/../Install-DevEnvironment.sh (linux/ folder)" ] || die "--build-openssl needs ../Install-DevEnvironment.sh (linux/ folder) next to this kit" 6
    run bash "$KIT_DIR/../Install-DevEnvironment.sh (linux/ folder)" --yes --only openssl || die "OpenSSL build failed" 6
  fi
  return 0
}

# ---------------------------------------------------------------- the data
CA_IDS=(); declare -A CA_DIR CA_CRT CA_SLUG CA_PORT CA_RCRT CA_RKEY
scan_source() {
  [ -d "$SOURCE" ] || die "--source must be the pki folder (not found: '$SOURCE')"
  [ -d "$SOURCE/publish" ] || die "$SOURCE\\publish does not exist: this is not a pki folder made by pki_setup.ps1"
  local f fp; declare -A SLUGFP
  for f in "$SOURCE"/publish/*.crt "$SOURCE"/publish/*.pem; do [ -f "$f" ] || continue; case "$f" in *.crl.pem|*/ca-bundle.crt|*/root.crt) continue;; esac
    fp="$(cert_fp "$f")"; [ -n "$fp" ] && SLUGFP[$fp]="$(basename "${f%.*}")"; done
  local idx d cnf id n=0
  while IFS= read -r idx; do
    d="$(dirname "$idx")"
    cnf="$(ls "$d"/*.cnf 2>/dev/null | grep -v 'issuer.tmp' | head -1)"; [ -n "$cnf" ] || continue
    id="$(basename "$cnf" .cnf)"; [ -f "$d/$id.crt" ] || continue
    fp="$(cert_fp "$d/$id.crt")"
    CA_IDS+=("$id"); CA_DIR[$id]="$d"; CA_CRT[$id]="$d/$id.crt"; CA_SLUG[$id]="${SLUGFP[$fp]:-$id}"; n=$((n+1))
  done < <(find "$SOURCE" -name index.txt -not -path '*/publish/*' -not -path '*/leafcerts/*' | sort)
  [ "$n" -gt 0 ] || die "no CA folder (index.txt + <id>.cnf + <id>.crt) found under $SOURCE"
  ok "CAs found in the source: $n  ($(IFS=,; echo "${CA_IDS[*]}"))"
}

# a leaf certificate with a given extended key usage -> sets LEAF_CRT / LEAF_KEY lists
find_leaves() {   # $1 = purpose text ("OCSP Signing" / "Time Stamping"), $2.. = folders
  local want="$1"; shift; local d f stem
  FOUND=()
  for d in "$@"; do
    [ -d "$d" ] || die "not a folder: $d"
    while IFS= read -r f; do
      case "$f" in *-fullchain.crt|*-chain.crt) continue;; esac
      stem="${f%.crt}"; [ -f "$stem.key" ] || continue
      "$OPENSSL_BIN" x509 -in "$f" -noout -ext extendedKeyUsage 2>/dev/null | grep -q "$want" && FOUND+=("$f")
    done < <(find "$d" -name '*.crt' | sort)
  done
}
match_ca() {   # certificate -> id of the CA that issued it (issuer hash = CA subject hash), or empty
  local ih sh id
  ih="$("$OPENSSL_BIN" x509 -in "$1" -noout -issuer_hash 2>/dev/null)"
  for id in "${CA_IDS[@]}"; do sh="$("$OPENSSL_BIN" x509 -in "${CA_CRT[$id]}" -noout -subject_hash 2>/dev/null)"; [ "$ih" = "$sh" ] && { echo "$id"; return; }; done
}

install_keymat() {   # $1 = source cert, $2 = target base name -> cert + key into ETC/keys
  mkdir -p "$ETC_DIR/keys"
  cp "$1" "$ETC_DIR/keys/$2.crt"; cp "${1%.crt}.key" "$ETC_DIR/keys/$2.key"; lf "$ETC_DIR/keys/$2.crt" "$ETC_DIR/keys/$2.key"
  chmod 640 "$ETC_DIR/keys/$2.key"; chown "root:$SVC_USER" "$ETC_DIR/keys/$2.key" 2>/dev/null || true
  # key must match the certificate
  [ "$("$OPENSSL_BIN" x509 -in "$1" -noout -pubkey | sha256sum)" = "$("$OPENSSL_BIN" pkey -in "${1%.crt}.key" -pubout | sha256sum)" ] || die "the key does not match the certificate: $1"
}

publish_files() {
  info "publishing CRLs and CA certificates to $WWW_DIR"
  mkdir -p "$WWW_DIR"
  local f b
  for f in "$SOURCE"/publish/*; do [ -f "$f" ] || continue; b="$(basename "$f")"; case "$b" in README.txt) continue;; esac
    cp -f "$f" "$WWW_DIR/$b"; case "$b" in *.pem|root.crt|ca-bundle.crt) lf "$WWW_DIR/$b";; esac; done
  {
    echo '<!doctype html><meta charset="utf-8"><title>Agantra Inovatif PKI</title><body style="font:15px sans-serif;max-width:60em;margin:2em auto">'
    echo '<h1>Agantra Inovatif Enterprise PKI</h1><p>CA certificates and revocation lists. Install <a href="root.crt">root.crt</a> (Enterprise Root) on clients.</p><table cellpadding="4"><tr><th align=left>File</th><th align=left>Size</th></tr>'
    for f in "$WWW_DIR"/*; do b="$(basename "$f")"; [ "$b" = index.html ] && continue; echo "<tr><td><a href=\"$b\">$b</a></td><td>$(stat -c %s "$f")</td></tr>"; done
    echo '</table></body>'
  } > "$WWW_DIR/index.html"
  chmod -R a+rX "$WWW_DIR"
}

setup_ocsp() {
  info "OCSP responders"
  mkdir -p "$LIB_DIR/ocsp" "$ETC_DIR/ocsp"; : > "$ETC_DIR/ocsp-backends"
  local dirs=(); [ -d "$ETC_DIR/imported" ] && dirs+=("$ETC_DIR/imported"); dirs+=("${OCSP_LEAVES[@]}"); [ -d "$SOURCE/ocsp" ] && dirs+=("$SOURCE/ocsp")
  find_leaves "OCSP Signing" "${dirs[@]}"
  local n=0 crt id port kh
  declare -A done_ca=()
  for crt in "${FOUND[@]}"; do
    id="$(match_ca "$crt")"; [ -n "$id" ] || { warn "OCSP certificate $(basename "$crt"): its issuer is not a CA of this PKI - skipped"; continue; }
    [ -n "${done_ca[$id]:-}" ] && { warn "a second OCSP certificate for $id ($(basename "$crt")) ignored"; continue; }
    done_ca[$id]=1; port=$((OCSP_BASE_PORT+n)); n=$((n+1))
    install_keymat "$crt" "ocsp-$id"
    mkdir -p "$LIB_DIR/ocsp/$id"
    # openssl ocsp refuses an index whose valid entries share a subject (every leaf of one organization does): the subject column is not
    # needed for an answer (serial + status are), so it is replaced by the serial number in the copy used by the responder.
    tr -d '\r' < "${CA_DIR[$id]}/index.txt" | awk -F'\t' 'BEGIN{OFS="\t"} NF>=6{$6="/CN="$4} {print}' > "$LIB_DIR/ocsp/$id/index.txt"
    cp -f "${CA_CRT[$id]}" "$LIB_DIR/ocsp/$id/ca.crt"; lf "$LIB_DIR/ocsp/$id/ca.crt"
    cat > "$ETC_DIR/ocsp/$id.env" <<EOF
PORT=$port
CA_CRT=$LIB_DIR/ocsp/$id/ca.crt
INDEX=$LIB_DIR/ocsp/$id/index.txt
RCERT=$ETC_DIR/keys/ocsp-$id.crt
RKEY=$ETC_DIR/keys/ocsp-$id.key
EOF
    kh="$("$OPENSSL_BIN" ocsp -issuer "$LIB_DIR/ocsp/$id/ca.crt" -serial 0x01 -reqout "$LIB_DIR/ocsp/$id/probe.req" -no_nonce 2>/dev/null; python3 -I - "$LIB_DIR/ocsp/$id/probe.req" <<'PYEOF'
import sys
b = open(sys.argv[1], 'rb').read()
i = b.find(b'\x04\x14'); j = b.find(b'\x04\x14', i + 22) if i >= 0 else -1
print(b[j + 2:j + 22].hex() if j >= 0 else '')
PYEOF
)"; rm -f "$LIB_DIR/ocsp/$id/probe.req"
    echo "$port $kh" >> "$ETC_DIR/ocsp-backends"
    CA_IDS_OCSP+=("$id")
    ok "OCSP $id  (${CA_SLUG[$id]})  port $port  responder $(basename "$crt")"
  done
  [ "$n" -gt 0 ] || warn "no OCSP-signing certificate matched a CA: no OCSP responder. Make them with GenerateLeafCertificate.ps1 (-Purpose OcspSigning) and pass --ocsp-leaf."
  chmod -R a+rX "$LIB_DIR" 2>/dev/null; chown -R "$SVC_USER:$SVC_USER" "$LIB_DIR" 2>/dev/null || true
}
CA_IDS_OCSP=()

setup_tsa() {
  local dirs=(); [ -d "$ETC_DIR/imported" ] && dirs+=("$ETC_DIR/imported"); [ -n "$TSA_LEAF" ] && dirs+=("$TSA_LEAF"); [ -d "$SOURCE/tsa" ] && dirs+=("$SOURCE/tsa")
  [ "${#dirs[@]}" -gt 0 ] || { warn "no time stamp certificate (--tsa-leaf, <source>/tsa or import-cert): the time stamp service is not configured"; return 0; }
  info "time stamp authority"
  find_leaves "Time Stamping" "${dirs[@]}"
  [ "${#FOUND[@]}" -gt 0 ] || { warn "no certificate with the Time Stamping purpose (and its .key) found: no time stamp service. Run csr / import-cert."; return 0; }
  local crt="${FOUND[0]}" id; id="$(match_ca "$crt")"
  [ -n "$id" ] || die "the time stamp certificate was not issued by a CA of this PKI"
  "$OPENSSL_BIN" x509 -in "$crt" -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'critical' || warn "the time stamping extended key usage is not critical (RFC 3161 wants it)"
  case "$("$OPENSSL_BIN" x509 -in "$crt" -noout -text | grep -m1 'Public Key Algorithm')" in *rsa*|*id-ecPublicKey*) ;; *) warn "TSA key is not RSA / ECDSA: the kit signs with a SHA-256 digest, a post-quantum TSA is not supported here";; esac
  install_keymat "$crt" tsa
  if [ "$TSA_POLICY_SET" = 0 ]; then
    local pol; pol="$("$OPENSSL_BIN" x509 -in "$crt" -noout -ext certificatePolicies 2>/dev/null | grep -o 'Policy: [0-9.]*' | awk '{print $2}' | grep -E '\.1\.4$' | head -1)"
    [ -n "$pol" ] && TSA_POLICY="$pol"
  fi
  # chain for the reply: the certificates above the TSA certificate
  : > "$ETC_DIR/keys/tsa-chain.pem"; local cur="$id" par hops=0
  while [ -n "$cur" ] && [ "$hops" -lt 8 ]; do
    tr -d '\r' < "${CA_CRT[$cur]}" >> "$ETC_DIR/keys/tsa-chain.pem"
    par="$(match_ca "${CA_CRT[$cur]}")"; [ "$par" = "$cur" ] && break; cur="$par"; hops=$((hops+1))
  done
  mkdir -p "$LIB_DIR"; [ -f "$LIB_DIR/tsa.serial" ] || echo 01 > "$LIB_DIR/tsa.serial"
  cat > "$ETC_DIR/tsa.cnf" <<EOF
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = $LIB_DIR
serial = \$dir/tsa.serial
crypto_device = builtin
signer_cert = $ETC_DIR/keys/tsa.crt
certs = $ETC_DIR/keys/tsa-chain.pem
signer_key = $ETC_DIR/keys/tsa.key
signer_digest = sha256
default_policy = $TSA_POLICY
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF
  chown -R "$SVC_USER:$SVC_USER" "$LIB_DIR" 2>/dev/null || true
  ok "TSA certificate $(basename "$crt") issued by $id; policy $TSA_POLICY"
  TSA_OK=1
}
TSA_OK=0

write_helpers() {
  mkdir -p "$OPT_DIR"
  cp -f "$KIT_DIR/pki-ocsp-dispatch.py" "$KIT_DIR/pki-tsa.py" "$OPT_DIR/"; chmod 755 "$OPT_DIR"/*.py
  cat > "$OPT_DIR/ocsp-run" <<EOF
#!/usr/bin/env bash
# starts the OCSP responder of one CA:  ocsp-run <ca-id>
. "$ETC_DIR/ocsp/\$1.env" || exit 1
$( [ -n "$LIBDIR_OSSL" ] && echo "export LD_LIBRARY_PATH=\"$LIBDIR_OSSL\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\"" )
exec "$OPENSSL_BIN" ocsp -index "\$INDEX" -port "\$PORT" -rsigner "\$RCERT" -rkey "\$RKEY" -CA "\$CA_CRT" -ndays 1 -text
EOF
  cat > "$OPT_DIR/tsa-run" <<EOF
#!/usr/bin/env bash
$( [ -n "$LIBDIR_OSSL" ] && echo "export LD_LIBRARY_PATH=\"$LIBDIR_OSSL\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\"" )
exec python3 "$OPT_DIR/pki-tsa.py" "$OPENSSL_BIN" "$ETC_DIR/tsa.cnf" $TSA_PORT
EOF
  cat > "$OPT_DIR/dispatch-run" <<EOF
#!/usr/bin/env bash
exec python3 "$OPT_DIR/pki-ocsp-dispatch.py" "$ETC_DIR/ocsp-backends" $DISPATCH_PORT
EOF
  chmod 755 "$OPT_DIR/ocsp-run" "$OPT_DIR/tsa-run" "$OPT_DIR/dispatch-run"
  cp -f "$KIT_DIR/pki-server.sh" "$OPT_DIR/pki-server.sh"; chmod 755 "$OPT_DIR/pki-server.sh"
}
LIBDIR_OSSL=""

write_nginx() {
  local conf names V6=""
  [ -e /proc/net/if_inet6 ] && V6=" listen [::]:80;"
  mkdir -p "$NGINX_ETC"
  if [ -d "$NGINX_ETC/sites-available" ] && [ -d "$NGINX_ETC/sites-enabled" ]; then conf="$NGINX_ETC/sites-available/agantra-pki-server.conf"; else mkdir -p "$NGINX_ETC/conf.d"; conf="$NGINX_ETC/conf.d/agantra-pki-server.conf"; fi
  [ -f "$conf" ] && cp -f "$conf" "$conf.bak"
  {
    echo "# Agantra Inovatif PKI server kit $KIT_VERSION - written by pki-server.sh (re-written on every install / update)"
    echo "# CRL + CA certificates"
    echo "server {"
    echo "    listen 80;$V6"
    echo "    server_name $(echo $HOSTS_CRL);"
    echo "    root $WWW_DIR;"
    echo "    index index.html;"
    echo "    types { application/pkix-crl crl; application/pkix-cert crt cer; application/x-pem-file pem; text/html html; text/plain txt; }"
    echo "    default_type application/octet-stream;"
    echo "    location / { try_files \$uri \$uri/ =404; add_header Cache-Control \"public, max-age=3600\"; limit_except GET HEAD { deny all; } }"
    echo "    access_log /var/log/nginx/pki-crl.access.log; error_log /var/log/nginx/pki-crl.error.log;"
    echo "}"
    if [ "${#CA_IDS_OCSP[@]}" -gt 0 ]; then
      echo "# OCSP: one URL, the dispatcher asks every CA responder"
      echo "server {"
      echo "    listen 80;$V6"
      echo "    server_name $(echo $HOSTS_OCSP);"
      echo "    client_max_body_size 64k;"
      echo "    location / { limit_except GET POST { deny all; } proxy_pass http://127.0.0.1:$DISPATCH_PORT; proxy_http_version 1.0; proxy_set_header Connection close; proxy_read_timeout 15s; }"
      echo "    access_log /var/log/nginx/pki-ocsp.access.log; error_log /var/log/nginx/pki-ocsp.error.log;"
      echo "}"
    fi
    if [ "$TSA_OK" = 1 ]; then
      echo "# RFC 3161 time stamping"
      echo "server {"
      echo "    listen 80;$V6"
      echo "    server_name $(echo $HOSTS_TSA);"
      echo "    client_max_body_size 64k;"
      echo "    location / { limit_except GET POST { deny all; } proxy_pass http://127.0.0.1:$TSA_PORT; proxy_http_version 1.0; proxy_set_header Connection close; proxy_read_timeout 30s; }"
      echo "    access_log /var/log/nginx/pki-tsa.access.log; error_log /var/log/nginx/pki-tsa.error.log;"
      echo "}"
    fi
  } > "$conf"
  [ -d "$NGINX_ETC/sites-enabled" ] && [ "$(dirname "$conf")" = "$NGINX_ETC/sites-available" ] && ln -sf "$conf" "$NGINX_ETC/sites-enabled/agantra-pki-server.conf"
  NGINX_CONF="$conf"
  if [ -n "$NGINX_BIN" ]; then
    if [ "$DRY" = 0 ]; then
      if "$NGINX_BIN" -t >/dev/null 2>&1; then ok "nginx configuration OK ($conf)"
        "$NGINX_BIN" -T 2>/dev/null | grep -q 'agantra-pki-server.conf' || warn "this nginx.conf does not include $conf (no sites-enabled / conf.d include): add  include $conf;  inside http { }"
      else
        warn "nginx -t failed with the new site:"; "$NGINX_BIN" -t 2>&1 | sed 's/^/    /'
        if [ -f "$conf.bak" ]; then cp -f "$conf.bak" "$conf"; else rm -f "$conf" "$NGINX_ETC/sites-enabled/agantra-pki-server.conf"; fi
        die "the nginx site was rolled back" 1
      fi
    fi
  fi
}
NGINX_CONF=""

write_units() {
  [ "$NO_SYSTEMD" = 1 ] && { info "systemd: skipped (--no-systemd). Start everything with:  $OPT_DIR/pki-server.sh run"; return 0; }
  have systemctl || { warn "systemctl not found: use  pki-server.sh run"; return 0; }
  local id u="$UNIT_DIR"; mkdir -p "$u"
  local common="User=$SVC_USER
Group=$SVC_USER
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$LIB_DIR
Restart=on-failure
RestartSec=3"
  for id in "${CA_IDS_OCSP[@]}"; do
    cat > "$u/agantra-ocsp-$id.service" <<EOF
[Unit]
Description=Agantra PKI OCSP responder ($id)
After=network.target
PartOf=agantra-pki.target
[Service]
$common
ExecStart=$OPT_DIR/ocsp-run $id
[Install]
WantedBy=agantra-pki.target
EOF
  done
  if [ "${#CA_IDS_OCSP[@]}" -gt 0 ]; then cat > "$u/agantra-ocsp-dispatch.service" <<EOF
[Unit]
Description=Agantra PKI OCSP dispatcher (one URL for all CAs)
After=network.target
PartOf=agantra-pki.target
[Service]
$common
ExecStart=$OPT_DIR/dispatch-run
[Install]
WantedBy=agantra-pki.target
EOF
  fi
  if [ "$TSA_OK" = 1 ]; then cat > "$u/agantra-tsa.service" <<EOF
[Unit]
Description=Agantra PKI time stamp authority (RFC 3161)
After=network.target
PartOf=agantra-pki.target
[Service]
$common
ExecStart=$OPT_DIR/tsa-run
[Install]
WantedBy=agantra-pki.target
EOF
  fi
  cat > "$u/agantra-pki.target" <<EOF
[Unit]
Description=Agantra PKI servers (OCSP, time stamping)
[Install]
WantedBy=multi-user.target
EOF
  cat > "$u/agantra-crl-check.service" <<EOF
[Unit]
Description=Agantra PKI CRL expiry check
[Service]
Type=oneshot
ExecStart=$OPT_DIR/pki-server.sh crl-check
EOF
  cat > "$u/agantra-crl-check.timer" <<EOF
[Unit]
Description=Daily CRL expiry check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable agantra-pki.target agantra-crl-check.timer >/dev/null 2>&1
  for id in "${CA_IDS_OCSP[@]}"; do systemctl enable "agantra-ocsp-$id.service" >/dev/null 2>&1; systemctl restart "agantra-ocsp-$id.service"; done
  [ "${#CA_IDS_OCSP[@]}" -gt 0 ] && { systemctl enable agantra-ocsp-dispatch.service >/dev/null 2>&1; systemctl restart agantra-ocsp-dispatch.service; }
  [ "$TSA_OK" = 1 ] && { systemctl enable agantra-tsa.service >/dev/null 2>&1; systemctl restart agantra-tsa.service; }
  systemctl start agantra-crl-check.timer
  # services of CAs that are no longer configured
  local s; for s in "$u"/agantra-ocsp-*.service; do [ -e "$s" ] || continue; case "$s" in *dispatch*) continue;; esac
    id="$(basename "$s" .service)"; id="${id#agantra-ocsp-}"; [[ " ${CA_IDS_OCSP[*]} " == *" $id "* ]] || { systemctl disable --now "agantra-ocsp-$id.service" >/dev/null 2>&1; rm -f "$s"; }; done
  ok "systemd units started"
}

# ---------------------------------------------------------------- commands
do_install() {
  [ -n "$SOURCE" ] || die "--source <pki folder> is required (see --help)"
  [ "$(id -u)" = 0 ] || [ "$DRY" = 1 ] || die "run as root: sudo ./pki-server.sh $CMD ..."
  load_saved
  if [ "$CMD" = install ]; then install_packages; else info "update: packages are not touched"; fi
  [ "$CMD" = update ] || [ "$NO_PACKAGES" = 1 ] && detect_nginx
  find_openssl || die "OpenSSL 4.x not found. Install it from the PPA (--openssl-package), or --openssl PATH, or --build-openssl." 4
  LIBDIR_OSSL="$(openssl_libdir)"
  ok "OpenSSL: $("$OPENSSL_BIN" version | cut -d'(' -f1)  [$OPENSSL_BIN]"
  id "$SVC_USER" >/dev/null 2>&1 || run useradd --system --home-dir "$LIB_DIR" --shell /usr/sbin/nologin "$SVC_USER" || true
  mkdir -p "$ETC_DIR" "$LIB_DIR"
  [ "$DRY" = 1 ] && { info "dry-run: stopping here"; return 0; }
  scan_source; compute_hosts
  publish_files; setup_ocsp; setup_tsa; write_helpers; write_nginx; write_units
  cat > "$SAVED" <<EOF
OPENSSL_BIN="$OPENSSL_BIN"
SAVED_CNF="${CNF}"
NGINX_BIN="$NGINX_BIN"
NGINX_SVC="$NGINX_SVC"
NGINX_ETC="$NGINX_ETC"
NGINX_PKG="$NGINX_PKG"
OPENSSL_PKG="$OPENSSL_PKG"
EOF
  chmod 600 "$SAVED"
  if [ -n "$NGINX_BIN" ] && [ "$NO_SYSTEMD" = 0 ] && have systemctl; then systemctl enable "$NGINX_SVC" >/dev/null 2>&1; systemctl reload "$NGINX_SVC" 2>/dev/null || systemctl restart "$NGINX_SVC"; fi
  ok "installed (kit $KIT_VERSION)"
  [ "$NO_SYSTEMD" = 0 ] && do_test || true
  echo; do_dns
}

do_dns() {
  load_saved; [ -n "$SAVED_CNF" ] && [ -z "$CNF" ] && CNF="$SAVED_CNF"; compute_hosts
  local ip="$SERVER_IP"; [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -n "$ip" ] || ip="<this VM's IP>"
  echo "DNS: point these names to $ip (router / DNS server):"
  { echo "$HOSTS_CRL"; echo "$HOSTS_OCSP"; echo "$HOSTS_TSA"; } | sort -u | grep -v '^$' | while read -r h; do printf '  %-40s A  %s\n' "$h" "$ip"; done
  echo "Public names (nextmantra.com) need an override on your internal DNS: they resolve to the Internet otherwise."
}

http_get() { curl -sS -m 10 -o "$2" -w '%{http_code}' -H "Host: $1" "http://127.0.0.1${3:-}"; }

do_test() {
  load_saved; find_openssl || die "OpenSSL 4.x not found" 4
  [ -n "$SAVED_CNF" ] && [ -z "$CNF" ] && CNF="$SAVED_CNF"; compute_hosts
  local fails=0 t="$(mktemp -d)" host id
  host="$(echo "$HOSTS_CRL" | head -1)"
  if have curl && (ss -ltn 2>/dev/null | grep -q ':80 '); then
    local f; for f in "$WWW_DIR"/*.crl; do [ -f "$f" ] || continue
      if [ "$(http_get "$host" "$t/x" "/$(basename "$f")")" = 200 ] && "$OPENSSL_BIN" crl -inform DER -in "$t/x" -noout 2>/dev/null; then ok "CRL via nginx: $(basename "$f")"; else warn "CRL not served: $(basename "$f")"; fails=$((fails+1)); fi; done
  else warn "nginx is not listening on port 80: CRL download not tested"; fi
  # OCSP
  local port d serial
  if [ -s "$ETC_DIR/ocsp-backends" ]; then
    for id in $(ls "$ETC_DIR/ocsp" 2>/dev/null | sed -n 's/\.env$//p'); do
      d="$LIB_DIR/ocsp/$id"; serial="$(awk -F'\t' '$1=="V"{print $4; exit}' "$d/index.txt")"
      [ -n "$serial" ] || { info "OCSP $id: no valid certificate in index.txt to ask about"; continue; }
      local out; out="$("$OPENSSL_BIN" ocsp -issuer "$d/ca.crt" -serial "0x$serial" -url "http://127.0.0.1:$DISPATCH_PORT" -CAfile "$WWW_DIR/ca-bundle.crt" 2>&1)"
      if echo "$out" | grep -q ": good"; then ok "OCSP $id: serial $serial is good (signature verified)"; else warn "OCSP $id: $(echo "$out" | tr '\n' ' ' | cut -c1-200)"; fails=$((fails+1)); fi
    done
  fi
  # time stamp
  if [ -f "$ETC_DIR/tsa.cnf" ]; then
    echo "pki-server self-test $(date -u +%FT%TZ)" > "$t/data.txt"
    "$OPENSSL_BIN" ts -query -data "$t/data.txt" -sha256 -cert -out "$t/q.tsq" 2>/dev/null
    if curl -sS -m 20 -H 'Content-Type: application/timestamp-query' --data-binary @"$t/q.tsq" -o "$t/r.tsr" "http://127.0.0.1:$TSA_PORT/" 2>/dev/null \
       && "$OPENSSL_BIN" ts -verify -data "$t/data.txt" -in "$t/r.tsr" -CAfile "$ETC_DIR/keys/tsa-chain.pem" >/dev/null 2>&1; then ok "time stamp: reply created and verified"
    else warn "time stamp: failed (is agantra-tsa running?)"; fails=$((fails+1)); fi
  fi
  rm -rf "$t"
  [ "$fails" = 0 ] && ok "self-test passed" || { warn "self-test: $fails problem(s)"; return 1; }
}

do_crl_check() {
  load_saved; find_openssl || die "OpenSSL 4.x not found" 4
  local f n now left worst=0
  now=$(date +%s)
  for f in "$WWW_DIR"/*.crl; do [ -f "$f" ] || continue
    n="$("$OPENSSL_BIN" crl -inform DER -in "$f" -noout -nextupdate 2>/dev/null | sed 's/nextUpdate=//')"
    [ -n "$n" ] || { warn "$(basename "$f"): cannot read"; worst=1; continue; }
    left=$(( ( $(date -d "$n" +%s) - now ) / 86400 ))
    if [ "$left" -lt 0 ]; then warn "$(basename "$f"): EXPIRED $((-left)) day(s) ago - make a new CRL on the CA machine and run update"; worst=1
    elif [ "$left" -lt 14 ]; then warn "$(basename "$f"): expires in $left day(s)"; worst=1
    else ok "$(basename "$f"): $left day(s) left"; fi
  done
  return $worst
}

do_status() {
  load_saved; find_openssl; echo "kit $KIT_VERSION   openssl: ${OPENSSL_BIN:-not found}   nginx: ${NGINX_BIN:-missing}"
  if have systemctl && [ -d "$UNIT_DIR" ]; then local u; for u in $(ls "$UNIT_DIR" 2>/dev/null | grep -E '^agantra-(ocsp|tsa).*\.service$'); do printf '  %-40s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null)"; done; printf '  %-40s %s\n' "$NGINX_SVC" "$(systemctl is-active "$NGINX_SVC" 2>/dev/null)"; fi
  [ -f "$ETC_DIR/tsa.cnf" ] && echo "  TSA certificate: $("$OPENSSL_BIN" x509 -in "$ETC_DIR/keys/tsa.crt" -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
  local f; for f in "$ETC_DIR"/keys/ocsp-*.crt; do [ -f "$f" ] && echo "  OCSP responder:  $(basename "$f" .crt) $("$OPENSSL_BIN" x509 -in "$f" -noout -enddate 2>/dev/null)"; done
  do_crl_check || true
}

do_run() {
  load_saved; find_openssl || die "OpenSSL 4.x not found" 4
  local pids=() id
  for id in $(ls "$ETC_DIR/ocsp" 2>/dev/null | sed -n 's/\.env$//p'); do "$OPT_DIR/ocsp-run" "$id" >"$LIB_DIR/ocsp-$id.log" 2>&1 & pids+=($!); done
  [ -s "$ETC_DIR/ocsp-backends" ] && { "$OPT_DIR/dispatch-run" 2>"$LIB_DIR/dispatch.log" & pids+=($!); }
  [ -f "$ETC_DIR/tsa.cnf" ] && { "$OPT_DIR/tsa-run" 2>"$LIB_DIR/tsa.log" & pids+=($!); }
  info "running ${#pids[@]} process(es); Ctrl+C stops them"; trap 'kill "${pids[@]}" 2>/dev/null' INT TERM EXIT; wait
}

do_check() {
  load_saved; echo "OS: $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
  detect_nginx >/dev/null; [ -n "$NGINX_BIN" ] && echo "nginx: $("$NGINX_BIN" -v 2>&1 | sed 's/.*: //')  [$NGINX_BIN]" || echo "nginx: not installed"
  if find_openssl; then
    echo "openssl: $("$OPENSSL_BIN" version | cut -d'(' -f1)  [$OPENSSL_BIN]"
    "$OPENSSL_BIN" list -providers -provider fips 2>/dev/null | grep -qi fips && echo "  FIPS provider: loads" || echo "  FIPS provider: not loadable without a fipsmodule.cnf config (see Install-DevEnvironment.sh --check)"
    "$OPENSSL_BIN" list -signature-algorithms 2>/dev/null | grep -qi 'ML-DSA' && echo "  ML-DSA: yes" || echo "  ML-DSA: no"
  else echo "openssl 4.x: not found"; fi
  have python3 && echo "python3: $(python3 -V)" || echo "python3: missing"
  [ -f "$SAVED" ] && echo "kit installed: yes ($ETC_DIR)" || echo "kit installed: no"
}

do_uninstall() {
  [ "$(id -u)" = 0 ] || die "run as root"
  if have systemctl; then local s; for s in "$UNIT_DIR"/agantra-*; do [ -e "$s" ] || continue; systemctl disable --now "$(basename "$s")" >/dev/null 2>&1; rm -f "$s"; done; systemctl daemon-reload; fi
  rm -f "$NGINX_ETC/sites-enabled/agantra-pki-server.conf" "$NGINX_ETC/sites-available/agantra-pki-server.conf" "$NGINX_ETC/conf.d/agantra-pki-server.conf"
  [ -n "$NGINX_BIN" ] && "$NGINX_BIN" -t >/dev/null 2>&1 && { have systemctl && systemctl reload "$NGINX_SVC" 2>/dev/null; }
  rm -rf "$OPT_DIR"
  if [ "$PURGE" = 1 ]; then rm -rf "$ETC_DIR" "$LIB_DIR" "$(dirname "$WWW_DIR")"; userdel "$SVC_USER" 2>/dev/null; ok "removed, including keys, indexes and published files"
  else ok "removed services, nginx site and helpers. Kept: $ETC_DIR (keys), $LIB_DIR, $WWW_DIR  (--purge removes them)"; fi
}

# ---------------------------------------------------------------- keys on the server: csr / import-cert
do_csr() {
  [ -n "$SOURCE" ] || die "--source <pki folder> is required (see --help)"
  load_saved; find_openssl || die "OpenSSL 4.x not found (install it first: install --openssl-package, or --openssl PATH)" 4
  scan_source
  local out="${OUTDIR:-./pki-server-csr}" pend="$ETC_DIR/pending" id keyargs name subj tsaca="$TSA_CA" n=0
  case "$KEYALGO" in rsa) keyargs=(-algorithm RSA -pkeyopt rsa_keygen_bits:2048);; ecdsa) keyargs=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256);; *) die "--key-algo is rsa or ecdsa";; esac
  if [ "$DRY" = 1 ]; then info "dry-run: would write CSRs for ${#CA_IDS[@]} CA(s) into $out"; return 0; fi
  [ "$(id -u)" = 0 ] || die "run as root (the keys are kept in $pend, readable by root and $SVC_USER only)"
  mkdir -p "$out" "$pend"; chmod 750 "$pend"
  if [ -z "$tsaca" ]; then for id in "${CA_IDS[@]}"; do case "$id" in *-ev) tsaca="$id"; break;; esac; done; [ -n "$tsaca" ] || tsaca="${CA_IDS[0]}"; fi
  [[ " ${CA_IDS[*]} " == *" $tsaca "* ]] || die "--tsa-ca $tsaca is not a CA of this PKI (${CA_IDS[*]})"
  local list=() x; for x in "${CA_IDS[@]}"; do case "$x" in *root*) ;; *) list+=("$x");; esac; done   # root CAs sign CAs only: no OCSP responder for them
  for id in "${list[@]}" "TSA:$tsaca"; do
    case "$id" in TSA:*) id="${id#TSA:}"; name="tsa-$id"; subj="/C=EE/O=Agantra Inovatif OÜ/CN=Agantra Inovatif OU Time Stamping Authority";;
      *) name="ocsp-$id"; subj="/C=EE/O=Agantra Inovatif OÜ/CN=Agantra Inovatif OU OCSP Responder ($id)";; esac
    if [ -f "$pend/$name.key" ]; then info "$name: key already exists, the CSR is made again from it"; else
      "$OPENSSL_BIN" genpkey "${keyargs[@]}" -out "$pend/$name.key" 2>/dev/null || die "key generation failed ($name)"; fi
    lf "$pend/$name.key"; chmod 640 "$pend/$name.key"; chown "root:$SVC_USER" "$pend/$name.key" 2>/dev/null || true
    "$OPENSSL_BIN" req -new -utf8 -key "$pend/$name.key" -subj "$subj" -out "$out/$name.csr" 2>/dev/null || die "CSR failed ($name)"
    lf "$out/$name.csr"; n=$((n+1)); ok "$out/$name.csr"
  done
  echo
  echo "Next: copy the .csr files to the CA machine (they hold no secret) and sign them there:"
  echo "  .\\PkiRevocation.ps1 -Action SignCsr -Csr ocsp-<ca>.csr -For Ocsp -Ca <ca>        (the TSA one: -For Tsa -Ca $tsaca)"
  echo "Then copy the .crt files back and run:  sudo ./pki-server.sh import-cert --cert <file> [--cert <file> ...]"
}

do_import_cert() {
  [ "${#CERTS[@]}" -gt 0 ] || die "--cert <signed certificate> is required (repeat for more)"
  [ "$(id -u)" = 0 ] || [ "$DRY" = 1 ] || die "run as root"
  load_saved; find_openssl || die "OpenSSL 4.x not found" 4
  local c k pend="$ETC_DIR/pending" imp="$ETC_DIR/imported" pub got n=0 base kind
  for c in "${CERTS[@]}"; do
    [ -f "$c" ] || die "certificate not found: $c"
    pub="$("$OPENSSL_BIN" x509 -in "$c" -noout -pubkey 2>/dev/null | sha256sum)" || true
    got=""
    for k in "$pend"/*.key; do [ -f "$k" ] || continue
      [ "$("$OPENSSL_BIN" pkey -in "$k" -pubout 2>/dev/null | sha256sum)" = "$pub" ] && { got="$k"; break; }; done
    [ -n "$got" ] || { warn "$(basename "$c"): no key made by 'csr' on this server matches it - skipped"; continue; }
    if "$OPENSSL_BIN" x509 -in "$c" -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'OCSP Signing'; then kind=ocsp
    elif "$OPENSSL_BIN" x509 -in "$c" -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'Time Stamping'; then kind=tsa
    else warn "$(basename "$c"): it is neither an OCSP-signing nor a time stamping certificate - skipped"; continue; fi
    base="$(basename "$got" .key)"
    [ "$DRY" = 1 ] && { info "dry-run: $(basename "$c") -> $kind ($base)"; continue; }
    mkdir -p "$imp"; "$OPENSSL_BIN" x509 -in "$c" -out "$imp/$base.crt" 2>/dev/null || die "cannot read $c"
    cp -f "$got" "$imp/$base.key"; lf "$imp/$base.crt" "$imp/$base.key"
    chmod 640 "$imp/$base.key"; chown "root:$SVC_USER" "$imp/$base.key" 2>/dev/null || true
    chmod 750 "$imp" 2>/dev/null || true
    ok "$(basename "$c") imported as $kind certificate ($base); expires $("$OPENSSL_BIN" x509 -in "$c" -noout -enddate | cut -d= -f2)"; n=$((n+1))
  done
  [ "$DRY" = 1 ] || { [ "$n" -gt 0 ] && echo "Now run:  sudo ./pki-server.sh update --source <pki folder>" || die "nothing imported" 1; }
}

case "$CMD" in
  csr) do_csr ;;
  import-cert) do_import_cert ;;
  info) do_status; do_dns ;;
  install|update) do_install ;;
  status) do_status ;;
  test) do_test ;;
  dns) do_dns ;;
  crl-check) do_crl_check ;;
  run) do_run ;;
  check) do_check ;;
  uninstall) do_uninstall ;;
  *) die "unknown command '$CMD' (try --help)" ;;
esac
