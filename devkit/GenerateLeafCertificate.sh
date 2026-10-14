#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# GenerateLeafCertificate.sh - Linux / Ubuntu twin of GenerateLeafCertificate.ps1 (DevKit). Independent of PowerShell:
# bash + openssl. Classic only (Quadrant 1 = RSA, non-FIPS; Quadrant 2 = ECDSA, FIPS). Manual: docs/DevKit-MANUAL.txt
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
    PKI_TOOL_VERSION="5.3.6"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
VERSION="5.3.6"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"

usage() {
cat <<'EOF'
============================================================
 GenerateLeafCertificate.sh - leaf certificates from the DevKit (Linux / Ubuntu)
 Version 5.3.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Runs on: Linux only (VM, bare metal or WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+. Other systems: error, exit 5.
 Manual : docs/DevKit-MANUAL.txt      Windows twin: GenerateLeafCertificate.ps1
 Needs  : bash, openssl 3.0+ (4.0.1+ recommended). The PKI must be installed first: ./Install-PkiTrust.sh

USAGE
  ./GenerateLeafCertificate.sh --dns www.example.com                         OV set: one certificate per purpose
  ./GenerateLeafCertificate.sh --ev --dns api.example.com --purpose ServerAuth
  ./GenerateLeafCertificate.sh --dns app.example.com --add-development-san --no-revocation-info
  ./GenerateLeafCertificate.sh --purpose EmailProtection --email me@example.com

LEVEL AND TRACK
  --ov (default)  --ev  --dv          Level. EV: 397 days at most, CPS = ev-cps.pdf, no High Assurance policy.
  --quadrant 1|2   1 = Classic non-FIPS (default, RSA)    2 = Classic FIPS (ECDSA).   --fips = --quadrant 2
  (The Quantum quadrants 3 and 4 need the PowerShell generator.)

PURPOSES
  none given            the SET: one certificate per purpose (ServerAuth, ClientAuth, ServerClientAuth, CodeSigning,
                        EmailProtection, TimeStamping, OcspSigning), each in its own folder
  --purpose A,B         ONE certificate with these purposes (ServerAuth ClientAuth ServerClientAuth CodeSigning
                        EmailProtection TimeStamping OcspSigning; TimeStamping and OcspSigning stand alone)
  --exclude-purpose A,B take these out of the set

NAMES
  --dns a,b   --ip a,b   --email a,b   --cn TEXT
  --add-development-san    merge the development list (DNS, IP, e-mail of devkit.env) into the SAN. S/MIME gets the
                           e-mail addresses only, and ECDSA P-384 / SHA-512 by default (like GeneratePersonLeafCertificate).

KEY AND SIGNATURE
  --key-type rsa|ecdsa   --key-bits 2048|3072|4096|8192   --curve P-256|P-384|P-521   --hash sha256|sha384|sha512
  Defaults: Quadrant 1 RSA 2048, Quadrant 2 ECDSA P-256; code signing is raised to RSA 4096 / ECDSA P-384.
  --days N                 validity (default: OV and DV from the configuration, EV 397)

REVOCATION INFORMATION
  --no-crl                 no CRL distribution point in any generated certificate
  --no-ocsp                no OCSP URL (the caIssuers URL stays)
  --no-revocation-info     both

OUTPUT
  --out DIR                default ./leafcerts          --pfx-password TEXT   default Abc12345! (the lab password)
  --openssl FILE           use this openssl             --help, -h   this text      --version
  --release N              the release of the PKI (R1, R2 ...). Default: the LATEST. A deleted release = the latest, with a warning.
  --no-ca-revocation-info  use the NoCR family (CA certificates without CRL / OCSP). Default: the normal family.

Each folder: <name>.crt .key .pub .pfx -chain.crt -fullchain.crt leaf-info.json. Every certificate is verified against the
roots (chain, and no CRL / OCSP when you asked for none) before the script reports it. Serial numbers are random 128-bit.
Certificates made from a DevKit copy are NOT in the CRL / OCSP database of the master PKI: they are development certificates.
EOF
}

LEVEL=OV; QUAD=1; PURPOSES=""; EXCLUDE=""; DNS=""; IPS=""; MAILS=""; CN=""; DEVSAN=0
KEYTYPE=""; KEYBITS=""; CURVE=""; HASH=""; DAYS=""; NOCRL=0; NOOCSP=0; OUT="$PWD/leafcerts"; PFXPW='Abc12345!'; OSSL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ov) LEVEL=OV ;; --ev) LEVEL=EV ;; --dv) LEVEL=DV ;; --level) LEVEL="$(pki_uc "$2")"; shift ;;
    --quadrant) QUAD="$2"; shift ;; --fips) QUAD=2 ;; --classic) ;;
    --purpose) PURPOSES="$2"; shift ;; --exclude-purpose) EXCLUDE="$2"; shift ;;
    --dns) DNS="$2"; shift ;; --ip) IPS="$2"; shift ;; --email) MAILS="$2"; shift ;; --cn|--common-name) CN="$2"; shift ;;
    --add-development-san) DEVSAN=1 ;;
    --key-type) KEYTYPE="$(pki_lc "$2")"; shift ;; --key-bits) KEYBITS="$2"; shift ;; --curve) CURVE="$(pki_uc "$2")"; shift ;; --hash) HASH="$(pki_lc "$2")"; shift ;;
    --days) DAYS="$2"; shift ;;
    --no-crl) NOCRL=1 ;; --no-ocsp) NOOCSP=1 ;; --no-revocation-info) NOCRL=1; NOOCSP=1 ;;
    --release) PKI_WANT_REL="$2"; shift ;; --no-ca-revocation-info) PKI_WANT_NOCR=1 ;;
    --out) OUT="$2"; shift ;; --pfx-password) PFXPW="$2"; shift ;; --openssl) OSSL="$2"; shift ;;
    --version) echo "GenerateLeafCertificate.sh $VERSION"; exit 0 ;;
    --help|-h) usage; exit 0 ;;
    *) pki_die "unknown option '$1'. See ./GenerateLeafCertificate.sh --help" ;;
  esac; shift
done
pki_load_env; pki_find_openssl "$OSSL"
case "$LEVEL" in OV|EV|DV) ;; *) pki_die "level must be OV, EV or DV" ;; esac
case "$QUAD" in 1|2) ;; 3|4) pki_die "Quadrants 3 and 4 (Quantum, ML-DSA) need GenerateLeafCertificate.ps1." ;; *) pki_die "quadrant must be 1 or 2" ;; esac
[ -z "$HASH" ] || case "$HASH" in sha256|sha384|sha512) ;; *) pki_die "hash must be sha256, sha384 or sha512 (weaker hashes are rejected)" ;; esac

ALL_PURPOSES="ServerAuth ClientAuth ServerClientAuth CodeSigning EmailProtection TimeStamping OcspSigning"
SETMODE=0
if [ -z "$PURPOSES" ]; then
  SETMODE=1; PLIST=""
  for p in $ALL_PURPOSES; do
    skip=0; for x in $(pki_list "$EXCLUDE"); do [ "$(pki_lc "$x")" = "$(pki_lc "$p")" ] && skip=1; done
    [ $skip = 0 ] && PLIST="$PLIST $p"
  done
else PLIST="$(pki_list "$PURPOSES" | tr '\n' ' ')"; fi
for p in $PLIST; do case " $ALL_PURPOSES " in *" $p "*) ;; *) pki_die "unknown purpose '$p'. Use: $ALL_PURPOSES" ;; esac; done
[ -n "$(printf '%s' "$PLIST" | tr -d ' ')" ] || pki_die "no purpose left"
if [ $SETMODE = 0 ]; then
  case " $PLIST " in *" TimeStamping "*|*" OcspSigning "*) [ "$(echo $PLIST | wc -w)" -gt 1 ] && pki_die "TimeStamping and OcspSigning must be the ONLY purpose of their certificate." ;; esac
fi

# ---- names: yours stay first; development list merged after
add_unique() { # add_unique "<existing newline list>" item  (case-insensitive)
  local l="$1" i="$2"; if printf '%s\n' "$l" | grep -qixF -- "$i"; then printf '%s' "$l"; else printf '%s%s' "${l:+$l$'\n'}" "$i"; fi
}
USER_DNS="$(pki_list "$DNS")"; USER_IP="$(pki_list "$IPS")"; USER_MAIL="$(pki_list "$MAILS")"
GIVEN=0; [ -n "$USER_DNS$USER_IP$USER_MAIL" ] && GIVEN=1
if [ $GIVEN = 0 ]; then USER_DNS="$(pki_list "${LEAF_SAN_DNS:-}")"; USER_IP="$(pki_list "${LEAF_SAN_IP:-}")"; USER_MAIL="$(pki_list "${LEAF_SAN_EMAIL:-}")"; fi
validate_dns() { local d="$1"; printf '%s' "$d" | grep -Eq '^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$' || pki_die "invalid DNS name '$d'"; }
for d in $USER_DNS; do validate_dns "$d"; done
for m in $USER_MAIL; do printf '%s' "$m" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' || pki_die "invalid e-mail address '$m'"; done
DEV_DNS_L="$(pki_list "${DEV_SAN_DNS:-}")"; DEV_IP_L="$(pki_list "${DEV_SAN_IP:-}")"; DEV_MAIL_L="$(pki_list "${DEV_SAN_EMAIL:-}")"
[ $DEVSAN = 1 ] && pki_warn "--add-development-san: development DNS / IP / e-mail names are added (development only; not EV-conformant)."
BASE_CN="$CN"
if [ -z "$BASE_CN" ]; then BASE_CN="$(printf '%s\n' "$USER_DNS" | head -1)"; [ -n "$BASE_CN" ] || BASE_CN="$(printf '%s\n' "$USER_IP" | head -1)"; [ -n "$BASE_CN" ] || BASE_CN="$(printf '%s\n' "$USER_MAIL" | head -1)"; [ -n "$BASE_CN" ] || BASE_CN="${ORG_NAME:-Agantra}"; fi
SETNAME="$(printf '%s' "$BASE_CN" | sed 's/^\*/wildcard/; s/[^A-Za-z0-9._-]/-/g; s/^-*//; s/-*$//')"
OUT="${OUT%/}"

# ---- one certificate
# issue <purposes (space list)> <folder> <role-for-cn>
issue() {
  local plist="$1" dir="$2" token="$3" role="$4"
  local eku="" ku="digitalSignature" iscs=0 isemail=0 isweb=0 istsa=0 isocsp=0 extra="" p
  for p in $plist; do
    case "$p" in
      ServerAuth) eku="$eku${eku:+,}serverAuth"; isweb=1 ;;
      ClientAuth) eku="$eku${eku:+,}clientAuth"; [ $isemail = 0 ] && isweb=1 ;;
      ServerClientAuth) eku="$eku${eku:+,}serverAuth,clientAuth"; isweb=1 ;;
      CodeSigning) eku="$eku${eku:+,}codeSigning"; iscs=1 ;;
      EmailProtection) eku="$eku${eku:+,}emailProtection,clientAuth"; isemail=1; isweb=0 ;;
      TimeStamping) eku="critical,timeStamping"; istsa=1 ;;
      OcspSigning) eku="OCSPSigning"; isocsp=1; extra="1.3.6.1.5.5.7.48.1.5 = ASN1:NULL" ;;
    esac
  done
  # key
  local kt="$KEYTYPE" bits="$KEYBITS" cv="$CURVE" md
  if [ -z "$kt" ]; then if [ "$isemail" = 1 ] && [ "$DEVSAN" = 1 ]; then kt=ecdsa; elif [ "$QUAD" = 2 ]; then kt=ecdsa; else kt=rsa; fi; fi
  case "$kt" in
    rsa) [ -n "$bits" ] || bits=2048; case "$bits" in 2048|3072|4096|8192) ;; *) pki_die "RSA key size must be 2048, 3072, 4096 or 8192" ;; esac
         [ $iscs = 1 ] && [ "$bits" -lt 4096 ] && { pki_info "code signing: RSA $bits raised to 4096"; bits=4096; } ;;
    ecdsa) [ -n "$cv" ] || { if [ "$isemail" = 1 ] && [ "$DEVSAN" = 1 ]; then cv=P-384; else cv=P-256; fi; }
         case "$cv" in P-256|P-384|P-521) ;; *) pki_die "curve must be P-256, P-384 or P-521" ;; esac
         [ $iscs = 1 ] && [ "$cv" = P-256 ] && { pki_info "code signing: ECDSA P-256 raised to P-384"; cv=P-384; } ;;
    *) pki_die "key type must be rsa or ecdsa" ;;
  esac
  pki_ca_info "q$QUAD" "$(pki_lc "$LEVEL")"
  md="$CA_MD"; [ -n "$HASH" ] && md="$HASH"
  [ -z "$HASH" ] && [ "$isemail" = 1 ] && [ "$DEVSAN" = 1 ] && md=sha512
  # key usage
  [ "$isemail" = 1 ] && ku="$ku,nonRepudiation"
  [ "$kt" = ecdsa ] && [ "$isemail" = 1 ] && ku="$ku,keyAgreement"
  [ "$kt" = rsa ] && { [ "$isemail" = 1 ] || printf '%s' "$plist" | grep -q 'ServerAuth\|ServerClientAuth'; } && ku="$ku,keyEncipherment"
  # SAN
  local sdns="" sip="" smail=""
  if [ $isweb = 1 ]; then
    sdns="$USER_DNS"; sip="$USER_IP"; smail=""
    [ $GIVEN = 1 ] && smail="$USER_MAIL"
    if [ $DEVSAN = 1 ]; then for d in $DEV_DNS_L; do sdns="$(add_unique "$sdns" "$d")"; done; for a in $DEV_IP_L; do sip="$(add_unique "$sip" "$a")"; done; for m in $DEV_MAIL_L; do smail="$(add_unique "$smail" "$m")"; done; fi
  elif [ $isemail = 1 ]; then
    smail="$USER_MAIL"; [ -n "$smail" ] || smail="${CONTACT_EMAIL:-info@nextmantra.com}"
    if [ $DEVSAN = 1 ]; then for m in $DEV_MAIL_L; do smail="$(add_unique "$smail" "$m")"; done; fi
  fi
  [ "$LEVEL" = EV ] && [ $DEVSAN = 0 ] && { printf '%s' "$sdns" | grep -q '\*' && pki_die "EV: a wildcard name is not allowed (use --add-development-san for a development EV certificate, or a non-wildcard name)"; [ -n "$sip" ] && pki_die "EV: an IP address is not allowed in the SAN"; }
  # subject
  local cn="$BASE_CN"
  if [ -n "$role" ]; then cn="$BASE_CN $role"; fi
  [ $isemail = 1 ] && [ -z "$CN" ] && cn="$(printf '%s\n' "$smail" | head -1)"
  local dnvar="DN_$LEVEL" dn; dn="${!dnvar}"; dn="${dn//__CN__/$cn}"
  # days
  local dv="${DAYS}"; if [ -z "$dv" ]; then dvar="DAYS_$LEVEL"; dv="${!dvar}"; [ $istsa = 1 ] && dv="${TSA_DAYS:-1825}"; [ $isocsp = 1 ] && dv="${OCSP_DAYS:-365}"; [ "$LEVEL" = EV ] && [ "$dv" -gt 397 ] && dv=397; fi
  [ "$LEVEL" = EV ] && [ "$dv" -gt 397 ] && pki_die "an EV certificate may not be valid longer than 397 days"
  # stem
  local ktag; if [ "$kt" = rsa ]; then ktag="rsa$bits"; else ktag="ecdsa-$(printf '%s' "$cv" | tr -d '-' | tr 'P' 'p')"; fi
  local stem="$SETNAME-$token-$(pki_lc "$LEVEL")-q$QUAD-$ktag"
  mkdir -p "$dir"; local cnf="$dir/$stem.cnf"; pki_author_hdr > "$cnf"
  pki_write_dn "$cnf" "$dn"
  PCNT=0; pki_write_policies "$cnf" "$LEVEL"
  pki_write_location "$cnf" "$CA_SLUG" "$NOCRL" "$NOOCSP"
  if [ -n "$sdns$sip$smail" ]; then
    printf '[ san ]\n' >> "$cnf"; local n=0 x
    n=0; for x in $sdns; do n=$((n+1)); printf 'DNS.%s = %s\n' $n "$x" >> "$cnf"; done
    n=0; for x in $sip; do n=$((n+1)); printf 'IP.%s = %s\n' $n "$x" >> "$cnf"; done
    n=0; for x in $smail; do n=$((n+1)); printf 'email.%s = %s\n' $n "$x" >> "$cnf"; done
    printf '\n' >> "$cnf"
  fi
  {
    printf '[ ext ]\nbasicConstraints = critical,CA:false\nkeyUsage = critical,%s\nextendedKeyUsage = %s\n' "$ku" "$eku"
    printf 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n'
    [ -n "$sdns$sip$smail" ] && printf 'subjectAltName = @san\n'
    [ -n "$POLICY_REFS" ] && printf 'certificatePolicies = %s\n' "$POLICY_REFS"
    [ -n "$EXT_CRL" ] && printf '%s\n' "$EXT_CRL"
    [ -n "$EXT_AIA" ] && printf '%s\n' "$EXT_AIA"
    [ -n "$extra" ] && printf '%s\n' "$extra"
  } >> "$cnf"
  pki_gen_key "$dir/$stem.key" "$kt" "$bits" "$cv"
  pki_sign "$cnf" "$dir/$stem.key" "$dir/$stem.crt" "$dv" "$md"
  pki_package "$dir" "$stem" "$PFXPW"
  pki_verify "$dir/$stem.crt" "$NOCRL" "$NOOCSP"
  local sig; sig="$("$OPENSSL" x509 -in "$dir/$stem.crt" -noout -text | awk -F': ' '/Signature Algorithm/ {print $2; exit}')"
  printf '{\n  "tool": "GenerateLeafCertificate.sh %s",\n  "level": "%s", "quadrant": %s, "purposes": "%s",\n  "issuer": "%s", "serial": "%s", "signature": "%s",\n  "commonName": "%s", "days": %s,\n  "san": {"dns": %s, "ip": %s, "email": %s},\n  "revocationInfo": {"crlDistributionPoints": %s, "ocsp": %s},\n  "developmentSan": %s\n}\n' \
    "$VERSION" "$LEVEL" "$QUAD" "$plist" "$CA_SLUG" "$PKI_LAST_SERIAL" "$sig" "$cn" "$dv" \
    "$(printf '%s\n' "$sdns" | awk 'NF{printf "%s\"%s\"", (n++?",":"["), $0} END{print (n?"]":"[]")}')" \
    "$(printf '%s\n' "$sip" | awk 'NF{printf "%s\"%s\"", (n++?",":"["), $0} END{print (n?"]":"[]")}')" \
    "$(printf '%s\n' "$smail" | awk 'NF{printf "%s\"%s\"", (n++?",":"["), $0} END{print (n?"]":"[]")}')" \
    "$([ $NOCRL = 1 ] && echo false || echo true)" "$([ $NOOCSP = 1 ] && echo false || echo true)" "$([ $DEVSAN = 1 ] && echo true || echo false)" > "$dir/leaf-info.json"
  pki_log_issue "$OUT" leaf "$cn" "$dir/$stem.crt"
  printf '  %-17s %-12s %-5s %s\n' "$plist" "$(pki_uc "$kt")${bits:+-$bits}${cv:+-$cv}" "$dv" "$dir/$stem.crt"
}

[ $NOCRL = 1 ] || [ $NOOCSP = 1 ] && pki_warn "revocation information left out: $([ $NOCRL = 1 ] && echo 'no CRL distribution point')$([ $NOCRL = 1 ] && [ $NOOCSP = 1 ] && echo ', ')$([ $NOOCSP = 1 ] && echo 'no OCSP URL'). These certificates cannot be checked or revoked through the left-out service."
pki_info "Level $LEVEL, Quadrant $QUAD ($([ "$QUAD" = 2 ] && echo 'Classic FIPS' || echo 'Classic non-FIPS')), name '$BASE_CN'"
echo "  PURPOSE           KEY          DAYS  FILE"
if [ $SETMODE = 1 ]; then
  for p in $PLIST; do
    case "$p" in
      ServerAuth) tk=server; role="" ;; ClientAuth) tk=client; role="" ;; ServerClientAuth) tk=server-client; role="" ;;
      CodeSigning) tk=codesign; role="Code Signing" ;; EmailProtection) tk=email; role="" ;;
      TimeStamping) tk=timestamp; role="Time Stamping" ;; OcspSigning) tk=ocsp; role="OCSP Responder" ;;
    esac
    fld="$(pki_lc "$p")"; [ "$p" = ServerClientAuth ] && fld=serverauth-clientauth
    issue "$p" "$OUT/$SETNAME/$fld" "$tk" "$role"
  done
else
  tk=""; role=""
  for p in $PLIST; do
    case "$p" in ServerAuth) t=server ;; ClientAuth) t=client ;; ServerClientAuth) t=server-client ;; CodeSigning) t=codesign; role="Code Signing" ;;
      EmailProtection) t=email ;; TimeStamping) t=timestamp; role="Time Stamping" ;; OcspSigning) t=ocsp; role="OCSP Responder" ;; esac
    tk="$tk${tk:+-}$t"
  done
  [ "$(echo $PLIST | wc -w)" -gt 1 ] && role=""
  issue "$PLIST" "$OUT/$SETNAME" "$tk" "$role"
fi
pki_ok "done. Folder: $OUT/$SETNAME   (log: $OUT/issued-by-devkit.tsv)"
