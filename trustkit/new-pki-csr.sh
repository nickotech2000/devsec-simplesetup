#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# new-pki-csr.sh - make a private key and a certificate request (CSR) step by step, on the computer that needs the certificate (the DESTINATION).
# The twin of New-PkiCsr.ps1. STANDALONE: only bash and OpenSSL 3.x / 4.x (prepare-computer.sh installs it).
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
    echo "[INFO] $(basename "$0") version 5.2.6" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
VERSION="5.2.6"
DEVSAN_MARKER="add-development-san.pki-marker.invalid"

show_help() {
cat <<'EOF'
============================================================
 new-pki-csr.sh - make a key and a certificate request (CSR) step by step (for the DESTINATION computer)
 Version 5.2.6
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
WHAT IT DOES
  Asks you, one question after the other, for the data of the certificate, makes a PRIVATE KEY and a CSR on this computer, and writes both into a new folder.
  You send ONLY the .csr to the owner of the PKI (he signs it with SignCsr.ps1 / SignCsr.sh). The .key never leaves this computer.
  Standalone: it needs only bash and OpenSSL 3.x or 4.x (prepare-computer.sh installs it).

WHAT THE REQUEST IS FOR  (--type, asked first)
  leaf             a certificate for a server, a person, code signing or e-mail (default). Signed by SignCsr.ps1 / SignCsr.sh.
  intermediate-ca  the certificate of a NEW CA of your department. The request asks for CA:TRUE and key usage keyCertSign + cRLSign, carries NO names (no SAN) and NEVER the
                   development names. Company, country, department (OU) and the name of the CA (CN) are required; the key is RSA 4096 / 8192 or ECDSA P-384 / P-521
                   (not ML-DSA, not RSA 2048 / 3072, not P-256). The owner of the PKI signs it with SignExternalCa.ps1 (a Quadrant Root; SignCsr refuses a CA request).

THE STEPS (press Enter to skip an optional one)
   1 Common name (CN)      the host name of the server, or the name of the certificate            REQUIRED
   2 Company ID            the registration number of the company: becomes the SERIAL NUMBER of the subject
   3 Company               the official company name (O)           4 E-mail   5 Contact phone   6 Contact person
   7 Address (street)      8 City   9 State / province   10 Country (2 letters, e.g. EE, ID, DE)   11 Postal code
  12 EV information        business category (Private Organization | Government Entity | Business Entity | Non-Commercial Entity) and the
                           jurisdiction of registration (country, state, locality). Fill it and the CA signs an EV certificate.
  13 IANA PEN (optional)   your Private Enterprise Number: your company policy OID 1.3.6.1.4.1.<PEN>.1 is put in the request
  14 Names (SAN)           DNS names, IP addresses and e-mail addresses, ONE BY ONE (empty line = finished).
                           "Add the development names?" puts a marker in the request: the CA then adds its development SAN list (like -AddDevelopmentSAN).
  15 Key                   RSA 4096 + SHA-384 (default), RSA 2048 / 3072 / 8192, ECDSA P-256 / P-384 / P-521, ML-DSA-44 / 65 / 87 (OpenSSL 3.5+ or 4)

WHICH CERTIFICATE YOU GET  (the CA decides by what the request carries; Classic, Quadrant 1 unless it says otherwise)
   EV information complete (business category + jurisdiction country + company ID + state + city)  ->  an EV certificate
   a company (name + country) without EV information                                                   ->  an OV certificate
   only a common name                                                                                    ->  a DV certificate
   The CRL and OCSP addresses in the certificate are those of the CA that signs it.

RULES (the request is REFUSED here when it breaks one - the CA checks the same)
   RSA below 2048 bit, ECDSA below P-256, ML-DSA other than 44 / 65 / 87, a request hash below SHA-256 (SHA-1, SHA-224, MD5 ...) are rejected.
   Code signing needs RSA 4096+, ECDSA P-384+, ML-DSA-65+.

USAGE   new-pki-csr.sh [options]            (options skip the questions; with --non-interactive nothing is asked)
  --type leaf|intermediate-ca   --ou <department>
  --cn <name>  --company-id <id>  --company <name>  --email <addr>  --phone <no>  --contact <person>  --address <street>  --city <c>  --state <s>
  --country <XX>  --postal-code <code>
  --business-category <one of the four>  --jurisdiction-country <XX>  --jurisdiction-state <s>  --jurisdiction-locality <c>   (EV; default Country / State / City)
  --pen <number>   --san <name> (repeat, or comma list)   --add-development-san
  --purpose ServerAuth (default) | ClientAuth | ServerClientAuth | CodeSigning | EmailProtection
  --key rsa (default) | ecdsa | mldsa    --bits 2048|3072|4096|8192    --curve P-256|P-384|P-521    --mldsa 44|65|87    --digest SHA256|SHA384|SHA512
  --name <text> (folder and file name, default the CN)   --out <folder> (default ./csr-requests)   --openssl <path>
  --non-interactive   -h | --help

RESULT  (folder  csr-requests/<name>_<yyyymmdd-HHMMSS>/ )
  <name>.key   your private key - KEEP IT SECRET, never send it     <name>.csr   the request - send THIS one
  request-info.txt   what the request contains and which level it asks for     README.txt   what to do next

WHERE IT RUNS
  Linux: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE 15+ (VM, bare metal, WSL).
  The PowerShell twin for Windows: New-PkiCsr.ps1.     EXIT CODES   0 ok   1 error   4 OpenSSL not found   5 system not supported
============================================================
EOF
}

say() { local l="$1"; shift; local c=""; case "$l" in OK) c=$'\e[32m';; WARN) c=$'\e[33m';; ERROR) c=$'\e[31m';; INFO) c=$'\e[36m';; esac
        if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then printf '%s[%s] %s\e[0m\n' "$c" "$l" "$*"; else printf '[%s] %s\n' "$l" "$*"; fi; }
die() { say ERROR "$1"; exit "${2:-1}"; }

CTYPE=""; OU=""; PURPOSE_GIVEN=0; CN=""; COMPANY_ID=""; COMPANY=""; EMAIL=""; PHONE=""; CONTACT=""; ADDRESS=""; CITY=""; STATE=""; COUNTRY=""; POSTAL=""
BCAT=""; JCOUNTRY=""; JSTATE=""; JLOC=""; PEN=""; SANS=(); DEVSAN=0; PURPOSE="ServerAuth"
KEYTYPE="rsa"; BITS=4096; CURVE="P-384"; MLDSA=65; DIGEST="SHA384"; NAME=""; OUTDIR=""; OPENSSL_ARG=""; NONINT=0; KEYGIVEN=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help|-help|--Help|help) show_help; exit 0 ;;
    --type) CTYPE="$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')"; shift 2 ;;   --ou) OU="${2:-}"; shift 2 ;;
    --cn) CN="${2:-}"; shift 2 ;;            --company-id) COMPANY_ID="${2:-}"; shift 2 ;;   --company) COMPANY="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;      --phone) PHONE="${2:-}"; shift 2 ;;             --contact) CONTACT="${2:-}"; shift 2 ;;
    --address) ADDRESS="${2:-}"; shift 2 ;;  --city) CITY="${2:-}"; shift 2 ;;               --state) STATE="${2:-}"; shift 2 ;;
    --country) COUNTRY="${2:-}"; shift 2 ;;  --postal-code) POSTAL="${2:-}"; shift 2 ;;
    --business-category) BCAT="${2:-}"; shift 2 ;;  --jurisdiction-country) JCOUNTRY="${2:-}"; shift 2 ;;
    --jurisdiction-state) JSTATE="${2:-}"; shift 2 ;; --jurisdiction-locality) JLOC="${2:-}"; shift 2 ;;
    --pen) PEN="${2:-}"; shift 2 ;;
    --san) IFS=', ;' read -r -a __t <<< "${2:-}"; for x in "${__t[@]}"; do [ -n "$x" ] && SANS+=("$x"); done; shift 2 ;;
    --add-development-san) DEVSAN=1; shift ;;
    --purpose) PURPOSE="${2:-}"; PURPOSE_GIVEN=1; shift 2 ;;
    --key) KEYTYPE="$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')"; KEYGIVEN=1; shift 2 ;;
    --bits) BITS="${2:-}"; KEYGIVEN=1; shift 2 ;;  --curve) CURVE="${2:-}"; KEYGIVEN=1; shift 2 ;;
    --mldsa) MLDSA="${2:-}"; KEYGIVEN=1; shift 2 ;;  --digest) DIGEST="${2:-}"; KEYGIVEN=1; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;  --out) OUTDIR="${2:-}"; shift 2 ;;  --openssl) OPENSSL_ARG="${2:-}"; shift 2 ;;
    --non-interactive) NONINT=1; shift ;;
    *) die "Unknown option: $1   (new-pki-csr.sh --help)" ;;
  esac
done

echo "============================================================"
echo " new-pki-csr.sh - a key and a certificate request (CSR), step by step"
echo " Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com"
echo "============================================================"

# ---------------------------------------------------------------- OpenSSL
OSSL=""
for c in "$OPENSSL_ARG" "${PKI_OPENSSL:-}" openssl4 openssl /opt/openssl4/bin/openssl /usr/local/openssl4/bin/openssl; do
  [ -n "$c" ] || continue
  p="$(command -v "$c" 2>/dev/null || true)"; [ -n "$p" ] || continue
  v="$("$p" version 2>/dev/null | head -n1)"
  case "$v" in OpenSSL\ [3-9]*|OpenSSL\ [1-9][0-9]*) OSSL="$p"; OSSL_TEXT="$v"; break ;; esac
done
[ -n "$OSSL" ] || die "OpenSSL 3.x or 4.x was not found. Install it:  ./prepare-computer.sh   or give --openssl <path>." 4
OSSL_MAJOR="$(printf '%s' "$OSSL_TEXT" | sed -E 's/^OpenSSL ([0-9]+)\..*/\1/')"; OSSL_MINOR="$(printf '%s' "$OSSL_TEXT" | sed -E 's/^OpenSSL [0-9]+\.([0-9]+).*/\1/')"
say INFO "OpenSSL: $OSSL_TEXT  ($OSSL)"
# the PKI may already be installed on this computer (install-pki-ca.sh / ca-certificates): the request needs none of it, so nothing is required or changed
if [ -r /var/lib/pki-trust-kit/installed.tsv ]; then
  __names="$(awk -F'\t' '!/^#/ && $1 != "" && $1 != "pki" {print $1}' /var/lib/pki-trust-kit/installed.tsv | sort -u | paste -sd, - | sed 's/,/, /g')"
  [ -n "$__names" ] && say INFO "PKI already installed on this computer: $__names. The request does not need it; the certificate you get back will chain to it."
fi

# ---------------------------------------------------------------- the questions
INTERACTIVE=0; [ "$NONINT" = 0 ] && { [ -t 0 ] || [ "${PKI_FORCE_INTERACTIVE:-}" = 1 ]; } && INTERACTIVE=1
STEP=0
# ask <var> <label> [hint] [required 0|1] [check-function] [default]    (the variable already holding a value = given on the command line)
ask() {
  local var="$1" label="$2" hint="${3:-}" req="${4:-0}" chk="${5:-}" def="${6:-}" cur v m suffix
  cur="${!var}"; if [ -n "$cur" ]; then printf -v "$var" '%s' "$(printf '%s' "$cur" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"; return 0; fi
  if [ "$INTERACTIVE" = 0 ]; then printf -v "$var" '%s' "$def"; return 0; fi
  STEP=$((STEP+1))
  while true; do
    suffix=""; if [ -n "$def" ]; then suffix=" [$def]"; elif [ "$req" = 0 ]; then suffix=" (Enter = skip)"; fi
    echo; printf '\e[36mStep %s: %s\e[0m\n' "$STEP" "$label"; [ -n "$hint" ] && echo "         $hint"
    read -r -p "         >$suffix " v || eof_die
    v="$(printf '%s' "$v" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"; [ -n "$v" ] || v="$def"
    if [ -z "$v" ]; then if [ "$req" = 1 ]; then say WARN "This one is required."; continue; else printf -v "$var" '%s' ""; return 0; fi; fi
    if [ -n "$chk" ]; then m="$($chk "$v")"; if [ -n "$m" ]; then say WARN "$m"; continue; fi; fi
    printf -v "$var" '%s' "$v"; return 0
  done
}
eof_die() { echo; die "The input ended before all questions were answered. Give the values as options, or use --non-interactive." 1; }
chk_cn()      { if [ "${#1}" -gt 64 ]; then echo "At most 64 characters."; else case "$1" in */*|*\\*) echo "Without / and \\." ;; esac; fi; }
chk_mail()    { printf '%s' "$1" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' || echo "Not an e-mail address."; }
chk_phone()   { printf '%s' "$1" | grep -Eq '^\+?[0-9][0-9 ()./-]{4,30}$' || echo "Digits, spaces and + - ( ) only, e.g. +372 5555 1234."; }
chk_country() { printf '%s' "$1" | grep -Eq '^[A-Z]{2}$' || echo "Two UPPER-case letters (ISO 3166), e.g. EE, ID, DE."; }
chk_pen()     { printf '%s' "$1" | grep -Eq '^[1-9][0-9]{0,9}$' || echo "Digits only, e.g. 12345."; }

say INFO "Answer the questions one by one. Optional steps: press Enter to skip."
if [ -z "$CTYPE" ]; then
  if [ "$INTERACTIVE" = 1 ]; then
    STEP=$((STEP+1)); echo; printf '\e[36mStep %s: What is the request for?\e[0m\n' "$STEP"
    echo "           1. Leaf: a server, a person, code signing, e-mail (default)"; echo "           2. Intermediate CA: the certificate of a new CA of your department (no names, no development names)"
    while true; do read -r -p "         Number [1] " n || eof_die; [ -n "$n" ] || n=1; case "$n" in 1) CTYPE=leaf; break ;; 2) CTYPE=intermediate-ca; break ;; esac; say WARN "1 or 2."; done
  else CTYPE=leaf; fi
fi
case "$CTYPE" in leaf) ISCA=0 ;; intermediate-ca|intermediateca|ca) ISCA=1; CTYPE=intermediate-ca ;; *) die "--type is leaf or intermediate-ca." ;; esac
[ "$ISCA" = 1 ] && say INFO "Request for an INTERMEDIATE CA: CA:TRUE, no names, no development names. The owner of the PKI signs it with SignExternalCa.ps1."
if [ "$ISCA" = 1 ]; then ask CN "Name of the CA (CN), e.g. Dept Issuing CA G1" "Not the name of a CA of the PKI that signs you." 1 chk_cn
else ask CN "Common name (CN): the host name of the server, e.g. app.example.com" "For a person or a code signing certificate: the name." 1 chk_cn; fi
ask COMPANY_ID "Company ID / registration number (becomes the SERIAL NUMBER of the subject)" "e.g. 17344131. Needed for an EV certificate."
ask COMPANY "Company name (O)" "The official name, as registered." "$ISCA"
ask OU "Department (OU)" "e.g. IT Department. Required for a CA." "$ISCA"
ask EMAIL "Contact e-mail" "" 0 chk_mail
ask PHONE "Contact phone" "e.g. +372 5555 1234" 0 chk_phone
ask CONTACT "Contact person (full name)"
ask ADDRESS "Address (street and number)"
ask CITY "City"
ask STATE "State / province"
ask COUNTRY "Country (2 letters)" "e.g. EE, ID, DE. Needed with the company name." "$ISCA" chk_country
ask POSTAL "Postal code"

# EV information
EVASKED=0; [ -n "$BCAT$JCOUNTRY$JSTATE$JLOC" ] && EVASKED=1
CATS=("Private Organization" "Government Entity" "Business Entity" "Non-Commercial Entity")
if [ "$EVASKED" = 0 ] && [ "$INTERACTIVE" = 1 ]; then
  STEP=$((STEP+1)); echo; printf '\e[36mStep %s: EV information (extended validation)\e[0m\n' "$STEP"
  echo "         Fill it when the company is registered and you want an EV certificate. The CA then signs it as EV."
  read -r -p "         Fill the EV information now? (y/N) " a || eof_die; case "$a" in y|Y|yes|YES|Yes) EVASKED=1 ;; esac
fi
if [ "$EVASKED" = 1 ]; then
  if [ -z "$BCAT" ]; then
    if [ "$INTERACTIVE" = 1 ]; then
      echo "         Business category:"; for i in 0 1 2 3; do echo "           $((i+1)). ${CATS[$i]}"; done
      while true; do read -r -p "         Number [1] " n || eof_die; [ -n "$n" ] || n=1; case "$n" in [1-4]) BCAT="${CATS[$((n-1))]}"; break ;; esac; say WARN "1, 2, 3 or 4."; done
    else BCAT="${CATS[0]}"; fi
  fi
  ask JCOUNTRY "Jurisdiction of registration: country (2 letters)" "" 1 chk_country "$COUNTRY"
  ask JSTATE "Jurisdiction of registration: state / province" "" 0 "" "$STATE"
  ask JLOC "Jurisdiction of registration: locality (city)" "" 0 "" "$CITY"
fi
ask PEN "IANA Private Enterprise Number (PEN) of the company" "Optional. Your company policy OID 1.3.6.1.4.1.<PEN>.1 is put in the request." 0 chk_pen

# names (SAN), one by one
if [ "$ISCA" = 0 ] && [ "${#SANS[@]}" -eq 0 ] && [ "$INTERACTIVE" = 1 ] && [ "$PURPOSE" != CodeSigning ]; then
  STEP=$((STEP+1)); echo; printf '\e[36mStep %s: Names of the certificate (SAN), one by one\e[0m\n' "$STEP"
  if [ "$PURPOSE" = EmailProtection ]; then echo "         E-mail addresses. An empty line = finished."; else echo "         DNS names (also *.example.com), IP addresses. An empty line = finished."; fi
  k=0; while true; do k=$((k+1)); read -r -p "         name $k: " v || eof_die; v="$(printf '%s' "$v" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"; [ -n "$v" ] || break; SANS+=("$v"); done
fi
if [ "$ISCA" = 0 ] && [ "$DEVSAN" = 0 ] && [ "$INTERACTIVE" = 1 ]; then
  case "$PURPOSE" in ServerAuth|ClientAuth|ServerClientAuth|EmailProtection)
    echo; read -r -p "         Add the DEVELOPMENT names too (the CA adds its development list: local host names and IP ranges)? (y/N) " a || eof_die
    case "$a" in y|Y|yes|YES|Yes) DEVSAN=1 ;; esac ;; esac
fi

# the key (step 15)
if [ "$ISCA" = 1 ] && [ "$INTERACTIVE" = 1 ] && [ "$KEYGIVEN" = 0 ]; then
  STEP=$((STEP+1)); echo; printf '\e[36mStep %s: Key and hash of the CA\e[0m\n' "$STEP"
  i=0; for t in "RSA 4096 + SHA-384 (default)" "RSA 8192 + SHA-512" "ECDSA P-384 + SHA-384" "ECDSA P-521 + SHA-512"; do i=$((i+1)); echo "           $i. $t"; done
  while true; do read -r -p "         Number [1] " n || eof_die; [ -n "$n" ] || n=1; case "$n" in [1-4]) break ;; esac; say WARN "1 to 4."; done
  case "$n" in 2) BITS=8192; DIGEST=SHA512 ;; 3) KEYTYPE=ecdsa; CURVE=P-384 ;; 4) KEYTYPE=ecdsa; CURVE=P-521; DIGEST=SHA512 ;; esac
elif [ "$INTERACTIVE" = 1 ] && [ "$KEYGIVEN" = 0 ]; then
  STEP=$((STEP+1)); echo; printf '\e[36mStep %s: Key and hash\e[0m\n' "$STEP"
  i=0; for t in "RSA 4096 + SHA-384 (default)" "RSA 3072 + SHA-384" "RSA 2048 + SHA-256" "ECDSA P-256 + SHA-256" "ECDSA P-384 + SHA-384" "ECDSA P-521 + SHA-512" "ML-DSA-65 (quantum, OpenSSL 3.5+/4)" "ML-DSA-87 (quantum)" "ML-DSA-44 (quantum)"; do i=$((i+1)); echo "           $i. $t"; done
  while true; do read -r -p "         Number [1] " n || eof_die; [ -n "$n" ] || n=1; case "$n" in [1-9]) break ;; esac; say WARN "1 to 9."; done
  case "$n" in
    2) BITS=3072 ;; 3) BITS=2048; DIGEST=SHA256 ;;
    4) KEYTYPE=ecdsa; CURVE=P-256; DIGEST=SHA256 ;; 5) KEYTYPE=ecdsa; CURVE=P-384 ;; 6) KEYTYPE=ecdsa; CURVE=P-521; DIGEST=SHA512 ;;
    7) KEYTYPE=mldsa; MLDSA=65 ;; 8) KEYTYPE=mldsa; MLDSA=87 ;; 9) KEYTYPE=mldsa; MLDSA=44 ;;
  esac
fi

# ---------------------------------------------------------------- check what was given
ERRS=(); err() { ERRS+=("$1"); }
is_dns() { local n="$1"; n="${n#\*.}"; printf '%s' "$n" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$' && [ "${#n}" -le 253 ]; }
is_ip() {
  if printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    printf '%s' "$1" | awk -F. '{ for (i = 1; i <= 4; i++) if ($i > 255) exit 1 }'; return $?
  fi
  printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f:]+$' && [ "$(printf '%s' "$1" | tr -cd ':' | wc -c)" -ge 2 ]
}
DNS=(); IPS=(); MAILS=()
has() { local x="$1"; shift; local e; for e in "$@"; do [ "${e,,}" = "${x,,}" ] && return 0; done; return 1; }
for n in "${SANS[@]}"; do
  if printf '%s' "$n" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'; then has "$n" "${MAILS[@]}" || MAILS+=("$n")
  elif is_ip "$n"; then has "$n" "${IPS[@]}" || IPS+=("$n")
  elif is_dns "$n"; then has "$n" "${DNS[@]}" || DNS+=("$n")
  else err "'$n' is not a DNS name, an IP address or an e-mail address."; fi
done
[ "${#CN}" -gt 64 ] && err "The common name is longer than 64 characters."
case "$CN" in */*|*\\*) err "The common name contains / or \\." ;; esac
[ -n "$CN" ] || err "The common name (CN) is required."
{ [ -n "$COMPANY" ] && [ -z "$COUNTRY" ]; } || { [ -n "$COUNTRY" ] && [ -z "$COMPANY" ]; } && err "The company name and the country go together: give both, or neither (then the request carries the common name only)."
[ -n "$COUNTRY" ] && ! printf '%s' "$COUNTRY" | grep -Eq '^[A-Z]{2}$' && err "Country: two UPPER-case letters."
[ -n "$EMAIL" ] && ! printf '%s' "$EMAIL" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' && err "The e-mail address is not valid."
[ -n "$PEN" ] && ! printf '%s' "$PEN" | grep -Eq '^[1-9][0-9]{0,9}$' && err "IANA PEN: digits only."
case "$PURPOSE" in ServerAuth|ClientAuth|ServerClientAuth|CodeSigning|EmailProtection) : ;; *) err "Purpose '$PURPOSE' is not one of ServerAuth, ClientAuth, ServerClientAuth, CodeSigning, EmailProtection." ;; esac
if [ "$EVASKED" = 1 ]; then
  [ -n "$COMPANY_ID" ] || err "EV information needs: Company ID (serial number)."; [ -n "$COMPANY" ] || err "EV information needs: Company."
  [ -n "$COUNTRY" ] || err "EV information needs: Country."; [ -n "$STATE" ] || err "EV information needs: State / province."; [ -n "$CITY" ] || err "EV information needs: City."
  [ -n "$BCAT" ] || err "EV information needs: Business category."; [ -n "$JCOUNTRY" ] || err "EV information needs: Jurisdiction country."
  ok=0; for c in "${CATS[@]}"; do [ "$c" = "$BCAT" ] && ok=1; done; [ "$ok" = 1 ] || err "BusinessCategory must be one of: ${CATS[*]// /_}  (Private Organization | Government Entity | Business Entity | Non-Commercial Entity)"
  [ -n "$JCOUNTRY" ] && ! printf '%s' "$JCOUNTRY" | grep -Eq '^[A-Z]{2}$' && err "Jurisdiction country: two UPPER-case letters."
  for d in "${DNS[@]}"; do case "$d" in *\**) err "An EV certificate may not have a wildcard name." ;; esac; done
fi
for v in "$CN" "$COMPANY" "$COMPANY_ID" "$CONTACT" "$ADDRESS" "$CITY" "$STATE" "$POSTAL" "$PHONE" "$EMAIL"; do case "$v" in *$'\n'*|*$'\r'*) err "A value contains a line break."; break ;; esac; done
# an intermediate CA request
if [ "$ISCA" = 1 ]; then
  [ "$DEVSAN" = 1 ] && err "An intermediate CA may not have the development names: --add-development-san is refused for --type intermediate-ca."
  [ "${#SANS[@]}" -gt 0 ] && err "A request for an intermediate CA carries no names (--san)."
  [ "$PURPOSE_GIVEN" = 1 ] && err "--purpose is for a leaf certificate; a CA request has none."
  [ -n "$COMPANY" ] || err "A CA request needs: Company (O)."; [ -n "$OU" ] || err "A CA request needs: Department (OU)."; [ -n "$COUNTRY" ] || err "A CA request needs: Country."
  [ "$KEYTYPE" = mldsa ] && err "A CA of this PKI is Classic: ML-DSA is refused for an intermediate CA request (RSA 4096 / 8192 or ECDSA P-384 / P-521)."
  if [ "$KEYTYPE" = rsa ] && [ "${BITS:-0}" -ge 2048 ] && [ "$BITS" != 4096 ] && [ "$BITS" != 8192 ]; then err "RSA $BITS bit is too small for a CA: 4096 or 8192."; fi
  [ "$KEYTYPE" = ecdsa ] && [ "$(printf '%s' "$CURVE" | tr 'a-z' 'A-Z' | sed -E 's/^P-?/P-/')" = P-256 ] && err "Curve P-256 is too small for a CA: P-384 or P-521."
fi
# the key and the hash
DIGEST="$(printf '%s' "$DIGEST" | tr 'a-z' 'A-Z' | tr -d '-')"
case "$DIGEST" in SHA256|SHA384|SHA512) : ;; *) err "Hash $DIGEST is refused: SHA256, SHA384 or SHA512 (SHA-1, SHA-224 and MD5 are below SHA-256)." ;; esac
STRONG=0; [ "$PURPOSE" = CodeSigning ] && STRONG=1
case "$KEYTYPE" in
  rsa)
    printf '%s' "$BITS" | grep -Eq '^[0-9]+$' || BITS=0
    if [ "$BITS" -lt 2048 ]; then err "RSA $BITS bit is refused: the minimum is 2048."
    elif [ "$BITS" != 2048 ] && [ "$BITS" != 3072 ] && [ "$BITS" != 4096 ] && [ "$BITS" != 8192 ]; then err "RSA $BITS bit is not a size of this PKI: 2048, 3072, 4096 or 8192."
    elif [ "$STRONG" = 1 ] && [ "$BITS" -lt 4096 ]; then err "Code signing needs RSA 4096 or more."; fi ;;
  ecdsa)
    CURVE="$(printf '%s' "$CURVE" | tr 'a-z' 'A-Z' | sed -E 's/^P-?/P-/')"
    case "$CURVE" in P-256) [ "$STRONG" = 1 ] && err "Code signing needs ECDSA P-384 or P-521." ;; P-384|P-521) : ;; *) err "Curve $CURVE is refused: P-256, P-384 or P-521." ;; esac ;;
  mldsa)
    case "$MLDSA" in 44) [ "$STRONG" = 1 ] && err "Code signing needs ML-DSA-65 or 87." ;; 65|87) : ;; *) err "ML-DSA-$MLDSA is refused: 44, 65 or 87." ;; esac
    if ! { [ "$OSSL_MAJOR" -ge 4 ] || { [ "$OSSL_MAJOR" -eq 3 ] && [ "$OSSL_MINOR" -ge 5 ]; }; }; then err "ML-DSA needs OpenSSL 3.5 or 4 (this is $OSSL_TEXT). prepare-computer.sh / Install-DevEnvironment.sh install a newer one."; fi ;;
  *) err "Key type '$KEYTYPE' is not rsa, ecdsa or mldsa." ;;
esac
[ "$ISCA" = 0 ] && case "$PURPOSE" in ServerAuth|ServerClientAuth|ClientAuth)
  if [ "${#DNS[@]}" -eq 0 ] && [ "${#IPS[@]}" -eq 0 ] && [ "$DEVSAN" = 0 ]; then
    if [ -n "$CN" ] && is_dns "$CN" && ! printf '%s' "$CN" | grep -q '[[:space:]]'; then DNS+=("$CN"); say INFO "No names given: the common name '$CN' is the DNS name."
    else err "A TLS certificate needs at least one DNS name or IP address (--san), or the development names."; fi
  fi ;; esac
if [ "$ISCA" = 0 ] && [ "$PURPOSE" = EmailProtection ] && [ "${#MAILS[@]}" -eq 0 ] && [ "$DEVSAN" = 0 ]; then
  if printf '%s' "$CN" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'; then MAILS+=("$CN"); elif [ -n "$EMAIL" ]; then MAILS+=("$EMAIL"); else err "An S/MIME certificate needs an e-mail address (--san or --email)."; fi
fi
if [ "${#ERRS[@]}" -gt 0 ]; then echo; for e in "${ERRS[@]}"; do say ERROR "$e"; done; die "The request was NOT made. Correct the points above and run again." 1; fi

# ---------------------------------------------------------------- make it
[ -n "$NAME" ] || NAME="$CN"
SAFE="$(printf '%s' "$NAME" | sed -E 's/^\*\./wildcard./; s/[^A-Za-z0-9._-]+/-/g; s/^[-.]+//; s/[-.]+$//')"; [ -n "$SAFE" ] || SAFE="request"
BASE="${OUTDIR:-$PWD/csr-requests}"; STAMP="$(date +%Y%m%d-%H%M%S)"
DIR="$BASE/${SAFE}_$STAMP"; mkdir -p "$DIR" || die "Cannot make $DIR"
KEYF="$DIR/$SAFE.key"; CSRF="$DIR/$SAFE.csr"; CNF="$DIR/req.tmp.cnf"
trap 'rm -f "$CNF"' EXIT

q() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//\$/\\\$}"; s="${s//#/\\#}"; printf '"%s"' "$s"; }
{
  printf '[ req ]\ndistinguished_name = dn\nreq_extensions = ext\nprompt = no\nutf8 = yes\nstring_mask = utf8only\n\n[ dn ]\n'
  dn() { [ -n "$2" ] && printf '%s = %s\n' "$1" "$(q "$2")"; return 0; }
  dn C "$COUNTRY"; dn ST "$STATE"; dn L "$CITY"; dn street "$ADDRESS"; dn postalCode "$POSTAL"
  dn O "$COMPANY"; dn OU "$OU"; dn name "$CONTACT"; dn emailAddress "$EMAIL"; dn telephoneNumber "$PHONE"
  [ -n "$COMPANY" ] && dn serialNumber "$COMPANY_ID"
  dn CN "$CN"
  if [ "$EVASKED" = 1 ]; then dn businessCategory "$BCAT"; dn jurisdictionC "$JCOUNTRY"; dn jurisdictionST "$JSTATE"; dn jurisdictionL "$JLOC"; fi
  printf '\n[ ext ]\n'
  HASSAN=0; [ "$ISCA" = 0 ] && { [ $(( ${#DNS[@]} + ${#IPS[@]} + ${#MAILS[@]} )) -gt 0 ] || [ "$DEVSAN" = 1 ]; } && HASSAN=1
  [ "$ISCA" = 1 ] && printf 'basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n'
  [ "$HASSAN" = 1 ] && printf 'subjectAltName = @alt\n'
  [ -n "$PEN" ] && printf 'certificatePolicies = 1.3.6.1.4.1.%s.1\n' "$PEN"
  if [ "$HASSAN" = 1 ]; then
    printf '\n[ alt ]\n'; i=0; for d in "${DNS[@]}"; do i=$((i+1)); printf 'DNS.%s = %s\n' "$i" "$d"; done
    [ "$DEVSAN" = 1 ] && { i=$((i+1)); printf 'DNS.%s = %s\n' "$i" "$DEVSAN_MARKER"; }
    i=0; for a in "${IPS[@]}"; do i=$((i+1)); printf 'IP.%s = %s\n' "$i" "$a"; done
    i=0; for m in "${MAILS[@]}"; do i=$((i+1)); printf 'email.%s = %s\n' "$i" "$m"; done
  fi
} > "$CNF"

fail() { rm -rf "$DIR"; die "$1" 1; }
umask 077
say INFO "Making the private key ..."
case "$KEYTYPE" in
  rsa)   "$OSSL" genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$BITS" -out "$KEYF" >/dev/null 2>"$DIR/.err" ;;
  ecdsa) "$OSSL" genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVE" -pkeyopt ec_param_enc:named_curve -out "$KEYF" >/dev/null 2>"$DIR/.err" ;;
  mldsa) "$OSSL" genpkey -algorithm "ML-DSA-$MLDSA" -out "$KEYF" >/dev/null 2>"$DIR/.err" ;;
esac
[ -s "$KEYF" ] || fail "OpenSSL could not make the key: $(tail -n2 "$DIR/.err" | tr '\n' ' ')"
say INFO "Making the request ..."
REQARGS=(req -new -key "$KEYF" -config "$CNF" -out "$CSRF"); [ "$KEYTYPE" != mldsa ] && REQARGS+=("-$(printf '%s' "$DIGEST" | tr 'A-Z' 'a-z')")
"$OSSL" "${REQARGS[@]}" >/dev/null 2>"$DIR/.err"
[ -s "$CSRF" ] || fail "OpenSSL could not make the request: $(tail -n3 "$DIR/.err" | tr '\n' ' ')"
"$OSSL" req -in "$CSRF" -noout -verify >/dev/null 2>&1 || fail "The request does not verify."
SIGALG="$("$OSSL" req -in "$CSRF" -noout -text 2>/dev/null | sed -nE 's/^[[:space:]]*Signature Algorithm:[[:space:]]*([^[:space:]]+).*/\1/p' | head -n1)"
if [ "$KEYTYPE" != mldsa ]; then case "$(printf '%s' "$SIGALG" | tr 'A-Z' 'a-z')" in *md5*|*sha1*|*sha-1*|*sha224*) fail "The request was signed with $SIGALG (below SHA-256). Not accepted." ;; esac; fi
rm -f "$DIR/.err"; chmod 600 "$KEYF" 2>/dev/null || say WARN "Could not restrict the key file: protect $KEYF yourself."
SUBJ="$("$OSSL" req -in "$CSRF" -noout -subject -nameopt RFC2253 2>/dev/null | sed -E 's/^subject=[[:space:]]*//')"

if [ "$EVASKED" = 1 ]; then LEVEL=EV; elif [ -n "$COMPANY" ] && [ -n "$COUNTRY" ]; then LEVEL=OV; else LEVEL=DV; fi
case "$KEYTYPE" in rsa) KEYDESC="RSA-$BITS" ;; ecdsa) KEYDESC="ECDSA-${CURVE//-/}" ;; mldsa) KEYDESC="ML-DSA-$MLDSA" ;; esac
if [ "$ISCA" = 1 ]; then TRACK="Classic only (signed by SignExternalCa.ps1 with a Quadrant Root: Quadrant 1, or 2 with -Fips)"; HASHTXT="$DIGEST"
elif [ "$KEYTYPE" = mldsa ]; then TRACK="Quantum (the CA signs it with -Quantum, Quadrant 3)"; HASHTXT="ML-DSA"; else TRACK="Classic (Quadrant 1 unless the CA decides otherwise)"; HASHTXT="$DIGEST"; fi
case "$LEVEL" in EV) LTXT="the EV information is complete: the CA signs an EV certificate" ;; OV) LTXT="a company without EV information: the CA signs an OV certificate" ;; *) LTXT="common name only: the CA signs a DV certificate" ;; esac
ALLN="$(IFS=,; echo "${DNS[*]:-} ${IPS[*]:-} ${MAILS[*]:-}" | sed -E 's/[[:space:]]+/, /g; s/^, //; s/, $//')"
HDR="$(printf '=%.0s' $(seq 1 60))
Author : Nicko Satria Utama
Company: Agantra Inovatif OU (NextMantra)
Email  : nicko@nextmantra.com
$(printf '=%.0s' $(seq 1 60))"
{
  echo "$HDR"; echo
  echo "CERTIFICATE REQUEST            $SAFE          (new-pki-csr.sh $VERSION, $(date '+%Y-%m-%d %H:%M'))"
  echo "Subject    : $SUBJ"
  echo "Names      : ${ALLN:-(none)}"
  [ "$DEVSAN" = 1 ] && echo "             + the development names (the request carries the marker)"
  echo "Key        : $KEYDESC, request signed with $HASHTXT"
  if [ "$ISCA" = 1 ]; then echo "Purpose    : Intermediate CA (CA:TRUE, keyCertSign + cRLSign, no names)"; else echo "Purpose    : $PURPOSE"; fi
  echo "Type       : $CTYPE"
  echo "Level      : $LEVEL  - $LTXT"
  echo "Track      : $TRACK"
  [ -n "$PEN" ] && echo "Company OID : 1.3.6.1.4.1.$PEN.1 (your PEN policy; the CA adds it to the certificate)"
} > "$DIR/request-info.txt"
{
  echo "$HDR"; echo
  echo "WHAT TO DO"
  echo "  1. Send the file  $SAFE.csr  to the owner of the PKI (e-mail is fine: it holds no secret)."
  echo "  2. KEEP  $SAFE.key  on this computer. It is your private key. NEVER send it. Whoever has it can pretend to be you."
  if [ "$ISCA" = 1 ]; then
    echo "  3. The owner signs the request (SignExternalCa.ps1 -Csr $SAFE.csr$([ "$LEVEL" = EV ] && echo ' -Level EV')) and sends you a folder: your CA certificate, the chain and root.crt."
    echo "  4. Install the certificate as the CA certificate of your CA together with $SAFE.key. Protect that key like a root key (offline or in an HSM)."
  else
    echo "  3. The owner signs the request (SignCsr.ps1 / SignCsr.sh) and sends you a folder: your certificate, the chain and root.crt."
    echo "  4. Use  $SAFE.key  together with  $SAFE-fullchain.crt  in your server or application."
  fi
  echo "  The CRL (revocation list) and OCSP addresses inside your certificate are those of the CA that signs it."
  echo; echo "LEVEL ASKED   $LEVEL   ($TRACK)"
} > "$DIR/README.txt"

echo
say OK "Request: $CSRF"
say OK "Private key (keep it secret): $KEYF"
say INFO "Subject: $SUBJ"
case "$LEVEL" in EV) T="The EV information is complete." ;; OV) T="No EV information: an OV certificate." ;; *) T="Common name only: a DV certificate." ;; esac
say INFO "Key $KEYDESC, level asked: $LEVEL. $T"
say INFO "Send ONLY the .csr to the owner of the PKI. Folder: $DIR"
exit 0
