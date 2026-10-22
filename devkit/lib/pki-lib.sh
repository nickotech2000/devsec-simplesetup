#!/usr/bin/env bash
# ============================================================
# PKI Script - DevKit shell library (sourced by the *.sh generators; not run on its own)
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# Needs: bash 4+ (Ubuntu), openssl 3.0+ (4.0.1+ recommended), python3 (JSON files only).
# Reads devkit.env (written by PkiTransport.ps1 -DevKit from the live configuration of the PKI).
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
    PKI_TOOL_VERSION="7.9.1"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi

PKI_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_KIT_DIR="$(cd "$PKI_LIB_DIR/.." && pwd)"
# Inside the project of the ORIGINAL PKI (devkit/ next to pki/): the PKI home is the parent folder (devkit.env: SignCsr.ps1 -WriteShellEnv).
# PKI_HOME=<folder> chooses another one.
if [ -n "${PKI_HOME:-}" ]; then PKI_KIT_DIR="$(cd "$PKI_HOME" && pwd)"
elif [ ! -f "$PKI_KIT_DIR/devkit.env" ] && [ -f "$PKI_KIT_DIR/../devkit.env" ]; then PKI_KIT_DIR="$(cd "$PKI_KIT_DIR/.." && pwd)"; fi
TAB="$(printf '\t')"

pki_die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
pki_warn() { printf '[WARN]  %s\n' "$*" >&2; }
pki_info() { printf '[INFO]  %s\n' "$*"; }
pki_ok()   { printf '[OK]    %s\n' "$*"; }

pki_load_env() {
  local f="$PKI_KIT_DIR/devkit.env"
  [ -f "$f" ] || pki_die "devkit.env not found in $PKI_KIT_DIR. Run these scripts from the DevKit folder (the zip made by PkiTransport.ps1 -DevKit)."
  set -a; . "$f"; set +a
}

# --openssl FILE or the first openssl 3.0+ found (an OpenSSL 4 under /opt is preferred)
pki_find_openssl() {
  local want="$1" c
  if [ -n "$want" ]; then OPENSSL="$want"
  else
    OPENSSL=""
    for c in /opt/openssl-4*/bin/openssl /usr/local/bin/openssl "$(command -v openssl 2>/dev/null)"; do
      [ -n "$c" ] && [ -x "$c" ] && { OPENSSL="$c"; break; }
    done
  fi
  [ -n "$OPENSSL" ] && [ -x "$OPENSSL" ] || pki_die "openssl not found. Ubuntu: sudo apt install openssl   (or use --openssl FILE)"
  local v; v="$("$OPENSSL" version 2>/dev/null | awk '{print $2}')"
  case "$v" in
    3.*|4.*|5.*) ;;
    *) pki_die "OpenSSL $v is too old: 3.0 or newer is needed (4.0.1+ recommended). Found: $OPENSSL" ;;
  esac
  case "$v" in 4.*|5.*) ;; *) pki_warn "OpenSSL $v works for Classic RSA / ECDSA certificates; the project recommends 4.0.1+ (Install-PkiTrust.sh can build it)." ;; esac
  OPENSSL_VERSION="$v"
}

# lower-case / upper-case without ${var,,} (works in bash 3.2 too)
pki_lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
pki_uc() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# comma / space list -> one item per line
pki_list() { printf '%s' "$1" | tr ',; ' '\n\n\n' | sed '/^$/d'; }

# 128-bit random serial, positive (first nibble 1-7). Printed as 32 hex digits.
pki_rand_serial() {
  local h; h="$("$OPENSSL" rand -hex 16)"
  printf '%x%s' $(( (0x${h:0:1} % 7) + 1 )) "${h:1}"
}

# ---------------------------------------------------------------- which PKI: releases (R2, R3 ...) and the NoCR variant
# The PKIs are folders:  pki/pki-default-01  pki/pki-raksaka-01  pki/pki-default-nocr-01 ... (5.0.0; the old pki/R1  pki/NoCR-R1 work too)   A PKI of an older version (and the PKI of a DevKit) sits directly in pki/
# (release and variant are then read from its pki-manifest.json; no entry = release 1, normal).
# The scripts offer   --release N   and   --no-ca-revocation-info   (PKI_WANT_REL, PKI_WANT_NOCR).  Default: the LATEST release of the
# normal family (the NoCR family when only that exists). A release that does not exist any more (deleted) is NOT an error: the latest is used, with a warning.
PKI_WANT_REL=""; PKI_WANT_NOCR=""
PKI_DIR=""; PKI_REL=1; PKI_NOCR=0; PKI_SLUG_SUFFIX=""

pki_manifest_field() {   # <manifest.json> <key>  ->  value (empty when the key is missing)
  grep -o "\"$2\": *[^,}]*" "$1" 2>/dev/null | head -1 | sed 's/^[^:]*: *//; s/[" ]//g'
}

pki_scan() {   # one line per PKI:  path|release|nocr(0/1)
  local d n rel nocr v
  for d in "$PKI_KIT_DIR/pki" "$PKI_KIT_DIR"/pki/R[0-9]* "$PKI_KIT_DIR"/pki/NoCR-R[0-9]* "$PKI_KIT_DIR"/pki/pki-*-[0-9][0-9]*; do
    [ -d "$d" ] || continue
    [ -f "$d/pki-manifest.json" ] || [ -f "$d/root/root.crt" ] || continue
    n="$(basename "$d")"; rel=1; nocr=0
    case "$n" in NoCR-R[0-9]*) nocr=1; rel="${n#NoCR-R}" ;; R[0-9]*) rel="${n#R}" ;; pki-*-nocr-[0-9]*) nocr=1; rel=$((10#${n##*-})) ;; pki-*-[0-9]*) rel=$((10#${n##*-})) ;; esac
    if [ -f "$d/pki-manifest.json" ]; then
      v="$(pki_manifest_field "$d/pki-manifest.json" release)"; [ -n "$v" ] && rel="$v"
      v="$(pki_manifest_field "$d/pki-manifest.json" noCaRevocationInfo)"
      [ "$v" = true ] && nocr=1; [ "$v" = false ] && nocr=0
    fi
    printf '%s|%s|%s\n' "$d" "$rel" "$nocr"
  done
}

pki_select_pki() {
  [ -n "$PKI_DIR" ] && return 0
  local all fam want_nocr=0 line best="" bestrel=-1 hit="" d r n nn
  all="$(pki_scan)"
  [ -n "$all" ] || pki_die "No PKI found in $PKI_KIT_DIR/pki. Run Install-PkiTrust (.ps1 on Windows, .sh on Linux) first: it unpacks the .certpacked."
  if [ "$PKI_WANT_NOCR" = 1 ]; then want_nocr=1
  elif ! printf '%s\n' "$all" | grep -q '|0$'; then want_nocr=1; pki_info "Only a NoCR PKI exists here: using it."; fi
  fam="$(printf '%s\n' "$all" | grep "|$want_nocr\$" || true)"
  [ -n "$fam" ] || pki_die "No $([ $want_nocr = 1 ] && echo NoCR || echo normal) PKI found in $PKI_KIT_DIR/pki."
  while IFS='|' read -r d r n; do
    [ -z "$d" ] && continue
    if [ "$r" -gt "$bestrel" ]; then bestrel="$r"; best="$d"; fi
    [ -n "$PKI_WANT_REL" ] && [ "$r" = "$PKI_WANT_REL" ] && hit="$d"
  done <<EOF
$fam
EOF
  if [ -n "$PKI_WANT_REL" ] && [ -z "$hit" ]; then
    pki_warn "Release R$PKI_WANT_REL does not exist here (deleted?). Using the latest release, R$bestrel."
  fi
  PKI_DIR="${hit:-$best}"
  PKI_REL="$(printf '%s\n' "$fam" | grep -F "$PKI_DIR|" | head -1 | cut -d'|' -f2)"
  PKI_NOCR="$want_nocr"
  PKI_SLUG_SUFFIX=""
  [ "$PKI_NOCR" = 1 ] && PKI_SLUG_SUFFIX="-nocr"
  [ "$PKI_REL" -gt 1 ] && PKI_SLUG_SUFFIX="$PKI_SLUG_SUFFIX-r$PKI_REL"
  PKI_LABEL="$([ "$PKI_NOCR" = 1 ] && printf 'NoCR ')R$PKI_REL"
}

# ---------------------------------------------------------------- the issuing CA
# pki_ca_info <q1|q2> <ov|ev|dv>  -> CA_BASE (path prefix without extension), CA_SLUG, CA_FAMILY, CA_MD, CA_KEY, CA_CRT, CA_CHAIN
#   (and PKI_DIR / PKI_REL / PKI_LABEL: the PKI that was chosen, see above)
pki_ca_info() {
  local id="${1}-${2}" var rec
  pki_select_pki
  var="CA_$(printf '%s' "$id" | tr '-' '_')"
  rec="${!var:-}"
  [ -n "$rec" ] || pki_die "This PKI has no CA '$id' (devkit.env lists: $CA_IDS)."
  CA_BASE="$PKI_DIR/$(printf '%s' "$rec" | cut -d'|' -f1)"
  CA_SLUG="$(printf '%s' "$rec" | cut -d'|' -f2)$PKI_SLUG_SUFFIX"
  CA_FAMILY="$(printf '%s' "$rec" | cut -d'|' -f3)"
  CA_MD="$(printf '%s' "$rec" | cut -d'|' -f4)"
  CA_KEY="$CA_BASE.key"; CA_CRT="$CA_BASE.crt"; CA_CHAIN="${CA_BASE}-chain.crt"
  [ -f "$CA_CRT" ] || pki_die "CA certificate not found: $CA_CRT. Run Install-PkiTrust (.ps1 on Windows, .sh on Linux) first: it unpacks the .certpacked into the pki folder."
  [ -f "$CA_KEY" ] || pki_die "The private key of the issuing CA '$id' is not here: $CA_KEY. This DevKit package holds no issuing keys (it was made without them), or the key is on the PKI server."
  [ -f "$CA_CHAIN" ] || CA_CHAIN="$CA_CRT"
}

# ---------------------------------------------------------------- config pieces
# pki_author_hdr : Author / Company / Email lines (comment style) for the text files written by the DevKit
pki_author_hdr() { printf '# Author : Nicko Satria Utama\n# Company: Agantra Inovatif OU (NextMantra)\n# Email  : nicko@nextmantra.com\n'; }

# pki_cps <level>
pki_cps() { if [ "$1" = "EV" ]; then printf '%s' "$CPS_URL_EV"; else printf '%s' "$CPS_URL"; fi; }

# pki_write_policies <file> <level>  -> sections [ lp_1 ].. and sets POLICY_REFS ("@lp_1,@lp_2,...")
pki_write_policies() {
  local f="$1" lvl="$2" var item oid cps n=0 refs=""
  var="POLICIES_$lvl"
  for item in ${!var}; do
    oid="${item%%|*}"; cps="${item#*|}"; n=$((n+1))
    { printf '[ lp_%s ]\npolicyIdentifier = %s\n' "$n" "$oid"; [ -n "$cps" ] && printf 'CPS.1 = %s\n' "$cps"; printf '\n'; } >> "$f"
    refs="$refs${refs:+,}@lp_$n"
  done
  POLICY_REFS="$refs"
}

# pki_write_location <file> <slug> <no_crl 0|1> <no_ocsp 0|1>  -> sets EXT_CRL / EXT_AIA lines (empty when none)
pki_write_location() {
  local f="$1" slug="$2" nocrl="$3" noocsp="$4" u n
  EXT_CRL=""; EXT_AIA=""
  if [ "$nocrl" != "1" ] && [ -n "${CRL_URLS:-}" ]; then
    printf '[ ll_crl ]\n' >> "$f"; n=0
    for u in $CRL_URLS; do n=$((n+1)); printf 'URI.%s = %s\n' "$n" "${u//\{ca\}/$slug}" >> "$f"; done
    printf '\n' >> "$f"; EXT_CRL="crlDistributionPoints = @ll_crl"
  fi
  local have=0
  [ "$noocsp" != "1" ] && [ -n "${OCSP_URLS:-}" ] && have=1
  [ -n "${CA_ISSUER_URLS:-}" ] && have=1
  if [ "$have" = "1" ]; then
    printf '[ ll_aia ]\n' >> "$f"
    if [ "$noocsp" != "1" ]; then n=0; for u in ${OCSP_URLS:-}; do n=$((n+1)); printf 'OCSP;URI.%s = %s\n' "$n" "${u//\{ca\}/$slug}" >> "$f"; done; fi
    n=0; for u in ${CA_ISSUER_URLS:-}; do n=$((n+1)); printf 'caIssuers;URI.%s = %s\n' "$n" "${u//\{ca\}/$slug}" >> "$f"; done
    printf '\n' >> "$f"; EXT_AIA="authorityInfoAccess = @ll_aia"
  fi
}

# pki_write_dn <file> <dnspec "k=v|k=v">   (a value may be empty-skipped; UTF-8 kept)
pki_write_dn() {
  local f="$1" spec="$2" pair IFS_SAVE="$IFS"
  printf '[ req ]\nprompt = no\nutf8 = yes\nstring_mask = utf8only\ndistinguished_name = dn\n\n[ dn ]\n' >> "$f"
  IFS='|'; for pair in $spec; do [ -n "$pair" ] && printf '%s = %s\n' "${pair%%=*}" "${pair#*=}" >> "$f"; done; IFS="$IFS_SAVE"
  printf '\n' >> "$f"
}

# pki_gen_key <file> <rsa|ecdsa> <bits> <curve>
pki_gen_key() {
  case "$2" in
    rsa)   "$OPENSSL" genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$3" -out "$1" 2>/dev/null || pki_die "RSA key generation failed" ;;
    ecdsa) "$OPENSSL" genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$4" -pkeyopt ec_param_enc:named_curve -out "$1" 2>/dev/null || pki_die "EC key generation failed" ;;
    *) pki_die "key type '$2' is not supported by the shell generators (rsa or ecdsa; Classic only)" ;;
  esac
  chmod 600 "$1" 2>/dev/null
}

# pki_sign <cnf> <key> <crt> <days> <md>   (uses CA_CRT / CA_KEY; random 128-bit serial; records the issue in the kit log)
pki_sign() {
  local cnf="$1" key="$2" crt="$3" days="$4" md="$5" csr="${3%.crt}.csr" ser
  "$OPENSSL" req -new -key "$key" -config "$cnf" -out "$csr" 2>/dev/null || pki_die "CSR failed (see $cnf)"
  ser="$(pki_rand_serial)"
  "$OPENSSL" x509 -req -in "$csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -set_serial "0x$ser" -days "$days" "-$md" \
      -extfile "$cnf" -extensions ext -out "$crt" 2>/dev/null || pki_die "Signing failed (openssl x509 -req): is $CA_KEY the key of $CA_CRT?"
  rm -f "$csr"
  PKI_LAST_SERIAL="$ser"
}

# pki_package <dir> <stem> <pfx-password>   chain, fullchain, pfx, public key
pki_package() {
  local d="$1" s="$2" pw="$3"
  cat "$d/$s.crt" "$CA_CHAIN" > "$d/$s-fullchain.crt"
  cat "$CA_CHAIN" > "$d/$s-chain.crt"
  "$OPENSSL" pkey -in "$d/$s.key" -pubout -out "$d/$s.pub" 2>/dev/null
  "$OPENSSL" pkcs12 -export -inkey "$d/$s.key" -in "$d/$s.crt" -certfile "$CA_CHAIN" -out "$d/$s.pfx" -passout "pass:$pw" 2>/dev/null \
    || pki_warn "PFX could not be written"
}

# pki_hash_files <dir> <stem> <list>   (6.4.2)  <stem>.sha256 / <stem>.sha512 ...: one file per algorithm next to the certificate.
# Lines are "<hash>  <file>" (sha256sum format) for every <stem>.crt .pem .cer .der .p7b .pfx that exists. list = sha256,sha512 | sha384 | None
pki_hash_files() {
  local d="$1" s="$2" list="${3:-sha256,sha512}" ha hcmd ext
  for ha in $(pki_list "$list"); do
    case "$(printf '%s' "$ha" | tr 'A-Z' 'a-z')" in none) continue ;; esac
    case "$ha" in sha256|sha384|sha512) hcmd="${ha}sum" ;; *) pki_warn "hash '$ha' is not supported by this script (sha256, sha384, sha512)"; continue ;; esac
    command -v "$hcmd" >/dev/null 2>&1 || hcmd="shasum -a ${ha#sha}"
    ( cd "$d" && : > "$s.$ha" && for ext in crt pem cert cer der p7b pfx; do [ -f "$s.$ext" ] && $hcmd "$s.$ext" >> "$s.$ha"; done; true )
  done
}

# pki_verify <crt> <expect: "no-crl" etc. as 0/1 flags>  -> proves the chain and reports revocation extensions
pki_verify() {
  local crt="$1" nocrl="$2" noocsp="$3" t roots
  roots="$PKI_KIT_DIR/ca/ca-bundle-roots.crt"
  if [ -f "$roots" ]; then
    "$OPENSSL" verify -CAfile "$roots" -untrusted "$CA_CHAIN" "$crt" >/dev/null 2>&1 || pki_die "chain verification FAILED for $crt"
  fi
  t="$("$OPENSSL" x509 -in "$crt" -noout -text)"
  if [ "$nocrl" = "1" ] && printf '%s' "$t" | grep -q 'CRL Distribution Points'; then pki_die "-NoCrl: the certificate still has a CRL distribution point"; fi
  if [ "$noocsp" = "1" ] && printf '%s' "$t" | grep -q 'OCSP - URI'; then pki_die "-NoOcsp: the certificate still has an OCSP URL"; fi
  return 0
}

# pki_log_issue <kind> <name> <crt> : one line per issued certificate in leafcerts/issued-by-devkit.tsv
pki_log_issue() {
  local root="$1" kind="$2" name="$3" crt="$4" log nb na sj
  log="$root/issued-by-devkit.tsv"
  [ -f "$log" ] || printf '# utc\tserial\tkind\tname\tnotAfter\tissuer\tmachine\n' > "$log"
  na="$("$OPENSSL" x509 -in "$crt" -noout -enddate | cut -d= -f2)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PKI_LAST_SERIAL" "$kind" "$name" "$na" "$CA_SLUG" "$(hostname 2>/dev/null)" >> "$log"
}

# yes/no word -> 1/0
pki_bool() { case "$(pki_lc "${1:-}")" in true|yes|y|1|on) echo 1 ;; *) echo 0 ;; esac; }
