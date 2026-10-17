#!/usr/bin/env bash
help_pager() {  # help text: one screen at a time on a terminal (Space = next page, q = quit); everything when piped
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -FRXK; elif [ -t 1 ] && command -v more >/dev/null 2>&1; then more; else cat; fi
}
# PKI Script - DevKit shell library for the person / Office 365 generators (sourced; not run on its own)
# Author : Nicko Satria Utama <nicko@nextmantra.com>   Company: Agantra Inovatif OU (NextMantra)
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
    PKI_TOOL_VERSION="6.4.1"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi

# person_main <person|office365> "$@"      (the caller has sourced pki-lib.sh and defined VERSION, TOOL, usage)
person_main() {
  local PROFILE="$1"; shift
  local FILE="" EXAMPLE="" VALIDATE=0 STOPERR=0 LEVEL="" QUAD=1 KEYTYPE="" KEYBITS="" CURVE="" HASH="" DAYS="" NOCRL=0 NOOCSP=0
  local OUT="$PWD/leafcerts" PFXPW='Abc12345!' OSSL="" QCS=0 NONREP=0 CHECKEE=0 DNSFLAG="" NODOCSIGN=0 FOLDER
  while [ $# -gt 0 ]; do
    case "$1" in
      --file|-f) FILE="$2"; shift ;; --example-file) EXAMPLE="$2"; shift ;; --validate-only) VALIDATE=1 ;; --stop-on-error) STOPERR=1 ;;
      --level) LEVEL="$(pki_uc "$2")"; shift ;; --ev) LEVEL=EV ;; --ov) LEVEL=OV ;;
      --quadrant) QUAD="$2"; shift ;; --fips) QUAD=2 ;;
      --key-type) KEYTYPE="$(pki_lc "$2")"; shift ;; --key-bits) KEYBITS="$2"; shift ;; --curve) CURVE="$(pki_uc "$2")"; shift ;;
      --hash) HASH="$(pki_lc "$2")"; shift ;; --days) DAYS="$2"; shift ;;
      --no-crl) NOCRL=1 ;; --no-ocsp) NOOCSP=1 ;; --no-revocation-info) NOCRL=1; NOOCSP=1 ;;
      --release) PKI_WANT_REL="$2"; shift ;; --no-ca-revocation-info) PKI_WANT_NOCR=1 ;;
      --out) OUT="$2"; shift ;; --hash-file) HASHFILES="$2"; shift ;; --pfx-password) PFXPW="$2"; shift ;; --openssl) OSSL="$2"; shift ;;
      --qc-statements) QCS=1 ;; --non-repudiation) NONREP=1 ;; --check-estonian-id) CHECKEE=1 ;;
      --no-dns-from-email) DNSFLAG="--no-dns-from-email" ;; --dns-from-email) DNSFLAG="--dns-from-email" ;;
      --no-document-signing-eku) NODOCSIGN=1 ;;
      --version) echo "$TOOL $VERSION"; exit 0 ;; --help|-h) usage | help_pager; exit 0 ;;
      *) pki_die "unknown option '$1'. See ./$TOOL --help" ;;
    esac; shift
  done
  pki_load_env
  command -v python3 >/dev/null 2>&1 || pki_die "python3 is needed to read the JSON file: sudo apt install python3"
  local exname; [ "$PROFILE" = person ] && exname=persons.example.json || exname=office365.example.json
  if [ -n "$EXAMPLE" ]; then
    case "$EXAMPLE" in *.json) ;; *) EXAMPLE="${EXAMPLE%.*}.json" ;; esac
    [ -f "$PKI_KIT_DIR/examples/$exname" ] || pki_die "examples/$exname is missing from the kit"
    cp "$PKI_KIT_DIR/examples/$exname" "$EXAMPLE" && pki_ok "example written: $EXAMPLE   (edit it, then: ./$TOOL --file $EXAMPLE)"; exit 0
  fi
  [ -n "$FILE" ] || pki_die "give the JSON file: --file persons.json   (an example: --example-file persons.json)"
  [ -f "$FILE" ] || pki_die "file not found: $FILE"
  pki_find_openssl "$OSSL"
  case "$HASH" in ""|sha256|sha384|sha512) ;; *) pki_die "hash must be sha256, sha384 or sha512" ;; esac
  [ "$QUAD" = 1 ] || [ "$QUAD" = 2 ] || pki_die "quadrant must be 1 (Classic non-FIPS) or 2 (Classic FIPS)"
  local sub; [ "$PROFILE" = person ] && sub=persons || sub=office365
  local root="$OUT/$sub" ok=0 bad=0 skip=0 SEP=$'\x1f' line
  mkdir -p "$root"
  local pyargs=(--quadrant "$QUAD"); [ -n "$LEVEL" ] && pyargs+=(--level "$LEVEL"); [ -n "$DAYS" ] && pyargs+=(--days "$DAYS")
  [ -n "$KEYTYPE" ] && pyargs+=(--key-type "$KEYTYPE"); [ -n "$KEYBITS" ] && pyargs+=(--key-bits "$KEYBITS"); [ -n "$CURVE" ] && pyargs+=(--curve "$CURVE")
  [ $NOCRL = 1 ] && pyargs+=(--no-crl 1); [ $NOOCSP = 1 ] && pyargs+=(--no-ocsp 1)
  [ -n "$DNSFLAG" ] && pyargs+=("$DNSFLAG"); [ $CHECKEE = 1 ] && pyargs+=(--check-estonian-id)
  [ "$PROFILE" = person ] && pki_info "Person certificates from $FILE: OV by default, Classic non-FIPS (Quadrant 1), ID = any identifier" || pki_info "Office 365 certificates from $FILE: Document Encryption + Secure Email$([ $NODOCSIGN = 0 ] && echo ' + Document Signing')"
  [ $NOCRL = 1 ] || [ $NOOCSP = 1 ] && pki_warn "revocation information left out: $([ $NOCRL = 1 ] && echo 'no CRL distribution point')$([ $NOCRL = 1 ] && [ $NOOCSP = 1 ] && echo ', ')$([ $NOOCSP = 1 ] && echo 'no OCSP URL'). Office / Outlook will not try to reach that revocation service."
  local rows; rows="$(python3 -I "$PKI_LIB_DIR/pki-persons.py" "$FILE" "$PROFILE" "${pyargs[@]}")" || pki_die "reading $FILE failed"
  # pass 1: validate everything first
  local errs=0
  while IFS="$SEP" read -r kind label rest; do
    [ "$kind" = ERR ] && { pki_warn "$label"; errs=$((errs+1)); }
  done <<< "$rows"
  if [ $errs -gt 0 ] && [ $STOPERR = 1 ]; then pki_die "$errs problem(s) in $FILE; nothing was issued (--stop-on-error)"; fi
  if [ $VALIDATE = 1 ]; then
    [ $errs = 0 ] && pki_ok "$FILE is valid ($(printf '%s\n' "$rows" | grep -c '^OK') to issue, $(printf '%s\n' "$rows" | grep -c '^SKIP') skipped)" || pki_die "$errs problem(s) in $FILE"
    exit 0
  fi
  local summary="$root/$PROFILE-batch-$(date +%Y%m%d-%H%M%S).tsv"
  printf '# status\tlabel\tfolder\tserial\tfile\n' > "$summary"
  echo "  PERSON                                  KEY           DAYS  FILE"
  while IFS="$SEP" read -r kind label folder serial given sur cn country email dns nocrl noocsp level q days kt kb curve pw; do
    case "$kind" in
      SKIP) skip=$((skip+1)); pki_info "skipped (isGenerate false): $label"; continue ;;
      ERR) bad=$((bad+1)); printf 'ERR\t%s\n' "$label" >> "$summary"; continue ;;
      OK) ;; *) continue ;;
    esac
    [ -z "$DAYS" ] || days="$DAYS"
    # key defaults per profile
    [ "$kt" = rsa ] && [ "${kb:-0}" = 0 ] && kb=4096; [ "$kt" = rsa ] && [ "$kb" -lt 2048 ] && kb=4096
    local md
    pki_ca_info "q$q" "$(pki_lc "$level")"
    if [ -n "$HASH" ]; then md="$HASH"; elif [ "$PROFILE" = person ]; then md=sha512; else md="$CA_MD"; fi
    local ku="digitalSignature" eku
    if [ "$PROFILE" = person ]; then
      eku="emailProtection,clientAuth"; [ $NONREP = 1 ] && ku="$ku,nonRepudiation"
    else
      eku="emailProtection,1.3.6.1.4.1.311.80.1"; [ $NODOCSIGN = 0 ] && eku="$eku,1.3.6.1.4.1.311.10.3.12"; ku="$ku,nonRepudiation"
    fi
    if [ "$kt" = ecdsa ]; then ku="$ku,keyAgreement"; [ "$PROFILE" = office365 ] && pki_warn "$label: ECDSA cannot do key encipherment: Office can sign but not encrypt documents with it. Use RSA to also encrypt."
    else ku="$ku,keyEncipherment"; fi
    local ktag; if [ "$kt" = rsa ]; then ktag="rsa$kb"; else ktag="ecdsa-$(printf '%s' "$curve" | tr -d '-' | tr 'P' 'p')"; fi
    local dir="$root/$folder"; [ -e "$dir" ] && dir="$dir-$(date +%H%M%S)"
    local stem="$folder-$(pki_lc "$level")-q$q-$ktag"
    mkdir -p "$dir"; local cnf="$dir/$stem.cnf"; pki_author_hdr > "$cnf"
    local dn=""; [ -n "$serial" ] && dn="serialNumber=$serial|"; dn="${dn}givenName=$given|surname=$sur|CN=$cn|C=$country"
    pki_write_dn "$cnf" "$dn"
    pki_write_policies "$cnf" "$level"
    pki_write_location "$cnf" "$CA_SLUG" "$nocrl" "$noocsp"
    printf '[ san ]\nemail.1 = %s\n' "$email" >> "$cnf"; local n=0 x; for x in $dns; do n=$((n+1)); printf 'DNS.%s = %s\n' $n "$x" >> "$cnf"; done; printf '\n' >> "$cnf"
    if [ $QCS = 1 ] && [ "$PROFILE" = person ]; then
      printf '[ person_qcs ]\nqc1 = SEQUENCE:person_qc_type\n\n[ person_qc_type ]\noid = OID:0.4.0.1862.1.6\ntypes = SEQUENCE:person_qc_types\n\n[ person_qc_types ]\nt1 = OID:0.4.0.1862.1.6.1\n\n' >> "$cnf"
    fi
    {
      printf '[ ext ]\nbasicConstraints = critical,CA:false\nkeyUsage = critical,%s\nextendedKeyUsage = %s\n' "$ku" "$eku"
      printf 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\nsubjectAltName = @san\n'
      [ -n "$POLICY_REFS" ] && printf 'certificatePolicies = %s\n' "$POLICY_REFS"
      [ -n "$EXT_CRL" ] && printf '%s\n' "$EXT_CRL"; [ -n "$EXT_AIA" ] && printf '%s\n' "$EXT_AIA"
      [ $QCS = 1 ] && [ "$PROFILE" = person ] && printf '1.3.6.1.5.5.7.1.3 = ASN1:SEQUENCE:person_qcs\n'
    } >> "$cnf"
    pki_gen_key "$dir/$stem.key" "$kt" "$kb" "$curve"
    pki_sign "$cnf" "$dir/$stem.key" "$dir/$stem.crt" "$days" "$md"
    pki_package "$dir" "$stem" "${pw:-$PFXPW}"
    pki_verify "$dir/$stem.crt" "$nocrl" "$noocsp"
    pki_hash_files "$dir" "$stem" "${HASHFILES:-sha256,sha512}"      # <stem>.sha256 / .sha512 ... (--hash-file)
    local t; t="$("$OPENSSL" x509 -in "$dir/$stem.crt" -noout -text)"
    printf '%s' "$t" | grep -q 'rfc822Name\|email:' || pki_die "$label: the SAN has no e-mail address"
    printf '{\n  "tool": "%s %s", "profile": "%s",\n  "subject": {"serialNumber": "%s", "givenName": "%s", "surname": "%s", "commonName": "%s", "country": "%s"},\n  "email": "%s", "dns": "%s",\n  "level": "%s", "quadrant": %s, "days": %s, "issuer": "%s", "serial": "%s",\n  "revocationInfo": {"crlDistributionPoints": %s, "ocsp": %s}\n}\n' \
      "$TOOL" "$VERSION" "$PROFILE" "$serial" "$given" "$sur" "$cn" "$country" "$email" "$dns" "$level" "$q" "$days" "$CA_SLUG" "$PKI_LAST_SERIAL" \
      "$([ "$nocrl" = 1 ] && echo false || echo true)" "$([ "$noocsp" = 1 ] && echo false || echo true)" > "$dir/$PROFILE-info.json"
    pki_log_issue "$OUT" "$PROFILE" "$cn" "$dir/$stem.crt"
    printf '  %-39s %-13s %-5s %s\n' "${cn:0:39}" "$([ "$kt" = rsa ] && echo "RSA-$kb" || echo "ECDSA-$curve")" "$days" "$dir/$stem.crt"
    printf 'OK\t%s\t%s\t%s\t%s\n' "$label" "$folder" "$PKI_LAST_SERIAL" "$dir/$stem.crt" >> "$summary"
    ok=$((ok+1))
  done <<< "$rows"
  if [ "$PROFILE" = office365 ] && [ $ok -gt 0 ]; then
    { printf '============================================================\n Author : Nicko Satria Utama\n Company: Agantra Inovatif OU (NextMantra)\n Email  : nicko@nextmantra.com\n============================================================\n\n'; cat <<'EON'
Microsoft Office / 365: install the .pfx (Abc12345! unless the file says otherwise) in the user's "Personal" store, and the CA chain
(ca\roots, ca\intermediates) in Trusted Root / Intermediate. Word / Excel: File > Info > Protect > Add a Digital Signature.
Word / Excel say "cannot connect to the revocation server": make the certificates with --no-revocation-info.
EON
    } > "$root/OFFICE-NOTES.txt"
  fi
  echo
  [ $bad -gt 0 ] && pki_warn "$bad person(s) failed"
  pki_ok "$ok certificate(s) issued, $skip skipped, $bad failed. Folder: $root   Summary: $summary"
  [ $bad -eq 0 ]
}
