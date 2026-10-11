#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# SignCsr.sh - sign the certificate request (CSR) of another department with the INTERMEDIATE CAs of this PKI (Linux / Ubuntu).
# The same rules as SignCsr.ps1; only bash, openssl and python3 are needed (no PowerShell).
VERSION="4.9.5-phaseC"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"

usage() {
cat <<'EOT'
============================================================
 SignCsr.sh - sign the certificate request (CSR) of another department with our PKI
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs/SignCsr-MANUAL.txt   Design: docs/PKI-Design-with-FIPS-and-PQC.txt (10.72, section 20)   The PowerShell twin: SignCsr.ps1 (same rules)
 Needs  : bash, openssl 3.0+ (4.0.1+ recommended; ML-DSA / Quantum needs 4.x), python3. The DevKit unpacked by Install-PkiTrust, or the
          project of the original PKI after  SignCsr.ps1 -WriteShellEnv  (then run  devkit/SignCsr.sh ).

WHAT IT DOES
  1. READS the request and CHECKS it against the specification of this PKI, printing every finding in colour with the reason and the fix:
        red ERROR   yellow WARN   green OK   cyan INFO
  2. refuses it when there is an ERROR (exit code 2, nothing is signed), or signs it with the right INTERMEDIATE CA,
  3. writes the result into a NEW folder  csr-signed/<name>_<yyyymmdd-HHMMSS>/ :
        <name>.crt <name>.cer       his certificate (PEM and DER)          <name>-fullchain.crt  certificate + our CA chain (his server file)
        <name>-chain.crt            our CA chain                           <name>.p7b            certificate + chain for Windows
        root.crt  our-ca-bundle.crt the trust anchor / chain + root        <name>.csr  sign-info.json  README.txt (tells HIM what to do)
     and one line in csr-signed/signed-csr.tsv. Send him the folder. He keeps his private key; we never see it.
  The certificate is recorded in the index.txt of the issuing CA (in the DevKit: of the DevKit copy; certificates signed here are NOT in the
  CRL / OCSP of the original PKI - the owner of the original PKI can revoke the intermediate if the kit leaks).

WHO SIGNS
  --dv (default) | --ov | --ev     level  =  CA q<N>-dv | q<N>-ov | q<N>-ev
  --classic (default) | --quantum  track.   --fips   FIPS quadrant (Classic Q2 / Quantum Q4). Without --fips: Q1 / Q3, non-FIPS.
  The roots never sign here. A request for a CA certificate is signed by the owner of the ORIGINAL PKI (SignExternalCa.ps1, Quadrant Root).

THE SPEC A REQUEST MUST FOLLOW (see docs/SignCsr-MANUAL.txt; the report names every deviation)
  Signature valid, SHA-256+.   Key  Classic: RSA 2048/3072/4096/8192, ECDSA P-256/P-384/P-521.  Quantum: ML-DSA-44/65/87.
  Code signing: RSA 4096+, ECDSA P-384+, ML-DSA-65+.  Never RSA < 2048, other curves, Ed25519, DSA.
  Subject  DV: CN only (rest dropped, WARN).  OV: C (2 letters), O, CN; ST, L recommended.
           EV: OV + ST, L, serialNumber, businessCategory (Private Organization | Government Entity | Business Entity | Non-Commercial Entity),
               jurisdictionC.  Code signing: C, O, CN.
  Names    TLS: DNS and IP.  EV: no wildcard, no IP, no internal name, no e-mail.  S/MIME: e-mail only.  Code signing / TSA / OCSP: none.
  Validity DV 5 years, OV 3 years, EV 397 days at most, time stamping 5 years, OCSP 1 year; never longer than the issuing CA.
  Ignored  keyUsage, extendedKeyUsage, policies, CRL / OCSP URLs of the request (this PKI sets them); CA:TRUE is refused.

OPTIONS
  --csr FILE               his request (PEM).                               --purpose P   ServerAuth (default) | ClientAuth | ServerClientAuth |
  --dv | --ov | --ev       level (default dv)                                              CodeSigning | EmailProtection | TimeStamping | OcspSigning
  --classic | --quantum    track (default classic)                          --fips        FIPS quadrant
  --days N                 validity in days (EV at most 397)                --name TEXT   folder / file name (default: his CN)
  --out DIR                where the per-request folders go (default ./csr-signed)
  --policy "OID|CPS-URL"   extra policy for this certificate
  --no-crl --no-ocsp --no-revocation-info    leave the CRL distribution point and / or the OCSP URL out
  --check                  only check the request, sign nothing             --strict      warnings count as errors
  --no-color               plain text (also NO_COLOR=1)                     --list        list the earlier requests
  --openssl FILE           the openssl to use                               --pki-home DIR   the PKI home (DevKit folder, or the project folder)
  --help, -h               this text                                        --version
EXAMPLES
  ./SignCsr.sh --csr web01.csr                                   DV, Classic non-FIPS (q1-dv), TLS server
  ./SignCsr.sh --csr web01.csr --ov --purpose ServerClientAuth   OV (q1-ov)
  ./SignCsr.sh --csr web01.csr --ev --fips --check               would q2-ev sign it? report only
  ./SignCsr.sh --csr pq.csr --quantum --ov                       ML-DSA request, q3-ov
HIS SIDE
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out web01.key
  openssl req -new -key web01.key -sha256 -subj "/CN=web01.dept.example" -addext "subjectAltName=DNS:web01.dept.example" -out web01.csr
EXIT CODES   0 ok   1 error   2 the request does not follow the spec
============================================================
EOT
}

CSR=""; LEVEL=DV; TRACK=Classic; FIPS=0; PURPOSE=ServerAuth; DAYS=""; NAME=""; OUT=""; POLICY=""; NOCRL=0; NOOCSP=0
CHECK=0; STRICT=0; NOCOLOR=0; LIST=0; OSSL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --csr) CSR="$2"; shift ;; --dv) LEVEL=DV ;; --ov) LEVEL=OV ;; --ev) LEVEL=EV ;;
    --classic) TRACK=Classic ;; --quantum) TRACK=Quantum ;; --fips) FIPS=1 ;;
    --purpose) PURPOSE="$2"; shift ;; --days) DAYS="$2"; shift ;; --name) NAME="$2"; shift ;; --out) OUT="$2"; shift ;; --policy) POLICY="$POLICY $2"; shift ;;
    --no-crl) NOCRL=1 ;; --no-ocsp) NOOCSP=1 ;; --no-revocation-info) NOCRL=1; NOOCSP=1 ;;
    --check) CHECK=1 ;; --strict) STRICT=1 ;; --no-color) NOCOLOR=1 ;; --list) LIST=1 ;;
    --openssl) OSSL="$2"; shift ;; --pki-home) export PKI_HOME="$2"; shift ;;
    --version) echo "SignCsr.sh $VERSION"; exit 0 ;; --help|-h) usage; exit 0 ;;
    *) pki_die "unknown option '$1'. See ./SignCsr.sh --help" ;;
  esac; shift
done
# lib/pki-lib.sh was sourced before the options: --pki-home needs a second look
if [ -n "${PKI_HOME:-}" ]; then PKI_KIT_DIR="$(cd "$PKI_HOME" && pwd)"; fi
[ -n "$OUT" ] || OUT="$PWD/csr-signed"; OUT="${OUT%/}"
if [ $LIST = 1 ]; then
  if [ -f "$OUT/signed-csr.tsv" ]; then cat "$OUT/signed-csr.tsv"; else pki_info "No request was signed yet ($OUT)."; fi; exit 0
fi
[ -n "$CSR" ] || pki_die "--csr FILE is required (see --help)."
[ -f "$CSR" ] || pki_die "CSR not found: $CSR"
case " ServerAuth ClientAuth ServerClientAuth CodeSigning EmailProtection TimeStamping OcspSigning " in *" $PURPOSE "*) ;; *) pki_die "unknown purpose '$PURPOSE'." ;; esac
case "$DAYS" in ""|*[!0-9]*) [ -z "$DAYS" ] || pki_die "--days must be a number." ;; esac
command -v python3 >/dev/null 2>&1 || pki_die "python3 is needed to check the request (Ubuntu: sudo apt install python3)."
pki_load_env
pki_find_openssl "$OSSL"
[ "$NOCOLOR" = 1 ] && export NO_COLOR=1

if [ "$TRACK" = Quantum ]; then QUAD=$([ $FIPS = 1 ] && echo 4 || echo 3); else QUAD=$([ $FIPS = 1 ] && echo 2 || echo 1); fi
LV="$(pki_lc "$LEVEL")"
case " $CA_IDS " in *" q$QUAD-$LV "*) ;; *) pki_die "This PKI has no CA q$QUAD-$LV (devkit.env lists: $CA_IDS)." ;; esac

TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
python3 "$PKI_LIB_DIR/pki-csr.py" --openssl "$OPENSSL" --csr "$CSR" --level "$LEVEL" --track "$TRACK" --purpose "$PURPOSE" --days "${DAYS:-0}" \
    $([ "$NOCOLOR" = 1 ] && echo --no-color) --emit "$TMPD/csr.env"
rc=$?
echo
[ $rc = 1 ] && exit 1
[ $rc = 2 ] && exit 2
. "$TMPD/csr.env"
if [ $STRICT = 1 ] && [ "${CSR_WARNINGS:-0}" -gt 0 ]; then printf '[ERROR] --strict: the warnings count as errors.\n' >&2; exit 2; fi
[ $CHECK = 1 ] && { pki_info "Check only (--check): nothing was signed."; exit 0; }

# ---- the issuing CA
pki_ca_info "q$QUAD" "$LV"
ISS_CNF="$CA_BASE.cnf"
[ -f "$ISS_CNF" ] || pki_die "Issuing CA configuration not found: $ISS_CNF"
case "$CSR_FAMILY" in rsa) FAM=rsa ;; ecdsa) FAM=ecdsa ;; *) FAM=pqc ;; esac

# ---- purpose -> key usage, extended key usage
EKU=""; KU="digitalSignature"; EXTRA=""; ISEMAIL=0; ISSERVER=0
case "$PURPOSE" in
  ServerAuth) EKU="serverAuth"; ISSERVER=1 ;; ClientAuth) EKU="clientAuth" ;; ServerClientAuth) EKU="serverAuth,clientAuth"; ISSERVER=1 ;;
  CodeSigning) EKU="codeSigning" ;; EmailProtection) EKU="emailProtection,clientAuth"; ISEMAIL=1 ;;
  TimeStamping) EKU="critical,timeStamping" ;; OcspSigning) EKU="OCSPSigning"; EXTRA="1.3.6.1.5.5.7.48.1.5 = ASN1:NULL" ;;
esac
[ $ISEMAIL = 1 ] && KU="$KU,nonRepudiation"
[ "$FAM" = ecdsa ] && [ $ISEMAIL = 1 ] && KU="$KU,keyAgreement"
[ "$FAM" = rsa ] && { [ $ISEMAIL = 1 ] || [ $ISSERVER = 1 ]; } && KU="$KU,keyEncipherment"

# ---- validity: by level / purpose, EV at most 397, never longer than the issuer
dv="$DAYS"
if [ -z "$dv" ]; then
  case "$PURPOSE" in TimeStamping) dv="${TSA_DAYS:-1825}" ;; OcspSigning) dv="${OCSP_DAYS:-365}" ;; *) dvar="DAYS_$LEVEL"; dv="${!dvar}" ;; esac
  [ "$LEVEL" = EV ] && [ "$dv" -gt 397 ] && dv=397
fi
end_epoch="$(date -u -d "$("$OPENSSL" x509 -in "$CA_CRT" -noout -enddate | cut -d= -f2)" +%s 2>/dev/null)"
if [ -n "$end_epoch" ]; then
  room=$(( (end_epoch - $(date -u +%s)) / 86400 - 1 ))
  if [ "$dv" -gt "$room" ]; then pki_warn "Validity limited by the issuer $CA_SLUG: $dv -> $room days."; dv="$room"; fi
  [ "$dv" -ge 1 ] || pki_die "The issuing CA has expired or ends within a day."
fi
md="$CA_MD"

# ---- output folder
SAFE_IN="${NAME:-$CSR_CN}"; [ -n "$SAFE_IN" ] || SAFE_IN=csr
SAFE="$(printf '%s' "$SAFE_IN" | sed 's/^\*\./wildcard./; s/[^A-Za-z0-9._-][^A-Za-z0-9._-]*/-/g; s/^[-.]*//; s/[-.]*$//')"; [ -n "$SAFE" ] || SAFE=csr
DIR="$OUT/${SAFE}_$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIR"
tr -d '\r' < "$CSR" > "$DIR/$SAFE.csr"

# ---- extensions
EXT="$TMPD/ext.cnf"; : > "$EXT"
pki_write_policies "$EXT" "$LEVEL"
if [ "$PURPOSE" = TimeStamping ] && [ -n "${TSA_POLICY_OID:-}" ]; then
  n=$(grep -c '^\[ lp_' "$EXT"); n=$((n+1))
  printf '[ lp_%s ]\npolicyIdentifier = %s\n\n' "$n" "$TSA_POLICY_OID" >> "$EXT"; POLICY_REFS="$POLICY_REFS,@lp_$n"
fi
for p in $POLICY; do
  n=$(grep -c '^\[ lp_' "$EXT"); n=$((n+1)); oid="${p%%|*}"; cps="${p#*|}"; [ "$cps" = "$p" ] && cps=""
  { printf '[ lp_%s ]\npolicyIdentifier = %s\n' "$n" "$oid"; [ -n "$cps" ] && printf 'CPS.1 = %s\n' "$cps"; printf '\n'; } >> "$EXT"; POLICY_REFS="$POLICY_REFS,@lp_$n"
done
pki_write_location "$EXT" "$CA_SLUG" "$NOCRL" "$NOOCSP"
HAVE_SAN=0
if [ -n "$SAN_DNS$SAN_IP$SAN_EMAIL" ]; then
  HAVE_SAN=1; printf '[ san ]\n' >> "$EXT"; n=0
  for x in $SAN_DNS; do n=$((n+1)); printf 'DNS.%s = %s\n' $n "$x" >> "$EXT"; done; n=0
  for x in $SAN_IP; do n=$((n+1)); printf 'IP.%s = %s\n' $n "$x" >> "$EXT"; done; n=0
  for x in $SAN_EMAIL; do n=$((n+1)); printf 'email.%s = %s\n' $n "$x" >> "$EXT"; done
  printf '\n' >> "$EXT"
fi
{
  printf '[ ext ]\nbasicConstraints = critical,CA:false\nkeyUsage = critical,%s\nextendedKeyUsage = %s\n' "$KU" "$EKU"
  [ -n "$EXTRA" ] && printf '%s\n' "$EXTRA"
  printf 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n'
  [ $HAVE_SAN = 1 ] && printf 'subjectAltName = @san\n'
  printf 'certificatePolicies = %s\n' "$POLICY_REFS"
  [ -n "$EXT_CRL" ] && printf '%s\n' "$EXT_CRL"
  [ -n "$EXT_AIA" ] && printf '%s\n' "$EXT_AIA"
} >> "$EXT"

# ---- issuer configuration for "openssl ca": the CA's own file, default provider only (signing does not need the FIPS module),
#      organizationIdentifier allowed in the policy
ICNF="$TMPD/issuer.cnf"
{ printf 'openssl_conf = openssl_init\n[ openssl_init ]\nproviders = provider_sect\n[ provider_sect ]\ndefault = default_sect\n[ default_sect ]\nactivate = 1\n\n'
  sed -n '/^\[ ca \]/,$p' "$ISS_CNF"; } > "$ICNF"
grep -q '^organizationIdentifier' "$ICNF" || sed -i 's/^\(\[ policy_any \]\)\s*$/\1\norganizationIdentifier = optional/' "$ICNF"

# the folder for the issued certificates may be missing (an empty folder is lost in a zip): openssl ca needs it
_cdir=$(sed -n 's/^dir[[:space:]]*=[[:space:]]*//p' "$ICNF" | head -1 | tr -d '\r')
[ -n "$_cdir" ] && mkdir -p "$_cdir/issued" 2>/dev/null
SIGOPT=()
if [ "${RSA_PSS:-0}" = 1 ] && [ "$FAM" = rsa ] && [ "$md" != default ]; then SIGOPT=(-sigopt rsa_padding_mode:pss -sigopt "rsa_mgf1_md:$md" -sigopt rsa_pss_saltlen:digest); fi
SUBJ=(); [ "$LEVEL" = DV ] && SUBJ=(-subj "/CN=$CSR_CN")
CRT="$DIR/$SAFE.crt"
if ! "$OPENSSL" ca -batch -notext -utf8 -preserveDN -config "$ICNF" -in "$DIR/$SAFE.csr" -out "$CRT" -extfile "$EXT" -extensions ext -days "$dv" -md "$md" \
       "${SIGOPT[@]}" "${SUBJ[@]}" 2> "$TMPD/ca.err"; then
  cat "$TMPD/ca.err" >&2; rm -rf "$DIR"; pki_die "openssl ca failed (is $CA_KEY the key of $CA_CRT? Was the kit unpacked with Install-PkiTrust?)"
fi
[ -s "$CRT" ] || { rm -rf "$DIR"; pki_die "no certificate was written"; }

# ---- chain files (CA chain: issuer + intermediate parents up to, not including, the root; the root separately)
cat "$CRT" "$CA_CHAIN" > "$DIR/$SAFE-fullchain.crt"
cp "$CA_CHAIN" "$DIR/$SAFE-chain.crt"
ROOTS="$PKI_KIT_DIR/ca/ca-bundle-roots.crt"
[ -f "$ROOTS" ] || ROOTS="$PKI_KIT_DIR/pki/root/root.crt"       # the original PKI has no ca/ folder
[ -f "$ROOTS" ] && cp "$ROOTS" "$DIR/root.crt"
if [ -f "$ROOTS" ]; then cat "$CA_CHAIN" "$ROOTS" > "$DIR/our-ca-bundle.crt"; else cp "$CA_CHAIN" "$DIR/our-ca-bundle.crt"; fi
"$OPENSSL" x509 -in "$CRT" -outform DER -out "$DIR/$SAFE.cer" 2>/dev/null
"$OPENSSL" crl2pkcs7 -nocrl -certfile "$DIR/$SAFE-fullchain.crt" -out "$DIR/$SAFE.p7b" 2>/dev/null
VERIFY="FAILED"; "$OPENSSL" verify -CAfile "$DIR/our-ca-bundle.crt" -x509_strict "$CRT" >/dev/null 2>&1 && VERIFY="OK"
SERIAL="$("$OPENSSL" x509 -in "$CRT" -noout -serial | cut -d= -f2)"
FPR="$("$OPENSSL" x509 -in "$CRT" -noout -fingerprint -sha256 | cut -d= -f2)"
ENDD="$("$OPENSSL" x509 -in "$CRT" -noout -enddate | cut -d= -f2)"
SUBJF="$("$OPENSSL" x509 -in "$CRT" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
NAMES="$(printf '%s %s %s' "$SAN_DNS" "$SAN_IP" "$SAN_EMAIL" | xargs | sed 's/ /, /g')"
TRK_TXT="$TRACK$([ $FIPS = 1 ] && echo ' FIPS' || echo ' non-FIPS')"
js() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
{
  printf '{\n  "name": "%s", "level": "%s", "quadrant": %s, "track": "%s", "fips": %s, "purpose": "%s",\n' "$(js "$SAFE")" "$LEVEL" "$QUAD" "$TRACK" "$([ $FIPS = 1 ] && echo true || echo false)" "$PURPOSE"
  printf '  "issuer": "q%s-%s", "subject": "%s", "key": "%s", "names": "%s",\n' "$QUAD" "$LV" "$(js "$SUBJF")" "$CSR_KEYDESC" "$(js "$NAMES")"
  printf '  "days": %s, "notAfter": "%s", "serial": "%s", "sha256": "%s", "signatureDigest": "%s",\n' "$dv" "$ENDD" "$SERIAL" "$FPR" "$md"
  printf '  "crlDistributionPoint": %s, "ocspUrl": %s, "openSslVerify": %s,\n' "$([ -n "$EXT_CRL" ] && echo true || echo false)" "$([ $NOOCSP = 0 ] && [ -n "${OCSP_URLS:-}" ] && echo true || echo false)" "$([ $VERIFY = OK ] && echo true || echo false)"
  printf '  "createdUtc": "%s", "generator": "SignCsr.sh %s"\n}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$VERSION"
} > "$DIR/sign-info.json"
cat > "$DIR/README.txt" <<EOT
SIGNED CERTIFICATE                    $SAFE
=====================================================================
Issuer       : q$QUAD-$LV   $CA_SLUG
Level        : $LEVEL   Quadrant $QUAD ($TRK_TXT)   Purpose: $PURPOSE
Subject      : $SUBJF
Names (SAN)  : $NAMES
Key          : $CSR_KEYDESC (YOUR key: we never saw the private key)
Valid until  : $ENDD   ($dv days)          Serial: $SERIAL
SHA-256      : $FPR
Revocation   : $([ -n "$EXT_CRL" ] && echo 'CRL distribution point' || echo 'no CRL distribution point'), $([ $NOOCSP = 0 ] && [ -n "${OCSP_URLS:-}" ] && echo 'OCSP URL' || echo 'no OCSP URL')
Verification : openssl verify against our chain: $VERIFY

FILES
  $SAFE.crt            your certificate (PEM)         $SAFE.cer   the same, DER (Windows: double click)
  $SAFE-fullchain.crt  your certificate + our CA chain (use this as the server certificate file)
  $SAFE-chain.crt      our CA chain only              $SAFE.p7b   certificate + chain for Windows
  root.crt             our Enterprise Root: clients must trust it (it is the trust anchor)
  our-ca-bundle.crt    our chain + root, for  openssl verify -CAfile
  $SAFE.csr            your request (unchanged)       sign-info.json   the facts for scripts
HIS SIDE
  Put your private key (the one you made the request with) and $SAFE-fullchain.crt in your server / application.
  Check:  openssl verify -CAfile our-ca-bundle.crt $SAFE.crt
EOT
TSV="$OUT/signed-csr.tsv"
[ -f "$TSV" ] || printf '# utc\tserial\tissuer\tlevel\tpurpose\tname\tnotAfter\n' > "$TSV"
printf '%s\t%s\tq%s-%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$SERIAL" "$QUAD" "$LV" "$LEVEL" "$PURPOSE" "$SAFE" "$ENDD" >> "$TSV"
pki_ok "Signed $CSR_KEYDESC request '$SAFE' with q$QUAD-$LV ($LEVEL, $dv days): $DIR"
[ "$VERIFY" = OK ] || pki_warn "openssl verify (strict) against our chain failed - see README.txt."
pki_info "Give him the content of $DIR  (README.txt explains the files)."
exit 0
