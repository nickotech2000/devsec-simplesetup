#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# GeneratePersonLeafCertificate.sh - Linux / Ubuntu twin of GeneratePersonLeafCertificate.ps1 (DevKit). bash + openssl + python3 (JSON). Manual: docs/DevKit-MANUAL.txt
VERSION="4.9.5-phaseC"; TOOL="GeneratePersonLeafCertificate.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"; . "$HERE/lib/pki-person.sh"

usage() {
cat <<'EOF'
============================================================
 GeneratePersonLeafCertificate.sh - person certificates from a JSON file (Linux / Ubuntu, DevKit)
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs/DevKit-MANUAL.txt      Windows twin: GeneratePersonLeafCertificate.ps1

USAGE
  ./GeneratePersonLeafCertificate.sh --example-file persons.json     write an example (5 made-up people, isGenerate true / false)
  ./GeneratePersonLeafCertificate.sh --file persons.json             issue the certificates
  ./GeneratePersonLeafCertificate.sh --file persons.json --validate-only
  ./GeneratePersonLeafCertificate.sh --file persons.json --ev --no-revocation-info

RULES  (same as the PowerShell generator)
  * JSON only. isGenerate true / false per person. The ID (idCode) is ANY identifier: national ID, passport, driver licence ...
  * Subject: serialNumber (= the ID), givenName, surname, CN, C (default EE). SAN: rfc822Name = the e-mail, DNS = the domain of the
    e-mail and *.domain (switch off: --no-dns-from-email or "dnsFromEmail": false).
  * Level OV (default) or EV, never DV. Classic only: Quadrant 1 non-FIPS (default) or 2 (--fips). ECDSA P-384 + SHA-512 by default.

OPTIONS
  --file F  --example-file F  --validate-only  --stop-on-error  --check-estonian-id  --non-repudiation  --qc-statements
  --level OV|EV (--ev)  --quadrant 1|2 (--fips)  --key-type rsa|ecdsa  --key-bits N  --curve P-256|P-384|P-521  --hash sha256|sha384|sha512  --days N
  --no-crl  --no-ocsp  --no-revocation-info     leave the CRL / OCSP information out of every certificate
  --no-dns-from-email  --out DIR (default ./leafcerts)  --pfx-password TEXT  --openssl FILE  --help  --version
  --release N (default: the LATEST release of the PKI)  --no-ca-revocation-info (the NoCR family)
Output: leafcerts/persons/<folder>/  (.crt .key .pub .pfx -chain -fullchain person-info.json) and a batch summary (.tsv).
EOF
}
person_main person "$@"
