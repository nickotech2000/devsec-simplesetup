#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# GenerateOffice365LeafCertificate.sh - Linux / Ubuntu twin of GenerateOffice365LeafCertificate.ps1 (DevKit). bash + openssl + python3 (JSON). Manual: docs/DevKit-MANUAL.txt
VERSION="4.9.5-phaseC"; TOOL="GenerateOffice365LeafCertificate.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"; . "$HERE/lib/pki-person.sh"

usage() {
cat <<'EOF'
============================================================
 GenerateOffice365LeafCertificate.sh - Microsoft Office / 365 document signing certificates (Linux / Ubuntu, DevKit)
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs/DevKit-MANUAL.txt      Windows twin: GenerateOffice365LeafCertificate.ps1

USAGE
  ./GenerateOffice365LeafCertificate.sh --example-file office365.json
  ./GenerateOffice365LeafCertificate.sh --file office365.json --no-revocation-info

CERTIFICATE
  EKU : Document Encryption (1.3.6.1.4.1.311.80.1) + Secure Email (emailProtection) + Document Signing (1.3.6.1.4.1.311.10.3.12;
        --no-document-signing-eku leaves the last one out).
  KU  : digitalSignature + nonRepudiation + keyEncipherment (RSA) / keyAgreement (ECDSA: signs, cannot encrypt documents).
  Key : RSA 4096 by default (Office minimum RSA 2048 / ECDSA P-256), SHA-2 only. Folder: leafcerts/office365/.
  Subject: serialNumber (optional ID), givenName, surname, CN "Given Surname", C. SAN: rfc822Name = the e-mail.

OPTIONS
  --file F  --example-file F  --validate-only  --stop-on-error  --no-document-signing-eku  --dns-from-email
  --level OV|EV (--ev)  --quadrant 1|2 (--fips)  --key-type rsa|ecdsa  --key-bits N  --curve P-256|P-384|P-521  --hash sha256|sha384|sha512  --days N
  --no-crl  --no-ocsp  --no-revocation-info     use these when Word / Excel say "cannot connect to the revocation server"
  --out DIR (default ./leafcerts)  --pfx-password TEXT  --openssl FILE  --help  --version
  --release N (default: the LATEST release of the PKI)  --no-ca-revocation-info (the NoCR family)
EOF
}
person_main office365 "$@"
