#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# GenerateOffice365LeafCertificate.sh - Linux / Ubuntu twin of GenerateOffice365LeafCertificate.ps1 (DevKit). bash + openssl + python3 (JSON). Manual: docs/DevKit-MANUAL.txt
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
    PKI_TOOL_VERSION="6.4.3"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
VERSION="6.4.3"; TOOL="GenerateOffice365LeafCertificate.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"; . "$HERE/lib/pki-person.sh"

usage() {
cat <<'EOF'
====================================================================================================
 GenerateOffice365LeafCertificate.sh  -  Office / Microsoft 365 signing certificates (Linux, DevKit)
 Version 6.4.3
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, Q = quit.
 Manual : docs/GenerateOffice365LeafCertificate-MANUAL.txt
 Windows twin: GenerateOffice365LeafCertificate.ps1
 Runs on: Linux (VM, bare metal, WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+,
          Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE. Other systems: error, exit 5.
 Needs  : bash, openssl and python3. Install the PKI trust first: ./Install-PkiTrust.sh

WHAT IT DOES
  Makes one certificate for each signer of a JSON list. It signs Word, Excel, PowerPoint and PDF
  documents, and can encrypt them. It is NOT a qualified certificate.

QUICK START
  ./GenerateOffice365LeafCertificate.sh --example-file office365.json      write an example
  ./GenerateOffice365LeafCertificate.sh --file office365.json --validate-only
  ./GenerateOffice365LeafCertificate.sh --file office365.json --no-revocation-info

THE CERTIFICATE
  Purposes  Document Encryption (1.3.6.1.4.1.311.80.1), Secure Email (emailProtection) and
            Document Signing (1.3.6.1.4.1.311.10.3.12; --no-document-signing-eku leaves it out).
  Key usage digitalSignature + nonRepudiation + keyEncipherment (RSA) or keyAgreement (ECDSA).
            ECDSA signs but cannot encrypt documents.
  Key       RSA 4096 by default (Office minimum RSA 2048 / ECDSA P-256). SHA-2 only.
  Subject   [serialNumber = ID], givenName, surname, CN "Given Surname", C.
  SAN       rfc822Name = the e-mail. --dns-from-email adds the domain and *.domain.
  Folder    leafcerts/office365/

OPTIONS
  --file F  --example-file F  --validate-only  --stop-on-error  --no-document-signing-eku
  --dns-from-email
  --level OV|EV (--ev)  --quadrant 1|2 (--fips)
  --key-type rsa|ecdsa  --key-bits N  --curve P-256|P-384|P-521  --hash sha256|sha384|sha512
  --days N
  --no-crl  --no-ocsp  --no-revocation-info    Use when Word / Excel say "cannot connect to the
                                               revocation server". It may not remove the message in
                                               Word 365: make the CRL address reachable instead.
  --release N                 Release of the PKI. Default: the latest.
  --no-ca-revocation-info     Use the NoCR family of CAs.
  --out DIR                   Default ./leafcerts.
  --hash-file LIST            Hash files per certificate. Default sha256,sha512. Also sha384, None.
                              Check:  sha256sum -c <name>.sha256
  --pfx-password TEXT         Default Abc12345! (lab password). Change it.
  --openssl FILE              Use this openssl.
  --help, -h                  This text.        --version   Print the version.

EXIT CODES
  0 done      1 an error or a failed signer      5 this system is refused
EOF
}
person_main office365 "$@"
