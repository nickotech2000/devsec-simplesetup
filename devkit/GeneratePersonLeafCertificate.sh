#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# GeneratePersonLeafCertificate.sh - Linux / Ubuntu twin of GeneratePersonLeafCertificate.ps1 (DevKit). bash + openssl + python3 (JSON). Manual: docs/DevKit-MANUAL.txt
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
VERSION="6.4.3"; TOOL="GeneratePersonLeafCertificate.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"; . "$HERE/lib/pki-person.sh"

usage() {
cat <<'EOF'
====================================================================================================
 GeneratePersonLeafCertificate.sh  -  certificates for persons from a JSON file (Linux, DevKit)
 Version 6.4.3
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, Q = quit.
 Manual : docs/GeneratePersonLeafCertificate-MANUAL.txt
 Windows twin: GeneratePersonLeafCertificate.ps1
 Runs on: Linux (VM, bare metal, WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+,
          Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE. Other systems: error, exit 5.
 Needs  : bash, openssl and python3. Install the PKI trust first: ./Install-PkiTrust.sh

WHAT IT DOES
  Makes one certificate for each person of a JSON list. The rules are the same as in the PowerShell
  twin. It is NOT a qualified certificate.

QUICK START
  ./GeneratePersonLeafCertificate.sh --example-file persons.json       write an example (5 people)
  ./GeneratePersonLeafCertificate.sh --file persons.json --validate-only   check, issue nothing
  ./GeneratePersonLeafCertificate.sh --file persons.json               issue the certificates
  ./GeneratePersonLeafCertificate.sh --file persons.json --ev --no-revocation-info

RULES
  * JSON only. "isGenerate": true makes the person, false skips it.
  * The ID (idCode) is ANY identifier: national ID, passport, driver licence ...
  * Subject: serialNumber (= the ID), givenName, surname, CN, C (default EE).
  * SAN: rfc822Name = the e-mail, and DNS = the domain of the e-mail and *.domain.
    Off: --no-dns-from-email, or "dnsFromEmail": false.
  * Level OV (default) or EV. Never DV.
  * Classic only: quadrant 1, no FIPS (default), or quadrant 2 (--fips).
  * ECDSA P-384 and SHA-512 by default.

OPTIONS
  --file F  --example-file F  --validate-only  --stop-on-error  --check-estonian-id
  --non-repudiation  --qc-statements  --no-dns-from-email
  --level OV|EV (--ev)  --quadrant 1|2 (--fips)
  --key-type rsa|ecdsa  --key-bits N  --curve P-256|P-384|P-521  --hash sha256|sha384|sha512
  --days N
  --no-crl  --no-ocsp  --no-revocation-info    leave the CRL / OCSP addresses out
  --release N                 Release of the PKI. Default: the latest.
  --no-ca-revocation-info     Use the NoCR family of CAs.
  --out DIR                   Default ./leafcerts.
  --hash-file LIST            Hash files per certificate. Default sha256,sha512. Also sha384, None.
                              Check:  sha256sum -c <name>.sha256
  --pfx-password TEXT         Default Abc12345! (lab password). Change it.
  --openssl FILE              Use this openssl.
  --help, -h                  This text.        --version   Print the version.

OUTPUT
  leafcerts/persons/<folder>/  (.crt .key .pub .pfx -chain -fullchain person-info.json, hash files)
  and a batch summary (.tsv).

EXIT CODES
  0 done      1 an error or a failed person      5 this system is refused
EOF
}
person_main person "$@"
