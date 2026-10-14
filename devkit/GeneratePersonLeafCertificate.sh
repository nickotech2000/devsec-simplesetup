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
    PKI_TOOL_VERSION="5.3.5"; echo "[INFO] $(basename "$0") version $PKI_TOOL_VERSION" >&2
    export PKI_GATE_DONE=1 ;;
  esac
fi
VERSION="5.3.5"; TOOL="GeneratePersonLeafCertificate.sh"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib/pki-lib.sh"; . "$HERE/lib/pki-person.sh"

usage() {
cat <<'EOF'
============================================================
 GeneratePersonLeafCertificate.sh - person certificates from a JSON file (Linux / Ubuntu, DevKit)
 Version 5.3.5
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Runs on: Linux only (VM, bare metal or WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+. Other systems: error, exit 5.
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
