#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# Install-PkiTrust.sh - DevKit, Linux / Ubuntu: unpack the .certpacked of this kit into the kit folder and put the whole PKI
# (every root and intermediate CA) in the system certificate store. A wrapper over pki-transport.sh (same folder).
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
VERSION="6.4.1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAB="$(printf '\t')"

help_pager() {  # help text: one screen at a time on a terminal (Space = next page, q = quit); everything when piped
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -FRXK; elif [ -t 1 ] && command -v more >/dev/null 2>&1; then more; else cat; fi
}
usage() {
cat <<'EOF'
============================================================
 Install-PkiTrust.sh - DevKit installer for Linux / Ubuntu
 Version 6.4.1
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Runs on: Linux only (VM, bare metal or WSL): Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+,
 Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+. Other systems: error, exit 5.
 Manual : docs/DevKit-MANUAL.txt     Windows twin: Install-PkiTrust.ps1

USAGE   (run as your normal user: the script asks sudo only for the system store and for missing
        packages)
  ./Install-PkiTrust.sh                      or:  bash Install-PkiTrust.sh        (no executable \
        bit needed)
  ./Install-PkiTrust.sh --trust-only         only the CA certificates; no issuing keys are unpacked
  ./Install-PkiTrust.sh --yes                install what is missing (7-Zip, ca-certificates) \
        without asking
  ./Install-PkiTrust.sh --reset              unpack pki/ again (your issued certificates in \
        leafcerts/ are kept)

WHAT IT DOES
  1. Finds the .certpacked of the kit (or --package FILE); the password: prompt, --password-file
     FILE, or PKI_TRANSPORT_PASSWORD.
  2. Scans the machine; installs 7-Zip and the certificate-store tools when missing (needs sudo);
     OpenSSL 3.0+ is enough for the generators, 4.0.1+ is needed for the chain proof of
     pki-transport.sh (--install-openssl builds it).
  3. Unpacks the CA certificates (ca/) and the pki/ folder with the ISSUING CA keys into THIS
     folder, checks every SHA-256.
  4. Installs the roots in the system store (/usr/local/share/ca-certificates +
     update-ca-certificates) and proves the chains.
  5. Gives every intermediate CA a NEW RANDOM serial counter (copies must not issue the same serial
     numbers).

OPTIONS
  --package FILE  --password-file FILE  --trust-only  --reset  --yes  --install-openssl
  --skip-openssl-check  --openssl FILE
  --7z FILE  --trust roots|enterprise|all-ca|none  --version  --help
EOF
}

TRUSTMODE=""; PACKAGE=""; PWFILE=""; TRUSTONLY=0; RESET=0; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --package) PACKAGE="$2"; shift ;; --password-file) PWFILE="$2"; shift ;;
    --trust-only) TRUSTONLY=1 ;; --reset) RESET=1 ;;
    --yes|-y|--install-openssl|--skip-openssl-check|--no-verify) EXTRA+=("$1") ;;
    --trust) TRUSTMODE="$2"; EXTRA+=("$1" "$2"); shift ;;
    --openssl|--7z|--openssl-prefix) EXTRA+=("$1" "$2"); shift ;;
    --version) echo "Install-PkiTrust.sh $VERSION"; exit 0 ;; --help|-h) usage | help_pager; exit 0 ;;
    *) echo "[ERROR] unknown option '$1'. See ./Install-PkiTrust.sh --help" >&2; exit 1 ;;
  esac; shift
done
[ "$(uname -s)" = Linux ] || echo "[WARN] this installer is written for Linux (Ubuntu); on macOS use pki-transport.sh directly." >&2
if [ -z "$PACKAGE" ]; then
  for f in "$HERE"/*.certpacked; do [ -f "$f" ] && PACKAGE="$f" && break; done
fi
[ -f "$PACKAGE" ] || { echo "[ERROR] no .certpacked in $HERE (use --package FILE)" >&2; exit 1; }
[ -f "$HERE/pki-transport.sh" ] || { echo "[ERROR] pki-transport.sh is missing in $HERE (the kit is incomplete)" >&2; exit 1; }

MARK="$HERE/pki/.devkit-instance.json"
ALREADY=0; [ -f "$MARK" ] && ALREADY=1
if [ $TRUSTONLY = 1 ]; then EXTRACT=ca
elif [ $ALREADY = 1 ] && [ $RESET = 0 ]; then EXTRACT=ca; echo "[INFO] pki/ is already unpacked here (serial counters and issued certificates stay). The trust is installed again; --reset unpacks pki/ anew."
else EXTRACT=ca,pki; fi
ARGS=(--package "$PACKAGE" --dest "$HERE" --extract "$EXTRACT")
[ -n "$PWFILE" ] && ARGS+=(--password-file "$PWFILE")
[ $RESET = 1 ] && ARGS+=(--force)
bash "$HERE/pki-transport.sh" "${ARGS[@]}" "${EXTRA[@]}"
rc=$?
[ $rc -eq 0 ] || { echo "[ERROR] pki-transport.sh stopped (exit $rc). Nothing else was changed." >&2; exit $rc; }

# ---- the pki folder: absolute paths of the manifest, a random serial per issuing CA, ownership
if [ -d "$HERE/pki" ] && [ $TRUSTONLY = 0 ] && { [ $ALREADY = 0 ] || [ $RESET = 1 ]; }; then
  python3 -I - "$HERE" <<'PY'
import json, os, sys, secrets, uuid, socket, datetime
kit = sys.argv[1]; pki = os.path.join(kit, 'pki')
# 1. paths in pki-manifest.json -> this folder
try:
    old = json.load(open(os.path.join(kit, 'certpack.json'), encoding='utf-8'))['source']['pkiRoot']
    mp = os.path.join(pki, 'pki-manifest.json')
    if os.path.isfile(mp):
        o = old.replace('\\', '/').rstrip('/')
        def fix(v):
            if isinstance(v, str):
                n = v.replace('\\', '/')
                return pki + n[len(o):] if n.lower().startswith(o.lower()) else v
            if isinstance(v, dict): return {k: fix(x) for k, x in v.items()}
            if isinstance(v, list): return [fix(x) for x in v]
            return v
        json.dump(fix(json.load(open(mp, encoding='utf-8'))), open(mp, 'w', encoding='utf-8'), indent=2)
except Exception as e:
    print('[WARN] pki-manifest.json paths not rewritten: %s' % e)
# 1b. the CA configuration files (dir = <old absolute path>) and the notes: the old path becomes this one
try:
    o1 = old.replace('\\', '/').rstrip('/'); n1 = pki.replace('\\', '/').rstrip('/')
    o2 = old.rstrip('\\/'); o3 = o2.replace('\\', '\\\\')
    cnt = 0
    for d, _, files in os.walk(pki):
        for f in files:
            if not f.endswith(('.cnf', '.txt', '.json')) or f == 'pki-manifest.json': continue
            p = os.path.join(d, f); t = open(p, encoding='utf-8', errors='surrogateescape').read(); t2 = t
            seen = set()
            for a, b in ((o1, n1), (o2, pki), (o3, pki)):
                if a and a != b and a not in seen: seen.add(a); t2 = t2.replace(a, b)
            if t2 != t: open(p, 'w', encoding='utf-8', errors='surrogateescape').write(t2); cnt += 1
    print('[OK] the old PKI path was replaced by this folder in %d configuration / note file(s).' % cnt)
except Exception as e:
    print('[WARN] CA configuration paths not rewritten: %s' % e)
# 2. a new random serial counter for every CA directory that holds a key
n = 0
for d, _, files in os.walk(pki):
    if 'serial' in files and any(f.endswith('.key') for f in files):
        b = bytearray(secrets.token_bytes(16)); b[0] = (b[0] % 0x70) + 0x10
        open(os.path.join(d, 'serial'), 'w').write(b.hex().upper() + '\n'); n += 1
json.dump({'id': str(uuid.uuid4()), 'installedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'machine': socket.gethostname(),
           'serialCountersRandomised': n}, open(os.path.join(pki, '.devkit-instance.json'), 'w'), indent=2)
print('[OK] %d issuing CA(s) got a new random serial counter.' % n)
PY
  find "$HERE/pki" -type f -name '*.key' -exec chmod 600 {} + 2>/dev/null
fi
# started with sudo: give the files back to the user
if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then chown -R "$SUDO_USER" "$HERE/pki" "$HERE/ca" "$HERE/certpack.json" 2>/dev/null; fi
bash "$HERE/make-executable.sh" "$HERE" >/dev/null 2>&1
echo
M="Make certificates now:  ./GenerateLeafCertificate.sh --ov --dns www.example.com   (more: START-HERE.txt)"
if [ "$TRUSTMODE" = none ]; then echo "[OK] Done (nothing was added to the system store, as asked). $M"; else echo "[OK] The PKI is trusted on this machine. $M"; fi
