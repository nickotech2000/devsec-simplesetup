#!/usr/bin/env bash
# ============================================================
# PKI Script - remove-pki-ca.sh  (STANDALONE: needs no other script)
# Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
# ============================================================
# Takes PKIs away again that install-pki-ca.sh put on this Linux machine: one company, several, or all.  Run:  ./remove-pki-ca.sh --help
VERSION="6.4.3"
set -u

help_pager() {  # help text: one screen at a time on a terminal (Space = next page, q = quit); everything when piped
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -FRXK; elif [ -t 1 ] && command -v more >/dev/null 2>&1; then more; else cat; fi
}
usage() {
cat <<'EOT'
============================================================
 remove-pki-ca.sh  -  remove PKIs that install-pki-ca.sh installed (Linux)
 Version 6.4.3
 Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email:
                               nicko@nextmantra.com
============================================================
WHAT IT DOES
  install-pki-ca.sh writes a list of everything it installed (/var/lib/pki-trust-kit/installed.tsv):
  the root files in the system store (pki-<company>-....crt), the files it opened into the folder
  pki/ next to it, and the Firefox imports (--firefox).
  This script reads that list and removes the files of the PKI(s) you name, then refreshes the
  system store (update-ca-certificates / update-ca-trust). It needs no package, no password and no
  other file. It is the "RemoveTrust / RemoveAllTrust" of the destination machine.

HOW TO RUN
    bash remove-pki-ca.sh --list               what the kit installed (company, release, root files)
    bash remove-pki-ca.sh --pki raksaka        remove ONE company (every release of it); --pki \
          agantra,raksaka for several
    bash remove-pki-ca.sh --pki raksaka --check   only show what would be removed
    bash remove-pki-ca.sh --all                remove EVERYTHING the kit installed (all companies)
    bash remove-pki-ca.sh --org raksaka        no list (or an older kit): remove \
          pki-raksaka-*.crt  from the system store
  sudo is used by itself for the system store (unless you are root).

OPTIONS
  --pki NAME[,NAME]   the company short name(s) as shown by --list
  --all               every PKI in the list
  --org NAME[,NAME]   by name, without the list: the files  <store>/pki-NAME-*.crt  (and the legacy
                      NAME-pki-*.crt)
  --list              show the list and stop
  --keep-files        leave the opened files in the folder pki/ (only the system store is cleaned)
  --check             show what would be removed, change nothing
  --yes               do not ask "Remove N file(s)?"
  --help

SUPPORTED  Ubuntu 24.04 / 26.04 or newer, CentOS Stream 10+, RHEL 10+, Rocky Linux 10+, Oracle Linux
10+, SUSE Linux Enterprise 15+ (15, 16 ...),
           openSUSE 15+ (Leap 15, 16 ..., Tumbleweed). Any other distribution or older version is
           REFUSED with an error (exit 5), nothing is changed.
EXIT     0 done   1 error   5 this Linux distribution / version is not supported
============================================================
EOT
}

C_OK=""; C_W=""; C_E=""; C_I=""; C_0=""
[ -t 1 ] && { C_OK=$'\033[32m'; C_W=$'\033[33m'; C_E=$'\033[31m'; C_I=$'\033[36m'; C_0=$'\033[0m'; }
info() { printf '%s[INFO]%s %s\n' "$C_I" "$C_0" "$*"; }
ok()   { printf '%s[OK]%s   %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_W" "$C_0" "$*" >&2; }
die()  { printf '%s[ERROR]%s %s\n' "$C_E" "$C_0" "$1" >&2; exit "${2:-1}"; }

PKIS=""; ORGS=""; ALL=0; LIST=0; CHECK=0; YES=0; KEEPFILES=0
case "${1:-}" in -h|--help) : ;; *) echo "[INFO] remove-pki-ca.sh version $VERSION" >&2 ;; esac
while [ $# -gt 0 ]; do
  case "$1" in
    --pki) [ $# -ge 2 ] || die "--pki needs a name"; PKIS="$PKIS,$2"; shift 2 ;;
    --org) [ $# -ge 2 ] || die "--org needs a name"; ORGS="$ORGS,$2"; shift 2 ;;
    --all) ALL=1; shift ;;
    --list) LIST=1; shift ;;
    --keep-files) KEEPFILES=1; shift ;;
    --check) CHECK=1; shift ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage | help_pager; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
done
PKIS="$(echo "$PKIS" | tr 'A-Z,;' 'a-z  ' | xargs -n1 2>/dev/null | sort -u | tr '\n' ' ')"
ORGS="$(echo "$ORGS" | tr 'A-Z,;' 'a-z  ' | xargs -n1 2>/dev/null | sort -u | tr '\n' ' ')"

echo "============================================================"
echo " remove-pki-ca.sh - remove PKIs installed by install-pki-ca.sh"
echo " Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com"
echo "============================================================"
[ "$(uname -s)" = Linux ] || die "This script is for Linux. On Windows use Remove-PkiCa.ps1." 1

# ---- which Linux? the same rules as install-pki-ca.sh (exit 5 otherwise)
OSREL="${PKI_OS_RELEASE_FILE:-/etc/os-release}"
OS_ID=""; OS_VER=""; OS_PRETTY=""
if [ -r "$OSREL" ]; then OS_ID="$(. "$OSREL"; echo "${ID:-}")"; OS_VER="$(. "$OSREL"; echo "${VERSION_ID:-}")"; OS_PRETTY="$(. "$OSREL"; echo "${PRETTY_NAME:-$NAME}")"; fi
OS_MAJOR="${OS_VER%%.*}"; case "$OS_MAJOR" in ''|*[!0-9]*) OS_MAJOR=0 ;; esac
OS_OK=0
case "$OS_ID" in
  ubuntu)                  [ "$OS_MAJOR" -ge 24 ] && OS_OK=1 ;;
  centos|rhel|rocky|ol)    [ "$OS_MAJOR" -ge 10 ] && OS_OK=1 ;;
  sles|sles_sap|sled|opensuse-leap) [ "$OS_MAJOR" -ge 15 ] && OS_OK=1 ;;
  opensuse-tumbleweed)     OS_OK=1 ;;
esac
[ "$OS_OK" = 1 ] || die "This system is '${OS_PRETTY:-unknown}' (ID=${OS_ID:-?} VERSION_ID=${OS_VER:-?}): NOT supported. Nothing was changed.
        Supported: Ubuntu 24.04 / 26.04 or newer; CentOS Stream 10+; RHEL 10+; Rocky Linux 10+; Oracle Linux 10+; SUSE Linux Enterprise 15+; openSUSE 15+ (Leap 15, 16 ..., Tumbleweed)." 5

STATE_DIR="${PKI_KIT_STATE_DIR:-/var/lib/pki-trust-kit}"
REG="$STATE_DIR/installed.tsv"
# the anchor folder and update command: from the list (written by the installer), else from this machine
UPDATE=""; ANCHOR=""
if [ -f "$REG" ]; then
  while IFS=$'\t' read -r k a b; do [ "$k" = "#update" ] && { UPDATE="$a"; ANCHOR="$b"; }; done < <(grep '^#update' "$REG" | tr -d '\r')
fi
if [ -z "$UPDATE" ]; then
  OSLIKE=""; [ -r /etc/os-release ] && OSLIKE="$(. /etc/os-release; echo "${ID_LIKE:-}")"
  case " $OS_ID $OSLIKE " in
    *" ubuntu "*|*" debian "*) ANCHOR="/usr/local/share/ca-certificates"; UPDATE="update-ca-certificates" ;;
    *" rhel "*|*" fedora "*|*" centos "*) ANCHOR="/etc/pki/ca-trust/source/anchors"; UPDATE="update-ca-trust extract" ;;
    *) ANCHOR="/etc/pki/trust/anchors"; UPDATE="update-ca-certificates" ;;
  esac
fi
ANCHOR="${PKI_ANCHOR_DIR:-$ANCHOR}"; UPDATE="${PKI_UPDATE_CMD:-$UPDATE}"
SUDO=""
if [ "$(id -u)" != 0 ] && [ -z "${PKI_ANCHOR_DIR:-}" ] && [ "$LIST" = 0 ] && [ "$CHECK" = 0 ]; then command -v sudo >/dev/null 2>&1 && SUDO="sudo" || die "root or sudo is needed for the system certificate store."; fi

# ---- the list
ROWS=()   # pki<TAB>release<TAB>kind<TAB>path<TAB>name
if [ -f "$REG" ]; then while IFS= read -r l; do ROWS+=("$l"); done < <(grep -v '^#' "$REG" | tr -d '\r' | grep -v '^$'); fi
if [ "$LIST" = 1 ] || { [ "$ALL" = 0 ] && [ -z "${PKIS// /}" ] && [ -z "${ORGS// /}" ]; }; then
  if [ "${#ROWS[@]}" -eq 0 ]; then info "The list is empty ($REG): this kit installed nothing here (or it was removed). Use --org NAME to remove by name."
  else
    info "${#ROWS[@]} entries in $REG:"
    printf '%s\n' "${ROWS[@]}" | cut -f1 | sort -u | while read -r pk; do
      rels="$(printf '%s\n' "${ROWS[@]}" | awk -F'\t' -v p="$pk" '$1==p && $2!="" {print $2}' | sort -u | tr '\n' ' ')"
      nroot="$(printf '%s\n' "${ROWS[@]}" | awk -F'\t' -v p="$pk" '$1==p && $3=="anchor"' | wc -l)"
      info "  $pk: $nroot root(s) in the system store; PKI folders: ${rels:-?}"
      printf '%s\n' "${ROWS[@]}" | awk -F'\t' -v p="$pk" '$1==p && $3=="anchor" {print "        " $4}'
    done
  fi
  [ "$LIST" = 1 ] || info "Say what to remove:  --pki NAME   or   --all   (or --org NAME).  --check only shows."
  exit 0
fi

# ---- what to remove
TODO=()   # kind<TAB>path<TAB>name
if [ -n "${PKIS// /}" ]; then
  for want in $PKIS; do
    n=0
    for r in "${ROWS[@]}"; do IFS=$'\t' read -r pk rel kind path name _x <<<"$r"; [ "$(echo "$pk" | tr 'A-Z' 'a-z')" = "$want" ] && { TODO+=("$kind"$'\t'"$path"$'\t'"$name"); n=$((n+1)); }; done
    [ "$n" -gt 0 ] || { known="$(printf '%s\n' "${ROWS[@]:-}" | cut -f1 | sort -u | tr '\n' ' ')"; die "'$want' is not in the list. Known: ${known:-(empty)}"; }
  done
fi
if [ "$ALL" = 1 ]; then for r in "${ROWS[@]}"; do IFS=$'\t' read -r pk rel kind path name _x <<<"$r"; TODO+=("$kind"$'\t'"$path"$'\t'"$name"); done; fi
if [ -n "${ORGS// /}" ]; then
  for want in $ORGS; do for f in "$ANCHOR/pki-$want"-*.crt "$ANCHOR/$want"-pki-*.crt; do [ -f "$f" ] && TODO+=("anchor"$'\t'"$f"$'\t'"$(basename "$f")"); done; done
fi
[ "${#TODO[@]}" -gt 0 ] || { info "Nothing to remove."; exit 0; }
info "${#TODO[@]} item(s) to remove:"
for t in "${TODO[@]}"; do IFS=$'\t' read -r kind path name <<<"$t"; info "  [$kind] $path"; done
if [ "$CHECK" = 1 ]; then ok "Check finished: nothing was changed."; exit 0; fi
if [ "$YES" = 0 ]; then
  [ -t 0 ] || die "Not a terminal: add --yes to remove without asking."
  read -r -p "Remove ${#TODO[@]} item(s)? (y/N) " a; case "$a" in y|Y|yes|YES) : ;; *) info "Cancelled, nothing was changed."; exit 0 ;; esac
fi

nanchor=0; nfile=0; nff=0; dirs=()
for t in "${TODO[@]}"; do
  IFS=$'\t' read -r kind path name <<<"$t"
  case "$kind" in
    anchor) if [ -f "$path" ]; then $SUDO rm -f "$path" && { nanchor=$((nanchor+1)); ok "removed from the system store: $(basename "$path")"; }; fi ;;
    file)   if [ "$KEEPFILES" = 0 ] && [ -f "$path" ]; then rm -f "$path" 2>/dev/null && { nfile=$((nfile+1)); dirs+=("$(dirname "$path")"); }; fi ;;
    firefox) command -v certutil >/dev/null 2>&1 && certutil -D -d "sql:$path" -n "$name" >/dev/null 2>&1 && { nff=$((nff+1)); ok "removed from Firefox profile $(basename "$path"): $name"; } ;;
  esac
done
# empty folders of the opened package go too
for d in $(printf '%s\n' "${dirs[@]:-}" | sort -u | awk '{print length, $0}' | sort -rn | cut -d' ' -f2-); do
  while [ -n "$d" ] && [ -d "$d" ] && [ -z "$(ls -A "$d" 2>/dev/null)" ] && case "$d" in */pki|*/pki/*) true ;; *) false ;; esac; do rmdir "$d" 2>/dev/null || break; d="$(dirname "$d")"; done
done
if [ "$nanchor" -gt 0 ]; then
  info "Running: $UPDATE"
  $SUDO $UPDATE 2>&1 | sed 's/^/        /'
fi
# update the list: remove the rows of what was removed
if [ -f "$REG" ]; then
  tmp="$(mktemp "${TMPDIR:-/tmp}/pki-reg.XXXXXX")"
  { grep '^#' "$REG"
    grep -v '^#' "$REG" | tr -d '\r' | while IFS=$'\t' read -r a b c d e g; do
      gone=0; for t in "${TODO[@]}"; do IFS=$'\t' read -r tk tp tn <<<"$t"; [ "$tp" = "$d" ] && [ "$tk" = "$c" ] && gone=1; done
      [ "$gone" = 1 ] || printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$a" "$b" "$c" "$d" "$e" "$g"
    done; } > "$tmp"
  if [ -z "$(grep -v '^#' "$tmp")" ]; then $SUDO rm -f "$REG"; $SUDO rmdir "$STATE_DIR" 2>/dev/null; else $SUDO cp -f "$tmp" "$REG"; fi
  rm -f "$tmp"
fi
# nothing of the kit is left: the information files of the opened package and the empty folders go as well
if [ "$KEEPFILES" = 0 ] && [ ! -f "$REG" ]; then
  for t in "${TODO[@]}"; do IFS=$'\t' read -r kind path name <<<"$t"; [ "$kind" = file ] && case "$path" in */pki/ca/*) echo "${path%/ca/*}" ;; esac; done | sort -u | while read -r base; do
    [ -d "$base" ] || continue
    rm -f "$base/README.txt" "$base/SHA256SUMS" "$base/certpack.json" "$base/certpack.tsv" 2>/dev/null
    find "$base" -depth -type d -empty -delete 2>/dev/null
  done
fi
# read back
left=0; for t in "${TODO[@]}"; do IFS=$'\t' read -r kind path name <<<"$t"; [ "$kind" = anchor ] && [ -f "$path" ] && { left=$((left+1)); warn "still there: $path"; }; done
[ "$left" = 0 ] || die "$left file(s) could not be removed from $ANCHOR."
ok "Removed $nanchor root(s) from the system store, $nfile opened file(s)$( [ "$nff" -gt 0 ] && echo ", $nff Firefox import(s)"). Restart browsers / tools."
exit 0
