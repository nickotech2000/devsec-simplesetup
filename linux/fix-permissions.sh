#!/usr/bin/env bash
# fix-permissions.sh - makes every script of the Linux side of the Agantra PKI executable and removes CRLF / BOM.
# Run it after unzip (when a zip tool dropped the execute bits), after copying from Windows or a share, or on a fresh clone
# (git hooks do the same automatically once  pwsh ./Setup-GitRepo.ps1  or  git config core.hooksPath .githooks  was run).
# Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
set -u
case "${1:-}" in -h|--help)
cat <<'TXT'
fix-permissions.sh [FOLDER]
  Makes *.sh and *.py executable (chmod 755), converts CRLF to LF and removes a BOM in *.sh, *.py, *.txt, *.cnf, *.json, *.crt, *.pem,
  and removes a "Zone.Identifier" file left by Windows. Default FOLDER: the package / repository root (one level above this script's folder).
  --check   only report, change nothing (exit 1 when something would change)
TXT
exit 0;; esac
CHECK=0; [ "${1:-}" = "--check" ] && { CHECK=1; shift; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP="${1:-$(dirname "$HERE")}"
changed=0
while IFS= read -r -d '' f; do
  if grep -q $'\r' "$f" 2>/dev/null || [ "$(head -c3 "$f" | od -An -tx1 | tr -d ' ')" = efbbbf ]; then
    changed=$((changed+1)); echo "LF/BOM : ${f#$TOP/}"; [ "$CHECK" = 1 ] || { sed -i '1s/^\xEF\xBB\xBF//; s/\r$//' "$f"; }
  fi
done < <(find "$TOP" \( -name .git -o -name node_modules \) -prune -o -type f \( -name '*.sh' -o -name '*.py' -o -name '*.txt' -o -name '*.cnf' -o -name '*.json' -o -name '*.crt' -o -name '*.pem' -o -name '*.pub' -o -name '*.md' \) -print0)
while IFS= read -r -d '' f; do
  if [ ! -x "$f" ]; then changed=$((changed+1)); echo "chmod +x: ${f#$TOP/}"; [ "$CHECK" = 1 ] || chmod 755 "$f"; fi
done < <(find "$TOP" -name .git -prune -o -type f \( -name '*.sh' -o -name '*.py' \) -print0)
find "$TOP" -name '*:Zone.Identifier' -delete 2>/dev/null
[ "$changed" = 0 ] && echo "all scripts are executable and LF" || { [ "$CHECK" = 1 ] && { echo "$changed file(s) need fixing"; exit 1; } || echo "fixed $changed file(s)"; }
exit 0
