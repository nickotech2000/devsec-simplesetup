#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# make-executable.sh - DevKit, Linux: LF line endings + executable bit for every .sh of this folder.
# Run it with bash (it needs no executable bit itself):   bash make-executable.sh [folder]
# Windows developers: use Make-ShExecutable.ps1 (the Windows twin).
case "${1:-}" in -h|--help)
cat <<'EOT'
make-executable.sh [folder]     folder = this script's folder by default
  1. CRLF -> LF in every *.sh, *.py, *.env (sed; a CRLF script fails with  $'\r': command not found)
  2. chmod +x on every *.sh
EOT
exit 0;; esac
DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
[ -d "$DIR" ] || { echo "[ERROR] not a folder: $DIR" >&2; exit 1; }
n=0; c=0
while IFS= read -r -d '' f; do
  if grep -q $'\r' "$f" 2>/dev/null; then sed -i 's/\r$//' "$f"; c=$((c+1)); fi
  case "$f" in *.sh) chmod +x "$f"; n=$((n+1)) ;; esac
done < <(find "$DIR" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.env' \) -print0)
echo "[OK] $n script(s) are executable now, $c file(s) converted from CRLF to LF. Folder: $DIR"
