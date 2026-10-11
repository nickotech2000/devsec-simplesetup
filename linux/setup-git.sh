#!/usr/bin/env bash
# setup-git.sh - run ONCE after "git clone" on Linux / WSL: turns on the repository hooks and makes every .sh / .py executable.
# (git does not copy hooks with a clone, so this one step is needed. The execute bits themselves come with the clone when the
#  index holds mode 100755 - Setup-GitRepo.ps1 on Windows writes them there - and this script is the safety net.)
# Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
case "${1:-}" in -h|--help) echo "setup-git.sh   (no options) - git config core.hooksPath .githooks, chmod 755 *.sh *.py, LF check. Run inside the clone."; exit 0;; esac
top="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not inside a git clone"; exit 1; }
cd "$top" || exit 1
git config core.hooksPath .githooks && echo "hooks: .githooks enabled"
git config core.autocrlf false; git config core.eol lf
chmod +x .githooks/* 2>/dev/null
bash "$top/linux/fix-permissions.sh" "$top"
if [ -d Scripts ] && [ ! -d scripts ]; then echo "WARNING: the folder is 'Scripts' but the code uses 'scripts' (Linux is case sensitive). On Windows run: pwsh ./Setup-GitRepo.ps1 -FixCase"; fi
echo "done. Try:  ./linux/pki-server/pki-server.sh --help"
