linux/  -  the shell scripts of the Agantra Inovatif PKI (same repository as the PowerShell scripts)
Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com

  pki-server/pki-server.sh     CRL + CA host (nginx), OCSP, RFC 3161 time stamping for Ubuntu 24.04 / 26.04.  --help, PKI-SERVER-MANUAL.txt
  pki-server/pki-ocsp-dispatch.py, pki-tsa.py   helpers of the server kit (python3, standard library only)
  pki-transport.sh             unpack a .certpacked PKI transport and install the trust (Linux, macOS).   --help
  Install-DevEnvironment.sh    developer bootstrap: OpenSSL 4 (FIPS + ML-DSA), 7-Zip, git ...   --help
  fix-permissions.sh           chmod 755 *.sh *.py, CRLF -> LF, BOM removed. Use after unzip, copy from Windows, /mnt/c.   --check, --help
  setup-git.sh                 run once after "git clone": enables .githooks and repairs the execute bits.

After "git clone" (the index holds mode 100755, so the scripts run at once):
  bash linux/setup-git.sh
  ./linux/pki-server/pki-server.sh --help
Windows side: Setup-GitRepo.ps1 (execute bit in the index, hooks, LF), New-PkiServerPackage.ps1 (zip for Ubuntu), PkiRevocation.ps1.
Design: ../PKI-Server-Design.txt
