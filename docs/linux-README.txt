linux/  -  the shell scripts of the Agantra Inovatif PKI (same repository as the PowerShell scripts)
Version 5.3.6   Author: Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com

  pki-server/pki-server.sh     CRL + CA host (nginx), OCSP, RFC 3161 time stamping for Ubuntu 24.04 / 26.04.  --help, docs/PKI-SERVER-MANUAL.txt
  pki-server/pki-ocsp-dispatch.py, pki-tsa.py   helpers of the server kit (python3, standard library only)
  pki-transport.sh             unpack a .certpacked PKI transport and install the trust (Linux, macOS).   --help
                               (the DevKit wraps it: devkit/Install-PkiTrust.sh)
  Install-DevEnvironment.sh    developer bootstrap: OpenSSL 4 (FIPS + ML-DSA), 7-Zip, git ...   --help
  (devkit\SignCsr.sh     sign a colleague's CSR (in the DevKit and in the project's devkit folder; needs python3).   --help)
  fix-permissions.sh           chmod 755 *.sh *.py, CRLF -> LF, BOM removed. Use after unzip, copy from Windows, /mnt/c.   --check, --help
  setup-git.sh                 run once after "git clone": enables .githooks and repairs the execute bits.

After "git clone" (the index holds mode 100755, so the scripts run at once):
  bash linux/setup-git.sh
  ./linux/pki-server/pki-server.sh --help
Windows side: Setup-GitRepo.ps1 (execute bit in the index, hooks, LF), New-PkiServerPackage.ps1 (zip for Ubuntu), PkiRevocation.ps1.
Design: PKI-Server-Design.txt (this folder: docs\). Since 4.9.5 all documentation text files are in docs\; the README of the project is README.md.
The DevKit (PkiTransport.ps1 -DevKit) carries pki-transport.sh and Install-DevEnvironment.sh to the developers; its Ubuntu scripts (Install-PkiTrust.sh, Generate*.sh) are in devkit\ of the project.

Releases: the shell generators use the latest release in pki/ (or the one in devkit.env); --release N picks one, --no-ca-revocation-info the NoCR family. See pki_setup-MANUAL.txt section 18.

Server: PkiTransport.ps1 -Server (on the CA machine) -> unzip on Ubuntu -> sudo ./linux/pki-server/pki-server.sh install --source ./pki. Install-DevEnvironment.sh: OpenSSL of the distribution by default; --openssl-source ppa|build; --only nginx for nginx from the PPA.

5.0.0: every .sh starts with a platform gate: Linux (VM, bare metal, WSL) Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES / SLED 15+, openSUSE Leap 15+ / Tumbleweed; anything else (macOS too) prints an error and exits with 5. --help always works. Test hook: PKI_OS_RELEASE_FILE.
