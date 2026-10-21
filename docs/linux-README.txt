====================================================================================================
 linux/  -  the shell scripts of the Agantra Inovatif PKI
 Version 7.6.8
 Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================

 READ THIS FIRST
----------------------------------------------------------------------------------------------------
 What it is   : The shell scripts for Linux: Ubuntu, the RHEL family (CentOS Stream, Rocky,
                Oracle) and SUSE. They live in the same repository as the PowerShell scripts.
 Who reads it : Linux administrators.
 You need     : bash and sudo.
 Start with   : Run any script with --help. It shows one page at a time (SPACE = next page).
                Run any script with --version for its version and your system (VERSION-INFO.txt).
 Words        : GLOSSARY.txt (technical terms), GLOSSARY-ENGLISH.txt (everyday English words)
----------------------------------------------------------------------------------------------------

 THE SCRIPTS
   pki-server/pki-server.sh     CRL + CA host (nginx), OCSP and RFC 3161 time stamping. The
                                automatic install uses apt, so it is for Ubuntu 24.04 / 26.04.
                                Manual: PKI-SERVER-MANUAL.txt
   pki-server/pki-ocsp-dispatch.py, pki-tsa.py
                                helpers of the server kit (python3, standard library only)
   pki-transport.sh             unpack a .certpacked PKI transport and install the trust (Linux).
                                The DevKit wraps it: devkit/Install-PkiTrust.sh
   Install-DevEnvironment.sh    developer bootstrap: OpenSSL 4 (FIPS + ML-DSA), 7-Zip, git ...
                                Manual: Install-DevEnvironment-MANUAL.txt
   fix-permissions.sh           chmod 755 *.sh *.py, CRLF to LF, BOM removed. Use it after unzip,
                                after a copy from Windows, or on /mnt/c.   Options: --check
   setup-git.sh                 run once after "git clone": enables .githooks and repairs the
                                execute bits.
   (devkit/SignCsr.sh            sign a colleague's CSR. It is in the DevKit and in the project's
                                devkit folder. Needs python3. Manual: SignCsr-MANUAL.txt)

 AFTER "git clone"  (the index holds mode 100755, so the scripts run at once)
   bash linux/setup-git.sh
   ./linux/pki-server/pki-server.sh --help
 Windows side: Setup-GitRepo.ps1 (execute bit in the index, hooks, LF), New-PkiServerPackage.ps1
 (zip for the Linux server), PkiRevocation.ps1.

 NOTES
   - Design: PKI-Server-Design.txt (this folder, docs\). Since 4.9.5 all documentation text files
     are in docs\. The README of the project is README.md.
   - The DevKit (PkiTransport.ps1 -DevKit) carries pki-transport.sh and Install-DevEnvironment.sh
     to the developers. Its Ubuntu scripts (Install-PkiTrust.sh, Generate*.sh) are in devkit\ of
     the project.
   - Releases: the shell generators use the latest release in pki/ (or the one in devkit.env).
     --release N picks one, --no-ca-revocation-info the NoCR family. See pki_setup-MANUAL.txt,
     section 9.
   - Server: PkiTransport.ps1 -Server (on the CA machine), unzip on the server, then
     sudo ./linux/pki-server/pki-server.sh install --source ./pki
   - Install-DevEnvironment.sh uses the OpenSSL of the distribution by default.
     --openssl-source ppa|build gets OpenSSL 4. --only nginx installs nginx from the PPA.

 PLATFORM GATE (since 5.0.0)
   Every .sh starts with a check. Allowed: Linux (VM, bare metal or WSL) with Ubuntu 24+,
   CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES / SLED 15+, openSUSE Leap 15+
   or Tumbleweed. Anything else, macOS too, prints an error and exits with 5. --help always works.
   Test hook: PKI_OS_RELEASE_FILE.
====================================================================================================
 Author: Nicko Satria Utama  Company: Agantra Inovatif OU (NextMantra)  Email: nicko@nextmantra.com
====================================================================================================
