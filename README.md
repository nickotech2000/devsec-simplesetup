# Agantra Inovatif Enterprise PKI

A private, multi-level PKI for development and internal use, written in **PowerShell 7** and **OpenSSL 4**.
It builds the CAs (classic RSA / ECDSA and post-quantum ML-DSA, FIPS and non-FIPS), issues TLS, code-signing, S/MIME, person and Office 365 certificates,
runs CRL / OCSP / time stamping on Ubuntu, and gives your developers one zip that installs the trust and lets them ask for their own certificates on **Windows or Linux**.

> **Version 7.6.4** · Author: Nicko Satria Utama · Company: Agantra Inovatif OÜ (NextMantra) · Email: nicko@nextmantra.com
> **Read the documentation as web pages:** open `html/index.html` (double click) or run `.\Serve-Docs.ps1` and open http://localhost:1434. Light / dark theme, accessibility panel, search. `.\Build-HtmlDocs.ps1 -Watch` rebuilds it when a text document changes.
> What changed: [`docs/PKI-ChangeLog.txt`](docs/PKI-ChangeLog.txt) · Which file to read: [`docs/START-HERE.txt`](docs/START-HERE.txt)
> The PKI itself (`pki/`, `leafcerts/`, every `*.key`, every `<company>_pki.cnf` except `agantra_pki.cnf`) is in `.gitignore` and never goes to Git.

## Contents

1. [Quick start](#quick-start) · 2. [Who does what](#who-does-what) · 3. [Get a certificate](#get-a-certificate-the-destination-side) · 4. [The scripts](#the-scripts)
5. [Several companies](#several-companies) · 6. [Releases and NoCR](#releases-and-nocr) · 7. [Requirements](#requirements) · 8. [Documentation](#documentation)
9. [Security](#security) · 10. [Status and testing](#status-and-testing)

## Quick start

On the machine that holds the PKI (PowerShell 7, OpenSSL 4.0.1+):

```powershell
.\Install-DevEnvironment.ps1                                   # OpenSSL 4, 7-Zip ... only what is missing
.\pki_setup.ps1 -Quadrant 1,2                                  # build the PKI (Classic, non-FIPS and FIPS)
.\GenerateLeafCertificate.ps1 -OV -DnsName www.example.com     # certificates, every format
.\GenerateCodeSigningCertificate.ps1 -Platform All            # EV code signing: Windows, Java, Android, Apple
.\Sign-Code.ps1 -UseGenerated -Folder .\bin\Release -Verbose   # sign with them (DigiCert timestamp)
.\New-PkiTrustKit.ps1 -All -GeneratePassword                   # one zip per system for people who only need to trust the PKI
.\PkiTransport.ps1 -DevKit -GeneratePassword                   # one zip for developers who also issue certificates
.\Backup-Pki.ps1                                               # the whole PKI, password protected, into backup-pki\ (Windows, Administrator pwsh)
```

Every script has `-Help` (PowerShell) or `--help` (shell), and `-Version` / `--version` (version, author, OS, .NET, Node.js, Python, Java, shells, Schannel, OpenSSL and its vendor; see `docs/VERSION-INFO.txt`). Version numbers are `major.minor.revision`; the zip is `PKI-DevSecOps-<yyyymmdd>-<version>.zip`.

## Who does what

| Person | Gets | Runs |
|---|---|---|
| **Owner of the PKI** | the project | `pki_setup`, `Generate*`, `SignCsr`, `PkiRevocation`, `New-PkiTrustKit`, `PkiTransport`, `Backup-Pki` |
| **Developer** (issues certificates) | the DevKit zip | `Install-PkiTrust`, `Generate*`, `SignCsr`, `New-PkiCsr` |
| **Tester / junior / customer** (only trusts the PKI) | a trust-kit zip for his system | `Install-PkiCa`, `Prepare-Computer`, `New-PkiCsr` |

## Get a certificate (the destination side)

Four standalone scripts are in **every trust-kit zip, the DevKit and the transport kit**. They need no other file of the project, and they work the same whether the PKI is
already installed on the computer (Local Machine store, `ca-certificates`) or not.

| Step | Windows | Linux |
|---|---|---|
| 1. Get OpenSSL and Python (Windows: PowerShell 7 and .NET SDK 8 + 10 too), put them on the PATH (once; what is the latest already is not installed again) | `.\Prepare-Computer.ps1` | `./prepare-computer.sh` |
| 2. Make the key and the request, step by step | `.\New-PkiCsr.ps1` | `./new-pki-csr.sh` |
| 3. Send **only the `.csr`** to the owner of the PKI | | |
| 4. The owner signs it (the level follows the request) | `.\SignCsr.ps1 -Csr x.csr` | `./SignCsr.sh --csr x.csr` |
| 5. Use the returned `-fullchain.crt` with your `.key` | | |

A request is either a **leaf** request (`-CertificateType Leaf`, signed by `SignCsr`) or an **intermediate CA** request (`-CertificateType IntermediateCA`: CA:TRUE, no names, never the development names; signed by `SignExternalCa`). The owner's scripts recognise the kind by themselves (`-CsrType Auto`) and name the right script if he starts the wrong one.

What the owner's `SignCsr` decides from the request: EV information complete → **EV**; company and country → **OV**; common name only → **DV**. Classic, Quadrant 1 unless he says `-Quantum` / `-FIPS`.
RSA below 2048, weak curves and hashes below SHA-256 are refused by the request maker and by the CA. CRL and OCSP addresses are those of the CA that signs. Manual: [`docs/NewPkiCsr-MANUAL.txt`](docs/NewPkiCsr-MANUAL.txt), [`docs/PrepareComputer-MANUAL.txt`](docs/PrepareComputer-MANUAL.txt).

## The scripts

| Job | Script | Manual (in `docs/`) |
|---|---|---|
| Build the CAs | `pki_setup.ps1` | `pki_setup-MANUAL.txt` |
| Windows laptop that runs unsigned scripts (development only) | `Enable-DevMachine.cmd` / `.ps1` | `Enable-DevMachine-MANUAL.txt` |
| Another company's PKI | `New-PkiConfig.ps1` | `PkiProfiles-MANUAL.txt` |
| TLS, client, code signing, document signing (Office 365 / Office, Adobe PDF), custom EKU OID, S/MIME, time stamping, OCSP certificates | `GenerateLeafCertificate.ps1` (+ `.sh` in the DevKit) | `GenerateLeafCertificate-MANUAL.txt` |
| Code signing certificates, OV / EV, per platform (Windows, Java, Android, Apple), .keystore / .jks, Visual Studio MAUI | `GenerateCodeSigningCertificate.ps1` (+ `.sh` in the DevKit) | `GenerateCodeSigningCertificate-MANUAL.txt` |
| People / Office 365 signers from a JSON file | `GeneratePersonLeafCertificate.ps1`, `GenerateOffice365LeafCertificate.ps1` | the two matching manuals |
| Sign the CSR of a colleague | `SignCsr.ps1` (+ `SignCsr.sh` in the DevKit) | `SignCsr-MANUAL.txt` |
| Sign the CA of another department | `SignExternalCa.ps1` | `SignExternalCa-MANUAL.txt` |
| Revoke, CRL, OCSP, time stamping | `PkiRevocation.ps1` | `PkiRevocation-MANUAL.txt` |
| Trust kits (CA certificates only, one zip per system, several PKIs in one) | `New-PkiTrustKit.ps1` | `PkiTrustKit-MANUAL.txt` |
| Remove a PKI from a destination | `Remove-PkiCa.ps1`, `remove-pki-ca.sh` (in the trust kit) | `PkiTrustKit-MANUAL.txt` |
| Move the PKI, DevKit | `PkiTransport.ps1`, `Unpack-PkiTransport.ps1`, `linux/pki-transport.sh` | `PkiTransport-MANUAL.txt`, `DevKit-MANUAL.txt` |
| CRL / OCSP / TSA server on Ubuntu | `New-PkiServerPackage.ps1`, `linux/pki-server/pki-server.sh` | `PKI-SERVER-MANUAL.txt` |
| Prepare a computer | `Install-DevEnvironment.ps1` / `.sh` (full project), `Prepare-Computer.ps1` / `.sh` (destination) | `Install-DevEnvironment-MANUAL.txt`, `PrepareComputer-MANUAL.txt` |
| Back up / restore the whole PKI (password protected, Windows only) | `Backup-Pki.ps1`, `Restore-Pki.ps1`, `Test-PkiBackup.ps1` | `PkiBackup-MANUAL.txt` |
| Delete a PKI | `pki_remove.ps1` | `-Help` |

## Several companies

The default PKI is Agantra (`agantra_pki.cnf`). For another company run `.\New-PkiConfig.ps1` (it asks for the company data and writes `raksaka_pki.cnf`, for example), then add `-Pki raksaka` to any script:

```powershell
.\pki_setup.ps1 -ListPki                      # the PKIs; Tab completes -Pki
.\pki_setup.ps1 -Pki raksaka -InstallTrust    # pki\pki-raksaka-01, the next run pki-raksaka-02 ...  (Agantra: pki\pki-default-01 ...)
.\New-PkiTrustKit.ps1 -All -Pki agantra,raksaka      # both PKIs in ONE .certpacked inside each zip; -AllProfiles = every company
```

Optional shared settings (default PKI, folders, OpenSSL path ...): `pki_tools.cnf`. Details: `docs/PkiProfiles-MANUAL.txt`.

## Releases and NoCR

Every build is a folder of `pki/`: `pki-default-01`, `pki-default-02`, `pki-default-nocr-01`, `pki-raksaka-01` ... `pki_setup.ps1 -NewRelease` builds the next release;
`-NoCaRevocationInfo` builds the NoCR family (CA certificates without CRL / OCSP URLs). Generators use the latest release; `-Release N` picks one.
`pki_remove.ps1 -List | -Pki name -Release N | -Pki name -All | -AllPki` removes trust and files.

## Requirements

| | Version |
|---|---|
| Backup / restore scripts | Windows 11 Home / Pro 24H2+, Windows Server 2025 Essentials / Standard / Datacenter; Intel / AMD 64 bit only (ARM refused); Administrator PowerShell 7; `Prepare-Computer.ps1` run before a restore (restore checks PowerShell 7, OpenSSL 4, Python 3, .NET SDK 8 and 10). The scripts are standalone; the restore skips every PKI that is in the pki folder or in the Local Machine store already |
| PowerShell (project scripts) | 7.0+; the destination scripts (`New-PkiCsr`, `Prepare-Computer`, `Install-PkiCa`, `Remove-PkiCa`) also run on Windows PowerShell 5.1 |
| OpenSSL | 4.0.1+ to build and issue (tested 4.0.1 – 4.0.3). Destination: 3.x or 4.x (ML-DSA needs 3.5+) |
| Windows | Windows 11 24H2+, Windows Server 2025, Windows Server 2022 (classic track only). Refused (exit 5): Windows 10 and earlier, Windows 11 before 24H2, Server before 2022, Chinese / Government / IoT / SE / Embedded editions |
| Linux | Ubuntu 24 / 26+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES / SLED 15+, openSUSE 15+ (VM, bare metal or WSL). Others and macOS: exit 5 |

## Documentation

All text files are in [`docs/`](docs/); start with `START-HERE.txt`.

| File | What |
|---|---|
| `START-HERE.txt` | which file for which job |
| `PKI-ChangeLog.txt` | what changed in each version |
| `PKI-Design-with-FIPS-and-PQC.txt` | design and every decision |
| `PKI-Acceptance-Checklists.txt` | what to run on your machines |
| `NewPkiCsr-MANUAL.txt` · `PrepareComputer-MANUAL.txt` · `PkiTrustKit-MANUAL.txt` | the destination side |
| `PkiBackup-MANUAL.txt` | backup and restore of the whole PKI |
| `pki_setup-MANUAL.txt` · `PkiProfiles-MANUAL.txt` · the four `Generate…-MANUAL.txt` · `SignCsr-MANUAL.txt` · `SignExternalCa-MANUAL.txt` · `PkiRevocation-MANUAL.txt` | the owner's side |
| `DevKit-MANUAL.txt` · `PkiTransport-MANUAL.txt` · `Install-DevEnvironment-MANUAL.txt` | kits, transport, bootstrap |
| `PKI-SERVER-MANUAL.txt` · `PKI-Server-Design.txt` · `PUBLIC-CA-ENTERPRISE-ROOT.txt` | the Ubuntu server; a public CA over the Enterprise Root |
| `scripts-README.txt` · `linux-README.txt` | PowerShell modules; shell scripts |

Backup and restore handle **only your PKI** (the Organization of your `*_pki.cnf`), never DigiCert, GlobalSign, Sectigo ... certificates; the password is asked first; a restore asks "Replace? [Y/n]" (Enter = Y) when your PKI is already there (`-Yes`).

Backups go to `backup-pki/` (in `.gitignore`, holds private keys). Folders: `scripts/` modules · `devkit/` source of the DevKit · `trustkit/` the standalone destination scripts · `linux/` shell scripts and the server · `docs/` everything above.

## Security

- Never commit `pki/`, `leafcerts/`, `*.key`, `*.pfx`, `*.certpacked`. `.gitignore` also ignores every `*_pki.cnf` except `agantra_pki.cnf`; the pre-commit hook refuses private keys, CRLF and BOM.
- Root keys stay on the PKI machine. A DevKit holds issuing-CA keys only: send it to named people, send the password by another channel, revoke the intermediate if a kit is lost. A trust kit holds no key.
- A request's `.key` never leaves the destination; only the `.csr` is sent.
- Keys that were pasted into chats or tickets are exposed: treat them as test keys and rebuild for production.

## Status and testing

Built and tested on Ubuntu 24.04 with PowerShell 7 and OpenSSL 4.0.3: PKI build, all generators, transport, DevKit, trust kits, request maker → signing → verification against the system store, backup → check → restore (identical files; the Windows checks simulated).
**Not tested on real systems:** Windows 11 / Server (certificate stores, winget and Chocolatey installs, PATH changes in the registry, `icacls`, Windows PowerShell 5.1; the platform gate was only simulated with `PKI_FAKE_OS`),
the real Windows checks of Backup / Restore (version names, ARM, Administrator, `icacls`), Linux distributions other than Ubuntu (simulated with `PKI_OS_RELEASE_FILE`), systemd / nginx on a real server. What to run on your machines: `docs/PKI-Acceptance-Checklists.txt`.

Author: Nicko Satria Utama · Company: Agantra Inovatif OÜ (NextMantra) · Email: nicko@nextmantra.com
