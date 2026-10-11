# Agantra Inovatif Enterprise PKI

A private, multi-level PKI for development and internal use, written in **PowerShell 7** and **OpenSSL 4**.
It builds a root → track → quadrant → DV / OV / EV hierarchy (classic **RSA / ECDSA** and post-quantum **ML-DSA**, FIPS and non-FIPS),
issues TLS, code-signing, S/MIME, person and Microsoft Office / 365 certificates, runs CRL / OCSP / time stamping on Ubuntu,
and hands your developers one zip that installs the trust and makes their own certificates on **Windows or Ubuntu**.

> Version **4.9.5-phaseC** · Author: Nicko Satria Utama · Agantra Inovatif OÜ (NextMantra) · nicko@nextmantra.com
> Private repository. The PKI itself (`pki/`, `leafcerts/`, any `*.key`) is in `.gitignore` and never goes to Git.

---

## Contents

1. [Quick start](#quick-start)
2. [What you get](#what-you-get)
3. [The scripts](#the-scripts)
4. [DevKit: one zip for your developers](#devkit-one-zip-for-your-developers)
5. [Hierarchy at a glance](#hierarchy-at-a-glance)
6. [Requirements](#requirements)
7. [Repository layout](#repository-layout)
8. [Documentation](#documentation)
9. [Security notes](#security-notes)
10. [Status and testing](#status-and-testing)

---

## Quick start

On the machine that holds the PKI (Windows 11 or Linux with PowerShell 7 and OpenSSL 4.0.1+):

```powershell
.\Install-DevEnvironment.ps1                 # OpenSSL 4 (FIPS + ML-DSA), 7-Zip ... only what is missing
.\pki_setup.ps1 -Quadrant 1,2                # build the PKI (Classic, non-FIPS and FIPS)
.\GenerateLeafCertificate.ps1 -OV -DnsName www.example.com       # 7 certificates, one per purpose, every format
.\PkiTransport.ps1 -DevKit -GeneratePassword                      # the zip for your developers
```

Every script has `-Help` (PowerShell) or `--help` (shell). The manuals are in [`docs/`](docs/).

## What you get

| Need | Script | Result |
|---|---|---|
| Build the CAs | `pki_setup.ps1` | Enterprise Root, Classic/Quantum Track Roots, Quadrant Roots, DV/OV/EV intermediates |
| TLS, client, code signing, S/MIME, time stamping, OCSP certificates | `GenerateLeafCertificate.ps1` | one folder per purpose: `.crt .key .pub .pfx .p7b .der` + chains |
| Certificates of people (any ID, JSON file) | `GeneratePersonLeafCertificate.ps1` | ID-card style subject, e-mail + DNS in the SAN, ECDSA P-384 / SHA-512 |
| Word / Excel / PDF signing | `GenerateOffice365LeafCertificate.ps1` | Document Encryption + Secure Email + Document Signing |
| Revocation, CRL, OCSP, time stamping | `pki_remove.ps1` | list the PKIs (`-List`), remove one release (`-Release N [-DeleteFiles]`) or everything (`-All`) | `-Help` |
| `PkiRevocation.ps1` | revoke, new CRL, responder and TSA certificates |
| `Start-PkiCrlServer.ps1` (CRL host `crl.nextmantra.internal`, OCSP host `ocsp.nextmantra.internal`, CA issuer `crt.nextmantra.internal`; `pki-server.sh dns` prints the hosts-file lines and the router records) | Windows: serve the CRLs / CA files on this machine (hosts file + web server) so Word / Outlook can check revocation |
| Sign the CSR of a colleague (TLS, e-mail, code signing ...) | `SignCsr.ps1` / `devkit/SignCsr.sh` | CSR in, certificate + chain out; DV (default), OV, EV; the CSR must follow the spec, errors shown in colour |
| Sign the CSR of another department's CA | `SignExternalCa.ps1` | signed by a Classic Quadrant Root only; OV (default), DV, EV; original PKI only |
| Move the PKI | `PkiTransport.ps1`, `Unpack-PkiTransport.ps1`, `linux/pki-transport.sh` | password-protected `.certpacked` |
| **Give developers the PKI** | **`PkiTransport.ps1 -DevKit`** | **one zip: installers + generators for Windows and Ubuntu** |
| CRL / OCSP / TSA server | `New-PkiServerPackage.ps1`, `linux/pki-server/pki-server.sh` | zip for Ubuntu, no private keys |

## The scripts

| Script | Purpose | Manual |
|---|---|---|
| `pki_setup.ps1` | build, verify, trust, clean the PKI (`agantra_pki.cnf` holds the settings); `-NoCaRevocationInfo`, `-NewRelease`, `-Release N` | `docs/pki_setup-MANUAL.txt` |
| `GenerateLeafCertificate.ps1` | leaf certificates; `-NoCrl -NoOcsp -NoRevocationInfo`, `-AddDevelopmentSAN` | `docs/GenerateLeafCertificate-MANUAL.txt` |
| `GeneratePersonLeafCertificate.ps1` | persons from `persons.json` (`isGenerate` per person) | `docs/GeneratePersonLeafCertificate-MANUAL.txt` |
| `GenerateOffice365LeafCertificate.ps1` | Office signers from `office365.json` | `docs/GenerateOffice365LeafCertificate-MANUAL.txt` |
| `PkiRevocation.ps1` | revoke, CRL, OCSP and TSA certificates | `docs/PkiRevocation-MANUAL.txt` |
| `SignCsr.ps1` (+ `SignCsr.sh` in the DevKit) | sign a colleague's CSR with a DV / OV / EV intermediate; `-Check` only reports | `docs/SignCsr-MANUAL.txt` |
| `SignExternalCa.ps1` | sign a department CA with a Classic Quadrant Root (`-Quadrant 1`, `-Fips` = Q2; default OV; O, OU, C required) | `docs/SignExternalCa-MANUAL.txt` |
| `PkiTransport.ps1` | `-Pack`, `-Install`, `-DevKit`, `-Server` (zip for the Ubuntu CRL / OCSP server), `-Check`, `-List`, `-RemoveTrust` | `docs/PkiTransport-MANUAL.txt`, `docs/DevKit-MANUAL.txt` |
| `Install-DevEnvironment.ps1` / `.sh` | OpenSSL (Linux default: the distribution's 3.x; `--openssl-source ppa\|build` for 4), nginx from the PPA, 7-Zip, git ... | `docs/Install-DevEnvironment-MANUAL.txt` |
| `New-PkiServerPackage.ps1`, `linux/pki-server/` | CRL / OCSP / TSA server for Ubuntu (nginx and OpenSSL 4 from the PPA); reads `pki/R<n>/server/` of the PKI | `docs/PKI-SERVER-MANUAL.txt` |
| `Setup-GitRepo.ps1`, `linux/setup-git.sh` | execute bit, hooks and LF in Git | `-Help` |

## DevKit: one zip for your developers

```powershell
.\PkiTransport.ps1 -DevKit -GeneratePassword          # agantra-pki-devkit-<date>.zip (the password is shown once)
```

The developer unzips it and runs **one** installer, then a generator. No Linux knowledge needed.

| | Windows 11 25H2+ (PowerShell 7, Administrator) | Ubuntu / Linux |
|---|---|---|
| Install the PKI | `.\Install-PkiTrust.ps1` (Local Machine store) | `./Install-PkiTrust.sh` (system store) |
| Leaf certificates | `.\GenerateLeafCertificate.ps1 -OV -DnsName a.example.com` | `./GenerateLeafCertificate.sh --ov --dns a.example.com` |
| Person certificates | `.\GeneratePersonLeafCertificate.ps1 -File persons.json` | `./GeneratePersonLeafCertificate.sh --file persons.json` |
| Office 365 | `.\GenerateOffice365LeafCertificate.ps1 -File office365.json` | `./GenerateOffice365LeafCertificate.sh --file office365.json` |
| Make the `.sh` executable | `.\Make-ShExecutable.ps1` | `bash make-executable.sh` |

Inside: the `.certpacked` (AES-256), the installers, the generators (`.ps1` and `.sh`), `devkit.env` (written from your live configuration),
examples, manuals and `START-HERE.txt`.
**Keys:** the package carries the private keys of the *issuing* (intermediate) CAs only — never a root key. Each copy gets its own random serial counter.
Certificates made from a copy are development certificates: they are not in the master CRL / OCSP. Read [`docs/DevKit-MANUAL.txt`](docs/DevKit-MANUAL.txt) before you send a kit.

## Releases and the NoCR variant

All PKIs live in `pki/`, one subfolder each: `pki/R1`, `pki/R2`, `pki/NoCR-R1` ... (an old flat `pki/` counts as R1).

- `pki_setup.ps1 -NewRelease` builds the next release (a new Enterprise Root and everything below it). Names get a suffix: `… Root CA G1`, `… Root CA G1 R2`, `… Root CA G1 (NoCR) R2`. Leaf names do not change. Running `pki_setup.ps1 -InstallTrust` again builds the next free release by itself; `-Release 8` stops with "R8 already exists" when the folder `pki\R8` or the Windows store already has it (`-Clean -Release 8` replaces). `-NoRevocationInfo` on the leaf scripts signs with the NoCR PKI (latest NoCR release). Every leaf PFX has the friendly name `<Primary EKU> for <CN> Sign by : <Intermediate CA CN>`.
- `pki_setup.ps1 -NoCaRevocationInfo` builds a separate family whose **CA certificates** have no CRL / OCSP / CA Issuers URL (leaves keep theirs; use `-NoRevocationInfo` on the leaf generators to drop them too). Remove the trust of the normal PKI and install this one.
- Every generator (`.ps1` and `.sh`) uses the **latest** release by default; `-Release N` (`--release N`) picks one, a release that no longer exists falls back to the latest with a warning. `-NoCaRevocationInfo` (`--no-ca-revocation-info`) selects the NoCR family.
- `pki_remove.ps1 -List | -Release N [-DeleteFiles] | -All` removes the Windows trust and the files of one release or of everything.
- A DevKit or server package holds one PKI. Details: `docs/pki_setup-MANUAL.txt` section 18, `docs/PKI-Design-with-FIPS-and-PQC.txt` section 21.

## CRL, OCSP and the Ubuntu server

- File names of the CRL and CA-issuer URLs follow the CA names: `agantra-root-g1.crl`, `agantra-classic-root-g1.crt`, `agantra-pqc-root-g2.crl`, `agantra-q1-root-g1.crl`, `agantra-q1-ov-g1.crl` (`-nocr`, `-r2` for the NoCR family / release 2). The OCSP responder and time stamp certificates are named the same way (`Agantra EV RSA-4096 G1 CA (NoCR) R2 OCSP Responder`).
- `pki_setup.ps1` and every `PkiRevocation.ps1` action write `pki/R<n>/server/` (`server-info.json`, `ca-list.tsv`, `server.env`, `expected-urls.tsv`, `DNS-RECORDS.txt`): the hosts, the CAs and every URL that the certificates of that PKI contain.
- `PkiTransport.ps1 -Server` (or `New-PkiServerPackage.ps1`) packs that PKI **without any private key** with `linux/pki-server/` into one zip. On Ubuntu 24.04 / 26.04: `sudo ./linux/pki-server/pki-server.sh install --source ./pki`. The server reads the hosts and CA list from the PKI, installs nginx and OpenSSL 4 from the PPA `ppa:nickotech2000/nicko-su-prod`, and `pki-server.sh test` asks every URL of the PKI.
- `Install-DevEnvironment.sh` on Linux uses the distribution's OpenSSL by default (Ubuntu 26.04: 3.5.x, 24.04: 3.0.x); nginx comes from the PPA (`--only nginx`); OpenSSL 4 from the PPA with `--openssl-source ppa`.

## Hierarchy at a glance

```
Enterprise Root (RSA 8192)
├── Classic Track Root
│   ├── Q1 Root  (RSA 4096, non-FIPS) ── DV / OV / EV intermediates (RSA 4096)
│   └── Q2 Root  (ECDSA P-384, FIPS)  ── DV / OV / EV intermediates (ECDSA P-384)
└── Quantum Track Root (ML-DSA)
    ├── Q1 Root (ML-DSA-87, non-FIPS) ── DV / OV / EV intermediates (ML-DSA)
    └── Q2 Root (ML-DSA-87, FIPS)     ── DV / OV / EV intermediates (ML-DSA)
```

Every policy carries a CPS pointer (`https://nextmantra.com/security/certs`, EV: `.../ev-cps.pdf`); OV certificates also carry the High Assurance policy
`1.3.6.1.4.1.67096.1.5`. Details and all decisions: [`docs/PKI-Design-with-FIPS-and-PQC.txt`](docs/PKI-Design-with-FIPS-and-PQC.txt).

## Requirements

| | Needed for | Version |
|---|---|---|
| PowerShell | every `.ps1` | 7.0+ (Windows, Linux, macOS) |
| OpenSSL | build and issue | 4.0.1+ (tested 4.0.1 – 4.0.3), full build with FIPS provider and ML-DSA |
| Windows | `PkiTransport.ps1 -Install`, `Install-PkiTrust.ps1` | Windows 11 25H2 or newer, administrator |
| Ubuntu | server kit, `*.sh` | 24.04 / 26.04; shell generators need bash, openssl 3.0+, python3 |
| 7-Zip | AES-256 for 7z packages, Linux unpack | installed on demand (`-InstallMissing`, `--yes`) |

## Repository layout

```
README.md                  this file
pki_setup.ps1  Generate*.ps1  PkiRevocation.ps1  SignCsr.ps1  SignExternalCa.ps1  PkiTransport.ps1  Unpack-PkiTransport.ps1
Install-DevEnvironment.ps1  New-PkiServerPackage.ps1  Setup-GitRepo.ps1
agantra_pki.cnf            all settings (names, URLs, policies, validity, person / Office defaults)
scripts/                   PowerShell modules 00 … 22 (PkiModules.ps1 loads them)
devkit/                    source of the DevKit: Install-PkiTrust, shell generators, lib/, START-HERE.txt
linux/                     Install-DevEnvironment.sh, pki-transport.sh, pki-server/ (CRL, OCSP, TSA), git helpers
docs/                      every manual, the design, the checklists (see below)
.githooks/ .gitattributes .gitignore
```

Created at run time and never committed (`pki/R1`, `pki/R2`, `pki/NoCR-R1` ... one subfolder per PKI): `pki/`, `leafcerts/`, `external-ca/`, `transport/`.

## Documentation

All documentation text files are in [`docs/`](docs/).

| File | What |
|---|---|
| `pki_setup-MANUAL.txt` | the PKI generator, trust on every device, using the certificates in servers |
| `GenerateLeafCertificate-MANUAL.txt` · `GeneratePersonLeafCertificate-MANUAL.txt` · `GenerateOffice365LeafCertificate-MANUAL.txt` | the three generators |
| `DevKit-MANUAL.txt` · `PkiTransport-MANUAL.txt` | the DevKit and the `.certpacked` transport |
| `PkiRevocation-MANUAL.txt` · `PKI-SERVER-MANUAL.txt` · `PKI-Server-Design.txt` | revocation and the Ubuntu server |
| `SignCsr-MANUAL.txt` · `SignExternalCa-MANUAL.txt` · `PUBLIC-CA-ENTERPRISE-ROOT.txt` | external CAs; an Enterprise Root signed by a public CA |
| `Install-DevEnvironment-MANUAL.txt` | the developer bootstrap |
| `PKI-Design-with-FIPS-and-PQC.txt` | design, decisions, limitations, change log |
| `PKI-Acceptance-Checklists.txt` | what to run on your machines to accept each phase |
| `scripts-README.txt` · `linux-README.txt` | modules; shell scripts |

## Security notes

- **Never commit** `pki/`, `leafcerts/`, `*.key`, `*.pfx`, `*.certpacked`. The pre-commit hook refuses private keys, CRLF and BOM.
- Root keys stay on the PKI machine. A DevKit holds issuing-CA keys only; send it to named people, send the password by another channel, revoke the intermediate if a kit is lost.
- Keys that were uploaded to chats or tickets are exposed: treat them as test keys and rebuild the PKI for production.
- Certificates made with `-NoCrl` / `-NoOcsp` cannot be checked or revoked through the left-out service: development and Office use.

## Status and testing

Built and tested on Ubuntu 24.04 with PowerShell 7.5 and OpenSSL 4.0.3: PKI build, all generators (PowerShell and shell), transport, DevKit end to end.
**Not tested by the author:** Windows 11 (store installation, WSL `chmod`), macOS, other Linux distributions, systemd/nginx on a real server.
The acceptance checklists in `docs/PKI-Acceptance-Checklists.txt` say what to run on your machines.
