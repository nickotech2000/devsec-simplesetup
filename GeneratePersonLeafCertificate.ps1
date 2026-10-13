# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Person (natural person) leaf certificates for e-mail and client authentication, in the form of the national ID card certificate:
    serialNumber = the ID, givenName, surname, CN SURNAME,GIVEN,<ID>, C, SAN e-mail + DNS (domain and *.domain of the e-mail), EKU clientAuth + emailProtection.
    The ID can be any identifier (national ID, passport, driver licence ...). Classic PKI only, OV by default (EV on request, never DV), non-FIPS by default.
    One person with parameters, or many persons from a JSON file ("isGenerate": true | false). Full help: .\GeneratePersonLeafCertificate.ps1 -Help
.EXAMPLE
    .\GeneratePersonLeafCertificate.ps1 -ExampleFile .\persons.json
.EXAMPLE
    .\GeneratePersonLeafCertificate.ps1 -File .\persons.json
.EXAMPLE
    .\GeneratePersonLeafCertificate.ps1 -IdCode 3674010101900001 -GivenName Budi -Surname Santoso -Email budi@example.co.id -Country ID
#>
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    # ---- one person ----
    [string]$IdCode,
    [string]$GivenName,
    [string]$Surname,
    [Alias('EmailAddress')][string]$Email,
    [string]$Country,
    [ValidatePattern('^[A-Za-z0-9]{2,6}$')][string]$IdType,
    [string]$SerialNumber,
    [string]$CommonName,
    # ---- many persons ----
    [string]$File,
    [string]$ExampleFile,
    [switch]$ValidateOnly,
    [switch]$StopOnError,
    # ---- certificate ----
    [ValidateSet('OV', 'EV')][string]$Level,
    [ValidateSet(1, 2)][int]$Quadrant = 1,
    [switch]$Fips,
    [string]$CommonNameFormat,
    [string]$SerialNumberFormat,
    [switch]$KeepCase,
    [switch]$NoCrl,
    [switch]$NoOcsp,
    [switch]$NoRevocationInfo,
    [switch]$CheckEstonianId,
    [switch]$NoDnsFromEmail,
    [ValidateSet('RSA', 'ECDSA')][string]$KeyType,
    [int]$KeyBits,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$Curve,
    [string]$Hash,
    [ValidateRange(1, 36500)][int]$Days,
    [string[]]$Policy,
    [string]$CpsUrl,
    [string]$CpsUrlEv,
    [switch]$NonRepudiation,
    [switch]$QcStatements,
    # ---- output ----
    [ValidateSet('PEM', 'DER', 'CER', 'CERT', 'P7B', 'RFC7468', 'PFX', 'ALL')][string[]]$Format = @('ALL'),
    [string]$OutputRoot,
    [string]$Password = 'Abc12345!',
    [switch]$LegacyPfx,
    [switch]$NoGuidance,
    [switch]$InstallPfx,
    # ---- environment ----
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose,
    [string]$ConfigFile,
    [string]$PkiRoot,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-PersonCertSerial { param([string]$Path) try { $t = Get-PkiCertText -Path $Path; if ($t -match 'Serial Number:\s*\r?\n?\s*([0-9a-fA-F:]+)') { return ($Matches[1] -replace ':','').ToUpper() } } catch { }; return '' }

function Show-PersonHelp {
    @'
============================================================
 GeneratePersonLeafCertificate.ps1 - certificates of PERSONS (e-mail + client authentication)
 Version 5.0.0
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\GeneratePersonLeafCertificate-MANUAL.txt     Design : docs\PKI-Design-with-FIPS-and-PQC.txt (10.59)
 Ubuntu : GeneratePersonLeafCertificate.sh in the DevKit (PkiTransport.ps1 -DevKit): bash + openssl + python3.
 Needs  : PowerShell 7+, OpenSSL 4.x, a PKI made by pki_setup.ps1.

WHAT IT MAKES   (the form of a national ID card certificate; NOT a qualified certificate)
  Subject      serialNumber = <the ID>   givenName = NICKO SATRIA   surname = UTAMA   CN = UTAMA,NICKO SATRIA,<ID>   C = <country, default EE>
               (this order; UTF-8, names in capitals unless -KeepCase)
  The ID       ANY identifier of the person: national ID (KTP/NIK, isikukood ...), passport, driver licence, tax number, staff number.
               There is no country-specific check (-CheckEstonianId switches the Estonian check digit test on for EE).
  SAN          rfc822Name = the e-mail address, and the DNS names TAKEN FROM IT: nicko@nextmantra.com  ->  DNS:nextmantra.com  and  DNS:*.nextmantra.com
               (-NoDnsFromEmail, or "dnsFromEmail": false for one person, leaves them out). No IP address.
  EKU          Client Authentication + Secure E-mail (emailProtection)
  Key usage    critical: digitalSignature + keyAgreement (ECDSA) | keyEncipherment (RSA); -NonRepudiation adds nonRepudiation
  Key          Classic PKI only: ECDSA P-384 (default, as the ID-card sample) or RSA; signature digest SHA-512 (-Hash).  Quadrant 1 = Classic NON-FIPS (default); -Fips or -Quadrant 2 = Classic FIPS.
  Level        OV (default). EV with -Level EV (valid 397 days then). DV is never used for a person.
  Validity     730 days (OV) by default, -Days; cut to what the issuing CA has left.
  Policies     the level policy + PEN + -Policy; CRL / OCSP / CA issuer URLs of the issuing CA (q1-ov by default)
  Output       leafcerts\persons\<id>-<SURNAME>-<GIVEN>\  every format (PEM DER CER CERT P7B RFC7468 PFX), key + public key, chain, leaf-info.json,
               person-info.json, and one persons-batch-<date>.json summary per run (no passwords in it).

ONE PERSON
  .\GeneratePersonLeafCertificate.ps1 -IdCode 3674010101900001 -GivenName Budi -Surname Santoso -Email budi.santoso@example.co.id -Country ID
  -IdCode <text>         The ID (any kind).        -IdType <code>   optional short code: PNO PAS IDC TIN NIK DL ... (only a label, used by -SerialNumberFormat)
  -GivenName / -Surname  Several given names are allowed ("NICKO SATRIA").
  -Email <address>       REQUIRED. Becomes the rfc822Name; the DNS names come from its domain.
  -Country <CC>          Two letters, default EE ([ person ] Country).
  -SerialNumber <text>   The subject serialNumber. Default = the ID.   -SerialNumberFormat "{IdType}{Country}-{IdCode}"  gives the ETSI form PNOEE-37605030299
  -CommonName <text>     Replaces the CN.  -CommonNameFormat "{Surname},{Given},{IdCode}"  tokens {Surname} {Given} {IdCode} {Country} {SurnameFirst}; max 64 characters.

MANY PERSONS - A JSON FILE  (JSON only; CSV is not accepted)
  .\GeneratePersonLeafCertificate.ps1 -ExampleFile .\persons.json    writes an example with 5 people (3 of them isGenerate true) and stops
  .\GeneratePersonLeafCertificate.ps1 -File .\persons.json -ValidateOnly   checks the file and shows the table, issues nothing
  .\GeneratePersonLeafCertificate.ps1 -File .\persons.json
  { "persons": [ { "isGenerate": true, "idCode": "3674010101900001", "serialNumber": "3674010101900001", "givenName": "Budi", "surname": "Santoso",
                   "email": "budi.santoso@example.co.id", "country": "ID" }, { ... } ] }
  Keys (any spelling or case):  idCode  givenName  surname  email   (required)       isGenerate (true | false; default true; false = skipped, not even checked)
  idType  serialNumber  country  level  quadrant  days  keyType  keyBits  curve  commonName  password  name (folder)  policy  dnsFromEmail  noCrl  noOcsp  noRevocationInfo   (optional)
  Keys that start with _ are comments. A missing optional key takes the default / the command line value.
  Every person with isGenerate true is checked BEFORE anything is written: one error = nothing is issued, every error is listed. A person is then issued
  on its own; a failure removes that person's folder and the run goes on (-StopOnError stops at the first failure). Exit 1 when one failed.

CERTIFICATE OPTIONS
  -Level OV|EV           OV (default: q1-ov).  EV: issuer q1-ev, limited to 397 days.  There is no DV.
  -Quadrant 1|2, -Fips   1 Classic non-FIPS (default), 2 Classic FIPS.  The Quantum quadrants are not used for persons.
  -KeyType RSA|ECDSA  -KeyBits  -Curve  as in GenerateLeafCertificate.ps1.   -Hash sha256|sha384|sha512   signature digest, default SHA-512 (the ID-card sample).
                         The sample is ECC P-384 (ECDH_P384) signed ecdsa-with-SHA-512: the leaf here has exactly that key and digest. The SIGNATURE ALGORITHM
                         follows the issuing CA: Q2 (ECDSA P-384 CA) gives ecdsa-with-SHA512; Q1 (RSA 4096 CA, the non-FIPS default) gives sha512WithRSAEncryption.
  -Days <n>  -Policy <oid|oid=cps>  -NonRepudiation
  -CpsUrl <url>          CPS pointer on every OV policy (default https://nextmantra.com/security/certs).   -CpsUrlEv <url>  on every EV policy (default .../security/certs/ev-cps.pdf).
  POLICIES               level policy (OV 2.23.140.1.2.2), company policy 1.3.6.1.4.1.<PEN>.1 and 1.3.6.1.4.1.<PEN>.1.2, and for OV the HIGH ASSURANCE policy
                         1.3.6.1.4.1.<PEN>.1.5 - each with the CPS pointer.
  -QcStatements          Adds the qcStatements extension with QcType eSign (ETSI 0.4.0.1862.1.6.1) like the ID card. It is NOT QcCompliance: this PKI is
                         private and does not issue qualified certificates.
  REVOCATION INFORMATION  (4.9.4)   by default the certificate has the CRL distribution point, the OCSP URL and the CA issuer URL of the issuing CA.
  -NoCrl                 No CRL distribution point (crlDistributionPoints extension) in the certificate.
  -NoOcsp                No OCSP URL (the OCSP method of Authority Information Access); the CA issuer URL stays.
  -NoRevocationInfo      Both: no CRL and no OCSP. Use it when Word / Excel / Outlook say "cannot connect to the revocation server" because the URLs of this
                         private PKI cannot be reached from the machine that checks the signature. Without any revocation URL a client has nothing to check:
                         it accepts the certificate until it expires. The certificate is still recorded in the CA database (PkiRevocation.ps1 can still revoke it
                         and the CRL lists it), but a client that has no URL will not learn about it. Per signer in the JSON file: "noCrl", "noOcsp", "noRevocationInfo"
                         (true | false). Defaults for all: [ person ] NoCrl / NoOcsp in agantra_pki.cnf.
                         NoCR: with this switch the leaf is signed by the NoCR PKI (latest NoCR release, or -Release N): its CA certificates carry no CRL / OCSP URL either. Without a NoCR PKI the script stops: pki_setup.ps1 -NoCaRevocationInfo -InstallTrust.
                         WORD 365: this alone does NOT remove "Recoverable Signature" (the revocation status stays unknown). Issue WITHOUT it from the normal PKI and run  .\Start-PkiCrlServer.ps1  (elevated): it serves the CRLs on this machine.
  -KeepCase              Do not convert the names to capitals.
  -Password <text>       Password of the PFX (default Abc12345!; the password key of a person replaces it). CHANGE IT for real use.
  -Format <list>         PEM DER CER CERT P7B RFC7468 PFX ALL (default ALL).   -LegacyPfx   -NoGuidance   -InstallPfx (Windows: import into the user store)
  -OutputRoot <path>     Default leafcerts\persons.
  -Unblock               UNBLOCK and UNLOCK the script folder, the pki folder and the output, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.
  -Release <n>         Release of the PKI to use (R1, R2 ...). Default: the LATEST release in .\pki\. A release that no longer exists
                       (deleted) is not an error: the latest release is used and a warning says so.
  -NoCaRevocationInfo  Use the NoCR family (pki\pki-<name>-nocr-<NN>, CA certificates without CRL / OCSP). Default: the normal family (the NoCR one
                       when it is the only one).   -PkiRoot <folder> names one PKI folder and overrides both.

DEFAULTS IN agantra_pki.cnf   [ person ]   Days  Level  CommonNameFormat  SerialNumberFormat  Country  KeyType  Curve  DnsFromEmail  NoCrl  NoOcsp
EXIT CODES   0 ok   1 an error or a failed person
============================================================

WHICH PKI  (-Pki, 5.0.0)
  -Pki <name>   the company whose PKI is used: the file <name>_pki.cnf next to the scripts. Default: agantra (or DefaultPki of pki_tools.cnf).
                The names: .\pki_setup.ps1 -ListPki  (press Tab after -Pki to see them). Make a new company: .\New-PkiConfig.ps1.
                The PKI folders are .\pki\pki-default-NN (agantra) and .\pki\pki-<name>-NN (NoCR: pki-<name>-nocr-NN).

WHERE IT RUNS  (5.0.0)
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022
  (Essentials, Standard, Datacenter; RTM or newer). On Windows Server 2022 only the CLASSIC track is generated or issued (no Quantum / ML-DSA);
  FIPS and non-FIPS, DV / OV / EV are available. REFUSED with an error (exit 5, nothing is done): Windows 10 and earlier, Windows 11 before 24H2,
  Windows Server before 2022, and the Chinese, Government, IoT / IoT Enterprise, SE and Embedded editions. Linux (pwsh): the distributions of the
  .sh scripts. Settings shared by all scripts (optional): pki_tools.cnf.
'@
}

if ($Help) { Show-PersonHelp; exit 0 }

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

function Invoke-PkiBootstrapUnlock {
    param([Parameter(Mandatory)][string]$Root)
    $ro = [System.IO.FileAttributes]::ReadOnly
    $unlocked = 0
    foreach ($i in (@(Get-Item -LiteralPath $Root -Force) + @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue))) {
        try { if (($i.Attributes -band $ro) -ne 0) { $i.Attributes = $i.Attributes -bxor $ro; $unlocked++ } } catch { }
        if ($IsWindows -and -not $i.PSIsContainer) { Unblock-File -LiteralPath $i.FullName -ErrorAction SilentlyContinue }
    }
    return $unlocked
}
$script:BootstrapUnlocked = 0
try { $script:BootstrapUnlocked = [int](Invoke-PkiBootstrapUnlock -Root $script:ScriptRoot) }
catch { Write-Host "[WARN] Automatic unblock / unlock failed: $($_.Exception.Message)" -ForegroundColor Yellow }

$script:PersonFolderCreated = $null
try {
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    if ($ExampleFile) {
        foreach ($f in (Write-PkiPersonExample -Path $ExampleFile)) { Write-Host "[OK] Example written: $f" -ForegroundColor Green }
        exit 0
    }
    if ($File -and ($IdCode -or $GivenName -or $Surname)) { throw 'Use -File OR -IdCode / -GivenName / -Surname, not both.' }
    if (-not $File -and -not ($IdCode -or $GivenName -or $Surname) -and -not $Unblock) { throw 'Give one person (-IdCode, -GivenName, -Surname, -Email) or a file (-File persons.json). -Help shows everything; -ExampleFile persons.json writes an example.' }
    if ($Fips) { if ($PSBoundParameters.ContainsKey('Quadrant') -and $Quadrant -ne 2) { throw '-Fips and -Quadrant 1 contradict each other.' }; $Quadrant = 2 }

    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    $c = $script:Pki
    $leafRoot = Get-PkiLeafRoot
    $personRoot = if ($OutputRoot) { $leafRoot } else { Join-Path $leafRoot 'persons' }
    if ($Unblock) {
        [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot, $personRoot)); exit 0
    }

    # ---------------- the persons ----------------
    $set = Get-PkiPersonSettings
    $defaults = @{
        CommonNameFormat = $(if ($CommonNameFormat) { $CommonNameFormat } else { $set.CommonNameFormat })
        SerialNumberFormat = $(if ($SerialNumberFormat) { $SerialNumberFormat } else { $set.SerialNumberFormat })
        KeepCase = [bool]$KeepCase; CheckEstonianId = [bool]$CheckEstonianId; DnsFromEmail = $(if ($NoDnsFromEmail) { $false } else { [bool]$set.DnsFromEmail })
        Country = $(if ($Country) { $Country } else { $set.Country }); IdType = $(if ($IdType) { $IdType } else { '' })
        Level = $(if ($Level) { $Level } else { $set.Level }); Days = $(if ($Days) { $Days } else { $set.Days }); DaysGiven = [bool]$Days
        Quadrant = $Quadrant; Password = $Password
        NoCrl = ([bool]$NoCrl -or [bool]$NoRevocationInfo -or [bool]$set.NoCrl); NoOcsp = ([bool]$NoOcsp -or [bool]$NoRevocationInfo -or [bool]$set.NoOcsp)
    }
    foreach ($k in 'KeyType', 'KeyBits', 'Curve') { if ($PSBoundParameters.ContainsKey($k)) { $defaults[$k] = $PSBoundParameters[$k] } }
    $records = [System.Collections.Generic.List[object]]::new()
    if ($File) { foreach ($r in (Read-PkiPersonFile -Path $File)) { [void]$records.Add($r) } }
    else {
        $one = [ordered]@{ _Line = 0 }
        foreach ($k in 'IdCode', 'GivenName', 'Surname', 'Email', 'Country', 'IdType', 'SerialNumber', 'CommonName', 'Level') { if ($PSBoundParameters.ContainsKey($k)) { $one[$k] = $PSBoundParameters[$k] } }
        [void]$records.Add($one)
    }
    if ($records.Count -eq 0) { throw 'The person file contains no person.' }

    $errors = [System.Collections.Generic.List[string]]::new()
    $entries = [System.Collections.Generic.List[object]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($rec in $records) {
        try {
            $e = ConvertTo-PkiPersonEntry -Record $rec -Defaults $defaults
            if ($e.Skip) { [void]$skipped.Add($e); continue }
            $key = "$($e.Country)|$($e.IdCode)|$($e.Level)|$($e.Quadrant)"
            if ($seen.ContainsKey($key)) { throw "Person $($e.Line) [$($e.Label)]: the same ID (country, ID, level, quadrant) is already on person $($seen[$key])." }
            $seen[$key] = $e.Line
            [void]$entries.Add($e)
        }
        catch { [void]$errors.Add($_.Exception.Message) }
    }

    $common = @{
        KeyType = $(if ($KeyType) { $KeyType } else { $set.KeyType }); Curve = $(if ($Curve) { $Curve } else { $set.Curve })
        Hash = $(if ($Hash) { $Hash } else { 'sha512' }); Days = $(if ($Days) { $Days } else { $set.Days }); Policy = @($Policy); Format = @($Format)
        NonRepudiation = [bool]$NonRepudiation; QcStatements = [bool]$QcStatements
    }

    # ---------------- OpenSSL and the PKI ----------------
    Initialize-OpenSSL
    $needFips = (@($entries | Where-Object { $_.Quadrant -eq 2 }).Count -gt 0)
    [void](Assert-PkiLeafOpenSslReady -NeedFips $needFips -NeedPqc $false)
    [void](Import-PkiExisting -SkipProviders)
    foreach ($qq in @($entries | ForEach-Object { $_.Quadrant } | Sort-Object -Unique)) { if ($c.Quadrants -notcontains $qq) { [void]$errors.Add("This PKI has no Quadrant $qq (it has: $(($c.Quadrants | ForEach-Object { "Q$_" }) -join ', ')).") } }

    # decide everything before anything is written
    $specs = @{}
    foreach ($e in @($entries)) {
        try {
            $o = New-PkiPersonOptions -Entry $e -Common $common
            $specs[$e.Label + '|' + $e.Line] = New-PkiLeafSpec -Options $o
        }
        catch { [void]$errors.Add("Person $($e.Line) [$($e.Label)]: $($_.Exception.Message)") }
    }
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-PkiLog "$($errors.Count) problem(s) - NOTHING was issued:" 'ERROR'
        foreach ($m in $errors) { Write-Host "   - $m" -ForegroundColor Red }
        exit 1
    }
    Write-PkiLog "Persons to issue: $($entries.Count)   skipped (isGenerate false): $($skipped.Count)   Output: $personRoot"
    Write-Host ''
    Write-Host ('{0,-3} {1,-20} {2,-26} {3,-30} {4,-3} {5,-5} {6}' -f 'NO', 'SERIAL NUMBER', 'NAME', 'E-MAIL', 'LVL', 'QUAD', 'DNS') -ForegroundColor Cyan
    foreach ($e in $entries) { Write-Host ('{0,-3} {1,-20} {2,-26} {3,-30} {4,-3} {5,-5} {6}' -f $e.Line, $e.SerialNumber, "$($e.Surname) $($e.GivenName)", $e.Email, $e.Level, "Q$($e.Quadrant)", (@($e.Dns) -join ', ')) }
    foreach ($e in $skipped) { Write-Host ('{0,-3} {1,-20} {2}' -f $e.Line, $e.IdCode, "SKIPPED (isGenerate false): $($e.Label)") -ForegroundColor DarkGray }
    Write-Host ''
    if ($entries.Count -eq 0) { Write-PkiLog 'No person has isGenerate true: nothing to issue.' 'WARN'; exit 0 }
    if ($ValidateOnly) { Write-PkiLog 'Validation only: every entry with isGenerate true is valid. Nothing was issued.' 'OK'; exit 0 }

    # ---------------- issue ----------------
    [void][System.IO.Directory]::CreateDirectory($personRoot)
    $done = [System.Collections.Generic.List[object]]::new(); $failed = [System.Collections.Generic.List[string]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $entries) {
        $spec = $specs[$e.Label + '|' + $e.Line]
        $pw = if ($e.Password) { $e.Password } else { $Password }
        Set-PkiSecretEnvironment -Password $pw
        try {
            $folder = New-PkiUniqueFolder -Root $personRoot -Name $spec.Folder -SuffixTemplate $spec.UniqueSuffix
            $script:PersonFolderCreated = $folder.Path
            $spec.OutDir = $folder.Path
            if ($folder.Renamed) { Write-PkiLog "The folder '$($spec.Folder)' exists already: a NEW folder was created: $($folder.Name)" 'WARN' }
            $r = New-PkiLeafCertificate -Spec $spec
            $v = Test-PkiLeafResult -Spec $spec -R $r
            $subject = Test-PkiPersonResult -Entry $e -Spec $spec -R $r -QcStatements:([bool]$QcStatements)
            Write-PkiLog "  validated  : $($e.Label)  [$subject]" 'OK'
            foreach ($oid in $v.UnsupportedPolicies) { Write-PkiLog "  policy $oid is in the certificate but the issuing CA does not carry it" 'WARN' }
            if (-not $NoGuidance) { [void](Write-PkiLeafGuidance -Spec $spec -R $r -NoTls) }
            $r.Files = @(@(Get-ChildItem -LiteralPath $r.Dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name }) + @('leaf-info.json', 'person-info.json') | Sort-Object -Unique)
            $entry = Add-PkiLeafIndex -Root $personRoot -Spec $spec -R $r -FolderName $folder.Name
            Write-Utf8NoBom -Path (Join-Path $r.Dir 'leaf-info.json') -Content ($entry | ConvertTo-Json -Depth 6)
            $pinfo = [ordered]@{
                person = [ordered]@{ serialNumber = $e.SerialNumber; idCode = $e.IdCode; idType = $e.IdType; country = $e.Country; givenName = $e.GivenName; surname = $e.Surname; commonName = $e.CommonName; email = $e.Email; dns = @($e.Dns) }
                certificate = [ordered]@{ subject = $subject; issuer = $spec.Ca.Id; level = $spec.Level; keyAlgorithm = $r.Actual.Algorithm; keyUsage = $spec.KeyUsage; extendedKeyUsage = @('clientAuth', 'emailProtection'); days = $r.Days; notAfter = $r.NotAfter; sha1 = $r.Sha1; sha256 = $r.Sha256; qcStatements = [bool]$QcStatements; qualified = $false }
                note = 'Private PKI certificate. Not a qualified certificate (no QcCompliance).'
                createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GeneratePersonLeafCertificate.ps1 $($script:PkiGeneratorVersion)"
            }
            Write-Utf8NoBom -Path (Join-Path $r.Dir 'person-info.json') -Content (($pinfo | ConvertTo-Json -Depth 6) + "`n")
            [void](Unblock-PkiTree -Path @($folder.Path)); [void](Unlock-PkiTree -Path @($folder.Path))
            if ($InstallPfx -and $IsWindows -and $r.Pfx) {
                Assert-Administrator
                $res2 = Install-PkiLeafPfx -Leaf ([ordered]@{ name = $r.Stem; pfx = $r.Pfx; sha1 = $r.Sha1 })
                if ($res2.Status -eq 'failed') { Write-PkiLog "The PFX of $($r.Stem) could not be imported: $($res2.Message)" 'WARN' }
            }
            $script:PersonFolderCreated = $null
            [void]$done.Add(@{ Entry = $e; R = $r; Spec = $spec; Folder = $folder })
            [void]$rows.Add([ordered]@{ status = 'OK'; idCode = $e.IdCode; serialNumber = $e.SerialNumber; givenName = $e.GivenName; surname = $e.Surname; email = $e.Email; dns = @($e.Dns); folder = $folder.Name; certificateSerial = (Get-PersonCertSerial -Path $r.Crt); notAfter = $r.NotAfter; sha1 = $r.Sha1; issuer = $spec.Ca.Id })
        }
        catch {
            $msg = ($_.Exception.Message -split "`n" | Select-Object -First 3) -join ' | '
            if ($script:PersonFolderCreated -and (Test-Path -LiteralPath $script:PersonFolderCreated)) {
                [void](Unlock-PkiTree -Path @($script:PersonFolderCreated)); Remove-Item -LiteralPath $script:PersonFolderCreated -Recurse -Force -ErrorAction SilentlyContinue
            }
            $script:PersonFolderCreated = $null
            [void]$failed.Add("$($e.Label): $msg")
            Write-PkiLog "FAILED $($e.Label): $msg" 'ERROR'
            [void]$rows.Add([ordered]@{ status = 'FAILED'; idCode = $e.IdCode; serialNumber = $e.SerialNumber; givenName = $e.GivenName; surname = $e.Surname; email = $e.Email; message = $msg })
            if ($StopOnError) { break }
        }
    }
    foreach ($e in $skipped) { [void]$rows.Add([ordered]@{ status = 'SKIPPED'; idCode = $e.IdCode; serialNumber = $e.SerialNumber; email = $e.Email; message = 'isGenerate is false' }) }
    $batch = Join-Path $personRoot ("persons-batch-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-Utf8NoBom -Path $batch -Content (([ordered]@{ createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GeneratePersonLeafCertificate.ps1 $($script:PkiGeneratorVersion)"; issued = $done.Count; failed = $failed.Count; skipped = $skipped.Count; persons = @($rows) } | ConvertTo-Json -Depth 6) + "`n")

    # ---------------- summary ----------------
    Write-Host ''
    Write-Host 'PERSON CERTIFICATES' -ForegroundColor Cyan
    Write-Host ("  Folder     : {0}" -f $personRoot)
    foreach ($d in $done) {
        Write-Host ("  OK   {0,-16} {1,-30} {2,-30} until {3}   {4}" -f $d.Entry.SerialNumber, "$($d.Entry.Surname) $($d.Entry.GivenName)", $d.Entry.Email, $d.R.NotAfter, $d.Folder.Name) -ForegroundColor Green
    }
    foreach ($f in $failed) { Write-Host "  FAIL $f" -ForegroundColor Red }
    Write-Host ("  Summary    : {0}   (no passwords in it)" -f $batch)
    Write-PkiLog ("{0} certificate(s) issued, {1} failed, {2} skipped (isGenerate false). The PKI server learns about them after New-PkiServerPackage.ps1 + 'pki-server.sh update'." -f $done.Count, $failed.Count, $skipped.Count) $(if ($failed.Count -eq 0) { 'OK' } else { 'WARN' })
    exit $(if ($failed.Count -eq 0) { 0 } else { 1 })
}
catch {
    $failure = $_
    if ($script:PersonFolderCreated -and (Test-Path -LiteralPath $script:PersonFolderCreated)) {
        try { [void](Unlock-PkiTree -Path @($script:PersonFolderCreated)); Remove-Item -LiteralPath $script:PersonFolderCreated -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
    if (-not $Verbose -and $failure.Exception.GetType().Name -eq 'RuntimeException') { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red; exit 1 }
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure } catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally { if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment } }
