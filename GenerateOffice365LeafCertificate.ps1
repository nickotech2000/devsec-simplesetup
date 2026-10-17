# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Microsoft Office / Microsoft 365 DOCUMENT SIGNING certificates for people: extended key usage E-mail Protection + Document Encryption + Document Signing,
    key usage Digital Signature + Non-Repudiation (+ Key Encipherment for RSA / Key Agreement for ECDSA), SAN e-mail address (the Microsoft 365 account).
    One signer with parameters, or many from a JSON file ("isGenerate": true | false). Output: leafcerts\office365\<name>\.
    Classic PKI only, OV by default (EV on request, never DV), non-FIPS by default. Full help: .\GenerateOffice365LeafCertificate.ps1 -Help
.EXAMPLE
    .\GenerateOffice365LeafCertificate.ps1 -ExampleFile .\office365.json
.EXAMPLE
    .\GenerateOffice365LeafCertificate.ps1 -File .\office365.json
.EXAMPLE
    .\GenerateOffice365LeafCertificate.ps1 -GivenName Budi -Surname Santoso -Email budi.santoso@example.co.id
#>
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    # ---- one signer ----
    [string]$IdCode,
    [string]$GivenName,
    [string]$Surname,
    [Alias('EmailAddress')][string]$Email,
    [string]$Country,
    [ValidatePattern('^[A-Za-z0-9]{2,6}$')][string]$IdType,
    [string]$SerialNumber,
    [string]$CommonName,
    # ---- many signers ----
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
    [switch]$DnsFromEmail,
    [switch]$NoDocumentSigningEku,
    [ValidateSet('RSA', 'ECDSA')][string]$KeyType,
    [int]$KeyBits,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$Curve,
    [string]$Hash,
    [ValidateRange(1, 36500)][int]$Days,
    [string[]]$Policy,
    [string]$CpsUrl,
    [string]$CpsUrlEv,
    # ---- output ----
    [ValidateSet('PEM', 'DER', 'CER', 'CERT', 'P7B', 'RFC7468', 'PFX', 'ALL')][string[]]$Format = @('ALL'),
    [ValidateSet('sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-384', 'sha3-512', 'None')][string[]]$HashFile = @('sha256', 'sha512'),
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
$script:PkiHashFileAlgs = @($HashFile)      # 6.4.2: <name>.sha256 / .sha512 next to every certificate

function Get-PersonCertSerial { param([string]$Path) try { $t = Get-PkiCertText -Path $Path; if ($t -match 'Serial Number:\s*\r?\n?\s*([0-9a-fA-F:]+)') { return ($Matches[1] -replace ':','').ToUpper() } } catch { }; return '' }

function Show-PersonHelp {
    @'
====================================================================================================
 GenerateOffice365LeafCertificate.ps1  -  Microsoft Office / 365 DOCUMENT SIGNING certificates
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\GenerateOffice365LeafCertificate-MANUAL.txt        Words : docs\GLOSSARY.txt
 Linux  : GenerateOffice365LeafCertificate.sh (DevKit). It needs bash, openssl and python3.
 Same mechanism as GeneratePersonLeafCertificate.ps1.

WHAT IT DOES
  Makes one certificate for each signer of a JSON list. The certificate signs Word, Excel,
  PowerPoint and PDF documents, and can encrypt them. It is NOT a qualified certificate.
  All data is checked BEFORE anything is written. One error = nothing is issued, all errors are
  listed. Then each signer is issued alone. If one fails, that folder is removed.

QUICK START
  1. Write an example ..... .\GenerateOffice365LeafCertificate.ps1 -ExampleFile .\office365.json
  2. Edit office365.json .. your signers (isGenerate true = make it, false = skip)
  3. Check, issue nothing . .\GenerateOffice365LeafCertificate.ps1 -File .\office365.json
    -ValidateOnly
  4. Issue ................ .\GenerateOffice365LeafCertificate.ps1 -File .\office365.json
  Files go to  .\leafcerts\office365\<name>\

BEFORE YOU START
  * The PKI exists (pki_setup.ps1).   * PowerShell 7 or newer.   * OpenSSL 4.x.
  * Fix a missing OpenSSL: .\Install-DevEnvironment.ps1 -Only OpenSSL,7Zip, then open a NEW window.
  * Every start unblocks and unlocks the script folders. -Unblock does only that.

WHAT IS INSIDE
  Purposes (EKU)  Document Encryption 1.3.6.1.4.1.311.80.1
                  Secure Email (S/MIME) 1.3.6.1.5.5.7.3.4
                  Document Signing 1.3.6.1.4.1.311.10.3.12  (-NoDocumentSigningEku leaves it out)
  Key usage       Critical: digital signature + non-repudiation + key encipherment (RSA) or key
                  agreement (ECDSA). ECDSA cannot encrypt documents: use RSA for that.
  Subject         [serialNumber = ID], givenName, surname, CN = "Given Surname", C = country
                  (default EE). Names stay as typed.
  SAN             The e-mail (the Microsoft 365 account). -DnsFromEmail adds DNS:<domain> and
                  DNS:*.<domain>.
  Key             Classic only. RSA 4096 by default (minimum 2048). ECDSA P-384 by default
                  (minimum P-256).
  Digest          SHA-2 only. The issuing CA decides (SHA-256 on Q1, SHA-384 on Q2) unless -Hash.
  Level           OV (default) or EV (397 days). Never DV.
  Validity        730 days (OV). -Days changes it. Never longer than the issuing CA.
  Policies        Level policy, company policies, High Assurance (OV), each with a CPS pointer.

THE JSON FILE   (JSON only; CSV is refused; keys starting with _ are comments)
  { "persons": [ { "isGenerate": true, "givenName": "Budi", "surname": "Santoso",
                   "email": "budi.santoso@example.co.id", "country": "ID" } ] }
  Required:  givenName  surname  email
  Optional:  isGenerate (default true; false = skipped, not even checked)  idCode  idType
             serialNumber  country  level  quadrant  days  keyType  keyBits  curve  commonName
             password  name (folder)  policy  dnsFromEmail  noCrl  noOcsp  noRevocationInfo
  -File <path>     The list.          -ExampleFile <path>   Write an example (5 made-up people).
  -ValidateOnly    Check, show the table, issue nothing.
  -StopOnError     Stop at the first failure.

ONE SIGNER, NO FILE
  .\GenerateOffice365LeafCertificate.ps1 -GivenName Budi -Surname Santoso `
        -Email budi.santoso@example.co.id [-Country ID] [-IdCode STAFF-0001]
  -GivenName / -Surname  Several given names are allowed.          -Email <address>   REQUIRED.
  -IdCode <text>         Optional (staff number, national ID, passport ...). Goes to the subject
                         serialNumber. -SerialNumber replaces it.
  -SerialNumberFormat    "{IdType}{Country}-{IdCode}".             -IdType <code>   Optional label.
  -Country <CC>          Two letters. Default EE.
  -CommonName <text>     Replaces the CN.
  -CommonNameFormat      "{Given} {Surname}". Tokens: {Given} {Surname} {SurnameFirst} {IdCode}
                         {Country}. 64 characters at most.
  -KeepCase              Names stay as typed (default for Office).
  -DnsFromEmail          Add DNS:<domain> and DNS:*.<domain> from the e-mail.

LEVEL, QUADRANT, KEYS
  -Level OV|EV           OV (default) or EV (397 days at most).
  -Quadrant 1|2, -Fips   1 = Classic, no FIPS (default). 2 = Classic FIPS.
  -KeyType RSA|ECDSA     -KeyBits 2048|3072|4096|8192     -Curve P-256|P-384|P-521
  -Hash sha256|sha384|sha512   Office baseline is SHA-256. SHA-384 and SHA-512 are supported.
  -Days <n>              -Policy <oid|oid=cps>     -NoDocumentSigningEku
  -CpsUrl <url>          CPS pointer for OV.       -CpsUrlEv <url>   CPS pointer for EV.

REVOCATION SWITCHES
  -NoCrl               No CRL address.
  -NoOcsp              No OCSP address. The CA issuer address stays.
  -NoRevocationInfo    Both. A client then has nothing to check, and never learns of a revocation.
  In the JSON file: "noCrl", "noOcsp", "noRevocationInfo". Defaults: [ office365 ] in
  agantra_pki.cnf.
  With these switches the NoCR PKI signs the leaf (latest NoCR release, or -Release N). Without
  it the script stops. Build it: .\pki_setup.ps1 -NoCaRevocationInfo -InstallTrust
  WORD 365: this alone does NOT remove "cannot connect to the revocation server" or "Recoverable
  Signature". Issue from the normal PKI and run .\Start-PkiCrlServer.ps1 as administrator.
  To see what fails:  certutil -verify -urlfetch <name>.cer

FILES YOU GET
  Per signer: <name>.crt .pem .cert .cer .der .p7b .rfc7468.pem .key (PRIVATE) .pub .pub.der .pfx
              -chain.crt -fullchain.crt, convert-formats.ps1, leaf-info.json, office365-info.json,
              OFFICE-NOTES.txt
  Per run:    office365-batch-<date>.json (who, until when; no passwords)
  -Password <text>     PFX password. Default Abc12345! (lab password). CHANGE IT for real use.
                       A "password" key of one signer replaces it.
  -Format <list>       PEM DER CER CERT P7B RFC7468 PFX ALL. Default ALL.
  -LegacyPfx           3DES / SHA-1 PFX for very old software.     -NoGuidance
  No convert-formats.ps1.
  -InstallPfx          Windows: also import the PFX into the user store.
  -OutputRoot <path>   Default leafcerts\office365.

HASH FILES
  -HashFile <list>   <name>.sha256 and <name>.sha512 next to the files (default).
                     Values: sha256 sha384 sha512 sha3-256 sha3-384 sha3-512 None.
  Each line is "<hash>  <file>". Check:  sha256sum -c <name>.sha256
  (Windows: Get-FileHash <file> -Algorithm SHA256)

USING THE CERTIFICATE   (OFFICE-NOTES.txt in every folder says the same)
  1  Import the .pfx into Current User > Personal (double-click, or -InstallPfx).
  2  The root CA of this PKI must be trusted on the computer that OPENS the document
     (pki_setup.ps1 -InstallTrust). Otherwise Office says "not trusted".
  3  Word, Excel, PowerPoint: File > Info > Protect Document > Add a Digital Signature.
     PDF in Adobe needs the same trust.
  4  The certificate also encrypts (RSA only). Publish the .cer for people who encrypt for you.
  It is a certificate of your own PKI. Microsoft 365 does not treat it as a public one.

WHICH PKI AND OTHER
  -Pki <name>          The company (file <name>_pki.cnf). Default agantra.
  -PkiRoot <path>      One PKI folder.    -Release <n>   Release to use. Default: the latest.
  -NoCaRevocationInfo  Use the NoCR family of CAs.        -ConfigFile <path>   Configuration file.
  -OpenSslPath <path>  Use this openssl (4.x).            -FipsModuleConfig <path>  fipsmodule.cnf.
  -Unblock   Unblock and unlock the folders, then stop.   -Verbose   Show OpenSSL commands.
  -Help      This text.
  Defaults: [ office365 ] in agantra_pki.cnf: Days Level CommonNameFormat SerialNumberFormat Country
            KeyType KeyBits Curve DnsFromEmail KeepCase NoCrl NoOcsp

LIMITS
  * Not a qualified certificate. Classic only. RSA is best; ECDSA cannot encrypt documents.
  * Change the PFX password. Never e-mail a .key file.

WHERE IT RUNS
  Windows 11 24H2 or newer, Windows Server 2025, Windows Server 2022 (Classic only), Linux with
    pwsh.
  Refused (exit 5): Windows 10, older Windows 11, macOS and special editions.

EXIT CODES
  0 done      1 an error or a failed signer      5 this system is refused
'@
}

function Out-PagedHelp {
    # Shows help one screen at a time on a terminal (Space = next page, Enter = next line, q = quit).
    # When the output is redirected (a file, a pipe, a pipeline) it prints everything.
    param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][AllowNull()][string[]]$InputObject)
    begin { $all = [System.Collections.Generic.List[string]]::new() }
    process { foreach ($x in $InputObject) { foreach ($l in ([string]$x -split "\r?\n")) { [void]$all.Add($l) } } }
    end {
        $page = 0; $width = 120
        try { if (-not ([Console]::IsOutputRedirected -or [Console]::IsInputRedirected)) { $page = [Console]::WindowHeight - 2; $width = [Console]::WindowWidth } } catch { $page = 0 }
        if ($page -lt 8) { foreach ($l in $all) { Write-Host $l }; return }
        $rows = 0
        foreach ($l in $all) {
            Write-Host $l
            $rows += [Math]::Max(1, [Math]::Ceiling($l.Length / [Math]::Max(20, $width)))
            if ($rows -ge $page) {
                Write-Host ' -- more --  Space = next page   Enter = next line   q = quit ' -NoNewline -ForegroundColor Yellow
                $k = [Console]::ReadKey($true)
                Write-Host ("`r" + (' ' * 64) + "`r") -NoNewline
                if ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') { return }
                $rows = if ($k.Key -eq 'Enter') { $page - 1 } else { 0 }
            }
        }
    }
}
function Invoke-PagedHelp {
    param([scriptblock]$Block)
    & $Block 6>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.InformationRecord]) { [string]$_.MessageData } else { [string]$_ } } | Out-PagedHelp
}

if ($Help) { Invoke-PagedHelp { Show-PersonHelp }; exit 0 }

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
        foreach ($f in (Write-PkiOfficeExample -Path $ExampleFile)) { Write-Host "[OK] Example written: $f" -ForegroundColor Green }
        exit 0
    }
    if ($File -and ($IdCode -or $GivenName -or $Surname)) { throw 'Use -File OR -IdCode / -GivenName / -Surname, not both.' }
    if (-not $File -and -not ($IdCode -or $GivenName -or $Surname) -and -not $Unblock) { throw 'Give one signer (-GivenName, -Surname, -Email) or a file (-File office365.json). -Help shows everything; -ExampleFile office365.json writes an example.' }
    if ($Fips) { if ($PSBoundParameters.ContainsKey('Quadrant') -and $Quadrant -ne 2) { throw '-Fips and -Quadrant 1 contradict each other.' }; $Quadrant = 2 }

    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    $c = $script:Pki
    $leafRoot = Get-PkiLeafRoot
    $personRoot = if ($OutputRoot) { $leafRoot } else { Join-Path $leafRoot 'office365' }
    if ($Unblock) {
        [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot, $personRoot)); exit 0
    }

    # ---------------- the persons ----------------
    $set = Get-PkiOfficeSettings
    $defaults = @{
        CommonNameFormat = $(if ($CommonNameFormat) { $CommonNameFormat } else { $set.CommonNameFormat })
        SerialNumberFormat = $(if ($SerialNumberFormat) { $SerialNumberFormat } else { $set.SerialNumberFormat })
        KeepCase = $(if ($PSBoundParameters.ContainsKey('KeepCase')) { [bool]$KeepCase } else { [bool]$set.KeepCase }); CheckEstonianId = $false; IdRequired = $false
        DnsFromEmail = $(if ($DnsFromEmail) { $true } else { [bool]$set.DnsFromEmail })
        Country = $(if ($Country) { $Country } else { $set.Country }); IdType = $(if ($IdType) { $IdType } else { '' })
        Level = $(if ($Level) { $Level } else { $set.Level }); Days = $(if ($Days) { $Days } else { $set.Days }); DaysGiven = [bool]$Days
        Quadrant = $Quadrant; Password = $Password
        NoCrl = ([bool]$NoCrl -or [bool]$NoRevocationInfo -or [bool]$set.NoCrl); NoOcsp = ([bool]$NoOcsp -or [bool]$NoRevocationInfo -or [bool]$set.NoOcsp)
    }
    if (-not $PSBoundParameters.ContainsKey('KeyType') -and -not $PSBoundParameters.ContainsKey('KeyBits')) { $defaults['KeyBits'] = $set.KeyBits }
    foreach ($k in 'KeyType', 'KeyBits', 'Curve') { if ($PSBoundParameters.ContainsKey($k)) { $defaults[$k] = $PSBoundParameters[$k] } }
    $records = [System.Collections.Generic.List[object]]::new()
    if ($File) { foreach ($r in (Read-PkiPersonFile -Path $File)) { [void]$records.Add($r) } }
    else {
        $one = [ordered]@{ _Line = 0 }
        foreach ($k in 'IdCode', 'GivenName', 'Surname', 'Email', 'Country', 'IdType', 'SerialNumber', 'CommonName', 'Level') { if ($PSBoundParameters.ContainsKey($k)) { $one[$k] = $PSBoundParameters[$k] } }
        [void]$records.Add($one)
    }
    if ($records.Count -eq 0) { throw 'The file contains no signer.' }

    $errors = [System.Collections.Generic.List[string]]::new()
    $entries = [System.Collections.Generic.List[object]]::new()
    $skipped = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($rec in $records) {
        try {
            $e = ConvertTo-PkiPersonEntry -Record $rec -Defaults $defaults
            if ($e.Skip) { [void]$skipped.Add($e); continue }
            $key = "$($e.Country)|$($e.IdCode)|$($e.Email.ToLowerInvariant())|$($e.Level)|$($e.Quadrant)"
            if ($seen.ContainsKey($key)) { throw "Person $($e.Line) [$($e.Label)]: the same signer (country, ID, e-mail, level, quadrant) is already on person $($seen[$key])." }
            $seen[$key] = $e.Line
            [void]$entries.Add($e)
        }
        catch { [void]$errors.Add($_.Exception.Message) }
    }

    $common = @{
        Profile = 'office365'; DocumentSigning = (-not $NoDocumentSigningEku); KeyType = $(if ($KeyType) { $KeyType } else { $set.KeyType }); Curve = $(if ($Curve) { $Curve } else { $set.Curve })
        Hash = $Hash; Days = $(if ($Days) { $Days } else { $set.Days }); Policy = @($Policy); Format = @($Format)
        NonRepudiation = $true; QcStatements = $false
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
    Write-PkiLog "Signers to issue: $($entries.Count)   skipped (isGenerate false): $($skipped.Count)   Output: $personRoot"
    Write-Host ''
    Write-Host ('{0,-3} {1,-20} {2,-26} {3,-30} {4,-3} {5,-5} {6}' -f 'NO', 'SERIAL NUMBER', 'NAME', 'E-MAIL', 'LVL', 'QUAD', 'DNS') -ForegroundColor Cyan
    foreach ($e in $entries) { Write-Host ('{0,-3} {1,-20} {2,-26} {3,-30} {4,-3} {5,-5} {6}' -f $e.Line, $e.SerialNumber, "$($e.Surname) $($e.GivenName)", $e.Email, $e.Level, "Q$($e.Quadrant)", (@($e.Dns) -join ', ')) }
    foreach ($e in $skipped) { Write-Host ('{0,-3} {1,-20} {2}' -f $e.Line, $e.IdCode, "SKIPPED (isGenerate false): $($e.Label)") -ForegroundColor DarkGray }
    Write-Host ''
    if ($entries.Count -eq 0) { Write-PkiLog 'No signer has isGenerate true: nothing to issue.' 'WARN'; exit 0 }
    foreach ($e in $entries) {
        $ktE = if ($e.KeyType) { $e.KeyType } else { [string]$common.KeyType }
        if ($ktE.ToUpperInvariant() -eq 'ECDSA') { Write-PkiLog "Signer $($e.Line) [$($e.Label)]: ECDSA keys cannot encipher keys (Key Agreement instead of Key Encipherment): signing works, document encryption with Office / IRM needs RSA." 'WARN' }
    }
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
            $subject = Test-PkiPersonResult -Entry $e -Spec $spec -R $r -Profile 'office365' -DocumentSigning:(-not $NoDocumentSigningEku)
            Write-PkiLog "  validated  : $($e.Label)  [$subject]" 'OK'
            foreach ($oid in $v.UnsupportedPolicies) { Write-PkiLog "  policy $oid is in the certificate but the issuing CA does not carry it" 'WARN' }
            if (-not $NoGuidance) { [void](Write-PkiLeafGuidance -Spec $spec -R $r -NoTls) }
            $r.Files = @(@(Get-ChildItem -LiteralPath $r.Dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name }) + @('leaf-info.json', 'office365-info.json', 'OFFICE-NOTES.txt') | Sort-Object -Unique)
            $entry = Add-PkiLeafIndex -Root $personRoot -Spec $spec -R $r -FolderName $folder.Name
            Write-Utf8NoBom -Path (Join-Path $r.Dir 'leaf-info.json') -Content ($entry | ConvertTo-Json -Depth 6)
            $pinfo = [ordered]@{
                person = [ordered]@{ serialNumber = $e.SerialNumber; idCode = $e.IdCode; idType = $e.IdType; country = $e.Country; givenName = $e.GivenName; surname = $e.Surname; commonName = $e.CommonName; email = $e.Email; dns = @($e.Dns) }
                certificate = [ordered]@{ subject = $subject; issuer = $spec.Ca.Id; level = $spec.Level; keyAlgorithm = $r.Actual.Algorithm; keyUsage = $spec.KeyUsage; extendedKeyUsage = @($spec.Eku); days = $r.Days; notAfter = $r.NotAfter; sha1 = $r.Sha1; sha256 = $r.Sha256; qualified = $false }
                note = 'Private PKI certificate for Microsoft Office / Microsoft 365 document signing. Office trusts it only where the Root CA of this PKI is in the Trusted Root store.'
                createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GenerateOffice365LeafCertificate.ps1 $($script:PkiGeneratorVersion)"
            }
            Write-Utf8NoBom -Path (Join-Path $r.Dir 'office365-info.json') -Content (($pinfo | ConvertTo-Json -Depth 6) + "`n")
            $notesText = @"
Office / Microsoft 365 document signing certificate - $($e.GivenName) $($e.Surname) <$($e.Email)>
Issuer: $($spec.Ca.Id) ($($spec.Level))    Valid until: $($r.NotAfter)    SHA-1: $($r.Sha1)
Purposes: Document Encryption (1.3.6.1.4.1.311.80.1), Secure Email / S/MIME (1.3.6.1.5.5.7.3.4)$(if (-not $NoDocumentSigningEku) { ', Document Signing (1.3.6.1.4.1.311.10.3.12)' }). Key usage: Digital Signature, Non-Repudiation, Key Encipherment (RSA) / Key Agreement (ECDSA).

1. Import the .pfx into Current User > Personal (double click). Office uses the private key from there.
2. The Root CA of this PKI must be in Trusted Root Certification Authorities on every machine that opens the signed document
   (pki_setup.ps1 -InstallTrust, or import the root.crt of the PKI). Without it Office says "signature not trusted".
3. Word / Excel / PowerPoint: File > Info > Protect Document > Add a Digital Signature, and choose this certificate.
   Revocation info in this certificate: CRL $(if ($spec.NoCrl) { 'no' } else { 'yes' }), OCSP $(if ($spec.NoOcsp) { 'no' } else { 'yes' }). If Office reports that it cannot connect to the revocation server, issue the certificate again with -NoRevocationInfo.
4. Give the .cer to people who want to encrypt documents or e-mail for you.
5. Change the PFX password if it is still the default (Abc12345!).
This is a certificate of a private PKI, not of a public trust list and not a qualified certificate.
"@
            Write-Utf8NoBom -Path (Join-Path $r.Dir 'OFFICE-NOTES.txt') -Content (($notesText -replace "`r", '') + "`n")
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
    $batch = Join-Path $personRoot ("office365-batch-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-Utf8NoBom -Path $batch -Content (([ordered]@{ createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GenerateOffice365LeafCertificate.ps1 $($script:PkiGeneratorVersion)"; issued = $done.Count; failed = $failed.Count; skipped = $skipped.Count; persons = @($rows) } | ConvertTo-Json -Depth 6) + "`n")

    # ---------------- summary ----------------
    Write-Host ''
    Write-Host 'OFFICE 365 CERTIFICATES' -ForegroundColor Cyan
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
