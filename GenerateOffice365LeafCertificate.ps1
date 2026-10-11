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
    [string]$OpenSslPath,
    [string]$FipsModuleConfig
)

$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-PersonCertSerial { param([string]$Path) try { $t = Get-PkiCertText -Path $Path; if ($t -match 'Serial Number:\s*\r?\n?\s*([0-9a-fA-F:]+)') { return ($Matches[1] -replace ':','').ToUpper() } } catch { }; return '' }

function Show-PersonHelp {
    @'
============================================================
 GenerateOffice365LeafCertificate.ps1 - Microsoft Office / Microsoft 365 DOCUMENT SIGNING certificates
 Version 4.9.5-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : docs\GenerateOffice365LeafCertificate-MANUAL.txt     Design : docs\PKI-Design-with-FIPS-and-PQC.txt (10.63)
 Ubuntu : GenerateOffice365LeafCertificate.sh in the DevKit (PkiTransport.ps1 -DevKit): bash + openssl + python3.
 Needs  : PowerShell 7+, OpenSSL 4.x, a PKI made by pki_setup.ps1.   Same mechanism as GeneratePersonLeafCertificate.ps1.

WHAT IT MAKES   (a certificate to sign Word / Excel / PowerPoint / PDF documents; NOT a qualified certificate)
  Extended key usage   Document Encryption 1.3.6.1.4.1.311.80.1  +  Secure Email / S/MIME 1.3.6.1.5.5.7.3.4  +  Document Signing 1.3.6.1.4.1.311.10.3.12
                       (-NoDocumentSigningEku leaves out the Microsoft Document Signing OID: then only the first two)
  Key usage            critical: Digital Signature (signing) + Non-Repudiation (contentCommitment) + Key Encipherment (RSA: the key exchange of document encryption)
                       ECDSA keys cannot encipher keys: they get Key Agreement instead. Office document encryption (IRM / S/MIME) is RSA based: use RSA there.
  Subject              [serialNumber = <ID>]  givenName  surname  CN = <Given> <Surname>  C = <country, default EE>   (names as you give them; UTF-8)
  SAN                  rfc822Name = the e-mail address (the Microsoft 365 account).  -DnsFromEmail (or "dnsFromEmail": true) adds DNS:<domain> and DNS:*.<domain>.
  Key                  Classic PKI only (Office uses the Windows CryptoAPI / CNG). RSA is the default and the most compatible: RSA 4096 (minimum 2048, enforced).
                       ECDSA: -KeyType ECDSA, P-384 (default) or P-256 / P-521 (minimum P-256, enforced).
                       Digest: the SHA-2 family only (SHA-1, MD5 and shorter are refused). The issuing CA decides (SHA-256 on Q1 RSA, SHA-384 on Q2 EC) unless
                       -Hash sha256|sha384|sha512.  Office baseline: SHA-256; SHA-384 / SHA-512 are supported.
  Level                OV (default). EV with -Level EV (397 days). DV is never used.     Quadrant 1 = Classic NON-FIPS (default); -Fips or -Quadrant 2 = Classic FIPS.
  Policies             the same as every OV / EV certificate: level policy, company PEN policies, the High Assurance policy (OV), each with the CPS pointer
                       (OV https://nextmantra.com/security/certs, EV .../ev-cps.pdf).
  Validity             730 days (OV) by default, -Days; cut to what the issuing CA has left.
  Output               leafcerts\office365\<name>\  every format (PEM DER CER CERT P7B RFC7468 PFX), key + public key, chain, leaf-info.json, office365-info.json,
                       OFFICE-NOTES.txt (how to use it), and one office365-batch-<date>.json summary per run (no passwords in it).

ONE SIGNER
  .\GenerateOffice365LeafCertificate.ps1 -GivenName Budi -Surname Santoso -Email budi.santoso@example.co.id [-Country ID] [-IdCode STAFF-0001]
  -GivenName / -Surname  Several given names are allowed.        -Email <address>   REQUIRED.
  -IdCode <text>         Optional identifier (staff number, national ID, passport ...). Goes to the subject serialNumber (-SerialNumber replaces it,
                         -SerialNumberFormat "{IdType}{Country}-{IdCode}" builds it).   -IdType <code>  optional label.
  -Country <CC>          Two letters, default EE ([ office365 ] Country).
  -CommonName <text>     Replaces the CN.   -CommonNameFormat "{Given} {Surname}"  tokens {Given} {Surname} {SurnameFirst} {IdCode} {Country}; max 64 characters.
  REVOCATION INFORMATION  (4.9.4)   by default the certificate has the CRL distribution point, the OCSP URL and the CA issuer URL of the issuing CA.
  -NoCrl                 No CRL distribution point (crlDistributionPoints extension) in the certificate.
  -NoOcsp                No OCSP URL (the OCSP method of Authority Information Access); the CA issuer URL stays.
  -NoRevocationInfo      Both: no CRL and no OCSP. Use it when Word / Excel / Outlook say "cannot connect to the revocation server" because the URLs of this
                         private PKI cannot be reached from the machine that checks the signature. Without any revocation URL a client has nothing to check:
                         it accepts the certificate until it expires. The certificate is still recorded in the CA database (PkiRevocation.ps1 can still revoke it
                         and the CRL lists it), but a client that has no URL will not learn about it. Per signer in the JSON file: "noCrl", "noOcsp", "noRevocationInfo"
                         (true | false). Defaults for all: [ office365 ] NoCrl / NoOcsp in agantra_pki.cnf.
  -KeepCase              Names are kept as given (default for Office; [ office365 ] KeepCase).

MANY SIGNERS - A JSON FILE  (JSON only; CSV is not accepted)
  .\GenerateOffice365LeafCertificate.ps1 -ExampleFile .\office365.json      writes an example with 5 people (3 isGenerate true) and stops
  .\GenerateOffice365LeafCertificate.ps1 -File .\office365.json -ValidateOnly   checks the file, shows the table, issues nothing
  .\GenerateOffice365LeafCertificate.ps1 -File .\office365.json
  { "persons": [ { "isGenerate": true, "givenName": "Budi", "surname": "Santoso", "email": "budi.santoso@example.co.id", "country": "ID" }, { ... } ] }
  Keys (any spelling or case):  givenName  surname  email  (required)     isGenerate (true | false; default true; false = skipped, not even checked)
  idCode  idType  serialNumber  country  level  quadrant  days  keyType  keyBits  curve  commonName  password  name (folder)  policy  dnsFromEmail  noCrl  noOcsp  noRevocationInfo  (optional)
  Keys that start with _ are comments. Every signer with isGenerate true is checked BEFORE anything is written: one error = nothing is issued, all errors
  are listed. A signer is then issued on its own; a failure removes that signer's folder and the run goes on (-StopOnError stops). Exit 1 when one failed.

CERTIFICATE OPTIONS
  -Level OV|EV   -Quadrant 1|2   -Fips   -KeyType RSA|ECDSA   -KeyBits 2048|3072|4096|8192   -NoDocumentSigningEku   -Curve P-256|P-384|P-521   -Hash   -Days <n>
  -Policy <oid|oid=cps>  -CpsUrl <url>  -CpsUrlEv <url>
  -Password <text>       Password of the PFX (default Abc12345!; the password key of a signer replaces it). CHANGE IT for real use.
  -Format <list>         PEM DER CER CERT P7B RFC7468 PFX ALL (default ALL).   -LegacyPfx   -NoGuidance   -InstallPfx (Windows: import into the user store)
  -OutputRoot <path>     Default leafcerts\office365.
  -Unblock               UNBLOCK and UNLOCK the script folder, the pki folder and the output, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.

USING THE CERTIFICATE  (OFFICE-NOTES.txt in every folder says the same)
  1  Import the .pfx into Current User > Personal (double click, or -InstallPfx). Office finds the private key there.
  1b Word / Excel say "cannot connect to the revocation server"? Issue the certificate with -NoRevocationInfo (no CRL / OCSP URL), or make the CRL / OCSP host reachable.
  2  The Root CA of this PKI must be trusted on the machine that OPENS the document (pki_setup.ps1 -InstallTrust, or the Root in Trusted Root Certification Authorities);
     otherwise Office shows the signature as "not trusted".
  3  Word / Excel / PowerPoint: File > Info > Protect Document > Add a Digital Signature.  PDF signing in Adobe needs the same trust on that machine.
  4  The certificate is also an encryption certificate (Document Encryption, Secure Email, Key Encipherment): publish the .cer for people who encrypt for you.
  This is an own-PKI certificate: Microsoft 365 does not treat it as a certificate of a public trust list.

DEFAULTS IN agantra_pki.cnf   [ office365 ]   Days  Level  CommonNameFormat  SerialNumberFormat  Country  KeyType  KeyBits  Curve  DnsFromEmail  KeepCase  NoCrl  NoOcsp
EXIT CODES   0 ok   1 an error or a failed signer
============================================================
'@
}

if ($Help) { Show-PersonHelp; exit 0 }

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
