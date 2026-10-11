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
    serialNumber PNOEE-<id>, givenName, surname, CN SURNAME,GIVEN,<id>, C, e-mail SAN, EKU clientAuth + emailProtection.
    One person with parameters, or many persons from a CSV / JSON file. Full help: .\GeneratePersonLeafCertificate.ps1 -Help
.EXAMPLE
    .\GeneratePersonLeafCertificate.ps1 -IdCode 37605030299 -GivenName Mari-Liis -Surname Männik
.EXAMPLE
    .\GeneratePersonLeafCertificate.ps1 -File .\persons.csv
#>
param(
    # ---- one person ----
    [string]$IdCode,
    [string]$GivenName,
    [string]$Surname,
    [Alias('EmailAddress')][string]$Email,
    [string]$Country,
    [ValidateSet('PNO', 'PAS', 'IDC', 'TIN')][string]$IdType,
    [string]$SerialNumber,
    [string]$CommonName,
    # ---- many persons ----
    [string]$File,
    [string]$ExampleFile,
    [switch]$ValidateOnly,
    [switch]$StopOnError,
    # ---- certificate ----
    [ValidateSet('DV', 'OV', 'EV')][string]$Level,
    [ValidateSet(1, 2, 3, 4)][int]$Quadrant = 1,
    [string]$EmailDomain,
    [string]$CommonNameFormat,
    [switch]$KeepCase,
    [switch]$NoIdCheck,
    [ValidateSet('RSA', 'ECDSA', 'MLDSA')][string]$KeyType,
    [int]$KeyBits,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$Curve,
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcAlgorithm,
    [string]$Hash,
    [ValidateRange(1, 36500)][int]$Days,
    [string[]]$Policy,
    [string]$CpsUrl,
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
 Version 4.9.4-phaseC
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
 Manual : GeneratePersonLeafCertificate-MANUAL.txt     Design : PKI-Design-with-FIPS-and-PQC.txt (10.59)
 Needs  : PowerShell 7+, OpenSSL 4.x, a PKI made by pki_setup.ps1.

WHAT IT MAKES   (the form of a national ID card certificate; NOT a qualified certificate)
  Subject      serialNumber = PNOEE-<id code>      givenName = NICKO SATRIA      surname = UTAMA      CN = UTAMA,NICKO SATRIA,<id code>      C = EE
               (this order; UTF-8, õ ä ö ü are kept; names in capitals unless -KeepCase)
  SAN          e-mail <id code>@eesti.ee, or the address you give (rfc822Name only; no DNS, no IP)
  EKU          Client Authentication + Secure E-mail (emailProtection)
  Key usage    critical: digitalSignature + keyAgreement (ECDSA) | keyEncipherment (RSA) | digitalSignature (ML-DSA); -NonRepudiation adds nonRepudiation
  Key          ECDSA P-384 (Quadrant 1 and 2); ML-DSA in Quadrants 3 and 4.   Valid 730 days by default.
  Policies     the level policy (OV default) + PEN + -Policy; CRL / OCSP / CA issuer URLs of the issuing CA (q1-ov by default)
  Output       leafcerts\persons\<id>-<SURNAME>-<GIVEN>\  every format (PEM DER CER CERT P7B RFC7468 PFX), key + public key, chain, leaf-info.json,
               person-info.json, and one persons-batch-<date>.csv summary per run (no passwords in it).

ONE PERSON
  .\GeneratePersonLeafCertificate.ps1 -IdCode 37605030299 -GivenName "Mari-Liis" -Surname "Männik" [-Email mari@example.ee]
  -IdCode <text>         National identification number. Estonia (-Country EE, -IdType PNO): 11 digits, the check digit is verified (-NoIdCheck skips it).
  -GivenName / -Surname  Several given names are allowed ("NICKO SATRIA").
  -Email <address>       Default <id code>@<EmailDomain>.   -EmailDomain <domain>  default eesti.ee  ([ person ] EmailDomain).
  -Country <CC>          Two letters, default EE.       -IdType PNO|PAS|IDC|TIN  personal number (default), passport, identity card, tax number
                         -> serialNumber "<IdType><Country>-<IdCode>" (ETSI EN 319 412-1 semantics identifier).   -SerialNumber replaces it as it is.
  -CommonName <text>     Replaces the CN.  -CommonNameFormat "{Surname},{Given},{IdCode}"  tokens {Surname} {Given} {IdCode} {Country} {SurnameFirst}; max 64 characters.

MANY PERSONS - A FILE
  .\GeneratePersonLeafCertificate.ps1 -File .\persons.csv           -ValidateOnly   checks the file and shows the table, issues nothing
  .\GeneratePersonLeafCertificate.ps1 -ExampleFile .\persons.csv    writes persons.csv and persons.json as examples and stops
  CSV  (comma, semicolon, tab or |; first line = column names; # = comment) / JSON ([ {..}, {..} ] or { "persons": [ ... ] }) / plain text in CSV form.
  Columns (any spelling: given_name, First Name ...):  IdCode, GivenName, Surname  (required);  Email, Country, IdType, Days, Password, Level, KeyType,
  KeyBits, Curve, CommonName, SerialNumber, Name (folder), Policy  (optional; empty = the default / the command line value).
  Every entry is checked BEFORE anything is written: one error = nothing is issued and every error is listed with its line. A person is then issued
  on its own; a failure removes that person's folder and the run goes on (-StopOnError stops at the first failure). Exit 1 when one failed.

CERTIFICATE OPTIONS
  -Level DV|OV|EV        Issuing level (default OV: q1-ov). A person has no organization in the subject; EV is limited to 398 days.
  -Quadrant 1|2|3|4      1 Classic non-FIPS (default), 2 Classic FIPS, 3 Quantum non-FIPS, 4 Quantum FIPS.
  -KeyType RSA|ECDSA|MLDSA  -KeyBits  -Curve  -PqcAlgorithm  -Hash   as in GenerateLeafCertificate.ps1 (rules: RSA >= 2048, P-256+, SHA-256+).
  -Days <n>              Validity (default 730, [ person ] Days; cut to what the issuer has left).
  -Policy <oid|oid=cps>  Extra certificate policies.   -CpsUrl <url>
  -NonRepudiation        Adds nonRepudiation (content commitment) to the key usage.
  -QcStatements          Adds the qcStatements extension with QcType eSign (ETSI 0.4.0.1862.1.6.1) like the ID card. It is NOT QcCompliance: this PKI is
                         private and does not issue qualified certificates. Use it only where an application wants to see the extension.
  -KeepCase              Do not convert the names to capitals.
  -Password <text>       Password of the PFX (default Abc12345!; the Password column of a file replaces it per person). CHANGE IT for real use.
  -Format <list>         PEM DER CER CERT P7B RFC7468 PFX ALL (default ALL).   -LegacyPfx   -NoGuidance   -InstallPfx (Windows: import into the user store)
  -OutputRoot <path>     Default leafcerts\persons.
  -Unblock               UNBLOCK and UNLOCK the script folder, the pki folder and the output, then stop.
  -ConfigFile <path> -PkiRoot <path> -OpenSslPath <path> -FipsModuleConfig <path> -Verbose   as in pki_setup.ps1.

DEFAULTS IN agantra_pki.cnf   [ person ]   EmailDomain  Days  Level  CommonNameFormat  Country  IdType  KeyType  Curve
EXIT CODES   0 ok   1 an error or a failed person
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
        foreach ($f in (Write-PkiPersonExample -Path $ExampleFile)) { Write-Host "[OK] Example written: $f" -ForegroundColor Green }
        exit 0
    }
    if ($File -and ($IdCode -or $GivenName -or $Surname)) { throw 'Use -File OR -IdCode / -GivenName / -Surname, not both.' }
    if (-not $File -and -not ($IdCode -or $GivenName -or $Surname) -and -not $Unblock) { throw 'Give one person (-IdCode, -GivenName, -Surname) or a file (-File persons.csv). -Help shows everything; -ExampleFile writes an example.' }

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
        EmailDomain = $(if ($EmailDomain) { $EmailDomain } else { $set.EmailDomain }); CommonNameFormat = $(if ($CommonNameFormat) { $CommonNameFormat } else { $set.CommonNameFormat })
        KeepCase = [bool]$KeepCase; NoIdCheck = [bool]$NoIdCheck
        Country = $(if ($Country) { $Country } else { $set.Country }); IdType = $(if ($IdType) { $IdType } else { $set.IdType })
        Level = $(if ($Level) { $Level } else { $set.Level }); Days = $(if ($Days) { $Days } else { $set.Days })
        Password = $Password
    }
    foreach ($k in 'KeyType', 'KeyBits', 'Curve') { if ($PSBoundParameters.ContainsKey($k)) { $defaults[$k] = $PSBoundParameters[$k] } }
    $records = [System.Collections.Generic.List[object]]::new()
    if ($File) { foreach ($r in (Read-PkiPersonFile -Path $File)) { [void]$records.Add($r) } }
    else {
        $one = [ordered]@{ _Line = 0 }
        foreach ($k in 'IdCode', 'GivenName', 'Surname', 'Email', 'Country', 'IdType', 'SerialNumber', 'CommonName') { if ($PSBoundParameters.ContainsKey($k)) { $one[$k] = $PSBoundParameters[$k] } }
        [void]$records.Add($one)
    }
    if ($records.Count -eq 0) { throw 'The person file contains no person.' }

    $errors = [System.Collections.Generic.List[string]]::new()
    $entries = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($rec in $records) {
        try {
            $e = ConvertTo-PkiPersonEntry -Record $rec -Defaults $defaults
            $key = "$($e.IdType)|$($e.Country)|$($e.IdCode)|$($e.Level)"
            if ($seen.ContainsKey($key)) { throw "Line $($e.Line) [$($e.Label)]: the same person (id code, country, type, level) is already on line $($seen[$key])." }
            $seen[$key] = $e.Line
            [void]$entries.Add($e)
        }
        catch { [void]$errors.Add($_.Exception.Message) }
    }

    $common = @{
        Quadrant = $Quadrant; KeyType = $(if ($KeyType) { $KeyType } else { $set.KeyType }); Curve = $(if ($Curve) { $Curve } else { $set.Curve })
        Hash = $Hash; PqcAlgorithm = $PqcAlgorithm; Days = $(if ($Days) { $Days } else { $set.Days }); Policy = @($Policy); Format = @($Format)
        NonRepudiation = [bool]$NonRepudiation; QcStatements = [bool]$QcStatements
    }

    # ---------------- OpenSSL and the PKI ----------------
    Initialize-OpenSSL
    $fipsQ = $Quadrant -in 2, 4
    [void](Assert-PkiLeafOpenSslReady -NeedFips $fipsQ -NeedPqc ($Quadrant -in 3, 4))
    [void](Import-PkiExisting -SkipProviders)
    if ($c.Quadrants -notcontains $Quadrant) { throw "This PKI has no Quadrant $Quadrant (it has: $(($c.Quadrants | ForEach-Object { "Q$_" }) -join ', '))." }

    # decide everything before anything is written
    $specs = @{}
    foreach ($e in @($entries)) {
        try {
            $o = New-PkiPersonOptions -Entry $e -Common $common
            $specs[$e.Label + '|' + $e.Line] = New-PkiLeafSpec -Options $o
        }
        catch { [void]$errors.Add("Line $($e.Line) [$($e.Label)]: $($_.Exception.Message)") }
    }
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-PkiLog "$($errors.Count) problem(s) - NOTHING was issued:" 'ERROR'
        foreach ($m in $errors) { Write-Host "   - $m" -ForegroundColor Red }
        exit 1
    }
    Write-PkiLog "Persons: $($entries.Count)   Level $($defaults.Level) (default)   Quadrant $Quadrant   Output: $personRoot"
    Write-Host ''
    Write-Host ('{0,-4} {1,-14} {2,-30} {3,-34} {4}' -f 'LINE', 'SERIAL NUMBER', 'NAME', 'E-MAIL', 'CN') -ForegroundColor Cyan
    foreach ($e in $entries) { Write-Host ('{0,-4} {1,-14} {2,-30} {3,-34} {4}' -f $e.Line, $e.SerialNumber, "$($e.Surname) $($e.GivenName)", $e.Email, $e.CommonName) }
    Write-Host ''
    if ($ValidateOnly) { Write-PkiLog 'Validation only: every entry is valid. Nothing was issued.' 'OK'; exit 0 }

    # ---------------- issue ----------------
    [void][System.IO.Directory]::CreateDirectory($personRoot)
    $done = [System.Collections.Generic.List[object]]::new(); $failed = [System.Collections.Generic.List[string]]::new()
    $csvRows = [System.Collections.Generic.List[string]]::new()
    [void]$csvRows.Add('Status,IdCode,SerialNumber,GivenName,Surname,Email,Folder,CertificateSerial,NotAfter,Sha1,Issuer,Message')
    $qc = { param($v) '"' + ([string]$v -replace '"', '""') + '"' }
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
                person = [ordered]@{ serialNumber = $e.SerialNumber; idCode = $e.IdCode; idType = $e.IdType; country = $e.Country; givenName = $e.GivenName; surname = $e.Surname; commonName = $e.CommonName; email = $e.Email }
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
            [void]$csvRows.Add((@('OK', $e.IdCode, $e.SerialNumber, $e.GivenName, $e.Surname, $e.Email, $folder.Name, (Get-PersonCertSerial -Path $r.Crt), $r.NotAfter, $r.Sha1, $spec.Ca.Id, '') | ForEach-Object { & $qc $_ }) -join ',')
        }
        catch {
            $msg = ($_.Exception.Message -split "`n" | Select-Object -First 3) -join ' | '
            if ($script:PersonFolderCreated -and (Test-Path -LiteralPath $script:PersonFolderCreated)) {
                [void](Unlock-PkiTree -Path @($script:PersonFolderCreated)); Remove-Item -LiteralPath $script:PersonFolderCreated -Recurse -Force -ErrorAction SilentlyContinue
            }
            $script:PersonFolderCreated = $null
            [void]$failed.Add("$($e.Label): $msg")
            Write-PkiLog "FAILED $($e.Label): $msg" 'ERROR'
            [void]$csvRows.Add((@('FAILED', $e.IdCode, $e.SerialNumber, $e.GivenName, $e.Surname, $e.Email, '', '', '', '', '', $msg) | ForEach-Object { & $qc $_ }) -join ',')
            if ($StopOnError) { break }
        }
    }
    $batch = Join-Path $personRoot ("persons-batch-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-Utf8NoBom -Path $batch -Content (($csvRows -join "`n") + "`n")

    # ---------------- summary ----------------
    Write-Host ''
    Write-Host 'PERSON CERTIFICATES' -ForegroundColor Cyan
    Write-Host ("  Folder     : {0}" -f $personRoot)
    foreach ($d in $done) {
        Write-Host ("  OK   {0,-16} {1,-30} {2,-30} until {3}   {4}" -f $d.Entry.SerialNumber, "$($d.Entry.Surname) $($d.Entry.GivenName)", $d.Entry.Email, $d.R.NotAfter, $d.Folder.Name) -ForegroundColor Green
    }
    foreach ($f in $failed) { Write-Host "  FAIL $f" -ForegroundColor Red }
    Write-Host ("  Summary    : {0}   (no passwords in it)" -f $batch)
    Write-PkiLog ("{0} certificate(s) issued, {1} failed. Issuer q{2}-{3}; the PKI server learns about them after New-PkiServerPackage.ps1 + 'pki-server.sh update'." -f $done.Count, $failed.Count, $Quadrant, $defaults.Level.ToLowerInvariant()) $(if ($failed.Count -eq 0) { 'OK' } else { 'WARN' })
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
