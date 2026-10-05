# ============================================================
# PKI Reuse Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Reuses an EXISTING PKI folder: checks it, makes it the PKI of this
    project, and installs its trust into Windows 11.

.DESCRIPTION
    Use this script when the PKI folder already exists (made earlier by
    pki_setup.ps1, or copied from another machine / backup) and you do not
    want to generate a new Root and Intermediate CA.

    It performs these steps:

      1. CHECK    The folder must contain root\root.crt and
                  intermediate\intermediate.crt. The script verifies that the
                  Intermediate CA chains to the Root CA, that both are CA
                  certificates inside their validity period, that the private
                  keys match the certificates, and that every leaf in leaf\
                  chains to the Intermediate CA.

      2. ADOPT    The folder becomes the project's .\pki folder, so
                  GenerateLeafCertificate.ps1 can issue new leaf certificates
                  from it. (-NoCopy keeps the folder where it is.)

      3. TRUST    Root CA   -> LocalMachine\Root
                  Intermediate CA -> LocalMachine\CA
                  (-ImportLeafPfx also imports leaf PFX files into
                  LocalMachine\My.)  Windows only, elevated PowerShell.

    The folder layout is the one pki_setup.ps1 creates:

        <folder>\root\root.crt                   required
        <folder>\root\root.key                   recommended
        <folder>\intermediate\intermediate.crt   required
        <folder>\intermediate\intermediate.key   needed to issue leaf certificates
        <folder>\leaf\*.crt, *.pfx               optional
        <folder>\publish\*                       optional (CRL, CA issuer file)

.PARAMETER AddPkiContentPath
    Folder that holds the existing PKI content. Default: .\pki next to this
    script. Alias: -PkiPath.

.PARAMETER CheckOnly
    Only check the folder. Nothing is copied or installed. Works on every
    operating system and does not need Administrator rights.

.PARAMETER NoCopy
    Do not copy the folder into .\pki; use it where it is. Trust is installed
    from that folder. Issue leaf certificates later with
    GenerateLeafCertificate.ps1 -AddPkiContentPath <folder>.

.PARAMETER NoTrust
    Check and adopt the folder, but do not touch the Windows certificate stores.

.PARAMETER ImportLeafPfx
    Also import every leaf\*.pfx into LocalMachine\My.

.PARAMETER Password
    Password of the leaf PFX files (only used with -ImportLeafPfx).
    Default: environment variable PKI_PFX_PASSWORD, otherwise you are asked.

.PARAMETER RemoveTrust
    Remove the Root and Intermediate CA of the folder from the Windows stores.

.PARAMETER Force
    Replace an existing, different .\pki folder. It is renamed to
    pki.backup-<date> first, never deleted.

.PARAMETER Help
    Show the help text.

.EXAMPLE
    .\pki_reuse.ps1
    Check .\pki and install its Root / Intermediate CA into Windows.

.EXAMPLE
    .\pki_reuse.ps1 -AddPkiContentPath D:\Backup\pki -Force
    Adopt a backup of the PKI as .\pki (the current .\pki is renamed) and trust it.

.EXAMPLE
    .\pki_reuse.ps1 -AddPkiContentPath D:\Backup\pki -CheckOnly
    Only check what is in the folder.

.NOTES
    Company: Agantra Inovatif OÜ (NextMantra)
    Email  : nicko@nextmantra.com
#>
[CmdletBinding()]
param(
    [Alias('PkiPath')]
    [string]$AddPkiContentPath,

    [string]$Password,

    [switch]$CheckOnly,
    [switch]$NoCopy,
    [switch]$NoTrust,
    [switch]$ImportLeafPfx,
    [switch]$RemoveTrust,
    [switch]$Force,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-ReuseHelp {
    @'
PKI Reuse - use an existing PKI folder
Author : Nicko Satria Utama
Company: Agantra Inovatif OÜ (NextMantra)
Email  : nicko@nextmantra.com

WHAT IT DOES
  1. CHECK  the folder (Root, Intermediate, keys, chain, leaf certificates)
  2. ADOPT  it as .\pki so GenerateLeafCertificate.ps1 can issue from it
  3. TRUST  install Root -> LocalMachine\Root, Intermediate -> LocalMachine\CA

USAGE
  .\pki_reuse.ps1                                    check .\pki and install trust
  .\pki_reuse.ps1 -AddPkiContentPath D:\Backup\pki   adopt another folder, then trust
  .\pki_reuse.ps1 -AddPkiContentPath D:\Backup\pki -CheckOnly
  .\pki_reuse.ps1 -AddPkiContentPath D:\Backup\pki -NoCopy
  .\pki_reuse.ps1 -ImportLeafPfx -Password 'YourPfxPassword'
  .\pki_reuse.ps1 -RemoveTrust
  .\pki_reuse.ps1 -Help

OPTIONS
  -AddPkiContentPath <folder>  Existing PKI folder. Default: .\pki. Alias: -PkiPath
  -CheckOnly                   Only check. No copy, no store changes, no admin needed.
  -NoCopy                      Use the folder in place instead of copying it to .\pki.
  -NoTrust                     Do not change the Windows certificate stores.
  -ImportLeafPfx               Also import leaf\*.pfx into LocalMachine\My.
  -Password <text>             PFX password for -ImportLeafPfx
                               (default: $env:PKI_PFX_PASSWORD, else you are asked).
  -RemoveTrust                 Remove this PKI's Root and Intermediate from Windows.
  -Force                       Replace a different existing .\pki (it is renamed to
                               pki.backup-<date>, never deleted).
  -Help                        This help.

THE FOLDER MUST CONTAIN (layout made by pki_setup.ps1)
  root\root.crt                      required
  intermediate\intermediate.crt      required
  root\root.key                      recommended
  intermediate\intermediate.key      needed to issue new leaf certificates
  leaf\*.crt, leaf\*.pfx             optional
  publish\*                          optional (CRL and CA issuer file)

AFTER IT HAS RUN
  .\GenerateLeafCertificate.ps1 -Domain example.com           uses .\pki
  .\GenerateLeafCertificate.ps1 -AddPkiContentPath D:\pki ... uses that folder directly

NOTES
  * Trust installation needs Windows and an elevated PowerShell. -CheckOnly
    runs anywhere.
  * Other devices (macOS, Ubuntu, Android, iOS, Firefox) need the Root CA
    installed too: see COMPATIBILITY.md.
'@ | Write-Host
}

function Write-ReuseLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Gray' }
    }

    $tag = switch ($Level) {
        'OK'    { '[ OK ]' }
        'WARN'  { '[WARN]' }
        'ERROR' { '[FAIL]' }
        default { '[INFO]' }
    }

    Write-Host "$tag $Message" -ForegroundColor $color
}

if ($Help) {
    Show-ReuseHelp
    exit 0
}

Write-Host '============================================================'
Write-Host 'PKI Reuse'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

# ============================================================
# Helpers
# ============================================================

function Get-CertificateFileSafe {
    param([Parameter(Mandatory)][string]$Path)

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
}

function Test-CaFlag {
    param([Parameter(Mandatory)]$Certificate)

    $basic = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.19' } |
        Select-Object -First 1

    if ($null -eq $basic) { return $false }

    return ([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basic).CertificateAuthority
}

function Test-PrivateKeyMatchesCertificate {
    # $true / $false, or $null when the key type could not be compared.
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)]$Certificate
    )

    $pem = [System.IO.File]::ReadAllText($KeyPath)

    try {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportFromPem($pem)

            $certKey = $Certificate.PublicKey.GetRSAPublicKey()
            if ($null -eq $certKey) { return $false }

            try {
                $a = $rsa.ExportRSAPublicKey()
                $b = $certKey.ExportRSAPublicKey()
                return ([Convert]::ToBase64String([byte[]]$a) -ceq [Convert]::ToBase64String([byte[]]$b))
            }
            finally { $certKey.Dispose() }
        }
        finally { $rsa.Dispose() }
    }
    catch { }

    try {
        $ec = [System.Security.Cryptography.ECDsa]::Create()
        try {
            $ec.ImportFromPem($pem)

            $certKey = $Certificate.PublicKey.GetECDsaPublicKey()
            if ($null -eq $certKey) { return $false }

            try {
                $a = $ec.ExportSubjectPublicKeyInfo()
                $b = $certKey.ExportSubjectPublicKeyInfo()
                return ([Convert]::ToBase64String([byte[]]$a) -ceq [Convert]::ToBase64String([byte[]]$b))
            }
            finally { $certKey.Dispose() }
        }
        finally { $ec.Dispose() }
    }
    catch { }

    return $null
}

function Test-ChainToRoot {
    # Builds the chain of $Certificate with $Root as the only trust anchor and
    # $Intermediate as the helper certificate.
    param(
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)]$Root,
        $Intermediate
    )

    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()

    try {
        $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        [void]$chain.ChainPolicy.CustomTrustStore.Add($Root)

        if ($null -ne $Intermediate) {
            [void]$chain.ChainPolicy.ExtraStore.Add($Intermediate)
        }

        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

        if ($chain.Build($Certificate)) {
            return [pscustomobject]@{ Valid = $true; Detail = '' }
        }

        $status = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ', '
        return [pscustomobject]@{ Valid = $false; Detail = $status }
    }
    finally { $chain.Dispose() }
}

function Test-ExistingPki {
    # Returns an object describing the folder; throws when it cannot be used.
    param([Parameter(Mandatory)][string]$Folder)

    $rootCrt  = Join-Path $Folder 'root/root.crt'
    $rootKey  = Join-Path $Folder 'root/root.key'
    $intCrt   = Join-Path $Folder 'intermediate/intermediate.crt'
    $intKey   = Join-Path $Folder 'intermediate/intermediate.key'
    $leafDir  = Join-Path $Folder 'leaf'

    $errors   = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    foreach ($required in @($rootCrt, $intCrt)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            [void]$errors.Add("Required file is missing: $required")
        }
    }

    if ($errors.Count -gt 0) {
        throw ("The folder is not a usable PKI:`n - " + ($errors -join "`n - ") +
            "`nExpected the layout pki_setup.ps1 creates (see -Help).")
    }

    $root = Get-CertificateFileSafe -Path $rootCrt
    $int  = Get-CertificateFileSafe -Path $intCrt

    $now = [DateTime]::UtcNow

    # ---- Root CA
    if ($root.Subject -ne $root.Issuer) {
        [void]$errors.Add("root\root.crt is not self-signed (subject differs from issuer).")
    }

    if (-not (Test-CaFlag -Certificate $root)) {
        [void]$errors.Add('root\root.crt is not a CA certificate.')
    }

    if ($now -lt $root.NotBefore.ToUniversalTime() -or $now -gt $root.NotAfter.ToUniversalTime()) {
        [void]$errors.Add("Root CA is outside its validity period ($($root.NotBefore.ToString('yyyy-MM-dd')) to $($root.NotAfter.ToString('yyyy-MM-dd'))).")
    }

    # ---- Intermediate CA
    if (-not (Test-CaFlag -Certificate $int)) {
        [void]$errors.Add('intermediate\intermediate.crt is not a CA certificate.')
    }

    if ($now -lt $int.NotBefore.ToUniversalTime() -or $now -gt $int.NotAfter.ToUniversalTime()) {
        [void]$errors.Add("Intermediate CA is outside its validity period ($($int.NotBefore.ToString('yyyy-MM-dd')) to $($int.NotAfter.ToString('yyyy-MM-dd'))).")
    }

    $intChain = Test-ChainToRoot -Certificate $int -Root $root

    if (-not $intChain.Valid) {
        [void]$errors.Add("The Intermediate CA does not chain to the Root CA ($($intChain.Detail)).")
    }

    # ---- private keys
    $canIssue = $false

    if (Test-Path -LiteralPath $intKey -PathType Leaf) {

        $match = Test-PrivateKeyMatchesCertificate -KeyPath $intKey -Certificate $int

        if ($match -eq $false) {
            [void]$errors.Add('intermediate\intermediate.key does not match intermediate\intermediate.crt.')
        }
        elseif ($null -eq $match) {
            [void]$warnings.Add('intermediate\intermediate.key could not be compared with the certificate (encrypted or unsupported key).')
            $canIssue = $true
        }
        else {
            $canIssue = $true
        }
    }
    else {
        [void]$warnings.Add('intermediate\intermediate.key is missing: this PKI can be trusted, but GenerateLeafCertificate.ps1 cannot issue new leaf certificates from it.')
    }

    if (Test-Path -LiteralPath $rootKey -PathType Leaf) {

        $match = Test-PrivateKeyMatchesCertificate -KeyPath $rootKey -Certificate $root

        if ($match -eq $false) {
            [void]$errors.Add('root\root.key does not match root\root.crt.')
        }
    }
    else {
        [void]$warnings.Add('root\root.key is missing (only needed to create another Intermediate CA).')
    }

    # ---- leaf certificates
    $leafOk = 0
    $leafBad = 0
    $leafPfx = @()

    if (Test-Path -LiteralPath $leafDir -PathType Container) {

        foreach ($file in Get-ChildItem -LiteralPath $leafDir -File -Filter '*.crt') {

            if ($file.Name -like '*-fullchain.crt') { continue }

            try {
                $leaf = Get-CertificateFileSafe -Path $file.FullName
                try {
                    $check = Test-ChainToRoot -Certificate $leaf -Root $root -Intermediate $int

                    if ($check.Valid) { $leafOk++ }
                    else {
                        $leafBad++
                        [void]$warnings.Add("Leaf $($file.Name) does not chain cleanly: $($check.Detail)")
                    }
                }
                finally { $leaf.Dispose() }
            }
            catch {
                $leafBad++
                [void]$warnings.Add("Leaf $($file.Name) could not be read: $($_.Exception.Message)")
            }
        }

        $leafPfx = @(Get-ChildItem -LiteralPath $leafDir -File -Filter '*.pfx')
    }

    if ($errors.Count -gt 0) {
        $root.Dispose(); $int.Dispose()
        throw ("The PKI in $Folder failed the check:`n - " + ($errors -join "`n - "))
    }

    $info = [pscustomobject]@{
        Folder             = $Folder
        RootCrt            = $rootCrt
        IntermediateCrt    = $intCrt
        RootSubject        = $root.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        RootThumbprint     = $root.Thumbprint
        RootExpires        = $root.NotAfter
        IntermediateSubject    = $int.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        IntermediateThumbprint = $int.Thumbprint
        IntermediateExpires    = $int.NotAfter
        CanIssue           = $canIssue
        LeafOk             = $leafOk
        LeafBad            = $leafBad
        LeafPfx            = $leafPfx
        Warnings           = @($warnings)
    }

    $root.Dispose()
    $int.Dispose()

    return $info
}

function Copy-PkiIntoProject {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$Force
    )

    if (Test-Path -LiteralPath $Destination) {

        $existing = @(Get-ChildItem -LiteralPath $Destination -Force -ErrorAction SilentlyContinue)

        if ($existing.Count -gt 0) {

            if (-not $Force) {
                throw @"
The project already has a PKI folder with content:

  $Destination

Choose one of:
  -Force    rename it to pki.backup-<date> and use the new folder
  -NoCopy   keep the new folder where it is (use GenerateLeafCertificate.ps1 -AddPkiContentPath)
  -CheckOnly   only check, change nothing
"@
            }

            $backup = '{0}.backup-{1}' -f $Destination, (Get-Date -Format 'yyyyMMdd-HHmmss')

            Move-Item -LiteralPath $Destination -Destination $backup

            Write-ReuseLog "Existing PKI folder kept as: $backup" 'WARN'
        }
    }

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null

    Copy-Item -Path (Join-Path $Source '*') -Destination $Destination -Recurse -Force

    Write-ReuseLog "PKI copied to: $Destination" 'OK'
}

# ============================================================
# Main
# ============================================================

try {

    # ---- 1. folder
    $projectPki = Join-Path $script:ScriptRoot 'pki'

    $sourceInput = if ([string]::IsNullOrWhiteSpace($AddPkiContentPath)) { $projectPki } else { $AddPkiContentPath }

    if (-not (Test-Path -LiteralPath $sourceInput -PathType Container)) {
        throw "PKI folder not found: $sourceInput"
    }

    $source = (Resolve-Path -LiteralPath $sourceInput).Path

    Write-ReuseLog "PKI folder: $source"

    # ---- 2. check
    $info = Test-ExistingPki -Folder $source

    Write-ReuseLog "Root CA          : $($info.RootSubject)" 'OK'
    Write-ReuseLog "                   thumbprint $($info.RootThumbprint), expires $($info.RootExpires.ToString('yyyy-MM-dd'))"
    Write-ReuseLog "Intermediate CA  : $($info.IntermediateSubject)" 'OK'
    Write-ReuseLog "                   thumbprint $($info.IntermediateThumbprint), expires $($info.IntermediateExpires.ToString('yyyy-MM-dd'))"
    Write-ReuseLog "Intermediate chains to the Root CA." 'OK'
    Write-ReuseLog "Leaf certificates: $($info.LeafOk) valid, $($info.LeafBad) with problems, $($info.LeafPfx.Count) PFX file(s)"

    if ($info.CanIssue) {
        Write-ReuseLog 'The Intermediate CA key is present: new leaf certificates can be issued.' 'OK'
    }

    foreach ($warning in $info.Warnings) {
        Write-ReuseLog $warning 'WARN'
    }

    if ($CheckOnly) {
        Write-ReuseLog 'Check finished. Nothing was copied or installed (-CheckOnly).' 'OK'
        exit 0
    }

    # ---- 3. adopt
    $trustFolder = $source

    $projectFull = [System.IO.Path]::GetFullPath($projectPki)
    $sourceFull  = [System.IO.Path]::GetFullPath($source)

    $sameFolder = [string]::Equals(
        $projectFull.TrimEnd('\', '/'),
        $sourceFull.TrimEnd('\', '/'),
        [System.StringComparison]::OrdinalIgnoreCase
    )

    if ($RemoveTrust) {
        # Nothing to adopt when removing.
    }
    elseif ($NoCopy -or $sameFolder) {
        if ($sameFolder) {
            Write-ReuseLog 'The folder already is the project PKI (.\pki).' 'OK'
        }
        else {
            Write-ReuseLog "Using the folder in place (-NoCopy): $source" 'INFO'
            Write-ReuseLog "Issue leaf certificates with: .\GenerateLeafCertificate.ps1 -AddPkiContentPath `"$source`" -Domain <name>" 'INFO'
        }
    }
    else {
        Copy-PkiIntoProject -Source $source -Destination $projectPki -Force:$Force
        $trustFolder = $projectPki
        Write-ReuseLog 'GenerateLeafCertificate.ps1 will now issue from this PKI.' 'OK'
    }

    # ---- 4. trust
    if ($NoTrust) {
        Write-ReuseLog 'Windows certificate stores were not changed (-NoTrust).' 'OK'
        exit 0
    }

    if (-not $IsWindows) {
        Write-ReuseLog 'Trust installation is only available on Windows. On macOS / Ubuntu / Android / iOS install root\root.crt as described in COMPATIBILITY.md.' 'WARN'
        exit 0
    }

    foreach ($module in @('07_TrustStore.ps1')) {
        $modulePath = Join-Path (Join-Path $script:ScriptRoot 'scripts') $module

        if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
            throw "Required module not found: $modulePath"
        }

        try { Unblock-File -LiteralPath $modulePath -ErrorAction SilentlyContinue } catch { }

        . $modulePath
    }

    if (-not (Test-IsAdministrator)) {
        throw 'Installing trust needs an elevated PowerShell (Run as administrator). Use -CheckOnly or -NoTrust to skip.'
    }

    $rootPath = Join-Path $trustFolder 'root/root.crt'
    $intPath  = Join-Path $trustFolder 'intermediate/intermediate.crt'

    if ($RemoveTrust) {

        Remove-CertificateThumbprint -Store Root -Thumbprint $info.RootThumbprint
        Remove-CertificateThumbprint -Store CA   -Thumbprint $info.IntermediateThumbprint

        Write-ReuseLog 'Root and Intermediate CA removed from LocalMachine.' 'OK'
        exit 0
    }

    Install-CertificateToStore -CertificatePath $rootPath -Store Root | Out-Null
    Write-ReuseLog 'Root CA installed in LocalMachine\Root.' 'OK'

    Install-CertificateToStore -CertificatePath $intPath -Store CA | Out-Null
    Write-ReuseLog 'Intermediate CA installed in LocalMachine\CA.' 'OK'

    if ($ImportLeafPfx) {

        $pfxPassword = $Password

        if ([string]::IsNullOrEmpty($pfxPassword)) { $pfxPassword = $env:PKI_PFX_PASSWORD }

        if ([string]::IsNullOrEmpty($pfxPassword)) {
            $secure = Read-Host 'PFX password' -AsSecureString
            $pfxPassword = ConvertFrom-SecureString -SecureString $secure -AsPlainText
        }

        $pfxFiles = @(Get-ChildItem -LiteralPath (Join-Path $trustFolder 'leaf') -File -Filter '*.pfx' -ErrorAction SilentlyContinue)

        foreach ($pfx in $pfxFiles) {
            Install-LeafPfxToMyStore -PfxPath $pfx.FullName -Password $pfxPassword | Out-Null
            Write-ReuseLog "Imported into LocalMachine\My: $($pfx.Name)" 'OK'
        }

        $pfxPassword = $null
    }

    Write-ReuseLog 'Done. Restart the browser so it reloads the Windows trust store.' 'OK'
    exit 0
}
catch {
    Write-ReuseLog $_.Exception.Message 'ERROR'
    exit 1
}
