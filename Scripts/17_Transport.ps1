# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 17_Transport.ps1  -  Phase C: carry a PKI to another machine as a password-protected ".certpacked" file
#
# SOURCE        PkiTransport.ps1 -Pack            makes the .certpacked (this module: plan, manifest, pack)
# DESTINATION   Unpack-PkiTransport.ps1           unpacks only (this module: open, verify, export)
#               PkiTransport.ps1 -Install         Windows 11 25H2 or newer ONLY: scan, unpack, install the trust
#               pki-transport.sh                  Linux and macOS: unpack and install the trust (own script)
#
# What goes into a package (the "scope"):
#   CA certificates only (default)   public certificates, chains and bundles: enough to TRUST the PKI
#   + -IncludeLeafCerts              the leafcerts folders (they contain the PRIVATE KEYS of the leaves)
#   + -IncludeCaKeys                 the whole pki folder with the CA private keys: the destination can ISSUE too
#
# Inside the archive:
#   certpack.json  certpack.tsv  SHA256SUMS  README.txt          description, SHA-256 of every file
#   ca\roots\<slug>.crt        ca\intermediates\<slug>.crt        every root (Enterprise, Track, Quadrant) / DV OV EV CA
#   ca\ca-bundle-roots.crt     ca\ca-bundle-all.crt               all roots / all CAs in one PEM file
#   ca\chains\<slug>-fullchain.crt                                intermediate + its parents, one PEM file each
#   ca\publish\...   ca\external-chain.pem   ca\cross-sign\...    CRLs, public-CA chain, cross-certificates (if any)
#   leafcerts\...                                                 (-IncludeLeafCerts)
#   pki\...                                                       (-IncludeCaKeys)
#
# Provides : Get-PkiWindowsSupport, Get-PkiDestinationOpenSsl, Test-PkiPackagePassword, New-PkiPackagePassword,
#            Read-PkiPackagePassword, Get-PkiPackagePlan, New-PkiCertPackage, Open-PkiCertPackage,
#            Get-PkiPackageSelection, Export-PkiPackageSelection, Install-PkiPackageWindows,
#            Remove-PkiPackageTrustWindows, Write-PkiTransportKit, Write-PkiScanLine
# Requires : 00_Common, 02_OpenSSL, 07_TrustStore, 09_Administrator, 16_CertPack
#            (packing also 01 - 04, 12, 13: the 'Library' set)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiPackageExtension = '.certpacked'
$script:PkiMinWindowsBuild = 26200                  # Windows 11 25H2
$script:PkiMinWindowsName = 'Windows 11 25H2'
$script:PkiMinOpenSsl = [version]'4.0.1'
$script:PkiTestedOpenSslMax = [version]'4.0.3'
$script:PkiPackageSelections = @('roots', 'intermediates', 'chains', 'ca', 'leafcerts', 'pki', 'all', 'fullchain')

# ------------------------------------------------------------
# Scans
# ------------------------------------------------------------
function Write-PkiScanLine {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status, [string]$Text = '')
    $color = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Gray' } }
    Write-Host ('[{0}] {1,-30} {2}' -f $Status, $Name, $Text) -ForegroundColor $color
}

function Get-PkiWindowsSupport {
    <#
    .SYNOPSIS
        Is this machine a supported destination for installing the trust? Only Windows 11 25H2 (build 26200) or newer,
        client edition. Windows 11 24H2 and older, Windows 10, 8.1, 7, Windows Server and everything else: not supported.
    .PARAMETER Simulate
        For tests: @{ IsWindows; Major; Minor; Build; ProductType; Caption; DisplayVersion; Ubr }
    #>
    param([hashtable]$Simulate)
    $i = [ordered]@{ IsWindows = $false; Caption = ''; Major = 0; Minor = 0; Build = 0; Ubr = 0; ProductType = 0; DisplayVersion = '' }
    if ($null -ne $Simulate) { foreach ($k in $Simulate.Keys) { $i[$k] = $Simulate[$k] } }
    elseif ($IsWindows) {
        $i.IsWindows = $true
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $i.Caption = [string]$os.Caption; $i.ProductType = [int]$os.ProductType
            $v = [version]$os.Version; $i.Major = $v.Major; $i.Minor = $v.Minor; $i.Build = [int]$os.BuildNumber
        }
        catch {
            $v = [System.Environment]::OSVersion.Version; $i.Major = $v.Major; $i.Minor = $v.Minor; $i.Build = $v.Build; $i.ProductType = 1
        }
        try {
            $rk = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            if ($rk.PSObject.Properties['DisplayVersion']) { $i.DisplayVersion = [string]$rk.DisplayVersion }
            if ($rk.PSObject.Properties['UBR']) { $i.Ubr = [int]$rk.UBR }
        }
        catch { }
    }
    else { $i.Caption = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription }

    $reason = ''
    if (-not $i.IsWindows) { $reason = 'This is not Windows. On Linux and macOS use pki-transport.sh.' }
    elseif ($i.Major -lt 10) {
        $old = switch ("$($i.Major).$($i.Minor)") { '6.1' { 'Windows 7' } '6.2' { 'Windows 8' } '6.3' { 'Windows 8.1' } '6.0' { 'Windows Vista' } '5.1' { 'Windows XP' } default { "Windows $($i.Major).$($i.Minor)" } }
        $reason = "$old (and every Windows before Windows 11 25H2) is not supported."
    }
    elseif ($i.ProductType -ne 1) { $reason = 'Windows Server and domain controllers are not supported: Windows 11 client only.' }
    elseif ($i.Build -lt 22000) { $reason = "Windows 10 (build $($i.Build)) is not supported." }
    elseif ($i.Build -lt $script:PkiMinWindowsBuild) { $reason = "Windows 11 before 25H2 (build $($i.Build); 24H2 is 26100) is not supported. Update to Windows 11 25H2 (build $($script:PkiMinWindowsBuild)) or newer." }
    $name = if (-not $i.IsWindows) { $i.Caption }
            elseif ($i.Build -ge 22000) { "Windows 11 $(if ($i.DisplayVersion) { $i.DisplayVersion } else { 'build ' + $i.Build })" }
            elseif ($i.Major -ge 10) { 'Windows 10' } else { "Windows $($i.Major).$($i.Minor)" }
    return [ordered]@{
        Supported = ($reason -eq ''); Reason = $reason; Name = $name; Caption = $i.Caption; Build = $i.Build; Ubr = $i.Ubr
        DisplayVersion = $i.DisplayVersion; ProductType = $i.ProductType; IsWindows = $i.IsWindows
        Required = "$($script:PkiMinWindowsName) (build $($script:PkiMinWindowsBuild)) or newer, client edition"
    }
}

function Get-PkiDestinationOpenSsl {
    <#
    .SYNOPSIS
        Finds an OpenSSL 4.0.1 or newer (4.0.1 to 4.0.3 is the tested range). Status: Ok | TooOld | Missing.
    #>
    param([string]$ExplicitPath)
    $found = [System.Collections.Generic.List[object]]::new()
    $cands = if ($ExplicitPath) { @($ExplicitPath) } else { @(Get-PkiOpenSslCandidates) }
    foreach ($exe in $cands) {
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
        $v = Get-PkiOpenSslVersionOf -Exe $exe
        if ($null -ne $v) { [void]$found.Add($v) }
    }
    $good = @($found | Where-Object { $_.Product -eq 'OpenSSL' -and ([version]::new($_.Major, $_.Minor, $_.Patch) -ge $script:PkiMinOpenSsl) })
    $best = $null
    if ($good.Count -gt 0) { $best = $good | Sort-Object -Property @{ Expression = 'Major'; Descending = $true }, @{ Expression = 'Minor'; Descending = $true }, @{ Expression = 'Patch'; Descending = $true } | Select-Object -First 1 }
    $anyOpenSsl = @($found | Where-Object { $_.Product -eq 'OpenSSL' }).Count -gt 0
    $status = if ($null -ne $best) { 'Ok' } elseif ($anyOpenSsl) { 'TooOld' } else { 'Missing' }
    return [ordered]@{
        Status = $status; Best = $best; Found = @($found)
        Required = "OpenSSL $($script:PkiMinOpenSsl) or newer (tested up to $($script:PkiTestedOpenSslMax))"
        Newer = ($null -ne $best -and ([version]::new($best.Major, $best.Minor, $best.Patch) -gt $script:PkiTestedOpenSslMax))
    }
}

# ------------------------------------------------------------
# Password
# ------------------------------------------------------------
function Test-PkiPackagePassword {
    # Returns the problems (empty = fine). Printable ASCII only: 7-Zip refuses other characters for AES zip.
    param([AllowEmptyString()][string]$Password)
    $p = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrEmpty($Password)) { [void]$p.Add('the password is empty'); return ,@($p) }
    if ($Password -cnotmatch '^[\x20-\x7E]+$') { [void]$p.Add('only printable ASCII characters are allowed (7-Zip and the other tools cannot agree on anything else)') }
    if ($Password.Length -lt 12) { [void]$p.Add("it has $($Password.Length) characters; at least 12 are required") }
    $classes = 0
    foreach ($re in '[a-z]', '[A-Z]', '[0-9]', '[^A-Za-z0-9]') { if ($Password -cmatch $re) { $classes++ } }
    if ($classes -lt 3) { [void]$p.Add('it must use at least 3 of: lower case, upper case, digits, symbols') }
    return ,@($p)      # the comma keeps an EMPTY list from vanishing
}

function New-PkiPackagePassword {
    # 20 characters, shell-safe symbols only (no quotes, $, !, backslash, space), all four classes present.
    $lower = 'abcdefghijkmnopqrstuvwxyz'; $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $digit = '23456789'; $sym = '-_.+=@#%'
    $all = $lower + $upper + $digit + $sym
    $rng = [System.Security.Cryptography.RandomNumberGenerator]
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($set in $lower, $upper, $digit, $sym) { [void]$chars.Add($set[$rng::GetInt32($set.Length)]) }
    while ($chars.Count -lt 20) { [void]$chars.Add($all[$rng::GetInt32($all.Length)]) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) { $j = $rng::GetInt32($i + 1); $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t }
    return (-join $chars)
}

function Read-PkiPackagePassword {
    # Prompts (not echoed). -Confirm asks twice and checks the policy.
    param([switch]$Confirm, [string]$Prompt = 'Package password')
    $s1 = Read-Host -Prompt $Prompt -AsSecureString
    $plain = [System.Net.NetworkCredential]::new('', $s1).Password
    if ($Confirm) {
        $s2 = Read-Host -Prompt "$Prompt (again)" -AsSecureString
        if ($plain -cne [System.Net.NetworkCredential]::new('', $s2).Password) { throw 'The two passwords differ.' }
    }
    return $plain
}

# ------------------------------------------------------------
# SOURCE: what goes into the package
# ------------------------------------------------------------
function Get-PkiFileSha256 {
    # Direct .NET: works for hidden files (.agantra-pki) and streams large files.
    param([Parameter(Mandatory)][string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    try { return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($fs)).ToLowerInvariant() }
    finally { $fs.Dispose() }
}

function Get-PkiPackagePlan {
    <#
    .SYNOPSIS
        Collects everything the package will hold. Needs the config and the catalog (Initialize-PkiConfiguration, then
        Import-PkiExisting -SkipProviders): the files are found from the PKI folder, not from stale paths in the manifest.
    .OUTPUTS
        @{ Entries = list of @{ Source; Entry; Role; Sha1; ... }; Staging = folder with the generated files;
           CaList; Leaves }
    #>
    param(
        [Parameter(Mandatory)][string]$LeafRoot, [bool]$IncludeLeafCerts = $false, [bool]$IncludeCaKeys = $false,
        [string[]]$LeafName = @(), [Parameter(Mandatory)][string]$Staging
    )
    $c = $script:Pki
    Ensure-PkiDirectory -Path $Staging
    $entries = [System.Collections.Generic.List[hashtable]]::new()
    $add = { param($src, $name, $role, $extra) $h = @{ Source = $src; Entry = ($name -replace '\\', '/'); Role = $role }; if ($extra) { foreach ($k in $extra.Keys) { $h[$k] = $extra[$k] } }; [void]$entries.Add($h) }
    $caList = [System.Collections.Generic.List[hashtable]]::new()

    $rootsPem = [System.Text.StringBuilder]::new()
    $allPem = [System.Text.StringBuilder]::new()
    $pemOf = { param($f) ([System.IO.File]::ReadAllText($f)).TrimEnd() + "`n" }

    foreach ($ca in $c.Catalog) {
        $paths = Get-PkiCaPaths -Ca $ca
        if (-not (Test-Path -LiteralPath $paths.Crt)) { throw "The PKI is incomplete: $($paths.Crt) is missing." }
        $b = $c.Built[$ca.Id]
        $isRoot = $ca.Kind -in 'root', 'track', 'quadrant'
        $rel = if ($isRoot) { "ca/roots/$($ca.Slug).crt" } else { "ca/intermediates/$($ca.Slug).crt" }
        $ext = ($b.Contains('externallySigned') -and [bool]$b['externallySigned'])
        & $add $paths.Crt $rel $(if ($isRoot) { 'root' } else { 'intermediate' }) @{ Kind = $ca.Kind; Sha1 = [string]$b['sha1']; Name = [string]$b['commonName']; Store = $(if ($ext) { 'CA' } elseif ($isRoot) { 'Root' } else { 'CA' }); ExternallySigned = $ext }
        [void]$allPem.Append((& $pemOf $paths.Crt))
        if ($isRoot) { [void]$rootsPem.Append((& $pemOf $paths.Crt)) }
        [void]$caList.Add([ordered]@{
            id = $ca.Id; kind = $ca.Kind; commonName = [string]$b['commonName']; track = $ca.Track; quadrant = $ca.Quadrant; fips = [bool]$ca.Fips
            validation = $ca.Validation; keyAlgorithm = [string]$b['keyAlgorithm']; slug = $ca.Slug; notAfter = [string]$b['notAfter']
            sha1 = [string]$b['sha1']; sha256 = [string]$b['sha256']; externallySigned = $ext; file = $rel
            store = $(if ($ext) { 'CA' } elseif ($isRoot) { 'Root' } else { 'CA' })
        })
        if (-not $isRoot) {
            # one fullchain file per intermediate: it + its parents up to and including the Enterprise Root
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.Append((& $pemOf $paths.Crt))
            foreach ($anc in (Get-PkiCaAncestors -Ca $ca)) { [void]$sb.Append((& $pemOf (Get-PkiCaPaths -Ca $anc).Crt)) }
            $f = Join-Path $Staging "$($ca.Slug)-fullchain.crt"
            Write-Utf8NoBom -Path $f -Content $sb.ToString()
            & $add $f "ca/chains/$($ca.Slug)-fullchain.crt" 'chain' $null
        }
    }
    $f = Join-Path $Staging 'ca-bundle-roots.crt'; Write-Utf8NoBom -Path $f -Content $rootsPem.ToString(); & $add $f 'ca/ca-bundle-roots.crt' 'bundle-roots' $null
    $f = Join-Path $Staging 'ca-bundle-all.crt';   Write-Utf8NoBom -Path $f -Content $allPem.ToString();   & $add $f 'ca/ca-bundle-all.crt' 'bundle' $null

    # public CA chain and cross-certificates, if the Enterprise Root was signed / cross-signed by a public CA
    $rootDir = Join-Path $c.PkiRoot 'root'
    if (Test-Path -LiteralPath (Join-Path $rootDir 'external-chain.pem')) { & $add (Join-Path $rootDir 'external-chain.pem') 'ca/external-chain.pem' 'external' $null }
    $cross = Join-Path $rootDir 'cross-sign'
    if (Test-Path -LiteralPath $cross) {
        foreach ($f in Get-ChildItem -LiteralPath $cross -File -Filter 'root-cross-*' | Where-Object { $_.Extension -in '.crt', '.pem' }) { & $add $f.FullName "ca/cross-sign/$($f.Name)" 'cross' $null }
    }
    # CRLs and the files pki_setup.ps1 wrote for publishing
    if (Test-Path -LiteralPath $c.PublishDir) {
        foreach ($f in Get-ChildItem -LiteralPath $c.PublishDir -File) { & $add $f.FullName "ca/publish/$($f.Name)" 'publish' $null }
    }

    # leafcerts
    $leaves = [System.Collections.Generic.List[object]]::new()
    if ($IncludeLeafCerts) {
        if (-not (Test-Path -LiteralPath $LeafRoot -PathType Container)) { throw "-IncludeLeafCerts: the leaf folder does not exist: $LeafRoot" }
        $tops = @(Get-ChildItem -LiteralPath $LeafRoot -Directory)
        if (@($LeafName).Count -gt 0) { $tops = @($tops | Where-Object { $n = $_.Name; @($LeafName | Where-Object { $n -like $_ }).Count -gt 0 }) }
        if ($tops.Count -eq 0) { throw "-IncludeLeafCerts: no leaf folder in $LeafRoot$(if (@($LeafName).Count) { " matches $($LeafName -join ', ')" })." }
        foreach ($t in $tops) {
            foreach ($f in Get-ChildItem -LiteralPath $t.FullName -Recurse -File) {
                $rel = $f.FullName.Substring($LeafRoot.TrimEnd('\', '/').Length).TrimStart('\', '/')
                & $add $f.FullName "leafcerts/$rel" 'leaf' $null
            }
        }
        $idxPath = Join-Path $LeafRoot 'leaf-index.json'
        if (Test-Path -LiteralPath $idxPath) {
            $all = @(Get-Content -LiteralPath $idxPath -Raw | ConvertFrom-Json -AsHashtable)
            $topNames = @($tops | ForEach-Object { $_.Name })
            foreach ($e in $all) {
                $folder = [string]$e['folder']; $top = ($folder -split '[\\/]')[0]
                if ($topNames -contains $top) { [void]$leaves.Add($e) }
            }
            $f = Join-Path $Staging 'leaf-index.json'
            Write-Utf8NoBom -Path $f -Content (ConvertTo-Json -InputObject @($leaves) -Depth 6)
            & $add $f 'leafcerts/leaf-index.json' 'leaf-index' $null
        }
    }

    # the whole PKI folder with the CA private keys
    if ($IncludeCaKeys) {
        $root = $c.PkiRoot.TrimEnd('\', '/')
        foreach ($f in Get-ChildItem -LiteralPath $c.PkiRoot -Recurse -File -Force | Where-Object { $_.Extension -notin '.tmp' -and $_.Name -notlike '*.untrusted.tmp' -and $_.Name -ne 'telemetry.json' }) {
            $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
            & $add $f.FullName "pki/$rel" 'pki' $null
        }
    }
    return [ordered]@{ Entries = $entries; Staging = $Staging; CaList = $caList; Leaves = $leaves }
}

function New-PkiCertPackage {
    <#
    .SYNOPSIS
        Builds the .certpacked file. Returns @{ Path; Format; Encryption; Files; Bytes; Scope }.
    #>
    param(
        [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$Password,
        [ValidateSet('zip', '7z')][string]$ArchiveFormat = 'zip', [ValidateSet('Aes256', 'ZipCrypto')][string]$ZipEncryption = 'Aes256',
        [bool]$IncludeLeafCerts = $false, [bool]$IncludeCaKeys = $false, [string[]]$LeafName = @(), [string]$LeafRoot,
        [string]$Comment = '', [string]$SevenZipPath, [switch]$NoVerify
    )
    $c = $script:Pki
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) "certpacked-$([guid]::NewGuid().ToString('N'))"
    try {
        $plan = Get-PkiPackagePlan -LeafRoot $LeafRoot -IncludeLeafCerts $IncludeLeafCerts -IncludeCaKeys $IncludeCaKeys -LeafName $LeafName -Staging (Join-Path $staging 'gen')
        $entries = $plan.Entries
        # de-duplicate by entry name
        $seen = @{}; $uniq = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($e in $entries) { if (-not $seen.ContainsKey($e.Entry)) { $seen[$e.Entry] = $true; [void]$uniq.Add($e) } }
        $entries = $uniq

        $files = foreach ($e in $entries) {
            [ordered]@{ path = $e.Entry; sha256 = (Get-PkiFileSha256 -Path $e.Source); size = ([System.IO.FileInfo]::new($e.Source)).Length; role = $e.Role }
        }
        $scope = [ordered]@{ caCertificates = $true; leafcerts = $IncludeLeafCerts; caPrivateKeys = $IncludeCaKeys }
        $manifest = [ordered]@{
            format = 'agantra-certpacked'; formatVersion = 1
            createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "PkiTransport.ps1 $($script:PkiGeneratorVersion)"
            comment = $Comment
            source = [ordered]@{ machine = [Environment]::MachineName; os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription; pkiRoot = $c.PkiRoot }
            archive = [ordered]@{ format = $ArchiveFormat; encryption = $(if ($ArchiveFormat -eq '7z') { 'AES-256, headers encrypted' } elseif ($ZipEncryption -eq 'Aes256') { 'AES-256 (WinZip AE-2)' } else { 'ZipCrypto (legacy, weak)' }) }
            scope = $scope
            mode = $(if ($c.ClassicPki) { 'ClassicPKI' } else { 'Full' }); quadrants = @($c.Quadrants)
            requirements = [ordered]@{
                windows = "$($script:PkiMinWindowsName) (build $($script:PkiMinWindowsBuild)) or newer, client edition (to install the trust)"
                openssl = "OpenSSL $($script:PkiMinOpenSsl) or newer, tested up to $($script:PkiTestedOpenSslMax)"
                linux = 'Ubuntu, Debian, RHEL / CentOS Stream / Rocky / Oracle / Alma Linux, SUSE / openSUSE (pki-transport.sh); macOS (pki-transport.sh)'
            }
            certificateAuthorities = @($plan.CaList)
            leaves = @($plan.Leaves | ForEach-Object { [ordered]@{ set = $_['set']; folder = (([string]$_['folder']) -replace '\\', '/'); stem = $_['stem']; level = $_['level']; quadrant = $_['quadrant']; purposes = $_['purposes']; keyAlgorithm = $_['keyAlgorithm']; notAfter = $_['notAfter']; sha1 = $_['sha1']; pfx = (@($_['files']) | Where-Object { $_ -like '*.pfx' -and $_ -notlike '*-fips.pfx' } | Select-Object -First 1) } })
            files = @($files)
        }
        # certpack.json, certpack.tsv (for shell scripts: no JSON parser needed), SHA256SUMS, README.txt
        $gen = Join-Path $staging 'gen'
        $jsonF = Join-Path $gen 'certpack.json'; Write-Utf8NoBom -Path $jsonF -Content ($manifest | ConvertTo-Json -Depth 8)
        $tsv = [System.Text.StringBuilder]::new()
        [void]$tsv.Append("# role`tpath`tsha256`tsize`tsha1`tstore`texternallySigned`tkind`tname`n")
        foreach ($e in $entries) {
            $f = $files | Where-Object { $_.path -eq $e.Entry } | Select-Object -First 1
            $sha1 = if ($e.ContainsKey('Sha1')) { $e.Sha1 } else { '' }
            $store = if ($e.ContainsKey('Store')) { $e.Store } else { '' }
            $extS = if ($e.ContainsKey('ExternallySigned') -and $e.ExternallySigned) { '1' } else { '0' }
            $nm = if ($e.ContainsKey('Name')) { $e.Name } else { '' }
            $kd = if ($e.ContainsKey('Kind')) { $e.Kind } else { '' }
            [void]$tsv.Append("$($e.Role)`t$($e.Entry)`t$($f.sha256)`t$($f.size)`t$sha1`t$store`t$extS`t$kd`t$nm`n")
        }
        $tsvF = Join-Path $gen 'certpack.tsv'; Write-Utf8NoBom -Path $tsvF -Content $tsv.ToString()
        $sums = [System.Text.StringBuilder]::new()
        foreach ($f in $files) { [void]$sums.Append("$($f.sha256)  $($f.path)`n") }
        $sumF = Join-Path $gen 'SHA256SUMS'; Write-Utf8NoBom -Path $sumF -Content $sums.ToString()
        $readme = @"
CERTPACKED - Agantra Inovatif Enterprise PKI transport package
==============================================================
Created : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC on $([Environment]::MachineName)
Archive : $($manifest.archive.format), $($manifest.archive.encryption)
Scope   : CA certificates$(if ($IncludeLeafCerts) { ', LEAF CERTIFICATES (with private keys)' })$(if ($IncludeCaKeys) { ', the whole PKI with the CA PRIVATE KEYS' })
$(if ($Comment) { "Comment : $Comment`n" })
This file is a password-protected archive. Rename it to .zip or .7z and open it with 7-Zip, or use:
  Windows 11 25H2+   PkiTransport.ps1 -Install -Package <file>      (unpacks and installs the trust)
  any pwsh 7         Unpack-PkiTransport.ps1 -Package <file>        (unpacks only)
  Linux, macOS       pki-transport.sh --package <file>              (unpacks and installs the trust)

Every file is listed with its SHA-256 in certpack.json, certpack.tsv and SHA256SUMS.
Install only the CA certificates (ca\roots) on machines that merely have to TRUST the PKI.
$(if ($IncludeLeafCerts -or $IncludeCaKeys) { "THIS PACKAGE CONTAINS PRIVATE KEYS. Protect the file and the password; delete the extracted keys when done.`n" })
"@
        $readF = Join-Path $gen 'README.txt'; Write-Utf8NoBom -Path $readF -Content ($readme + "`n")

        $final = [System.Collections.Generic.List[hashtable]]::new()
        [void]$final.Add(@{ Source = $jsonF; Entry = 'certpack.json' }); [void]$final.Add(@{ Source = $tsvF; Entry = 'certpack.tsv' })
        [void]$final.Add(@{ Source = $sumF; Entry = 'SHA256SUMS' }); [void]$final.Add(@{ Source = $readF; Entry = 'README.txt' })
        foreach ($e in $entries) { [void]$final.Add(@{ Source = $e.Source; Entry = $e.Entry }) }

        Ensure-PkiDirectory -Path (Split-Path -Parent $OutFile)
        if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }
        if ($ArchiveFormat -eq 'zip') {
            New-PkiAesZipArchive -Path $OutFile -Files $final -Password $Password -Encryption $ZipEncryption
        }
        else {
            $stage7 = Join-Path $staging 'seven'
            foreach ($e in $final) {
                $dest = Join-Path $stage7 ($e.Entry -replace '/', [System.IO.Path]::DirectorySeparatorChar)
                Ensure-PkiDirectory -Path (Split-Path -Parent $dest)
                Copy-Item -LiteralPath $e.Source -Destination $dest -Force
            }
            New-PkiSevenZipArchive -Path $OutFile -StagingDirectory $stage7 -Password $Password -Exe $SevenZipPath
        }
        if (-not $NoVerify) {
            [void](Expand-PkiArchive -Path $OutFile -Password $Password -SevenZipPath $SevenZipPath)      # decrypts and authenticates every entry
        }
        return [ordered]@{ Path = $OutFile; Format = $ArchiveFormat; Encryption = $manifest.archive.encryption; Files = $final.Count; Bytes = ([System.IO.FileInfo]::new($OutFile)).Length; Scope = $scope; Manifest = $manifest }
    }
    finally { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
}

# ------------------------------------------------------------
# DESTINATION: open, select, export
# ------------------------------------------------------------
function Open-PkiCertPackage {
    <#
    .SYNOPSIS
        Decrypts a .certpacked into a temporary folder, reads certpack.json and checks the SHA-256 of EVERY file
        against it. Returns @{ Dir; Manifest; Type; Verified }. Remove the folder with Remove-PkiOpenedPackage.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Password, [string]$SevenZipPath)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Package not found: $Path" }
    $type = Get-PkiArchiveType -Path $Path
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) "certpacked-open-$([guid]::NewGuid().ToString('N'))"
    Ensure-PkiDirectory -Path $dir
    try {
        [void](Expand-PkiArchive -Path $Path -Destination $dir -Password $Password -SevenZipPath $SevenZipPath)
        $mf = Join-Path $dir 'certpack.json'
        if (-not (Test-Path -LiteralPath $mf)) { throw 'This archive has no certpack.json: it is not a .certpacked made by PkiTransport.ps1.' }
        $m = Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json -AsHashtable
        if ($m['format'] -ne 'agantra-certpacked') { throw "Unknown package format '$($m['format'])'." }
        if ([int]$m['formatVersion'] -gt 1) { throw "This package has format version $($m['formatVersion']); this script understands version 1. Use a newer PkiTransport.ps1." }
        $bad = [System.Collections.Generic.List[string]]::new()
        foreach ($f in @($m['files'])) {
            $p = Join-Path $dir (([string]$f['path']) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (-not (Test-Path -LiteralPath $p)) { [void]$bad.Add("$($f['path']) is missing"); continue }
            if ((Get-PkiFileSha256 -Path $p) -ne [string]$f['sha256']) { [void]$bad.Add("$($f['path']) has a different SHA-256") }
        }
        if ($bad.Count -gt 0) { throw ("The package does not match its own list of files:`n  - " + ($bad -join "`n  - ")) }
        return [ordered]@{ Dir = $dir; Manifest = $m; Type = $type; Verified = @($m['files']).Count }
    }
    catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }
}

function Remove-PkiOpenedPackage {
    param($Opened)
    if ($null -ne $Opened -and $Opened.Dir -and (Test-Path -LiteralPath $Opened.Dir)) {
        [void](Unlock-PkiTree -Path @($Opened.Dir))
        Remove-Item -LiteralPath $Opened.Dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-PkiPackageSelection {
    # Select names -> the files of the manifest. roots, intermediates, chains, ca, leafcerts, pki, all (= fullchain).
    param([Parameter(Mandatory)][hashtable]$Manifest, [string[]]$Select = @('ca'), [string[]]$LeafName = @())
    $want = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $Select) {
        switch ($s.ToLowerInvariant()) {
            'roots'         { foreach ($r in 'root', 'bundle-roots') { [void]$want.Add($r) } }
            'intermediates' { [void]$want.Add('intermediate') }
            'chains'        { foreach ($r in 'chain', 'bundle', 'bundle-roots') { [void]$want.Add($r) } }
            'ca'            { foreach ($r in 'root', 'intermediate', 'chain', 'bundle', 'bundle-roots', 'publish', 'external', 'cross') { [void]$want.Add($r) } }
            'leafcerts'     { foreach ($r in 'leaf', 'leaf-index') { [void]$want.Add($r) } }
            'pki'           { [void]$want.Add('pki') }
            { $_ -in 'all', 'fullchain' } { foreach ($r in 'root', 'intermediate', 'chain', 'bundle', 'bundle-roots', 'publish', 'external', 'cross', 'leaf', 'leaf-index', 'pki') { [void]$want.Add($r) } }
            default { throw "Unknown selection '$s'. Use: $($script:PkiPackageSelections -join ', ')." }
        }
    }
    $out = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($f in @($Manifest['files'])) {
        $role = [string]$f['role']
        if (-not $want.Contains($role)) { continue }
        if ($role -in 'leaf', 'leaf-index' -and @($LeafName).Count -gt 0) {
            $rel = ([string]$f['path']) -replace '^leafcerts/', ''
            $top = ($rel -split '/')[0]
            if ($role -eq 'leaf' -and -not (@($LeafName | Where-Object { $top -like $_ }).Count -gt 0)) { continue }
        }
        [void]$out.Add(@{ Path = [string]$f['path']; Role = $role; Sha256 = [string]$f['sha256'] })
    }
    return $out
}

function ConvertTo-PkiRebasedValue {
    # Replaces the old PKI root at the start of a path string by the new one.
    param($Value, [string]$OldRoot, [string]$NewRoot)
    if ($Value -is [string]) {
        $norm = $Value -replace '\\', '/'; $o = ($OldRoot -replace '\\', '/').TrimEnd('/')
        if ($o -and $norm.StartsWith($o, [StringComparison]::OrdinalIgnoreCase)) {
            $rest = $norm.Substring($o.Length).TrimStart('/') -replace '/', [System.IO.Path]::DirectorySeparatorChar
            return (Join-Path $NewRoot $rest)
        }
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in $Value.Keys) { $h[$k] = ConvertTo-PkiRebasedValue -Value $Value[$k] -OldRoot $OldRoot -NewRoot $NewRoot }; return $h
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        return @($Value | ForEach-Object { ConvertTo-PkiRebasedValue -Value $_ -OldRoot $OldRoot -NewRoot $NewRoot })
    }
    return $Value
}

function Export-PkiPackageSelection {
    <#
    .SYNOPSIS
        Copies the selected files from an opened package to -Destination (structure kept; certpack.json always).
        When the whole PKI (pki\) is extracted, the absolute paths in pki\pki-manifest.json are rewritten to the new place.
    #>
    param([Parameter(Mandatory)]$Opened, [Parameter(Mandatory)][string]$Destination, [string[]]$Select = @('ca'), [string[]]$LeafName = @(), [switch]$Force)
    $sel = @(Get-PkiPackageSelection -Manifest $Opened.Manifest -Select $Select -LeafName $LeafName)
    if ($sel.Count -eq 0) {
        $roles = (@($Opened.Manifest['files']) | ForEach-Object { $_['role'] } | Select-Object -Unique) -join ', '
        $has = @('CA certificates')
        if ($Opened.Manifest['scope']['leafcerts']) { $has += 'leafcerts' }
        if ($Opened.Manifest['scope']['caPrivateKeys']) { $has += 'pki with the CA keys' }
        throw ('Nothing in this package matches the selection ' + ($Select -join ', ') + '. The package holds: ' + ($has -join ', ') + ' (roles: ' + $roles + ').')
    }
    Ensure-PkiDirectory -Path $Destination
    $written = [System.Collections.Generic.List[string]]::new()
    $copy = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($s in $sel) { [void]$copy.Add($s) }
    foreach ($extra in 'certpack.json', 'README.txt') { [void]$copy.Add(@{ Path = $extra; Role = 'meta' }) }
    foreach ($s in $copy) {
        $src = Join-Path $Opened.Dir ($s.Path -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        $dst = Join-Path $Destination ($s.Path -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if ((Test-Path -LiteralPath $dst) -and -not $Force) {
            if ((Get-PkiFileSha256 -Path $dst) -eq (Get-PkiFileSha256 -Path $src)) { [void]$written.Add($s.Path); continue }
            throw "$dst exists and differs. Use -Force to overwrite, or another -Destination."
        }
        Ensure-PkiDirectory -Path (Split-Path -Parent $dst)
        Copy-Item -LiteralPath $src -Destination $dst -Force
        [void]$written.Add($s.Path)
    }
    $pm = Join-Path (Join-Path $Destination 'pki') 'pki-manifest.json'
    if (Test-Path -LiteralPath $pm) {
        $old = [string]$Opened.Manifest['source']['pkiRoot']
        $m = Get-Content -LiteralPath $pm -Raw | ConvertFrom-Json -AsHashtable
        $m2 = ConvertTo-PkiRebasedValue -Value $m -OldRoot $old -NewRoot (Join-Path $Destination 'pki')
        Write-Utf8NoBom -Path $pm -Content ($m2 | ConvertTo-Json -Depth 20)
    }
    [void](Unblock-PkiTree -Path @($Destination)); [void](Unlock-PkiTree -Path @($Destination))
    return @($written)
}

# ------------------------------------------------------------
# DESTINATION (Windows): trust
# ------------------------------------------------------------
function Install-PkiPackageWindows {
    <#
    .SYNOPSIS
        Installs the CA certificates of an extracted package: every root in Trusted Root, every intermediate in the
        Intermediate store (the rules of pki_setup.ps1 -InstallTrust), reads the stores back, and with -InstallLeafPfx
        imports the leaf PFX files into My (only the leaf). The caller has already passed the Windows scan.
    #>
    param(
        [Parameter(Mandatory)]$Opened, [Parameter(Mandatory)][string]$Destination,
        [switch]$InstallLeafPfx, [string]$PfxPassword = 'Abc12345!'
    )
    $cas = foreach ($c in @($Opened.Manifest['certificateAuthorities'])) {
        [ordered]@{
            id = $c['id']; kind = $c['kind']; commonName = $c['commonName']; sha1 = $c['sha1']; externallySigned = [bool]$c['externallySigned']
            certificate = (Join-Path $Destination (([string]$c['file']) -replace '/', [System.IO.Path]::DirectorySeparatorChar))
        }
    }
    $leaves = @()
    if ($InstallLeafPfx) {
        $leaves = @(foreach ($l in @($Opened.Manifest['leaves'])) {
            if (-not $l['pfx']) { continue }
            $pfx = Join-Path (Join-Path (Join-Path $Destination 'leafcerts') (([string]$l['folder']) -replace '/', [System.IO.Path]::DirectorySeparatorChar)) ([string]$l['pfx'])
            if (Test-Path -LiteralPath $pfx) { [ordered]@{ name = [string]$l['stem']; pfx = $pfx; sha1 = [string]$l['sha1'] } }
        })
        Write-PkiLog "Leaf PFX files to import into My (leaf only): $($leaves.Count)"
    }
    Initialize-PkiMinimalContext -PkiRoot $Destination -Password $PfxPassword
    $manifest = [ordered]@{ certificateAuthorities = @($cas); leaves = @($leaves) }
    Install-PkiTrust -Manifest ([pscustomobject]$manifest)
}

function Remove-PkiPackageTrustWindows {
    # Removes the CA certificates of the package (by thumbprint) from LocalMachine Root and CA. Leaf PFX files in My stay.
    param([Parameter(Mandatory)]$Opened)
    Assert-PkiWindows; Assert-Administrator
    $n = 0
    foreach ($c in @($Opened.Manifest['certificateAuthorities'])) {
        foreach ($store in 'Root', 'CA') {
            if (Test-PkiCertificateInStore -Thumbprint ([string]$c['sha1']) -Store $store) {
                if (Remove-PkiCertificateFromStore -Thumbprint ([string]$c['sha1']) -Store $store) { $n++; Write-PkiLog "  removed from $store : $($c['commonName'])" 'OK' }
                else { Write-PkiLog "  could not remove from $store : $($c['commonName'])" 'WARN' }
            }
        }
    }
    Write-PkiLog "$n certificate(s) removed from the Windows stores." 'OK'
}

function Write-PkiTransportKit {
    <#
    .SYNOPSIS
        Copies what a destination needs next to a package: the three transport scripts, the shared modules the
        destination uses, and the manual. The kit does not need the rest of the project.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$KitDirectory)
    Ensure-PkiDirectory -Path $KitDirectory
    $scripts = Join-Path $KitDirectory 'scripts'
    Ensure-PkiDirectory -Path $scripts
    $top = 'PkiTransport.ps1', 'Unpack-PkiTransport.ps1', 'pki-transport.sh', 'Install-DevEnvironment.ps1', 'Install-DevEnvironment.sh', 'PkiTransport-MANUAL.txt', 'Install-DevEnvironment-MANUAL.txt'
    foreach ($f in $top) {
        # the shell scripts are in <root>/linux/; the kit is flat
        $src = @((Join-Path $Root $f), (Join-Path (Join-Path $Root 'linux') $f)) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if ($src) { Copy-Item -LiteralPath $src -Destination $KitDirectory -Force }
    }
    foreach ($f in 'PkiModules.ps1', '00_Common.ps1', '02_OpenSSL.ps1', '07_TrustStore.ps1', '09_Administrator.ps1', '16_CertPack.ps1', '17_Transport.ps1') {
        $src = Join-Path (Join-Path $Root 'scripts') $f
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $scripts -Force } else { throw "Kit: $src is missing." }
    }
    $sh = Join-Path $KitDirectory 'pki-transport.sh'
    if (Test-Path -LiteralPath $sh) { try { if (-not $IsWindows) { & chmod +x $sh } } catch { } }
    return @(Get-ChildItem -LiteralPath $KitDirectory -Recurse -File | ForEach-Object { $_.FullName.Substring($KitDirectory.TrimEnd('\', '/').Length).TrimStart('\', '/') })
}

function Test-PkiPackageChains {
    <#
    .SYNOPSIS
        Proves with OpenSSL 4 that every CA (and every extracted leaf) of the package chains to the roots of the package.
        ML-DSA signatures need OpenSSL 4: this is what the destination OpenSSL is for.
    #>
    param([Parameter(Mandatory)]$Opened, [Parameter(Mandatory)][string]$Destination, [Parameter(Mandatory)][string]$OpenSslExe)
    $script:Pki.OpenSslExe = $OpenSslExe
    $roots = Join-Path $Destination 'ca/ca-bundle-roots.crt'; $all = Join-Path $Destination 'ca/ca-bundle-all.crt'
    if (-not (Test-Path -LiteralPath $roots) -or -not (Test-Path -LiteralPath $all)) { Write-PkiLog 'The CA bundles were not extracted: the chain check is skipped.' 'WARN'; return $true }
    $ok = 0; $bad = [System.Collections.Generic.List[string]]::new()
    $targets = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($c in @($Opened.Manifest['certificateAuthorities'])) { [void]$targets.Add(@{ Name = [string]$c['commonName']; Path = (Join-Path $Destination (([string]$c['file']) -replace '/', [System.IO.Path]::DirectorySeparatorChar)) }) }
    foreach ($f in @($Opened.Manifest['files'])) {
        if ($f['role'] -ne 'leaf') { continue }
        $p = [string]$f['path']
        if ($p -match '\.crt$' -and $p -notmatch '-(full)?chain\.crt$') {
            $full = Join-Path $Destination ($p -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (Test-Path -LiteralPath $full) { [void]$targets.Add(@{ Name = $p; Path = $full }) }
        }
    }
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t.Path)) { [void]$bad.Add("$($t.Name): file missing"); continue }
        $r = Invoke-OpenSSL -AllowFailure -Arguments @('verify', '-CAfile', $roots, '-untrusted', $all, $t.Path)
        if ($r.ExitCode -eq 0) { $ok++ } else { [void]$bad.Add("$($t.Name): $((($r.StdErr + $r.StdOut) -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1))") }
    }
    if ($bad.Count -eq 0) { Write-PkiLog "$(if (Get-Variable -Name PkiDestOpenSslText -Scope Script -ErrorAction SilentlyContinue) { $script:PkiDestOpenSslText } else { 'OpenSSL' }): all $ok certificate(s) chain to the roots of the package." 'OK'; return $true }
    Write-PkiLog "$($bad.Count) of $($targets.Count) certificate(s) do NOT chain to the roots of the package:" 'ERROR'
    foreach ($b in $bad) { Write-PkiLog "  $b" 'ERROR' }
    return $false
}


function Install-PkiOpenSsl {
    <#
    .SYNOPSIS
        Installs OpenSSL 4 (FIPS and quantum-safe, proven) with the bootstrap script: Install-DevEnvironment.ps1 on Windows
        (-Only OpenSSL, elevated), Install-DevEnvironment.sh elsewhere (--yes --only openssl). Returns $true when the bootstrap
        reports success; the caller scans again.
    #>
    if ($IsWindows) {
        $ide = Find-PkiCompanionScript -Name 'Install-DevEnvironment.ps1'
        if (-not $ide) { Write-PkiLog 'Install-DevEnvironment.ps1 was not found next to the scripts. Copy it here (the -Kit has it) and run it:  .\Install-DevEnvironment.ps1 -Only OpenSSL' 'WARN'; return $false }
        Assert-Administrator
        Write-PkiLog "Installing OpenSSL 4 with $ide (FireDaemon OpenSSL: FIPS + quantum-safe, then proven)" 'INFO'
        & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File $ide -Only OpenSSL | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        return ($LASTEXITCODE -eq 0)
    }
    $sh = Find-PkiCompanionScript -Name 'Install-DevEnvironment.sh'
    if (-not $sh) { Write-PkiLog 'Install-DevEnvironment.sh was not found next to the scripts (the -Kit has it).' 'WARN'; return $false }
    Write-PkiLog "Installing OpenSSL 4 with $sh (a FULL build: FIPS + ML-DSA / ML-KEM; minutes on several cores, over an hour on one)" 'INFO'
    & bash $sh --yes --only openssl | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    return ($LASTEXITCODE -eq 0)
}

function Confirm-PkiInstall {
    # Asks (when a person is there) whether to install what is missing.
    param([Parameter(Mandatory)][string]$Question)
    if ([Console]::IsInputRedirected -or -not [Environment]::UserInteractive) { return $false }
    return ((Read-Host "$Question [y/N]") -match '^(y|yes)$')
}
