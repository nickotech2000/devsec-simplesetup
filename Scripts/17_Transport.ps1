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
#               PkiTransport.ps1 -Install         Windows 11 24H2 or newer, Windows Server 2025 / 2022: scan, unpack, install the trust
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
#   (7.9.1, several PKIs: ca\roots\<folder>-<slug>.crt ..., ca\publish\<folder>\, pki\<folder>\ - the -Pack default)
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
#            7.9.1 (several PKIs in one package, the strict replace): Resolve-PkiPackPkis, Select-PkiCaTree,
#            Get-PkiMultiPackagePlan, Get-PkiPackagePkiList, Get-PkiTaggedManifest, Select-PkiPackageContent,
#            Write-PkiPackagePkiTable, Read-PkiTrustLedger, Update-PkiTrustLedger, Get-PkiOldTrustPlan, Remove-PkiOldTrustWindows
# Requires : 00_Common, 02_OpenSSL, 07_TrustStore, 09_Administrator, 16_CertPack
#            (packing also 01 - 04, 12, 13: the 'Library' set)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiPackageExtension = '.certpacked'
$script:PkiMinWindowsBuild = 26100                  # Windows 11 24H2 / Windows Server 2025 (5.0.0; before: 25H2). Windows Server 2022 (20348) is allowed too: classic only
$script:PkiMinWindowsName = 'Windows 11 24H2'
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
        Is this machine a supported destination for installing the trust? Windows 11 24H2 (build 26100) or newer, Windows Server 2025, or Windows Server 2022
        (classic certificates only). Windows 10 and older, Windows 11 before 24H2, Windows Server before 2022: not supported.
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
        $reason = "$old (and every Windows before Windows 11 24H2 / Windows Server 2022) is not supported."
    }
    elseif ($i.ProductType -ne 1) {
        # Windows Server (Server 2022 build 20348 = classic certificates only; Server 2025 = everything). The edition rules are in scripts\00a_Platform.ps1.
        if ($i.Build -lt 20348) { $reason = "Windows Server before 2022 (build $($i.Build)) is not supported." }
        elseif ($i.Build -ge 22000 -and $i.Build -lt $script:PkiMinWindowsBuild) { $reason = "This Windows Server build ($($i.Build)) is not supported: Windows Server 2022 (RTM) or Windows Server 2025 (build 26100 or newer)." }
    }
    elseif ($i.Build -lt 22000) { $reason = "Windows 10 (build $($i.Build)) is not supported." }
    elseif ($i.Build -lt $script:PkiMinWindowsBuild) { $reason = "Windows 11 before 24H2 (build $($i.Build)) is not supported. Update to Windows 11 24H2 (build $($script:PkiMinWindowsBuild)) or newer." }
    $name = if (-not $i.IsWindows) { $i.Caption }
            elseif ($i.Build -ge 22000) { "Windows 11 $(if ($i.DisplayVersion) { $i.DisplayVersion } else { 'build ' + $i.Build })" }
            elseif ($i.Major -ge 10) { 'Windows 10' } else { "Windows $($i.Major).$($i.Minor)" }
    return [ordered]@{
        Supported = ($reason -eq ''); Reason = $reason; Name = $name; Caption = $i.Caption; Build = $i.Build; Ubr = $i.Ubr
        DisplayVersion = $i.DisplayVersion; ProductType = $i.ProductType; IsWindows = $i.IsWindows
        Required = "$($script:PkiMinWindowsName) (build $($script:PkiMinWindowsBuild)) or newer, Windows Server 2025, or Windows Server 2022 (classic certificates only)"
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
        [string[]]$LeafName = @(), [Parameter(Mandatory)][string]$Staging, [bool]$IssuingKeysOnly = $false
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
        & $add $paths.Crt $rel $(if ($isRoot) { 'root' } else { 'intermediate' }) @{ Kind = $ca.Kind; Sha1 = [string]$b['sha1']; Name = [string]$b['commonName']; Store = $(if ($ext) { 'CA' } elseif ($isRoot) { 'Root' } else { 'CA' }); ExternallySigned = $ext; Id = [string]$ca.Id; Parent = [string]$ca.Parent }
        [void]$allPem.Append((& $pemOf $paths.Crt))
        if ($isRoot) { [void]$rootsPem.Append((& $pemOf $paths.Crt)) }
        [void]$caList.Add([ordered]@{
            id = $ca.Id; kind = $ca.Kind; commonName = [string]$b['commonName']; track = $ca.Track; quadrant = $ca.Quadrant; fips = [bool]$ca.Fips
            validation = $ca.Validation; keyAlgorithm = [string]$b['keyAlgorithm']; slug = $ca.Slug; notAfter = [string]$b['notAfter']
            sha1 = [string]$b['sha1']; sha256 = [string]$b['sha256']; externallySigned = $ext; file = $rel
            store = $(if ($ext) { 'CA' } elseif ($isRoot) { 'Root' } else { 'CA' }); parent = [string]$ca.Parent
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
        # -IssuingKeysOnly (DevKit): private keys only inside the folders of the INTERMEDIATE (issuing) CAs. No root, track-root,
        # quadrant-root, OCSP, TSA or old leaf key, and no .pfx/.p12 (they hold keys too). Certificates, CRLs, databases stay.
        $issuingDirs = [System.Collections.Generic.List[string]]::new()
        if ($IssuingKeysOnly) {
            foreach ($ca in $c.Catalog) {
                if ($ca.Kind -in 'root', 'track', 'quadrant') { continue }
                [void]$issuingDirs.Add(([System.IO.Path]::GetFullPath((Split-Path -Parent (Get-PkiCaPaths -Ca $ca).Crt))).TrimEnd('\', '/'))
            }
        }
        $isSecret = { param($f) ($f.Extension -in '.key', '.pfx', '.p12', '.p8', '.pk8') -or ($f.Name -match '(?i)private|\.key\.') }
        foreach ($f in Get-ChildItem -LiteralPath $c.PkiRoot -Recurse -File -Force | Where-Object { $_.Extension -notin '.tmp' -and $_.Name -notlike '*.untrusted.tmp' -and $_.Name -ne 'telemetry.json' }) {
            if ($IssuingKeysOnly -and (& $isSecret $f)) {
                $dir = [System.IO.Path]::GetFullPath($f.DirectoryName).TrimEnd('\', '/')
                $inIssuing = $f.Extension -in '.key' -and ($issuingDirs -contains $dir)
                if (-not $inIssuing) { continue }
            }
            elseif ($IssuingKeysOnly -and $f.Extension -eq '.pem' -and ((Get-Content -LiteralPath $f.FullName -TotalCount 40 -ErrorAction SilentlyContinue) -match 'PRIVATE KEY')) { continue }
            $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
            & $add $f.FullName "pki/$rel" 'pki' $null
        }
    }
    return [ordered]@{ Entries = $entries; Staging = $Staging; CaList = $caList; Leaves = $leaves }
}

# ------------------------------------------------------------
# SOURCE (7.9.1): several PKIs in ONE package - every company, every release, chosen by parameters
# ------------------------------------------------------------
function Resolve-PkiPackPkis {
    <#
    .SYNOPSIS
        Which PKI folders go into a -Pack package. Default (no parameter): EVERY PKI folder in .\pki\ - every company, every
        release, normal and NoCR. The parameters narrow it down:
          -Pki <names or <name>_pki.cnf files>   only these companies
          -Release <n,...>                       only these release numbers        -NoCr   only the NoCR family
          -Latest                                only the latest release of each company
          -PkiRoot <folders>                     exactly these PKI folders (the others are not used)
    .OUTPUTS
        objects: Path, Folder (unique name, used in the package paths), Profile, Release, NoCr, Label
    #>
    param([Parameter(Mandatory)][string]$ScriptRoot, [string[]]$Pki = @(), [int[]]$Release = @(), [switch]$NoCr, [switch]$Latest, [string[]]$PkiRoot = @())
    $out = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $addOne = {
        param([string]$Path)
        $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        if ($seen.ContainsKey($full)) { return }
        if (-not (Test-Path -LiteralPath (Join-Path $full 'pki-manifest.json') -PathType Leaf)) { throw "No PKI in $full (pki-manifest.json is missing). Build it with pki_setup.ps1, or leave it out." }
        $fi = Get-PkiFolderInfo -Path $full
        $prof = if ($null -ne $fi) { [string]$fi.Profile } else { 'agantra' }
        $rel = if ($null -ne $fi) { [int]$fi.Release } else { 1 }
        $nocr = ($null -ne $fi -and [bool]$fi.NoCr)
        $folder = Split-Path -Leaf $full
        if ($folder -notmatch '^pki-[a-z][a-z0-9]*-(nocr-)?\d{2,}$') { $folder = Get-PkiFolderName -NoCr $nocr -Release $rel -Profile $prof }   # old layouts (pki\, R1, NoCR-R1): a unique, readable name
        foreach ($o in $out) { if ($o.Folder -eq $folder) { throw "Two PKI folders would have the same name in the package ($folder): $($o.Path) and $full. Pack them separately." } }
        $seen[$full] = $true
        [void]$out.Add([pscustomobject]@{ Path = $full; Folder = $folder; Profile = $prof; Release = $rel; NoCr = $nocr; Label = "$prof $(if ($nocr) { 'NoCR ' })R$rel" })
    }
    if (@($PkiRoot | Where-Object { $_ }).Count -gt 0) {
        foreach ($p in @($PkiRoot | Where-Object { $_ })) { & $addOne $p }
        return @($out)
    }
    # the companies: a short name (agantra) or a configuration file (D:\cfg\raksaka_pki.cnf): the name comes from the file name
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @($Pki | Where-Object { $_ })) {
        $n = $n.Trim()
        if ($n -match '\.cnf$' -or $n -match '[\\/]') {
            if (-not (Test-Path -LiteralPath $n -PathType Leaf)) { throw "-Pki: the configuration file $n does not exist." }
            $leaf = [System.IO.Path]::GetFileName($n).ToLowerInvariant()
            if ($leaf -notmatch '^(?<n>[a-z][a-z0-9]*)_pki\.cnf$') { throw "-Pki: $n is not a PKI configuration file (the name must be <name>_pki.cnf, like agantra_pki.cnf)." }
            $n = $Matches['n']
        }
        if ($names -notcontains $n.ToLowerInvariant()) { [void]$names.Add($n.ToLowerInvariant()) }
    }
    $all = @(Get-PkiInstalledPkis -ScriptRoot $ScriptRoot)
    $all = @($all | Where-Object { Test-Path -LiteralPath (Join-Path $_.Path 'pki-manifest.json') -PathType Leaf })
    if ($names.Count -gt 0) {
        foreach ($n in $names) {
            if (@($all | Where-Object { $_.Profile -eq $n }).Count -eq 0) {
                $known = @($all | ForEach-Object { $_.Profile } | Select-Object -Unique)
                throw "No PKI is built for '$n'. PKIs found here: $(if ($known.Count) { $known -join ', ' } else { '(none)' }). Build it: .\pki_setup.ps1 -Pki $n"
            }
        }
        $all = @($all | Where-Object { $names -contains $_.Profile })
    }
    if ($NoCr) { $all = @($all | Where-Object { $_.NoCr }) }
    if (@($Release | Where-Object { $_ -gt 0 }).Count -gt 0) {
        $want = @($Release | Where-Object { $_ -gt 0 })
        foreach ($r in $want) { if (@($all | Where-Object { $_.Release -eq $r }).Count -eq 0) { Write-PkiLog "Release R$r was not found$(if ($names.Count) { ' for ' + ($names -join ', ') })$(if ($NoCr) { ' (NoCR)' }): left out." 'WARN' } }
        $all = @($all | Where-Object { $want -contains $_.Release })
    }
    if ($Latest) {
        $keep = [System.Collections.Generic.List[object]]::new()
        foreach ($g in ($all | Group-Object Profile)) {
            $fam = @($g.Group | Where-Object { -not $_.NoCr }); if ($NoCr -or $fam.Count -eq 0) { $fam = @($g.Group) }
            [void]$keep.Add(($fam | Sort-Object Release -Descending | Select-Object -First 1))
        }
        $all = @($keep)
    }
    foreach ($i in $all) { & $addOne $i.Path }
    if ($out.Count -eq 0) { throw "No PKI matches the selection (container $(Get-PkiContainer -ScriptRoot $ScriptRoot)). List the PKIs: .\pki_setup.ps1 -ListPki" }
    return @($out)
}

function Select-PkiCaTree {
    <#
    .SYNOPSIS
        -Ca patterns -> the ids of the CAs of ONE PKI that are taken. A pattern is a CA id (q1-dv), a slug (agantra-q1-dv-g1)
        or a common name; wildcards allowed. A ROOT (Enterprise, track or quadrant root) brings every CA below it; any CA brings
        its parents up to the Enterprise Root (a chain must be complete). No pattern = every CA.
        -Chosen: only the CAs that match and the CAs below a matching root, WITHOUT the parents (whose private keys may be packed).
    #>
    param([Parameter(Mandatory)][object[]]$Cas, [string[]]$Filter = @(), [switch]$Chosen)
    $ids = [System.Collections.Generic.List[string]]::new()
    $byId = @{}; foreach ($c in $Cas) { $byId[[string]$c['id']] = $c }
    $pats = @($Filter | Where-Object { $_ } | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($pats.Count -eq 0) { foreach ($c in $Cas) { [void]$ids.Add([string]$c['id']) }; return @($ids) }
    $addUp = { param($c) $x = $c; $guard = 0; while ($null -ne $x -and $guard -lt 20) { $i = [string]$x['id']; if (-not $ids.Contains($i)) { [void]$ids.Add($i) }; $p = [string]$x['parent']; $x = if ($p -and $byId.ContainsKey($p)) { $byId[$p] } else { $null }; $guard++ } }
    $addDown = $null
    $addDown = { param([string]$Id) foreach ($c in $Cas) { if ([string]$c['parent'] -eq $Id) { $i = [string]$c['id']; if (-not $ids.Contains($i)) { [void]$ids.Add($i) }; & $addDown $i } } }
    foreach ($c in $Cas) {
        $hit = $false
        foreach ($p in $pats) { foreach ($v in @([string]$c['id'], [string]$c['slug'], [string]$c['commonName'])) { if ($v -and $v -like $p) { $hit = $true } } }
        if (-not $hit) { continue }
        if ($Chosen) { $i = [string]$c['id']; if (-not $ids.Contains($i)) { [void]$ids.Add($i) } } else { & $addUp $c }
        if ([string]$c['kind'] -in 'root', 'track', 'quadrant') { & $addDown ([string]$c['id']) }
    }
    return @($ids)
}

function Get-PkiFolderCaFile {
    # The certificate file of a CA of a PKI folder: the path of pki-manifest.json moved into the folder (the folder may have been copied), else publish\<slug>.crt.
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)]$Ca)
    $cands = [System.Collections.Generic.List[string]]::new()
    $cert = [string]$Ca['certificate']
    if ($cert) {
        $norm = $cert -replace '\\', '/'
        $m = [regex]::Match($norm, '/' + [regex]::Escape((Split-Path -Leaf $Folder)) + '/(?<rest>.+)$')
        if ($m.Success) { [void]$cands.Add((Join-Path $Folder ($m.Groups['rest'].Value -replace '/', [System.IO.Path]::DirectorySeparatorChar))) }
        [void]$cands.Add($cert)
    }
    if ($Ca['slug']) { [void]$cands.Add((Join-Path (Join-Path $Folder 'publish') "$($Ca['slug']).crt")) }
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c } }
    throw "The certificate of '$($Ca['commonName'])' was not found in $Folder."
}

function Get-PkiMultiPackagePlan {
    <#
    .SYNOPSIS
        What a package of SEVERAL PKIs holds (7.9.1). Read from the pki-manifest.json of every PKI folder; no configuration needed.
        Paths: ca/roots/<folder>-<slug>.crt  ca/intermediates/<folder>-<slug>.crt  ca/chains/<folder>-<slug>-fullchain.crt
               ca/publish/<folder>/...  ca/external/<folder>-external-chain.pem  ca/cross-sign/<folder>-<file>  pki/<folder>/... (keys)
        Every entry carries the company (pki) and the PKI folder (release) it belongs to.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Pkis, [string[]]$CaFilter = @(), [Parameter(Mandatory)][string]$Staging,
        [bool]$IncludeCaKeys = $false, [bool]$IssuingKeysOnly = $false, [bool]$IncludeLeafCerts = $false, [string[]]$LeafName = @(), [string]$LeafRoot
    )
    Ensure-PkiDirectory -Path $Staging
    $entries = [System.Collections.Generic.List[hashtable]]::new()
    $add = { param($src, $name, $role, $extra) $h = @{ Source = $src; Entry = ($name -replace '\\', '/'); Role = $role }; if ($extra) { foreach ($k in $extra.Keys) { $h[$k] = $extra[$k] } }; [void]$entries.Add($h) }
    $caList = [System.Collections.Generic.List[object]]::new(); $pkiList = [System.Collections.Generic.List[object]]::new()
    $rootsPem = [System.Text.StringBuilder]::new(); $allPem = [System.Text.StringBuilder]::new()
    $pemOf = { param($f) ([System.IO.File]::ReadAllText($f)).TrimEnd() + "`n" }
    $restricted = (@($CaFilter | Where-Object { $_ }).Count -gt 0)
    foreach ($pk in $Pkis) {
        $man = Get-Content -LiteralPath (Join-Path $pk.Path 'pki-manifest.json') -Raw | ConvertFrom-Json -AsHashtable
        $cas = @($man['certificateAuthorities'])
        if ($cas.Count -eq 0) { throw "No CA certificate is listed in $(Join-Path $pk.Path 'pki-manifest.json')." }
        $ids = @(Select-PkiCaTree -Cas $cas -Filter $CaFilter)
        $keyIds = @(Select-PkiCaTree -Cas $cas -Filter $CaFilter -Chosen)      # private keys: never of a parent that is only there for the chain
        if ($ids.Count -eq 0) { Write-PkiLog "$($pk.Label): no CA matches -Ca $($CaFilter -join ','); this PKI is left out." 'INFO'; continue }
        $tag = @{ Pki = $pk.Profile; Release = $pk.Folder }
        $byId = @{}; foreach ($c in $cas) { $byId[[string]$c['id']] = $c }
        $fileOf = @{}; $caDirs = @{}; $slugs = @{}; $allSlugs = @{}
        foreach ($c in $cas) { if ($c['slug']) { $allSlugs[[string]$c['slug']] = $true } }
        foreach ($c in $cas) {
            $id = [string]$c['id']; if ($ids -notcontains $id) { continue }
            $src = Get-PkiFolderCaFile -Folder $pk.Path -Ca $c
            $fileOf[$id] = $src
            $kind = [string]$c['kind']; $isRoot = $kind -in 'root', 'track', 'quadrant'
            $ext = ($c.ContainsKey('externallySigned') -and [bool]$c['externallySigned'])
            $slug = if ($c['slug']) { [string]$c['slug'] } else { $id }
            $slugs[$slug] = $true
            if ($keyIds -contains $id) { $caDirs[([System.IO.Path]::GetFullPath((Split-Path -Parent $src))).TrimEnd('\', '/')] = @{ Id = $id; IsRoot = $isRoot } }
            $rel = "ca/$(if ($isRoot) { 'roots' } else { 'intermediates' })/$($pk.Folder)-$slug.crt"
            $store = if ($ext) { 'CA' } elseif ($isRoot) { 'Root' } else { 'CA' }
            & $add $src $rel $(if ($isRoot) { 'root' } else { 'intermediate' }) @{ Kind = $kind; Sha1 = [string]$c['sha1']; Name = [string]$c['commonName']; Store = $store; ExternallySigned = $ext; Pki = $pk.Profile; Release = $pk.Folder; Id = $id; Parent = [string]$c['parent'] }
            [void]$allPem.Append((& $pemOf $src)); if ($isRoot) { [void]$rootsPem.Append((& $pemOf $src)) }
            [void]$caList.Add([ordered]@{
                id = $id; kind = $kind; commonName = [string]$c['commonName']; track = $c['track']; quadrant = $c['quadrant']; fips = [bool]$c['fips']
                validation = $c['validation']; keyAlgorithm = [string]$c['keyAlgorithm']; slug = $slug; notAfter = [string]$c['notAfter']
                sha1 = [string]$c['sha1']; sha256 = [string]$c['sha256']; externallySigned = $ext; file = $rel; store = $store
                parent = [string]$c['parent']; pki = $pk.Profile; release = $pk.Folder
            })
        }
        # one fullchain file per intermediate: it + its parents up to the Enterprise Root
        foreach ($c in $cas) {
            $id = [string]$c['id']; if ($ids -notcontains $id) { continue }
            if ([string]$c['kind'] -in 'root', 'track', 'quadrant') { continue }
            $sb = [System.Text.StringBuilder]::new(); $x = $c; $guard = 0
            while ($null -ne $x -and $guard -lt 20) { $xi = [string]$x['id']; if ($fileOf.ContainsKey($xi)) { [void]$sb.Append((& $pemOf $fileOf[$xi])) }; $p = [string]$x['parent']; $x = if ($p -and $byId.ContainsKey($p)) { $byId[$p] } else { $null }; $guard++ }
            $slug = if ($c['slug']) { [string]$c['slug'] } else { $id }
            $f = Join-Path $Staging "$($pk.Folder)-$slug-fullchain.crt"
            Write-Utf8NoBom -Path $f -Content $sb.ToString()
            & $add $f "ca/chains/$($pk.Folder)-$slug-fullchain.crt" 'chain' $tag
        }
        # the public CA chain and cross-certificates (if the Enterprise Root was signed / cross-signed by a public CA), the CRLs and published files
        $rootDir = Join-Path $pk.Path 'root'
        if (Test-Path -LiteralPath (Join-Path $rootDir 'external-chain.pem')) { & $add (Join-Path $rootDir 'external-chain.pem') "ca/external/$($pk.Folder)-external-chain.pem" 'external' $tag }
        $cross = Join-Path $rootDir 'cross-sign'
        if (Test-Path -LiteralPath $cross) { foreach ($f in Get-ChildItem -LiteralPath $cross -File -Filter 'root-cross-*' | Where-Object { $_.Extension -in '.crt', '.pem' }) { & $add $f.FullName "ca/cross-sign/$($pk.Folder)-$($f.Name)" 'cross' $tag } }
        $pub = Join-Path $pk.Path 'publish'
        if (Test-Path -LiteralPath $pub) {
            foreach ($f in Get-ChildItem -LiteralPath $pub -File) {
                if ($restricted) { $stem = ($f.Name -split '\.')[0]; if ($allSlugs.ContainsKey($stem) -and -not $slugs.ContainsKey($stem)) { continue } }     # the files of a CA that was not chosen stay out
                & $add $f.FullName "ca/publish/$($pk.Folder)/$($f.Name)" 'publish' $tag
            }
        }
        # the PKI folder with the CA private keys
        $keys = 0
        if ($IncludeCaKeys) {
            $root = $pk.Path.TrimEnd('\', '/')
            $isSecret = { param($f) ($f.Extension -in '.key', '.pfx', '.p12', '.p8', '.pk8') -or ($f.Name -match '(?i)private|\.key\.') }
            foreach ($f in Get-ChildItem -LiteralPath $pk.Path -Recurse -File -Force | Where-Object { $_.Extension -notin '.tmp' -and $_.Name -notlike '*.untrusted.tmp' -and $_.Name -ne 'telemetry.json' }) {
                if (($IssuingKeysOnly -or $restricted) -and (& $isSecret $f)) {
                    # only the key of a CHOSEN CA, in its own folder (<id>.key; -IssuingKeysOnly: intermediates only, and only the .key)
                    $dir = [System.IO.Path]::GetFullPath($f.DirectoryName).TrimEnd('\', '/')
                    if (-not $caDirs.ContainsKey($dir)) { continue }
                    $owner = $caDirs[$dir]
                    if ($f.BaseName -ne $owner.Id) { continue }
                    if ($IssuingKeysOnly -and ($owner.IsRoot -or $f.Extension -ne '.key')) { continue }
                    if ($f.Extension -notin '.key', '.pfx') { continue }
                    $keys++
                }
                elseif (($IssuingKeysOnly -or $restricted) -and $f.Extension -eq '.pem' -and ((Get-Content -LiteralPath $f.FullName -TotalCount 40 -ErrorAction SilentlyContinue) -match 'PRIVATE KEY')) { continue }
                elseif (& $isSecret $f) { $keys++ }
                $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/')
                & $add $f.FullName "pki/$($pk.Folder)/$rel" 'pki' $tag
            }
        }
        [void]$pkiList.Add([ordered]@{ pki = $pk.Profile; release = $pk.Folder; releaseNumber = [int]$pk.Release; noCr = [bool]$pk.NoCr; label = $pk.Label; caCertificates = $ids.Count; privateKeys = $keys; sourcePath = $pk.Path })
    }
    if ($caList.Count -eq 0) { throw "No CA matches -Ca $($CaFilter -join ', '). See the CAs of a PKI with: .\PkiTransport.ps1 -Pack -ListCa" }
    $f = Join-Path $Staging 'ca-bundle-roots.crt'; Write-Utf8NoBom -Path $f -Content $rootsPem.ToString(); & $add $f 'ca/ca-bundle-roots.crt' 'bundle-roots' $null
    $f = Join-Path $Staging 'ca-bundle-all.crt';   Write-Utf8NoBom -Path $f -Content $allPem.ToString();   & $add $f 'ca/ca-bundle-all.crt' 'bundle' $null

    # leafcerts (one folder for the project, as for one PKI)
    $leaves = [System.Collections.Generic.List[object]]::new()
    if ($IncludeLeafCerts) {
        if (-not (Test-Path -LiteralPath $LeafRoot -PathType Container)) { throw "-IncludeLeafCerts: the leaf folder does not exist: $LeafRoot" }
        $tops = @(Get-ChildItem -LiteralPath $LeafRoot -Directory)
        if (@($LeafName).Count -gt 0) { $tops = @($tops | Where-Object { $n = $_.Name; @($LeafName | Where-Object { $n -like $_ }).Count -gt 0 }) }
        if ($tops.Count -eq 0) { throw "-IncludeLeafCerts: no leaf folder in $LeafRoot$(if (@($LeafName).Count) { " matches $($LeafName -join ', ')" })." }
        foreach ($t in $tops) { foreach ($f in Get-ChildItem -LiteralPath $t.FullName -Recurse -File) { & $add $f.FullName ("leafcerts/" + $f.FullName.Substring($LeafRoot.TrimEnd('\', '/').Length).TrimStart('\', '/')) 'leaf' $null } }
        $idxPath = Join-Path $LeafRoot 'leaf-index.json'
        if (Test-Path -LiteralPath $idxPath) {
            $topNames = @($tops | ForEach-Object { $_.Name })
            foreach ($e in @(Get-Content -LiteralPath $idxPath -Raw | ConvertFrom-Json -AsHashtable)) { if ($topNames -contains (([string]$e['folder']) -split '[\\/]')[0]) { [void]$leaves.Add($e) } }
            $f = Join-Path $Staging 'leaf-index.json'; Write-Utf8NoBom -Path $f -Content (ConvertTo-Json -InputObject @($leaves) -Depth 6)
            & $add $f 'leafcerts/leaf-index.json' 'leaf-index' $null
        }
    }
    return [ordered]@{ Entries = $entries; Staging = $Staging; CaList = $caList; Leaves = $leaves; Pkis = $pkiList }
}

function New-PkiCertPackage {
    <#
    .SYNOPSIS
        Builds the .certpacked file. Returns @{ Path; Format; Encryption; Files; Bytes; Scope }.
    #>
    param(
        [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$Password,
        [ValidateSet('zip', '7z')][string]$ArchiveFormat = 'zip', [ValidateSet('Aes256', 'ZipCrypto')][string]$ZipEncryption = 'Aes256',
        [bool]$IncludeLeafCerts = $false, [bool]$IncludeCaKeys = $false, [bool]$IssuingKeysOnly = $false, [string[]]$LeafName = @(), [string]$LeafRoot,
        [string]$Comment = '', [string]$SevenZipPath, [switch]$NoVerify,
        # 7.9.1: several PKIs (Resolve-PkiPackPkis) and the -Ca choice. Without -Pkis: the ONE PKI of the configuration (DevKit)
        [object[]]$Pkis, [string[]]$CaFilter = @(), [hashtable]$Selection
    )
    $c = $script:Pki
    $multi = ($null -ne $Pkis -and @($Pkis).Count -gt 0)
    $staging = Join-Path ([System.IO.Path]::GetTempPath()) "certpacked-$([guid]::NewGuid().ToString('N'))"
    try {
        if ($multi) {
            $plan = Get-PkiMultiPackagePlan -Pkis $Pkis -CaFilter $CaFilter -Staging (Join-Path $staging 'gen') -IncludeCaKeys $IncludeCaKeys -IssuingKeysOnly $IssuingKeysOnly `
                -IncludeLeafCerts $IncludeLeafCerts -LeafName $LeafName -LeafRoot $LeafRoot
            $pkiList = @($plan.Pkis)
        }
        else {
            $plan = Get-PkiPackagePlan -LeafRoot $LeafRoot -IncludeLeafCerts $IncludeLeafCerts -IncludeCaKeys $IncludeCaKeys -IssuingKeysOnly $IssuingKeysOnly -LeafName $LeafName -Staging (Join-Path $staging 'gen')
            # 7.9.1: the one PKI carries its company and folder too, so the destination can replace an older copy of exactly this PKI
            $oneProf = if ($c.Contains('Profile') -and $c.Profile) { ([string]$c.Profile).ToLowerInvariant() } else { 'agantra' }
            $oneFolder = Split-Path -Leaf ($c.PkiRoot.TrimEnd('\', '/'))
            foreach ($e in $plan.Entries) { if ($e.Role -notin 'bundle', 'bundle-roots', 'leaf', 'leaf-index') { $e['Pki'] = $oneProf; $e['Release'] = $oneFolder } }
            foreach ($ca in $plan.CaList) { $ca['pki'] = $oneProf; $ca['release'] = $oneFolder }
            $pkiList = @([ordered]@{ pki = $oneProf; release = $oneFolder; releaseNumber = [int]$c.Release; noCr = [bool]$c.NoCaRevocationInfo; label = "$oneProf $(if ($c.NoCaRevocationInfo) { 'NoCR ' })R$([int]$c.Release)"; caCertificates = @($plan.CaList).Count; privateKeys = $(if ($IncludeCaKeys) { -1 } else { 0 }); sourcePath = $c.PkiRoot })
        }
        $entries = $plan.Entries
        # de-duplicate by entry name
        $seen = @{}; $uniq = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($e in $entries) { if (-not $seen.ContainsKey($e.Entry)) { $seen[$e.Entry] = $true; [void]$uniq.Add($e) } }
        $entries = $uniq

        $files = foreach ($e in $entries) {
            $fe = [ordered]@{ path = $e.Entry; sha256 = (Get-PkiFileSha256 -Path $e.Source); size = ([System.IO.FileInfo]::new($e.Source)).Length; role = $e.Role }
            if ($e.ContainsKey('Pki') -and $e.Pki) { $fe['pki'] = $e.Pki; $fe['release'] = $e.Release }
            $fe
        }
        $scope = [ordered]@{ caCertificates = $true; leafcerts = $IncludeLeafCerts; caPrivateKeys = $IncludeCaKeys; issuingKeysOnly = ($IncludeCaKeys -and $IssuingKeysOnly); multiPki = (@($pkiList).Count -gt 1) }
        if ($null -ne $Selection) { $scope['selection'] = $Selection }
        $manifest = [ordered]@{
            format = 'agantra-certpacked'; formatVersion = 1
            createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "PkiTransport.ps1 $($script:PkiGeneratorVersion)"
            comment = $Comment
            source = [ordered]@{ machine = [Environment]::MachineName; os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription; pkiRoot = $(if ($multi) { '' } else { $c.PkiRoot }) }
            archive = [ordered]@{ format = $ArchiveFormat; encryption = $(if ($ArchiveFormat -eq '7z') { 'AES-256, headers encrypted' } elseif ($ZipEncryption -eq 'Aes256') { 'AES-256 (WinZip AE-2)' } else { 'ZipCrypto (legacy, weak)' }) }
            scope = $scope
            mode = $(if ($multi) { 'MultiPKI' } elseif ($c.ClassicPki) { 'ClassicPKI' } else { 'Full' }); quadrants = @($(if (-not $multi) { $c.Quadrants }))
            pkis = @($pkiList)
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
        [void]$tsv.Append("# role`tpath`tsha256`tsize`tsha1`tstore`texternallySigned`tkind`tname`tpki`trelease`tid`tparent`n")
        foreach ($e in $entries) {
            $f = $files | Where-Object { $_.path -eq $e.Entry } | Select-Object -First 1
            $sha1 = if ($e.ContainsKey('Sha1')) { $e.Sha1 } else { '' }
            $store = if ($e.ContainsKey('Store')) { $e.Store } else { '' }
            $extS = if ($e.ContainsKey('ExternallySigned') -and $e.ExternallySigned) { '1' } else { '0' }
            $nm = if ($e.ContainsKey('Name')) { $e.Name } else { '' }
            $kd = if ($e.ContainsKey('Kind')) { $e.Kind } else { '' }
            $pkT = if ($e.ContainsKey('Pki')) { $e.Pki } else { '' }; $relT = if ($e.ContainsKey('Release')) { $e.Release } else { '' }
            $idT = if ($e.ContainsKey('Id')) { $e.Id } else { '' }; $parT = if ($e.ContainsKey('Parent')) { $e.Parent } else { '' }
            [void]$tsv.Append("$($e.Role)`t$($e.Entry)`t$($f.sha256)`t$($f.size)`t$sha1`t$store`t$extS`t$kd`t$nm`t$pkT`t$relT`t$idT`t$parT`n")
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
Scope   : CA certificates$(if ($IncludeLeafCerts) { ', LEAF CERTIFICATES (with private keys)' })$(if ($IncludeCaKeys -and $IssuingKeysOnly) { ', the PKI folder with the PRIVATE KEYS OF THE ISSUING (intermediate) CAs only - no root key' } elseif ($IncludeCaKeys) { ', the whole PKI with the CA PRIVATE KEYS' })
PKIs    : $((@($pkiList) | ForEach-Object { "$($_.label) ($($_.release), $($_.caCertificates) CA)" }) -join ', ')
$(if ($Comment) { "Comment : $Comment`n" })
This file is a password-protected archive. Rename it to .zip or .7z and open it with 7-Zip, or use:
  Windows 11 24H2+ / Server 2025 / 2022   PkiTransport.ps1 -Install -Package <file>      (unpacks and installs the trust)
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
    # where each unpacked PKI folder came from: pki\ (one PKI, before 7.9.1 and the DevKit) or pki\<folder>\ (7.9.1: several PKIs)
    $moves = [System.Collections.Generic.List[object]]::new()
    $multiDirs = @(@($Opened.Manifest['pkis']) | Where-Object { $_ -and $_.Contains('sourcePath') -and $_['sourcePath'] -and (Test-Path -LiteralPath (Join-Path (Join-Path $Destination 'pki') ([string]$_['release'])) -PathType Container) })
    if (@($Opened.Manifest['files'] | Where-Object { ([string]$_['path']) -like 'pki/pki-manifest.json' }).Count -gt 0) { [void]$moves.Add(@([string]$Opened.Manifest['source']['pkiRoot'], (Join-Path $Destination 'pki'))) }
    else { foreach ($p in $multiDirs) { [void]$moves.Add(@([string]$p['sourcePath'], (Join-Path (Join-Path $Destination 'pki') ([string]$p['release'])))) } }
    foreach ($mv in $moves) { Update-PkiUnpackedPkiPaths -OldRoot $mv[0] -PkiDest $mv[1] }
    [void](Unblock-PkiTree -Path @($Destination)); [void](Unlock-PkiTree -Path @($Destination))
    return @($written)
}

function Update-PkiUnpackedPkiPaths {
    # An unpacked PKI folder: the absolute paths of the machine it came from (pki-manifest.json, the CA configuration files, the notes) are rewritten to the new place.
    param([string]$OldRoot, [Parameter(Mandatory)][string]$PkiDest)
    if (-not $OldRoot -or -not (Test-Path -LiteralPath $PkiDest -PathType Container)) { return }
    $pm = Join-Path $PkiDest 'pki-manifest.json'
    if (Test-Path -LiteralPath $pm) {
        $m = Get-Content -LiteralPath $pm -Raw | ConvertFrom-Json -AsHashtable
        $m2 = ConvertTo-PkiRebasedValue -Value $m -OldRoot $OldRoot -NewRoot $PkiDest
        Write-Utf8NoBom -Path $pm -Content ($m2 | ConvertTo-Json -Depth 20)
    }
    # The CA configuration files (dir = <absolute path>) and the revocation notes hold the OLD pki path too: without this the
    # unpacked PKI would still read and WRITE the database of the machine it came from (or fail when that path does not exist).
    $pkiDest = $PkiDest
    if (Test-Path -LiteralPath $pkiDest -PathType Container) {
        $oldRoot = $OldRoot
        if ($oldRoot) {
            $pairs = [System.Collections.Generic.List[object]]::new()
            $oF = ($oldRoot -replace '\\', '/').TrimEnd('/'); $nF = ($pkiDest -replace '\\', '/').TrimEnd('/')
            [void]$pairs.Add(@($oF, $nF)); [void]$pairs.Add(@($oldRoot.TrimEnd('\', '/'), $pkiDest.TrimEnd('\', '/')))
            [void]$pairs.Add(@(($oldRoot.TrimEnd('\', '/') -replace '\\', '\\'), ($pkiDest.TrimEnd('\', '/') -replace '\\', '\\')))
            $nRewritten = 0
            foreach ($f in Get-ChildItem -LiteralPath $pkiDest -Recurse -File | Where-Object { $_.Extension -in '.cnf', '.txt', '.json' -and $_.Name -ne 'pki-manifest.json' -and $_.Length -lt 5MB }) {
                $t = [System.IO.File]::ReadAllText($f.FullName); $t2 = $t
                $doneOld = @{}
                foreach ($pr in $pairs) { if ($pr[0] -and -not $doneOld.ContainsKey([string]$pr[0])) { $doneOld[[string]$pr[0]] = $true; $t2 = $t2.Replace([string]$pr[0], [string]$pr[1], [StringComparison]::OrdinalIgnoreCase) } }
                if ($t2 -ne $t) { Write-Utf8NoBom -Path $f.FullName -Content $t2; $nRewritten++ }
            }
            if ($nRewritten -gt 0) { Write-PkiLog "The old PKI path ($oldRoot) was replaced by the new one in $nRewritten configuration / note file(s)." 'INFO' }
        }
    }
}

# ------------------------------------------------------------
# DESTINATION (7.9.1): the PKIs of a package, choosing some of them, and replacing an older copy of OUR PKI only
# ------------------------------------------------------------
function Get-PkiPackagePkiList {
    <#
    .SYNOPSIS
        The PKIs a package holds: @{ pki; release (the PKI folder); releaseNumber; noCr; label; caCertificates }.
        Packages of 7.9.1 list them (pkis); older ones: from the tags of the CAs, else from the source folder name, else one PKI without a name.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest)
    $out = [System.Collections.Generic.List[object]]::new()
    $cas = @($Manifest['certificateAuthorities'])
    if ($Manifest.Contains('pkis') -and @($Manifest['pkis']).Count -gt 0) {
        foreach ($p in @($Manifest['pkis'])) {
            $n = @($cas | Where-Object { [string]$_['release'] -eq [string]$p['release'] -and [string]$_['pki'] -eq [string]$p['pki'] }).Count
            $x = [ordered]@{}; foreach ($k in $p.Keys) { $x[$k] = $p[$k] }        # keeps sourcePath, privateKeys ...
            $x['pki'] = [string]$p['pki']; $x['release'] = [string]$p['release']
            $x['releaseNumber'] = $(if ($p.Contains('releaseNumber')) { [int]$p['releaseNumber'] } else { Get-PkiReleaseNumberOfFolder ([string]$p['release']) })
            $x['noCr'] = $(if ($p.Contains('noCr')) { [bool]$p['noCr'] } else { ([string]$p['release']) -match '-nocr-' })
            $x['label'] = $(if ($p['label']) { [string]$p['label'] } else { "$($p['pki']) $($p['release'])" }); $x['caCertificates'] = $n
            [void]$out.Add($x)
        }
        return @($out)
    }
    $tagged = @($cas | Where-Object { $_.Contains('release') -and $_['release'] })
    if ($tagged.Count -gt 0) {
        foreach ($g in ($tagged | Group-Object { "$($_['pki'])|$($_['release'])" })) {
            $pk, $rl = $g.Name -split '\|', 2
            [void]$out.Add([ordered]@{ pki = $pk; release = $rl; releaseNumber = (Get-PkiReleaseNumberOfFolder $rl); noCr = ($rl -match '-nocr-'); label = "$pk $rl"; caCertificates = $g.Count })
        }
        return @($out)
    }
    # a package made before 7.9.1: one PKI; its folder name (pki-default-01 ...) says which
    $src = ''; if ($Manifest.Contains('source') -and $Manifest['source'] -and $Manifest['source'].Contains('pkiRoot')) { $src = [string]$Manifest['source']['pkiRoot'] }
    $leaf = if ($src) { (($src -replace '\\', '/').TrimEnd('/') -split '/')[-1] } else { '' }
    if ($leaf -match '^pki-(?<tok>[a-z][a-z0-9]*)-(?<nocr>nocr-)?(?<rel>\d{2,})$') {
        $pk = if ($Matches['tok'] -eq 'default') { 'agantra' } else { $Matches['tok'] }
        [void]$out.Add([ordered]@{ pki = $pk; release = $leaf; releaseNumber = [int]$Matches['rel']; noCr = ($Matches['nocr'] -ne ''); label = "$pk $leaf"; caCertificates = $cas.Count })
    }
    else { [void]$out.Add([ordered]@{ pki = ''; release = ''; releaseNumber = 0; noCr = $false; label = 'one PKI (the package does not name it)'; caCertificates = $cas.Count }) }
    return @($out)
}

function Get-PkiReleaseNumberOfFolder {
    param([string]$Folder)
    if ($Folder -match '-(\d{2,})$') { return [int]$Matches[1] }
    return 0
}

function Get-PkiTaggedManifest {
    # A copy of the manifest where every CA and every file of a PKI carries pki / release (older packages: from Get-PkiPackagePkiList).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest)
    $list = @(Get-PkiPackagePkiList -Manifest $Manifest)
    $m = [ordered]@{}; foreach ($k in $Manifest.Keys) { $m[$k] = $Manifest[$k] }
    if ($list.Count -eq 1) {
        $one = $list[0]
        $m['certificateAuthorities'] = @(foreach ($c in @($Manifest['certificateAuthorities'])) { $x = [ordered]@{}; foreach ($k in $c.Keys) { $x[$k] = $c[$k] }; if (-not $x.Contains('release') -or -not $x['release']) { $x['pki'] = $one.pki; $x['release'] = $one.release }; $x })
        $m['files'] = @(foreach ($f in @($Manifest['files'])) { $x = [ordered]@{}; foreach ($k in $f.Keys) { $x[$k] = $f[$k] }; if ((-not $x.Contains('release') -or -not $x['release']) -and [string]$x['role'] -notin 'bundle', 'bundle-roots', 'leaf', 'leaf-index') { $x['pki'] = $one.pki; $x['release'] = $one.release }; $x })
    }
    $m['pkis'] = @($list)
    return $m
}

function Select-PkiPackageContent {
    <#
    .SYNOPSIS
        Narrows an opened package to some of its PKIs and CAs (-Pki <company>, -Release <n | folder>, -Ca <id | slug | name>).
        Nothing given: the whole package. Shared files (the bundles, the leaf certificates) always stay. Returns a manifest.
        -Release 2 = release 2 of each company (normal and NoCR); -Release pki-raksaka-nocr-01 = that folder (wildcards allowed).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest, [string[]]$Pki = @(), [string[]]$Release = @(), [string[]]$Ca = @())
    $m = Get-PkiTaggedManifest -Manifest $Manifest
    $pk = @($Pki | Where-Object { $_ } | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    $rl = @($Release | Where-Object { $_ } | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $caF = @($Ca | Where-Object { $_ })
    if ($pk.Count -eq 0 -and $rl.Count -eq 0 -and $caF.Count -eq 0) { return $m }
    $keepPki = @(foreach ($p in @($m['pkis'])) {
        if ($pk.Count -gt 0 -and $pk -notcontains ([string]$p['pki']).ToLowerInvariant()) { continue }
        if ($rl.Count -gt 0) {
            $hit = $false
            foreach ($r in $rl) { if ($r -match '^\d+$') { if ([int]$r -eq [int]$p['releaseNumber']) { $hit = $true } } elseif ([string]$p['release'] -like $r) { $hit = $true } }
            if (-not $hit) { continue }
        }
        $p
    })
    if ($keepPki.Count -eq 0) {
        throw ("No PKI of this package matches$(if ($pk.Count) { ' -Pki ' + ($pk -join ',') })$(if ($rl.Count) { ' -Release ' + ($rl -join ',') }). The package holds: " + ((@($m['pkis']) | ForEach-Object { "$($_['pki']) $($_['release'])" }) -join ', ') + '.')
    }
    $keyOf = { param($x) "$($x['pki'])|$($x['release'])" }
    $keepKeys = @($keepPki | ForEach-Object { & $keyOf $_ })
    $cas = @($m['certificateAuthorities'] | Where-Object { $keepKeys -contains (& $keyOf $_) })
    if ($caF.Count -gt 0) {
        $sel = [System.Collections.Generic.List[object]]::new()
        foreach ($g in ($cas | Group-Object { & $keyOf $_ })) { $ids = @(Select-PkiCaTree -Cas @($g.Group) -Filter $caF); foreach ($c in $g.Group) { if ($ids -contains [string]$c['id']) { [void]$sel.Add($c) } } }
        if ($sel.Count -eq 0) { throw "No CA of the chosen PKI(s) matches -Ca $($caF -join ', '). See them with -List." }
        $cas = @($sel)
        $keepPki = @($keepPki | Where-Object { $k = & $keyOf $_; @($cas | Where-Object { (& $keyOf $_) -eq $k }).Count -gt 0 })
        $keepKeys = @($keepPki | ForEach-Object { & $keyOf $_ })
    }
    $caFiles = @($cas | ForEach-Object { [string]$_['file'] })
    $chainNames = @($cas | ForEach-Object { $s = if ($_['slug']) { [string]$_['slug'] } else { [string]$_['id'] }; "$s-fullchain.crt"; "$($_['release'])-$s-fullchain.crt" })
    $files = @(foreach ($f in @($m['files'])) {
        $role = [string]$f['role']
        if (-not $f.Contains('release') -or -not $f['release']) { $f; continue }          # shared: bundles, leaf certificates
        if ($keepKeys -notcontains (& $keyOf $f)) { continue }
        if ($caF.Count -gt 0) {
            if ($role -in 'root', 'intermediate' -and $caFiles -notcontains [string]$f['path']) { continue }
            if ($role -eq 'chain' -and $chainNames -notcontains (([string]$f['path']) -split '/')[-1]) { continue }
        }
        $f
    })
    $m['certificateAuthorities'] = @($cas); $m['files'] = @($files); $m['pkis'] = @($keepPki)
    return $m
}

function Write-PkiPackagePkiTable {
    # -List: the PKIs of the package, then every CA with its company and PKI folder.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest)
    $m = Get-PkiTaggedManifest -Manifest $Manifest
    Write-Host ''
    Write-Host ('PKIs IN THIS PACKAGE: {0}' -f @($m['pkis']).Count) -ForegroundColor Cyan
    Write-Host ('  {0,-12} {1,-26} {2,-8} {3}' -f 'COMPANY', 'PKI FOLDER (-Release)', 'CAs', 'LABEL') -ForegroundColor Cyan
    foreach ($p in @($m['pkis'])) { Write-Host ('  {0,-12} {1,-26} {2,-8} {3}' -f $p['pki'], $p['release'], $p['caCertificates'], $p['label']) }
    Write-Host ''
    Write-Host ('{0,-12} {1,-24} {2,-12} {3,-12} {4,-11} {5}' -f 'COMPANY', 'PKI FOLDER', 'KIND', 'KEY', 'EXPIRES', 'COMMON NAME   [id]') -ForegroundColor Cyan
    foreach ($ca in @($m['certificateAuthorities'])) { Write-Host ('{0,-12} {1,-24} {2,-12} {3,-12} {4,-11} {5}   [{6}]' -f $ca['pki'], $ca['release'], $ca['kind'], $ca['keyAlgorithm'], $ca['notAfter'], $ca['commonName'], $ca['id']) }
}

# ---- the list of what WE installed (the only proof that a certificate in a store is ours) ----
function Get-PkiTrustLedgerPath {
    # PkiTransport: %ProgramData%\PkiTransport\installed.tsv (Windows) | /var/lib/pki-transport/installed.tsv. PKI_TRANSPORT_STATE_DIR moves it (tests).
    param([ValidateSet('Transport', 'TrustKit')][string]$Kind = 'Transport')
    $base = if ($env:PKI_TRANSPORT_STATE_DIR) { $env:PKI_TRANSPORT_STATE_DIR } elseif ($IsWindows) { $(if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }) } else { '/var/lib' }
    $dir = if ($Kind -eq 'Transport') { $(if ($IsWindows -or $env:PKI_TRANSPORT_STATE_DIR) { 'PkiTransport' } else { 'pki-transport' }) } else { $(if ($IsWindows -or $env:PKI_TRANSPORT_STATE_DIR) { 'PkiTrustKit' } else { 'pki-trust-kit' }) }
    return (Join-Path (Join-Path $base $dir) 'installed.tsv')
}

function Read-PkiTrustLedger {
    # Every certificate PkiTransport (and the trust kits, Machine scope) installed: @{ Pki; Release; Store; Thumbprint; Name; From }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($kind in 'Transport', 'TrustKit') {
        $p = Get-PkiTrustLedgerPath -Kind $kind
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        foreach ($l in [System.IO.File]::ReadAllLines($p)) {
            if (-not $l -or $l.StartsWith('#')) { continue }
            $c = $l.Split("`t")
            if ($c.Count -lt 4 -or $c[3] -notmatch '^[0-9A-Fa-f]{40}$') { continue }
            if ($kind -eq 'TrustKit' -and $c.Count -ge 7 -and $c[6] -and $c[6] -ne 'Machine') { continue }     # a kit installed for one user only: not in LocalMachine
            [void]$rows.Add([pscustomobject]@{ Pki = $c[0].ToLowerInvariant(); Release = $c[1]; Store = $c[2]; Thumbprint = $c[3].ToUpperInvariant(); Name = $(if ($c.Count -gt 4) { $c[4] } else { '' }); From = $kind })
        }
    }
    return @($rows)
}

function Update-PkiTrustLedger {
    # Adds the rows of the certificates installed now and drops the rows of the certificates removed now (PkiTransport list only).
    param([object[]]$Add = @(), [string[]]$RemoveThumbprints = @())
    $p = Get-PkiTrustLedgerPath -Kind 'Transport'
    $drop = @{}; foreach ($t in @($RemoveThumbprints) + @($Add | ForEach-Object { $_.Thumbprint })) { if ($t) { $drop[$t.ToUpperInvariant()] = $true } }
    $keep = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        foreach ($l in [System.IO.File]::ReadAllLines($p)) { if (-not $l -or $l.StartsWith('#')) { continue }; $c = $l.Split("`t"); if ($c.Count -ge 4 -and $drop.ContainsKey($c[3].ToUpperInvariant())) { continue }; [void]$keep.Add($l) }
    }
    $now = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')
    foreach ($a in $Add) { [void]$keep.Add((@($a.Pki, $a.Release, $a.Store, $a.Thumbprint.ToUpperInvariant(), $a.Name, '', 'Machine', $now) -join "`t")) }
    Ensure-PkiDirectory -Path (Split-Path -Parent $p)
    [System.IO.File]::WriteAllLines($p, [string[]](@("# pki`trelease`tstore`tthumbprint`tname`torganization`tscope`tinstalledUtc   (PkiTransport.ps1: the CA certificates it installed; only these are ever replaced)") + $keep))
    return $p
}

function Get-PkiOldTrustPlan {
    <#
    .SYNOPSIS
        Which certificates in the stores are an OLDER copy of a PKI of this package, and may be removed before the new one is installed.
        STRICT: a certificate is removed only when its SHA-1 thumbprint is in OUR list of installed certificates (PkiTransport,
        or a trust kit) for the SAME company AND the SAME PKI folder - or it is a certificate file of that PKI folder on this
        computer. A certificate of the package itself is never removed. A name is never enough: public CAs, other companies'
        PKIs and any other private PKI are never touched, whatever their name.
    .PARAMETER StoreCerts
        what the stores hold: @{ Store; Thumbprint; Name }
    .PARAMETER LocalThumbprints
        PKI folder name -> SHA-1 thumbprints of the certificate files of that folder on this computer (pki\<folder>)
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest, [Parameter(Mandatory)][System.Collections.IDictionary]$FullManifest,
          [object[]]$StoreCerts = @(), [object[]]$Ledger = @(), [hashtable]$LocalThumbprints = @{})
    $inPackage = @{}; foreach ($c in @($FullManifest['certificateAuthorities'])) { if ($c['sha1']) { $inPackage[([string]$c['sha1']).ToUpperInvariant()] = $true } }
    $targets = @{}
    foreach ($c in @($Manifest['certificateAuthorities'])) { if ($c['release']) { $targets["$(([string]$c['pki']).ToLowerInvariant())|$($c['release'])"] = $true } }
    $ours = @{}
    foreach ($r in $Ledger) { $k = "$($r.Pki)|$($r.Release)"; if ($r.Release -and $targets.ContainsKey($k)) { $ours[$r.Thumbprint] = [pscustomobject]@{ Pki = $r.Pki; Release = $r.Release; Why = "installed earlier ($($r.From) list)" } } }
    foreach ($k in $targets.Keys) {
        $pk, $rl = $k -split '\|', 2
        if ($LocalThumbprints.ContainsKey($rl)) { foreach ($t in $LocalThumbprints[$rl]) { $u = ([string]$t).ToUpperInvariant(); if (-not $ours.ContainsKey($u)) { $ours[$u] = [pscustomobject]@{ Pki = $pk; Release = $rl; Why = "a certificate file of pki\$rl on this computer" } } } }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $StoreCerts) {
        $t = ([string]$s.Thumbprint).ToUpperInvariant()
        if ($inPackage.ContainsKey($t)) { continue }        # the new PKI itself: kept
        if (-not $ours.ContainsKey($t)) { continue }        # not proven ours: never touched
        $o = $ours[$t]
        [void]$out.Add([pscustomobject]@{ Store = $s.Store; Thumbprint = $t; Name = $s.Name; Pki = $o.Pki; Release = $o.Release; Why = $o.Why })
    }
    return @($out)
}

function Remove-PkiOldTrustWindows {
    # Step 1 of -Install: the older copy of each PKI of the package is removed (strict, see Get-PkiOldTrustPlan). Returns the thumbprints removed.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Manifest, [Parameter(Mandatory)][System.Collections.IDictionary]$FullManifest, [string]$ScriptRoot)
    $targets = @(@($Manifest['certificateAuthorities']) | Where-Object { $_['release'] } | ForEach-Object { "$($_['pki']) $($_['release'])" } | Select-Object -Unique)
    if ($targets.Count -eq 0) { Write-PkiLog 'This package does not say which PKI it holds (made before 7.9.1 from an old layout): no older copy is removed. Remove one by hand with -RemoveTrust -Package <the older package>.' 'INFO'; return @() }
    $storeCerts = [System.Collections.Generic.List[object]]::new()
    foreach ($name in 'Root', 'CA') {
        try {
            $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
            try { foreach ($c in $st.Certificates) { [void]$storeCerts.Add([pscustomobject]@{ Store = $name; Thumbprint = $c.Thumbprint; Name = (Get-PkiCertDisplayName -Certificate $c) }) } }
            finally { $st.Close() }
        }
        catch { Write-PkiLog "LocalMachine\$name could not be read ($($_.Exception.Message.Split("`n")[0])): nothing is removed from it." 'WARN' }
    }
    $local = @{}
    if ($ScriptRoot) {
        $container = Join-Path $ScriptRoot 'pki'
        foreach ($rl in @(@($Manifest['certificateAuthorities']) | Where-Object { $_['release'] } | ForEach-Object { [string]$_['release'] } | Select-Object -Unique)) {
            $d = Join-Path $container $rl
            if (Test-Path -LiteralPath $d -PathType Container) { $local[$rl] = @(Get-PkiFolderThumbprints -Folder $d) }
        }
    }
    $plan = @(Get-PkiOldTrustPlan -Manifest $Manifest -FullManifest $FullManifest -StoreCerts @($storeCerts) -Ledger @(Read-PkiTrustLedger) -LocalThumbprints $local)
    Write-PkiLog "Replace: $($targets.Count) PKI(s) in this package ($($targets -join ', ')); $($plan.Count) older certificate(s) of exactly these PKIs found (matched by thumbprint against the list of what was installed). Public CAs and other PKIs are not touched." 'INFO'
    $removed = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $plan) {
        if (Remove-PkiCertificateFromStore -Thumbprint $p.Thumbprint -Store $p.Store) { [void]$removed.Add($p.Thumbprint); Write-PkiLog "  removed the old $($p.Store) : $($p.Name)   [$($p.Thumbprint.Substring(0, 12))...] $($p.Pki) $($p.Release), $($p.Why)" 'OK' }
        else { Write-PkiLog "  could not remove the old $($p.Store) : $($p.Name) [$($p.Thumbprint.Substring(0, 12))...]" 'WARN' }
    }
    return @($removed)
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
        7.9.1: FIRST the older copy of each PKI of the package is removed (only certificates proven ours: Get-PkiOldTrustPlan),
        THEN the new certificates are installed and written to the list of what PkiTransport installed.
    #>
    param(
        [Parameter(Mandatory)]$Opened, [Parameter(Mandatory)][string]$Destination,
        [switch]$InstallLeafPfx, [string]$PfxPassword = 'Abc12345!', [string]$ScriptRoot, [switch]$KeepOld
    )
    $fullManifest = if ($Opened.Contains('FullManifest') -and $Opened.FullManifest) { $Opened.FullManifest } else { $Opened.Manifest }
    $tagged = Get-PkiTaggedManifest -Manifest $Opened.Manifest
    $removedOld = @()
    if ($KeepOld) { Write-PkiLog '-KeepOld: older copies of these PKIs stay in the stores.' 'INFO' }
    else { $removedOld = @(Remove-PkiOldTrustWindows -Manifest $tagged -FullManifest (Get-PkiTaggedManifest -Manifest $fullManifest) -ScriptRoot $ScriptRoot) }
    # Windows Server 2022 cannot use post-quantum (ML-DSA) certificates: only the classic CAs are installed there
    $plat = if ($null -ne (Get-Variable -Name PkiPlatform -Scope Global -ErrorAction SilentlyContinue)) { $global:PkiPlatform } else { $null }
    $classicOnly = ($null -ne $plat -and [bool]$plat.ClassicOnly)
    $allCas = @($Opened.Manifest['certificateAuthorities'])
    if ($classicOnly) {
        $skip = @($allCas | Where-Object { [string]$_['track'] -eq 'Quantum' -or [string]$_['id'] -match '^(quantum-root|q[34]-)' })
        if ($skip.Count -gt 0) { Write-PkiLog "Windows Server 2022: $($skip.Count) post-quantum (ML-DSA) CA certificate(s) of the package are NOT installed (only the classic PKI is)." 'WARN' }
        $allCas = @($allCas | Where-Object { $skip -notcontains $_ })
    }
    $cas = foreach ($c in $allCas) {
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
    # remember what was installed: the next package of the same PKI replaces exactly these certificates, nothing else
    $tagOf = @{}; foreach ($c in @($tagged['certificateAuthorities'])) { if ($c['sha1']) { $tagOf[([string]$c['sha1']).ToUpperInvariant()] = $c } }
    $rows = @(foreach ($c in $allCas) {
        $t = ([string]$c['sha1']).ToUpperInvariant(); $tg = $tagOf[$t]
        if (-not $t -or $null -eq $tg -or -not $tg['release']) { continue }
        if (-not (Test-PkiCertificateInStore -Thumbprint $t -Store (Get-PkiTrustStoreOf -Entry $c))) { continue }
        [pscustomobject]@{ Pki = ([string]$tg['pki']).ToLowerInvariant(); Release = [string]$tg['release']; Store = (Get-PkiTrustStoreOf -Entry $c); Thumbprint = $t; Name = [string]$c['commonName'] }
    })
    try { $lp = Update-PkiTrustLedger -Add $rows -RemoveThumbprints $removedOld; Write-PkiLog "Remembered $($rows.Count) installed CA certificate(s) in $lp (a newer package of the same PKI replaces exactly these)." 'INFO' }
    catch { Write-PkiLog "Could not write the list of installed certificates ($($_.Exception.Message.Split("`n")[0])): the next package of this PKI cannot replace them automatically." 'WARN' }
}

function Remove-PkiPackageTrustWindows {
    # Removes the CA certificates of the package (by thumbprint) from LocalMachine Root and CA. Leaf PFX files in My stay.
    param([Parameter(Mandatory)]$Opened)
    Assert-PkiWindows; Assert-Administrator
    $n = 0; $gone = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @($Opened.Manifest['certificateAuthorities'])) {
        foreach ($store in 'Root', 'CA') {
            if (Test-PkiCertificateInStore -Thumbprint ([string]$c['sha1']) -Store $store) {
                if (Remove-PkiCertificateFromStore -Thumbprint ([string]$c['sha1']) -Store $store) { $n++; [void]$gone.Add([string]$c['sha1']); Write-PkiLog "  removed from $store : $($c['commonName'])" 'OK' }
                else { Write-PkiLog "  could not remove from $store : $($c['commonName'])" 'WARN' }
            }
        }
    }
    if ($gone.Count -gt 0) { try { [void](Update-PkiTrustLedger -RemoveThumbprints @($gone)) } catch { } }
    Write-PkiLog "$n certificate(s) removed from the Windows stores (matched by the thumbprints of the package; nothing else is touched)." 'OK'
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
    $top = 'PkiTransport.ps1', 'Unpack-PkiTransport.ps1', 'pki-transport.sh', 'Install-DevEnvironment.ps1', 'Install-DevEnvironment.sh', 'Create-WebServerConfig.ps1', 'Create-WebServerConfig.sh'
    $kitDocs = Join-Path $KitDirectory 'docs'
    foreach ($d in 'PkiTransport-MANUAL.txt', 'Install-DevEnvironment-MANUAL.txt', 'NewPkiCsr-MANUAL.txt', 'PrepareComputer-MANUAL.txt', 'Create-WebServerConfig-MANUAL.txt') {
        $dsrc = Join-Path (Join-Path $Root 'docs') $d
        if (Test-Path -LiteralPath $dsrc -PathType Leaf) { Ensure-PkiDirectory -Path $kitDocs; Copy-Item -LiteralPath $dsrc -Destination $kitDocs -Force }
    }
    foreach ($f in $top) {
        # the shell scripts are in <root>/linux/; the kit is flat
        $src = @((Join-Path $Root $f), (Join-Path (Join-Path $Root 'linux') $f)) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if ($src) { Copy-Item -LiteralPath $src -Destination $KitDirectory -Force }
    }
    # 5.2.2: the destination tools - CSR maker and OpenSSL installer (templates in trustkit\)
    foreach ($f in 'New-PkiCsr.ps1', 'Prepare-Computer.ps1', 'new-pki-csr.sh', 'prepare-computer.sh') {
        $src = Join-Path (Join-Path $Root 'trustkit') $f
        if (Test-Path -LiteralPath $src -PathType Leaf) { Copy-Item -LiteralPath $src -Destination $KitDirectory -Force } else { throw "Kit: $src is missing." }
    }
    foreach ($f in 'PkiModules.ps1', '00a_Platform.ps1', '00b_Profiles.ps1', '00_Common.ps1', '02_OpenSSL.ps1', '07_TrustStore.ps1', '09_Administrator.ps1', '16_CertPack.ps1', '17_Transport.ps1') {
        $src = Join-Path (Join-Path $Root 'scripts') $f
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $scripts -Force } else { throw "Kit: $src is missing." }
    }
    foreach ($shn in 'pki-transport.sh', 'new-pki-csr.sh', 'prepare-computer.sh', 'Create-WebServerConfig.sh') { $sh = Join-Path $KitDirectory $shn; if (Test-Path -LiteralPath $sh) { try { if (-not $IsWindows) { & chmod +x $sh } } catch { } } }
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
        & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy RemoteSigned -File $ide -Only OpenSSL | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
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
