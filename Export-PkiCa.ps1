# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Takes the root and intermediate CA certificates out of the PKI (or out of the chain of a leaf certificate) and writes them in many
    formats, with hash files, and with file names ready for Cloudflare, Azure, CloudFront, Alibaba, Google Cloud and Akamai.
    Full help: .\Export-PkiCa.ps1 -Help     Manual: docs\Export-PkiCa-MANUAL.txt
.EXAMPLE
    .\Export-PkiCa.ps1
.EXAMPLE
    .\Export-PkiCa.ps1 -Ca q1-ov -WithPath -Target Cloudflare,AzureCdn
.EXAMPLE
    .\Export-PkiCa.ps1 -Leaf .\www.example.com-fullchain.crt -Target All
#>
param(
    # which company's PKI (default: agantra; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    # ---- what to take ----
    [string[]]$Ca = @('Roots'),
    [switch]$WithPath,
    [switch]$BothVariants,
    # ---- or: the chain of a leaf certificate ----
    [string]$Leaf,
    [string]$LeafKey,
    [string]$LeafPassword = '',
    [string[]]$ChainFile,
    [switch]$FetchAia,
    [switch]$NoPki,
    # ---- how to write it ----
    [ValidateSet('PEM', 'CRT', 'CER', 'DER', 'P7B', 'TXT', 'ALL')][string[]]$Format = @('ALL'),
    [ValidateSet('Cloudflare', 'AzureCdn', 'CloudFront', 'AlibabaCdn', 'GoogleCdn', 'Akamai', 'All', 'None')][string[]]$Target = @('Cloudflare'),
    [ValidateSet('All', 'Auto', 'sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-384', 'sha3-512', 'None')][string[]]$Hash = @('All'),
    [switch]$IncludeKey,
    [string]$KeyPassword,
    [string]$OutFolder,
    [switch]$List,
    [switch]$Force,
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

function Show-ExportPkiCaHelp {
    @'
====================================================================================================
 Export-PkiCa.ps1 - take CA certificates out of the PKI, ready for a CDN, a proxy or a load balancer
 Version 6.4.1
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 Manual : docs\Export-PkiCa-MANUAL.txt
 Design : docs\PKI-Design-with-FIPS-and-PQC.txt (decisions 10.150 - 10.152)
 Needs  : PowerShell 7+, OpenSSL 4.x. Works on Windows 11 24H2+, Windows Server 2022 / 2025, Linux.

WHAT IT IS FOR (in plain words)
  A CDN, a reverse proxy or a load balancer sits between the visitor and your server. When it
  talks to YOUR server (or checks a client certificate), it must know which certificate
  authority (CA) to trust. A public service knows DigiCert or Let's Encrypt, but it does not
  know your private PKI. This script gives you the CA certificates of your PKI in the files
  and formats that those services ask for, so they will trust certificates from your PKI.

  It only writes PUBLIC certificates. Private keys are NOT written, unless you ask (-IncludeKey).

WHERE THE FILES GO
  <script folder>\transport\ca-export_<pki>_<what>_<nokey|withkey>_<targets>_<date-time>\
  Example:  ca-export_pki-default-01_roots_nokey_cloudflare_20261017-113000
  A folder is never overwritten: every run makes a new one.

  Inside, every CA has its own sub-folder with its own files:
     01_enterprise-root_agantra-root-g1\
         agantra-root-g1.pem  .crt  .cer  .der  .p7b  .txt        the certificate in many formats
         agantra-root-g1.sha256  .sha384  .sha512                 the hashes of those files
         agantra-root-g1.cloudflare.pem  .cloudflare.crt           for Cloudflare (one per -Target)
  and at the top: README.txt, export-info.json, ca-bundle.pem (all CAs in one file) and
  ca-bundle.<target>.pem, and SHA256SUMS / SHA384SUMS / SHA512SUMS of every file.

WHICH CAs  (-Ca, default Roots)
  -Ca Roots              every root: the Enterprise Root, the Track roots and the Quadrant roots
  -Ca EnterpriseRoot     only the Enterprise Root       -Ca TrackRoots   Classic and Quantum track roots
  -Ca QuadrantRoots      the Q1..Q4 roots               -Ca Intermediates  all DV / OV / EV CAs
  -Ca Classic | Quantum  every CA of that track         -Ca All          every CA
  -Ca Q1                 the Q1 root and its DV, OV, EV intermediates (Q1..Q4)
  -Ca DV | OV | EV       those intermediates of every quadrant
  -Ca q1-ov              one CA by its id (see -List); several are allowed: -Ca q1-root,q1-ov
  -WithPath              also add every parent up to the Enterprise Root, each with its own files.
                         Example: -Ca q1-ov -WithPath  = Enterprise Root, Classic Root, Q1 Root, Q1
                         OV.
  -BothVariants          do it for the normal PKI (with CRL / OCSP in its CA certificates) AND the
                         NoCR PKI (without them). Without it, one PKI is used: see
                         -NoCaRevocationInfo.
  -List                  show the CAs you can choose (id, kind, key, validity) and stop.

HOW  (-Format, -Hash)
  -Format <list>         PEM CRT CER DER P7B TXT ALL (default ALL).
                           PEM / CRT  text with BEGIN CERTIFICATE (Linux, nginx, most clouds)
                           CER / DER  binary (Windows, Azure, Java)       P7B  PKCS#7 (Windows, IIS)
                           TXT        the certificate in readable form (openssl x509 -text)
  -Hash <list>           All (default) = sha256, sha384, sha512. Also: sha3-256 sha3-384 sha3-512,
                         None, and Auto = ONE hash that matches the key: sha512 for RSA-8192, ECDSA
                         P-521 and ML-DSA-87; sha384 for RSA-4096, P-384, ML-DSA-65; else sha256.
                         Each hash file has the lines "<hash>  <file>": sha256sum -c name.sha256

CDN AND CLOUD FILES  (-Target, default Cloudflare)
  -Target <list>         Cloudflare  AzureCdn  CloudFront  AlibabaCdn  GoogleCdn  Akamai  All  None
  For each target a copy of every certificate is written with the target in the name:
     <name>.cloudflare.pem  <name>.cloudflare.crt        <name>.azure.pem  .azure.crt  .azure.cer
     <name>.cloudfront.pem  <name>.alibaba.pem  <name>.google.pem  <name>.akamai.pem (+ .crt)
  Each is ONE certificate in PEM, with LF line ends and nothing before BEGIN: what the web forms
  of those services accept. The README.txt of the export says where each service wants the file.
  WARNINGS you get on the screen: a post-quantum (ML-DSA) CA is NOT accepted by CDNs and public
  clouds today (they take RSA and ECDSA) - use the Classic CAs for them; an RSA-8192 CA may be too
  big for some services (many limit RSA to 4096) - use the Q1 Root or an intermediate;
  an expired CA; a certificate that is not a CA.

THE KEY  (-IncludeKey)
  Default: no key. -IncludeKey adds, for each CA that has its key on this computer:
     <name>.key.pem   the key, ENCRYPTED (PKCS#8, AES-256)       <name>.pfx   key + certificate + chain
  -KeyPassword <text>    the password. Not given: one is made for you and shown ONCE on the screen.
  The Enterprise Root key needs -Force as well. A DevKit has no root keys: they are skipped.
  Keep such a folder like a safe: whoever has a CA key can issue certificates your clients trust.

START FROM A LEAF CERTIFICATE  (-Leaf)
  Helper for a customer who has a certificate and asks "which CA files do I give the CDN?".
  -Leaf <file>           the leaf certificate: .pem .crt .cer .der, a full chain file, .p7b, or
                         .pfx/.p12
  -LeafKey <file>        optional private key of the leaf: checked that it belongs to the leaf
  -LeafPassword <text>   password of the .pfx and/or of an encrypted key
  -ChainFile <list>      extra files with intermediate / root certificates to look in
  -FetchAia              download missing intermediates from the "CA Issuers" address inside the
                         certificate (needs the network; off by default)
  -NoPki                 do not look for issuers in this project's own PKI
  The script follows the chain leaf -> intermediate(s) -> root, takes each CA out in all formats
  (with -Target and -Hash as above), and writes the leaf too (certificate only; with -IncludeKey and
  -LeafKey also an encrypted .pfx). It works for your private PKI and for a public CA alike.
  If an issuer is missing it says which one, so you can add it with -ChainFile or -FetchAia.

OTHER OPTIONS
  -OutFolder <path>      where the export folders go (default: <script folder>\transport)
  -Pki <name>            which company's PKI (default agantra). -Release <n>, -NoCaRevocationInfo
                         (the NoCR PKI), -PkiRoot <folder>, -OpenSslPath, -ConfigFile: as in
                         pki_setup.ps1
  -Unblock               unblock and unlock the script folder, then stop      -Verbose  more detail
  -Help                  this text

EXAMPLES
  .\Export-PkiCa.ps1                                    all roots, all formats, Cloudflare names, `
        no key
  .\Export-PkiCa.ps1 -List                              see the ids you can use
  .\Export-PkiCa.ps1 -Ca EnterpriseRoot                 only the Enterprise Root
  .\Export-PkiCa.ps1 -Ca q1-ov -WithPath -Target Cloudflare,AzureCdn,CloudFront
  .\Export-PkiCa.ps1 -Ca Classic -Target All -Hash Auto
  .\Export-PkiCa.ps1 -Ca Roots -BothVariants            normal and NoCR PKI
  .\Export-PkiCa.ps1 -Ca q1-ov -WithPath -IncludeKey    with encrypted keys (password shown once)
  .\Export-PkiCa.ps1 -Leaf .\www.example.com-fullchain.crt -Target All
  .\Export-PkiCa.ps1 -Leaf .\shop.pfx -LeafPassword 'Abc12345!' -FetchAia -NoPki
EXIT CODES   0 ok   1 error (the message says why)   2 nothing to export (the selection is empty)
====================================================================================================
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

if ($Help) { Invoke-PagedHelp { Show-ExportPkiCaHelp }; exit 0 }

# Where may this script run? (same gate as the other tools)
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 1 }
. $__pf; Assert-PkiPlatform

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

function Invoke-PkiExportOne {
    # One export folder for one PKI folder (or for one leaf chain). Returns the folder path.
    param([Parameter(Mandatory)][string]$FolderName, [Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][string]$Where,
          [object[]]$Targets, [string[]]$HashChoice, [string[]]$Fmt, [bool]$WithKeys, [string]$Pw, [string]$Root, [hashtable]$Facts)
    # $Items: objects with Info (certificate facts), Label (kind), Slug, Cn, KeyFile (or '')
    $out = Join-Path $Root $FolderName
    $n = 2; while (Test-Path -LiteralPath $out) { $out = Join-Path $Root ("$FolderName-$n"); $n++ }
    [void](New-Item -ItemType Directory -Path $out -Force)
    $all = [System.Collections.Generic.List[string]]::new()
    $bundle = [System.Text.StringBuilder]::new()
    $bundleTarget = @{}; foreach ($t in $Targets) { $bundleTarget[$t.Tag] = [System.Text.StringBuilder]::new() }
    $warnings = [System.Collections.Generic.List[string]]::new()
    $summary = [System.Collections.Generic.List[object]]::new()
    $idx = 0
    foreach ($it in $Items) {
        $idx++
        $info = $it.Info
        $dirName = '{0:00}_{1}_{2}' -f $idx, $it.Label, $it.Slug
        $dir = Join-Path $out $dirName
        [void](New-Item -ItemType Directory -Path $dir -Force)
        $hashes = Get-PkiHashChoice -Hash $HashChoice -KeyLabel $info.KeyLabel
        $files = [System.Collections.Generic.List[string]]::new()
        foreach ($f in (Write-PkiCaFiles -Info $info -Directory $dir -Name $it.Slug -Format $Fmt -HashAlgorithm $hashes)) { [void]$files.Add($f) }
        if (@($Targets).Count -gt 0) {
            foreach ($f in (Write-PkiTargetFiles -Info $info -Directory $dir -Name $it.Slug -Target $Targets -HashAlgorithm $hashes)) { [void]$files.Add($f) }
            $tn = if (@($Targets).Count -eq 1) { @($Targets)[0].Name } else { 'these services' }
            foreach ($w in (Test-PkiCaForTarget -Info $info -TargetName $tn)) { if (-not $warnings.Contains($w)) { [void]$warnings.Add($w) } }
        }
        else { foreach ($w in (Test-PkiCaForTarget -Info $info -TargetName 'a CDN or cloud')) { if (-not $warnings.Contains($w)) { [void]$warnings.Add($w) } } }
        $keyNote = 'no key'
        if ($WithKeys) {
            if ($it.KeyFile) {
                $chainPem = (@($Items | Where-Object { $_.Slug -ne $it.Slug } | ForEach-Object { $_.Info.Pem }) -join '')
                foreach ($f in (Write-PkiProtectedKey -KeyFile $it.KeyFile -CertPem $info.Pem -ChainPem $chainPem -Directory $dir -Name $it.Slug -Password $Pw -KeyPassword '')) { [void]$files.Add($f) }
                $keyNote = 'key included (encrypted)'
            }
            else { $keyNote = 'key not on this computer'; Write-PkiLog "$($info.Cn): the private key is not on this computer: only the certificate is exported." 'WARN' }
        }
        [void]$bundle.Append($info.Pem)
        foreach ($t in $Targets) { [void]$bundleTarget[$t.Tag].Append($info.Pem) }
        foreach ($f in $files) { [void]$all.Add((Join-Path $dirName $f)) }
        [void]$summary.Add([ordered]@{ folder = $dirName; id = $it.Id; kind = $it.Label; commonName = $info.Cn; key = $info.KeyLabel; notAfter = $info.NotAfter.ToString('yyyy-MM-dd'); sha256 = $info.Sha256; keyInExport = $keyNote; files = @($files) })
        Write-PkiLog ("  {0,-34} {1,-11} {2,-10} {3}" -f $info.Cn, $info.KeyLabel, $info.NotAfter.ToString('yyyy-MM-dd'), $keyNote) 'INFO'
    }
    # bundles at the top
    [System.IO.File]::WriteAllText((Join-Path $out 'ca-bundle.pem'), $bundle.ToString(), [System.Text.UTF8Encoding]::new($false)); [void]$all.Add('ca-bundle.pem')
    foreach ($t in $Targets) { $bn = "ca-bundle.$($t.Tag).pem"; [System.IO.File]::WriteAllText((Join-Path $out $bn), $bundleTarget[$t.Tag].ToString(), [System.Text.UTF8Encoding]::new($false)); [void]$all.Add($bn) }
    # README
    $r = [System.Text.StringBuilder]::new()
    [void]$r.AppendLine('CA certificates exported by Export-PkiCa.ps1 (version 6.4.1)')
    [void]$r.AppendLine("Where   : $Where")
    [void]$r.AppendLine("When    : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$r.AppendLine("Private keys: $(if ($WithKeys) { 'INCLUDED, encrypted (see the .key.pem and .pfx files). Keep this folder like a safe.' } else { 'NOT included. Everything in this folder is public information.' })")
    [void]$r.AppendLine('')
    [void]$r.AppendLine('FOLDERS')
    foreach ($s in $summary) { [void]$r.AppendLine(("  {0}   {1}  ({2}, valid until {3})" -f $s.folder, $s.commonName, $s.key, $s.notAfter)) }
    [void]$r.AppendLine('')
    [void]$r.AppendLine('FILES IN EVERY SUB-FOLDER')
    [void]$r.AppendLine('  <name>.pem .crt   text certificate (-----BEGIN CERTIFICATE-----)   <name>.cer .der   binary certificate')
    [void]$r.AppendLine('  <name>.p7b        PKCS#7 (Windows)     <name>.txt   readable form     <name>.sha256 .sha384 .sha512   hashes (sha256sum -c)')
    if (@($Targets).Count -gt 0) {
        [void]$r.AppendLine('')
        [void]$r.AppendLine('FOR THE CDN / CLOUD  (file name: <name>.<target>.pem / .crt; ca-bundle.<target>.pem has all CAs in one file)')
        foreach ($t in $Targets) {
            [void]$r.AppendLine("  $($t.Name)   (*.$($t.Tag).pem, *.$($t.Tag).crt$(if ($t.Extra -contains 'cer') { ', *.' + $t.Tag + '.cer' }))")
            [void]$r.AppendLine("      Where : $($t.Where)")
        }
        [void]$r.AppendLine('  Menu names change from time to time: read the current documentation of the service. Upload the ROOT CA, and the intermediate CA')
        [void]$r.AppendLine('  too when your server sends only its own (leaf) certificate.')
    }
    if ($warnings.Count -gt 0) { [void]$r.AppendLine(''); [void]$r.AppendLine('WARNINGS'); foreach ($w in $warnings) { [void]$r.AppendLine("  - $w") } }
    [System.IO.File]::WriteAllText((Join-Path $out 'README.txt'), $r.ToString(), [System.Text.UTF8Encoding]::new($false)); [void]$all.Add('README.txt')
    # info + sums of everything
    $info = [ordered]@{ tool = 'Export-PkiCa.ps1 6.4.1'; created = (Get-Date).ToString('o'); where = $Where; privateKeys = $WithKeys; targets = @($Targets | ForEach-Object { $_.Tag }); certificates = @($summary) }
    if ($Facts) { foreach ($k in $Facts.Keys) { $info[$k] = $Facts[$k] } }
    [System.IO.File]::WriteAllText((Join-Path $out 'export-info.json'), ($info | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false)); [void]$all.Add('export-info.json')
    $sumAlgs = @($HashChoice | Where-Object { $_ -in 'All', 'sha256', 'sha384', 'sha512' } | ForEach-Object { if ($_ -eq 'All') { 'sha256', 'sha384', 'sha512' } else { $_ } } | Select-Object -Unique)
    if (@($HashChoice) -contains 'Auto') { $sumAlgs = @('sha256') }
    foreach ($a in $sumAlgs) {
        $lines = foreach ($f in ($all | Where-Object { $_ -notmatch '\.(sha256|sha384|sha512)$' -and $_ -notmatch '\.(key\.pem|pfx)$' })) { '{0}  {1}' -f (Get-PkiFileHashHex -Path (Join-Path $out $f) -Algorithm $a), ($f -replace '\\', '/') }
        [System.IO.File]::WriteAllText((Join-Path $out ($a.ToUpperInvariant() + 'SUMS')), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }
    foreach ($w in $warnings) { Write-PkiLog $w 'WARN' }
    return $out
}

try {
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    $c = $script:Pki
    if ($Unblock) { [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot)); exit 0 }
    Initialize-OpenSSL
    $transportRoot = if ($OutFolder) { $OutFolder } else { Join-Path $script:ScriptRoot 'transport' }
    $targets = @(Get-PkiExportTargets -Name $Target)

    # ---- the password of the keys ----
    $pw = ''
    if ($IncludeKey) {
        if ($KeyPassword) { $pw = $KeyPassword } else { $pw = New-PkiRandomPassword }
        if ($pw.Length -lt 12) { throw '-KeyPassword must have at least 12 characters.' }
        Write-PkiLog 'The private keys will be written ENCRYPTED. Keep the folder like a safe.' 'WARN'
        if (-not $KeyPassword) { Write-Host ''; Write-Host "  PASSWORD of the keys (shown once, write it down): $pw" -ForegroundColor Yellow; Write-Host '' }
    }

    # =========================== from a LEAF certificate ===========================
    if ($Leaf) {
        $leafCerts = @(Read-PkiCertificatesFromFile -Path $Leaf -Password $LeafPassword)
        if ($leafCerts.Count -eq 0) { throw "No certificate found in $Leaf." }
        $leafInfo = @($leafCerts | Where-Object { -not $_.IsCa }) | Select-Object -First 1
        if (-not $leafInfo) { $leafInfo = $leafCerts[0]; Write-PkiLog 'The file has no end-entity certificate: the first certificate is used as the leaf.' 'WARN' }
        Write-PkiLog "Leaf: $($leafInfo.Cn)  (issuer: $($leafInfo.Issuer))" 'INFO'
        $keyFile = ''
        if ($LeafKey) {
            if (-not (Test-PkiKeyMatchesCertificate -KeyFile $LeafKey -CertPem $leafInfo.Pem -KeyPassword $LeafPassword)) { throw "The private key $LeafKey does NOT belong to the certificate $Leaf. Nothing was written." }
            Write-PkiLog 'The private key belongs to the leaf certificate.' 'OK'
            $keyFile = $LeafKey
        }
        # the pool: the same file, -ChainFile, the PKI of this project
        $pool = [System.Collections.Generic.List[object]]::new()
        foreach ($x in $leafCerts) { if ($x.Sha256 -ne $leafInfo.Sha256) { [void]$pool.Add($x) } }
        foreach ($cf in @($ChainFile | Where-Object { $_ })) { foreach ($x in (Read-PkiCertificatesFromFile -Path $cf -Password $LeafPassword)) { [void]$pool.Add($x) } }
        if (-not $NoPki) {
            try {
                foreach ($e in (Get-PkiExportCaList -PkiRoot $c.PkiRoot)) { foreach ($x in (Read-PkiCertificatesFromFile -Path $e.Certificate)) { [void]$pool.Add($x) } }
                Write-PkiLog "Issuers are also looked for in the PKI: $($c.PkiRoot)" 'INFO'
            }
            catch { Write-PkiLog 'No PKI of this project to look in (-NoPki, or none built here).' 'INFO' }
        }
        $res = Resolve-PkiChain -Leaf $leafInfo -Pool @($pool) -FetchAia:$FetchAia
        if (-not $res.Complete) {
            Write-PkiLog "The chain is NOT complete. Missing issuer: $($res.Missing)" 'WARN'
            Write-PkiLog '  Add the file with -ChainFile <file>, or use -FetchAia to download it from the address inside the certificate.' 'WARN'
        }
        if (@($res.Chain).Count -eq 0) { Write-PkiLog 'No CA certificate was found for this leaf.' 'ERROR'; exit 2 }
        # order: root first
        $ordered = @($res.Chain); [array]::Reverse($ordered)
        $items = [System.Collections.Generic.List[object]]::new()
        $n = 0
        foreach ($x in $ordered) {
            $n++
            $label = if ($x.SelfSigned) { 'root' } else { 'intermediate' }
            [void]$items.Add([pscustomobject]@{ Info = $x; Label = $label; Slug = (ConvertTo-PkiExportName $x.Cn); Id = ''; KeyFile = '' })
        }
        $leafSlug = ConvertTo-PkiExportName $leafInfo.Cn
        $folder = New-PkiExportFolderName -Where "leaf-$leafSlug" -What 'chain' -WithKey ([bool]($IncludeKey -and $keyFile)) -TargetTags @($targets | ForEach-Object { $_.Tag })
        Write-PkiLog "Chain: $(@($items | ForEach-Object { $_.Info.Cn }) -join '  >  ')  >  $($leafInfo.Cn)" 'INFO'
        Write-PkiLog ("  {0,-34} {1,-11} {2,-10} {3}" -f 'CA', 'KEY', 'VALID TO', 'KEY FILE') 'INFO'
        $fmt = @($Format)
        $out = Invoke-PkiExportOne -FolderName $folder -Items @($items) -Where "chain of the leaf certificate '$($leafInfo.Cn)' ($Leaf)" -Targets $targets -HashChoice $Hash -Fmt $fmt `
            -WithKeys $false -Pw '' -Root $transportRoot -Facts @{ leaf = $leafInfo.Cn; leafSha256 = $leafInfo.Sha256; chainComplete = [bool]$res.Complete }
        # the leaf itself
        $ld = Join-Path $out ('00_leaf_' + $leafSlug); [void](New-Item -ItemType Directory -Path $ld -Force)
        $lhash = Get-PkiHashChoice -Hash $Hash -KeyLabel $leafInfo.KeyLabel
        [void](Write-PkiCaFiles -Info $leafInfo -Directory $ld -Name $leafSlug -Format $fmt -HashAlgorithm $lhash)
        if ($IncludeKey -and $keyFile) {
            $chainPem = (@($ordered | ForEach-Object { $_.Pem }) -join '')
            [void](Write-PkiProtectedKey -KeyFile $keyFile -CertPem $leafInfo.Pem -ChainPem $chainPem -Directory $ld -Name $leafSlug -Password $pw -KeyPassword $LeafPassword)
            Write-PkiLog 'The leaf key was written ENCRYPTED (.key.pem and .pfx).' 'WARN'
        }
        elseif ($IncludeKey) { Write-PkiLog '-IncludeKey: no -LeafKey given, so there is no key to include.' 'INFO' }
        Write-PkiLog "Done. Folder: $out" 'OK'
        exit 0
    }

    # =========================== from the PKI of this project ===========================
    $roots = @($c.PkiRoot)
    if ($BothVariants) {
        $fi = Get-PkiFolderInfo -Path $c.PkiRoot
        $prof = if ($fi) { $fi.Profile } else { 'agantra' }
        $all = @(Get-PkiInstalledPkis -ScriptRoot $script:ScriptRoot -Profile $prof)
        $pick = foreach ($nocr in @($false, $true)) {
            $fam = @($all | Where-Object { $_.NoCr -eq $nocr })
            if ($Release -gt 0) { $fam = @($fam | Where-Object { $_.Release -eq $Release }) }
            $fam | Sort-Object Release -Descending | Select-Object -First 1
        }
        $roots = @($pick | Where-Object { $_ } | ForEach-Object { $_.Path })
        if ($roots.Count -eq 0) { throw 'No PKI folder found for -BothVariants.' }
    }
    $exported = 0
    foreach ($pr in $roots) {
        $caList = @(Get-PkiExportCaList -PkiRoot $pr)
        if ($List) {
            Write-Host ''; Write-Host "CAs in $pr" -ForegroundColor Cyan
            Write-Host ('{0,-14} {1,-13} {2,-9} {3,-11} {4,-9} {5}' -f 'ID', 'KIND', 'QUADRANT', 'KEY', 'KEY HERE', 'COMMON NAME')
            foreach ($e in $caList) { Write-Host ('{0,-14} {1,-13} {2,-9} {3,-11} {4,-9} {5}' -f $e.Id, $e.Kind, $(if ($e.Quadrant -gt 0) { "Q$($e.Quadrant)" } else { '-' }), $e.KeyAlgorithm, $(if ($e.KeyFile) { 'yes' } else { 'no' }), $e.CommonName) }
            continue
        }
        $sel = @(Select-PkiExportCa -All $caList -Ca $Ca -WithPath:$WithPath)
        if ($sel.Count -eq 0) { Write-PkiLog "Nothing selected in $pr." 'WARN'; continue }
        $items = foreach ($e in $sel) {
            $label = switch ($e.Kind) { 'root' { 'enterprise-root' } 'track' { 'track-root' } 'quadrant' { 'quadrant-root' } default { 'intermediate' } }
            $info = Read-PkiCertificatesFromFile -Path $e.Certificate | Select-Object -First 1
            $kf = if ($IncludeKey -and $e.KeyFile) {
                if ($e.Kind -eq 'root' -and -not $Force) { Write-PkiLog "The Enterprise Root key is NOT exported without -Force." 'WARN'; '' } else { $e.KeyFile }
            } else { '' }
            [pscustomobject]@{ Info = $info; Label = $label; Slug = $e.Slug; Id = $e.Id; KeyFile = $kf }
        }
        $pkiName = Split-Path -Leaf $pr
        $what = if (@($Ca).Count -eq 1) { $Ca[0] } else { 'selection' }; if ($WithPath) { $what += '-path' }
        $folder = New-PkiExportFolderName -Where $pkiName -What $what -WithKey ([bool]$IncludeKey) -TargetTags @($targets | ForEach-Object { $_.Tag })
        Write-PkiLog "Exporting $(@($items).Count) CA certificate(s) of $pkiName ..." 'INFO'
        Write-PkiLog ("  {0,-34} {1,-11} {2,-10} {3}" -f 'CA', 'KEY', 'VALID TO', 'KEY FILE') 'INFO'
        $out = Invoke-PkiExportOne -FolderName $folder -Items @($items) -Where "PKI folder $pr" -Targets $targets -HashChoice $Hash -Fmt @($Format) -WithKeys ([bool]$IncludeKey) -Pw $pw -Root $transportRoot `
            -Facts @{ pkiFolder = $pkiName; selection = @($Ca); withPath = [bool]$WithPath }
        Write-PkiLog "Done. Folder: $out" 'OK'
        $exported++
    }
    if (-not $List -and $exported -eq 0) { exit 2 }
    exit 0
}
catch {
    $failure = $_
    if (-not $Verbose -and $failure.Exception -is [System.Management.Automation.RuntimeException] -and $failure.Exception.GetType().Name -eq 'RuntimeException') {
        Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red; exit 1
    }
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) { try { Write-PkiFatalError -ErrorRecord $failure } catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red } }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally { if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment } }
