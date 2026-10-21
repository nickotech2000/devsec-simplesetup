# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 23_CaExport.ps1  -  take CA certificates out of the PKI (or out of the chain of a leaf certificate) and
#                     write them in many formats, ready for a CDN, a proxy, a load balancer or a cloud
#
# Used by Export-PkiCa.ps1. Version 7.5.3.
#
# Provides : Get-PkiCertInfo, Read-PkiCertificatesFromFile, Resolve-PkiChain, Get-PkiExportTargets,
#            Get-PkiExportCaList, Select-PkiExportCa, Write-PkiCaFiles, Write-PkiTargetFiles,
#            New-PkiExportFolderName, Test-PkiCaForTarget, Get-PkiHashChoice
# Requires : 00_Common (Write-PkiLog, Write-PkiHashFiles), 02_OpenSSL (Invoke-OpenSSL)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# The targets (-Target). Tag = the word in the file name:  <name>.<tag>.pem   <name>.<tag>.crt
# ------------------------------------------------------------
$script:PkiExportTargetTable = [ordered]@{
    Cloudflare = @{ Tag = 'cloudflare'; Name = 'Cloudflare';                               Extra = @();      Where = 'Dashboard > SSL/TLS > Origin Server (custom origin trust store / Authenticated Origin Pulls with your own CA). One certificate per PEM file.' }
    AzureCdn   = @{ Tag = 'azure';      Name = 'Azure CDN / Front Door / Application Gateway'; Extra = @('cer'); Where = 'Trusted root certificate (Application Gateway, Front Door custom CA). Azure accepts Base-64 .cer (PEM text) or the .pem/.crt.' }
    CloudFront = @{ Tag = 'cloudfront'; Name = 'AWS CloudFront (and AWS load balancers)';  Extra = @();      Where = 'CloudFront mutual TLS: a trust store (a PEM bundle in an S3 bucket). Use the ca-bundle file of this export for several CAs.' }
    AlibabaCdn = @{ Tag = 'alibaba';    Name = 'Alibaba Cloud CDN / SLB';                  Extra = @();      Where = 'Alibaba Cloud console: CDN / Server Load Balancer > certificates > CA certificate (PEM text).' }
    GoogleCdn  = @{ Tag = 'google';     Name = 'Google Cloud CDN / Cloud Load Balancing';  Extra = @();      Where = 'Certificate Manager > TrustConfig (trust anchor / intermediate CA, PEM).' }
    Akamai     = @{ Tag = 'akamai';     Name = 'Akamai CDN';                               Extra = @();      Where = 'Property Manager / Edge: custom CA set (PEM) for origin or client certificate checks.' }
}

function Get-PkiExportTargets {
    # -Target list -> target objects (Cloudflare, AzureCdn, CloudFront, AlibabaCdn, GoogleCdn, Akamai, All, None)
    param([string[]]$Name = @('Cloudflare'))
    $names = @($Name | Where-Object { $_ })
    if ($names.Count -eq 0 -or $names -contains 'None') { return @() }
    if ($names -contains 'All') { $names = @($script:PkiExportTargetTable.Keys) }
    foreach ($n in ($names | Select-Object -Unique)) {
        $k = @($script:PkiExportTargetTable.Keys | Where-Object { $_ -ieq $n }) | Select-Object -First 1
        if (-not $k) { throw "Unknown -Target '$n'. Use: $($script:PkiExportTargetTable.Keys -join ', '), All, None." }
        $t = $script:PkiExportTargetTable[$k]
        [pscustomobject]@{ Key = $k; Tag = $t.Tag; Name = $t.Name; Extra = @($t.Extra); Where = $t.Where }
    }
}

# ------------------------------------------------------------
# Reading certificates
# ------------------------------------------------------------
function ConvertTo-PkiPemFromDerBytes {
    param([Parameter(Mandatory)][byte[]]$Der)
    $b64 = [Convert]::ToBase64String($Der)
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
    return "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
}

function Get-PkiCertInfo {
    <#
    .SYNOPSIS
        One PEM certificate -> its facts (read with OpenSSL, so ML-DSA works too).
    .OUTPUTS
        Pem, Der, Subject, Issuer, Cn, SelfSigned, IsCa, Ski, Aki, NotAfter, Expired, KeyLabel, Sha256, AiaUrls
    #>
    param([Parameter(Mandatory)][string]$Pem)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('pkicert-' + [Guid]::NewGuid().ToString('N') + '.pem')
    try {
        [System.IO.File]::WriteAllText($tmp, $Pem, [System.Text.UTF8Encoding]::new($false))
        $t = (Invoke-OpenSSL -Arguments @('x509', '-in', $tmp, '-noout', '-text', '-nameopt', 'RFC2253')).StdOut
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $m = [regex]::Match($Pem, '-----BEGIN CERTIFICATE-----(?<b>[^-]+)-----END CERTIFICATE-----')
    $der = [byte[]][Convert]::FromBase64String(($m.Groups['b'].Value -replace '\s', ''))
    $get = { param($rx) $x = [regex]::Match($t, $rx); if ($x.Success) { $x.Groups[1].Value.Trim() } else { '' } }
    $subject = & $get '(?m)^\s*Subject:\s*(.*)$'
    $issuer = & $get '(?m)^\s*Issuer:\s*(.*)$'
    $cn = ''
    $cm = [regex]::Match($subject, '(?:^|,)CN=((?:\\,|[^,])+)')
    if ($cm.Success) { $cn = ($cm.Groups[1].Value -replace '\\,', ',') } else { $cn = $subject }
    $ski = (& $get '(?s)X509v3 Subject Key Identifier:[^\n]*\n\s*([0-9A-Fa-f:]+)') -replace ':', ''
    $aki = (& $get '(?s)X509v3 Authority Key Identifier:[^\n]*\n\s*(?:keyid:)?([0-9A-Fa-f:]+)') -replace ':', ''
    $na = & $get '(?m)Not After\s*:\s*(.*)$'
    $notAfter = [DateTime]::MaxValue
    try { $notAfter = [DateTime]::ParseExact(($na -replace ' GMT', '' -replace '\s+', ' ').Trim(), 'MMM d HH:mm:ss yyyy', [Globalization.CultureInfo]::InvariantCulture) } catch { }
    $alg = & $get '(?m)Public Key Algorithm:\s*(.*)$'
    $bits = & $get '(?m)Public-Key:\s*\((\d+) bit\)'
    $curve = & $get '(?m)ASN1 OID:\s*(\S+)'
    $label = if ($alg -match 'rsa') { "RSA-$bits" } elseif ($alg -match 'ML-DSA|mldsa') { ($alg.ToUpperInvariant() -replace 'MLDSA', 'ML-DSA') } elseif ($alg -match 'ecPublicKey|EC') { 'ECDSA-' + ($curve -replace 'secp(\d+)r1', 'P$1' -replace 'prime256v1', 'P256') } else { $alg }
    $aia = @([regex]::Matches($t, 'CA Issuers - URI:(\S+)') | ForEach-Object { $_.Groups[1].Value })
    return [pscustomobject]@{
        Pem = ($Pem -replace '\r', '').Trim() + "`n"; Der = $der; Subject = $subject; Issuer = $issuer; Cn = $cn
        SelfSigned = ($subject -ceq $issuer); IsCa = ($t -match 'CA:TRUE'); Ski = $ski; Aki = $aki
        NotAfter = $notAfter; Expired = ($notAfter -lt [DateTime]::UtcNow); KeyLabel = $label
        Sha256 = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($der)) -replace '-', '')
        AiaUrls = $aia
    }
}

function Read-PkiCertificatesFromFile {
    <#
    .SYNOPSIS
        Every certificate of a file: PEM (one or many), DER (.cer .der .crt), PKCS#12 (.pfx .p12, needs -Password), PKCS#7 (.p7b).
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$Password = '')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $pems = [System.Collections.Generic.List[string]]::new()
    if ($ext -in '.pfx', '.p12') {
        $done = $false; $lastErr = ''
        $Path = (Resolve-Path -LiteralPath $Path).ProviderPath      # full path: never depends on the process directory
        foreach ($legacy in @($false, $true)) {
            $a = @('pkcs12', '-in', $Path, '-nokeys', '-passin', "pass:$Password")
            if ($legacy) { $a += '-legacy' }
            $r = Invoke-OpenSSL -Arguments $a -AllowFailure
            if ($r.ExitCode -eq 0) { foreach ($x in [regex]::Matches($r.StdOut, '-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----')) { [void]$pems.Add($x.Value) }; $done = $true; break }
            if (-not $legacy) { $lastErr = (($r.StdErr -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' | ') }
        }
        if (-not $done) { throw "The PFX could not be opened: $Path`n  OpenSSL says: $lastErr`n  'Mac verify error' = wrong password (-LeafPassword; the default of GenerateLeafCertificate is Abc12345!). 'No such file' = wrong path." }
    }
    elseif ($ext -in '.p7b', '.p7c') {
        $r = Invoke-OpenSSL -Arguments @('pkcs7', '-in', $Path, '-print_certs') -AllowFailure
        if ($r.ExitCode -ne 0) { $r = Invoke-OpenSSL -Arguments @('pkcs7', '-inform', 'DER', '-in', $Path, '-print_certs') }
        foreach ($x in [regex]::Matches($r.StdOut, '-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----')) { [void]$pems.Add($x.Value) }
    }
    else {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($text -match '-----BEGIN (TRUSTED |X509 )?CERTIFICATE-----') {
            foreach ($x in [regex]::Matches($text, '-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----')) { [void]$pems.Add($x.Value) }
        }
        else { [void]$pems.Add((ConvertTo-PkiPemFromDerBytes -Der $bytes)) }
    }
    return @($pems | ForEach-Object { Get-PkiCertInfo -Pem $_ })
}

# ------------------------------------------------------------
# Chain of a leaf: issuer = subject (and AKI = SKI when both exist)
# ------------------------------------------------------------
function Resolve-PkiChain {
    <#
    .OUTPUTS
        @{ Chain = the issuers in order (intermediates first, root last); Complete = $true when it ends with a self-signed root; Missing = the issuer DN that was not found }
    #>
    param([Parameter(Mandatory)]$Leaf, [object[]]$Pool = @(), [switch]$FetchAia, [int]$MaxDepth = 8)
    $chain = [System.Collections.Generic.List[object]]::new()
    $known = [System.Collections.Generic.List[object]]::new(); foreach ($p in $Pool) { [void]$known.Add($p) }
    $cur = $Leaf; $missing = ''
    for ($i = 0; $i -lt $MaxDepth; $i++) {
        if ($cur.SelfSigned) { return @{ Chain = @($chain); Complete = $true; Missing = '' } }
        $cands = @($known | Where-Object { $_.Subject -ceq $cur.Issuer -and $_.Sha256 -ne $cur.Sha256 })
        $hit = $null
        if ($cur.Aki) { $hit = @($cands | Where-Object { $_.Ski -and $_.Ski -ieq $cur.Aki }) | Select-Object -First 1 }
        if (-not $hit) { $hit = $cands | Select-Object -First 1 }
        if (-not $hit -and $FetchAia) {
            foreach ($u in @($cur.AiaUrls)) {
                if ($u -notmatch '^https?://') { continue }
                try {
                    Write-PkiLog "Downloading the issuer certificate: $u" 'INFO'
                    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('aia-' + [Guid]::NewGuid().ToString('N'))
                    Invoke-WebRequest -Uri $u -OutFile $tmp -TimeoutSec 20 -UseBasicParsing | Out-Null
                    foreach ($n in (Read-PkiCertificatesFromFile -Path $tmp)) { [void]$known.Add($n) }
                    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                    $cands = @($known | Where-Object { $_.Subject -ceq $cur.Issuer }); $hit = $cands | Select-Object -First 1
                    if ($hit) { break }
                }
                catch { Write-PkiLog "  could not download: $($_.Exception.Message)" 'WARN' }
            }
        }
        if (-not $hit) { $missing = $cur.Issuer; break }
        [void]$chain.Add($hit); $cur = $hit
    }
    return @{ Chain = @($chain); Complete = ($chain.Count -gt 0 -and $chain[$chain.Count - 1].SelfSigned); Missing = $missing }
}

# ------------------------------------------------------------
# The CAs of a PKI folder (from pki-manifest.json) and the selection (-Ca)
# ------------------------------------------------------------
function Get-PkiExportCaList {
    param([Parameter(Mandatory)][string]$PkiRoot)
    $mp = Join-Path $PkiRoot 'pki-manifest.json'
    if (-not (Test-Path -LiteralPath $mp)) { throw "No pki-manifest.json in $PkiRoot (no PKI there)." }
    $m = Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json -AsHashtable
    $list = foreach ($e in @($m['certificateAuthorities'])) {
        $id = [string]$e['id']
        # the path inside the manifest may belong to another computer: find <id>.crt below the PKI folder
        $crt = @(Get-ChildItem -LiteralPath $PkiRoot -Recurse -File -Filter "$id.crt" -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '[\\/]issued[\\/]' }) | Select-Object -First 1
        if (-not $crt) { continue }
        $key = Join-Path $crt.DirectoryName "$id.key"
        [pscustomobject]@{
            Id = $id; Kind = [string]$e['kind']; CommonName = [string]$e['commonName']; Slug = [string]$e['slug']; Parent = [string]$e['parent']
            Track = [string]$e['track']; Quadrant = [int]$e['quadrant']; Fips = [bool]$e['fips']; Validation = [string]$e['validation']
            KeyAlgorithm = [string]$e['keyAlgorithm']; Certificate = $crt.FullName; KeyFile = $(if (Test-Path -LiteralPath $key) { $key } else { '' })
        }
    }
    return @($list)
}

function Select-PkiExportCa {
    <#
    .SYNOPSIS
        -Ca words -> CAs. Words: Roots (default: every root: Enterprise, Track, Quadrant), EnterpriseRoot, TrackRoots, QuadrantRoots, Intermediates,
        Classic, Quantum, All, Q1 Q2 Q3 Q4 (the quadrant: its root and its three intermediates), DV OV EV (those intermediates), or an id / slug / common name.
        -WithPath adds every parent up to the Enterprise Root.
    #>
    param([Parameter(Mandatory)][object[]]$All, [string[]]$Ca = @('Roots'), [switch]$WithPath)
    $sel = [System.Collections.Generic.List[object]]::new()
    $add = { param($x) foreach ($i in @($x)) { if ($i -and -not ($sel | Where-Object { $_.Id -eq $i.Id })) { [void]$sel.Add($i) } } }
    foreach ($w in @($Ca | Where-Object { $_ })) {
        $word = $w.Trim()
        switch -Regex ($word) {
            '^(?i)roots$'          { & $add @($All | Where-Object { $_.Kind -in 'root', 'track', 'quadrant' }); continue }
            '^(?i)enterpriseroot$' { & $add @($All | Where-Object { $_.Kind -eq 'root' }); continue }
            '^(?i)trackroots$'     { & $add @($All | Where-Object { $_.Kind -eq 'track' }); continue }
            '^(?i)quadrantroots$'  { & $add @($All | Where-Object { $_.Kind -eq 'quadrant' }); continue }
            '^(?i)intermediates$'  { & $add @($All | Where-Object { $_.Kind -eq 'intermediate' }); continue }
            '^(?i)classic$'        { & $add @($All | Where-Object { $_.Track -eq 'Classic' }); continue }
            '^(?i)quantum$'        { & $add @($All | Where-Object { $_.Track -eq 'Quantum' }); continue }
            '^(?i)all$'            { & $add $All; continue }
            '^(?i)q([1-4])$'       { $q = [int]$Matches[1]; & $add @($All | Where-Object { $_.Quadrant -eq $q }); continue }
            '^(?i)(dv|ov|ev)$'     { $v = $Matches[1].ToUpperInvariant(); & $add @($All | Where-Object { $_.Validation -eq $v }); continue }
            default {
                $hit = @($All | Where-Object { $_.Id -ieq $word -or $_.Slug -ieq $word -or $_.CommonName -ieq $word })
                if ($hit.Count -eq 0) { throw "-Ca '$word' is not a known CA. Words: Roots EnterpriseRoot TrackRoots QuadrantRoots Intermediates Classic Quantum All Q1..Q4 DV OV EV, or an id: $((@($All | ForEach-Object { $_.Id }) -join ', '))." }
                & $add $hit
            }
        }
    }
    if ($WithPath) {
        $i = 0
        while ($i -lt $sel.Count) {
            $p = $sel[$i].Parent
            if ($p) { & $add @($All | Where-Object { $_.Id -eq $p }) }
            $i++
        }
    }
    # order: Enterprise Root, Track Roots, Quadrant Roots, Intermediates
    $rank = @{ root = 0; track = 1; quadrant = 2; intermediate = 3 }
    return @($sel | Sort-Object @{ Expression = { $rank[$_.Kind] } }, Quadrant, Id)
}

# ------------------------------------------------------------
# Checks for CDNs / clouds. They accept classic RSA / ECDSA CA certificates; most of them limit the size.
# ------------------------------------------------------------
function Test-PkiCaForTarget {
    param([Parameter(Mandatory)]$Info, [Parameter(Mandatory)][string]$TargetName)
    $w = [System.Collections.Generic.List[string]]::new()
    if ($Info.KeyLabel -like 'ML-DSA*') { [void]$w.Add("$($Info.Cn): key $($Info.KeyLabel) is post-quantum. $TargetName (like every public CDN / cloud today) accepts RSA and ECDSA CA certificates only. Use a CLASSIC CA for it.") }
    elseif ($Info.KeyLabel -match '^RSA-(\d+)$' -and [int]$Matches[1] -gt 4096) { [void]$w.Add("$($Info.Cn): key $($Info.KeyLabel). Many services limit RSA to 4096 bits. If $TargetName does not accept it, use the Quadrant Root or an intermediate (RSA-4096).") }
    if ($Info.Expired) { [void]$w.Add("$($Info.Cn): the certificate is EXPIRED ($($Info.NotAfter.ToString('yyyy-MM-dd'))).") }
    if (-not $Info.IsCa) { [void]$w.Add("$($Info.Cn): this is not a CA certificate (CA:TRUE is missing).") }
    return @($w)
}

# ------------------------------------------------------------
# Hash choice. Auto = one hash that matches the key strength (RSA-8192, P-521, ML-DSA-87 -> sha512; RSA-4096, P-384, ML-DSA-65 -> sha384; else sha256)
# ------------------------------------------------------------
function Get-PkiHashChoice {
    param([string[]]$Hash = @('All'), [string]$KeyLabel = '')
    $h = @($Hash | Where-Object { $_ })
    if ($h.Count -eq 0 -or $h -contains 'None') { return @() }
    if ($h -contains 'All') { return @('sha256', 'sha384', 'sha512') }
    if ($h -contains 'Auto') {
        if ($KeyLabel -match 'RSA-(\d+)' -and [int]$Matches[1] -ge 7680) { return @('sha512') }
        if ($KeyLabel -match 'ECDSA-P521|ML-DSA-87') { return @('sha512') }
        if ($KeyLabel -match 'RSA-(\d+)' -and [int]$Matches[1] -ge 3072) { return @('sha384') }
        if ($KeyLabel -match 'ECDSA-P384|ML-DSA-65') { return @('sha384') }
        return @('sha256')
    }
    return @($h | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
}

# ------------------------------------------------------------
# Names
# ------------------------------------------------------------
function ConvertTo-PkiExportName {
    param([Parameter(Mandatory)][string]$Text, [int]$Max = 48)
    $t = (ConvertTo-PkiAscii $Text) -replace '[^A-Za-z0-9]+', '-'
    $t = $t.Trim('-').ToLowerInvariant()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max).Trim('-') }
    if (-not $t) { $t = 'ca' }
    return $t
}

function New-PkiExportFolderName {
    # ca-export_<where>_<what>_<key|nokey>_<targets>_<yyyyMMdd-HHmmss>   (the folder name tells what is inside)
    param([string]$Where, [string]$What, [bool]$WithKey, [string[]]$TargetTags)
    $tg = if (@($TargetTags).Count -eq 0) { 'notarget' } elseif (@($TargetTags).Count -gt 2) { 'targets-' + @($TargetTags).Count } else { (@($TargetTags) -join '-') }
    $parts = @('ca-export', (ConvertTo-PkiExportName $Where 40), (ConvertTo-PkiExportName $What 30), $(if ($WithKey) { 'withkey' } else { 'nokey' }), $tg, (Get-Date).ToString('yyyyMMdd-HHmmss'))
    return ($parts -join '_')
}

# ------------------------------------------------------------
# Writing files
# ------------------------------------------------------------
function Write-PkiPemFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Pem)
    [System.IO.File]::WriteAllText($Path, (($Pem -replace '\r', '').TrimEnd() + "`n"), [System.Text.UTF8Encoding]::new($false))
}

function Write-PkiCaFiles {
    <#
    .SYNOPSIS
        One CA certificate in many formats: <name>.pem .crt (PEM) .cer .der (DER) .p7b (PKCS#7) .txt (readable text), and the hash files.
    .PARAMETER Format  PEM CRT CER DER P7B TXT or ALL.
    .OUTPUTS
        the names of the files written.
    #>
    param(
        [Parameter(Mandatory)]$Info, [Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Name,
        [string[]]$Format = @('ALL'), [string[]]$HashAlgorithm = @('sha256', 'sha384', 'sha512')
    )
    $f = @($Format | ForEach-Object { $_.ToUpperInvariant() })
    if ($f -contains 'ALL') { $f = @('PEM', 'CRT', 'CER', 'DER', 'P7B', 'TXT') }
    $made = [System.Collections.Generic.List[string]]::new()
    $pem = Join-Path $Directory "$Name.pem"
    $tmp = $null
    if ($f -contains 'PEM') { Write-PkiPemFile -Path $pem -Pem $Info.Pem; [void]$made.Add("$Name.pem") }
    if ($f -contains 'CRT') { Write-PkiPemFile -Path (Join-Path $Directory "$Name.crt") -Pem $Info.Pem; [void]$made.Add("$Name.crt") }
    if ($f -contains 'CER') { [System.IO.File]::WriteAllBytes((Join-Path $Directory "$Name.cer"), $Info.Der); [void]$made.Add("$Name.cer") }
    if ($f -contains 'DER') { [System.IO.File]::WriteAllBytes((Join-Path $Directory "$Name.der"), $Info.Der); [void]$made.Add("$Name.der") }
    if ($f -contains 'P7B' -or $f -contains 'TXT') {
        $tmp = Join-Path $Directory ".$Name.tmp.pem"
        Write-PkiPemFile -Path $tmp -Pem $Info.Pem
        try {
            if ($f -contains 'P7B') {
                [void](Invoke-OpenSSL -Arguments @('crl2pkcs7', '-nocrl', '-certfile', $tmp, '-out', (Join-Path $Directory "$Name.p7b")))
                [void]$made.Add("$Name.p7b")
            }
            if ($f -contains 'TXT') {
                $t = (Invoke-OpenSSL -Arguments @('x509', '-in', $tmp, '-noout', '-text', '-fingerprint', '-sha256')).StdOut
                [System.IO.File]::WriteAllText((Join-Path $Directory "$Name.txt"), (($t -replace '\r', '').TrimEnd() + "`n"), [System.Text.UTF8Encoding]::new($false))
                [void]$made.Add("$Name.txt")
            }
        }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    foreach ($h in (Write-PkiHashFiles -Directory $Directory -Stem $Name -Algorithm $HashAlgorithm -Extension @('pem', 'crt', 'cer', 'der', 'p7b', 'txt'))) { [void]$made.Add($h) }
    return @($made)
}

function Write-PkiTargetFiles {
    <#
    .SYNOPSIS
        <name>.<tag>.pem and <name>.<tag>.crt (one certificate, PEM, LF, no text before it) for each target; some targets also get .cer (DER).
    #>
    param(
        [Parameter(Mandatory)]$Info, [Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object[]]$Target, [string[]]$HashAlgorithm = @('sha256', 'sha384', 'sha512')
    )
    $made = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $Target) {
        $stem = "$Name.$($t.Tag)"
        Write-PkiPemFile -Path (Join-Path $Directory "$stem.pem") -Pem $Info.Pem; [void]$made.Add("$stem.pem")
        Write-PkiPemFile -Path (Join-Path $Directory "$stem.crt") -Pem $Info.Pem; [void]$made.Add("$stem.crt")
        if ($t.Extra -contains 'cer') { [System.IO.File]::WriteAllBytes((Join-Path $Directory "$stem.cer"), $Info.Der); [void]$made.Add("$stem.cer") }
        foreach ($h in (Write-PkiHashFiles -Directory $Directory -Stem $stem -Algorithm $HashAlgorithm -Extension @('pem', 'crt', 'cer'))) { [void]$made.Add($h) }
    }
    return @($made)
}

function Write-PkiProtectedKey {
    <#
    .SYNOPSIS
        A private key as an ENCRYPTED PKCS#8 file (<name>.key.pem, AES-256) and, with the certificate and its chain, a .pfx. Never written without a password.
    #>
    param(
        [Parameter(Mandatory)][string]$KeyFile, [Parameter(Mandatory)][string]$CertPem, [string]$ChainPem = '',
        [Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Password,
        [string]$KeyPassword = ''
    )
    $made = [System.Collections.Generic.List[string]]::new()
    $env:PKI_EXPORT_PW = $Password; $env:PKI_EXPORT_KEYPW = $KeyPassword
    $crtTmp = Join-Path $Directory ".$Name.cert.tmp.pem"; $chTmp = Join-Path $Directory ".$Name.chain.tmp.pem"
    try {
        Write-PkiPemFile -Path $crtTmp -Pem $CertPem
        $kin = @('-passin', 'env:PKI_EXPORT_KEYPW')
        [void](Invoke-OpenSSL -Arguments (@('pkcs8', '-topk8', '-v2', 'aes-256-cbc', '-in', $KeyFile, '-out', (Join-Path $Directory "$Name.key.pem"), '-passout', 'env:PKI_EXPORT_PW') + $kin))
        [void]$made.Add("$Name.key.pem")
        $pa = @('pkcs12', '-export', '-inkey', $KeyFile, '-in', $crtTmp, '-out', (Join-Path $Directory "$Name.pfx"), '-name', $Name, '-passout', 'env:PKI_EXPORT_PW') + $kin
        if ($ChainPem) { Write-PkiPemFile -Path $chTmp -Pem $ChainPem; $pa += @('-certfile', $chTmp) }
        [void](Invoke-OpenSSL -Arguments $pa)
        [void]$made.Add("$Name.pfx")
    }
    finally {
        Remove-Item -LiteralPath $crtTmp, $chTmp -Force -ErrorAction SilentlyContinue
        Remove-Item Env:PKI_EXPORT_PW, Env:PKI_EXPORT_KEYPW -ErrorAction SilentlyContinue
    }
    return @($made)
}

function Test-PkiKeyMatchesCertificate {
    # $true when the private key belongs to the certificate (same public key)
    param([Parameter(Mandatory)][string]$KeyFile, [Parameter(Mandatory)][string]$CertPem, [string]$KeyPassword = '')
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('pkimatch-' + [Guid]::NewGuid().ToString('N') + '.pem')
    $env:PKI_EXPORT_KEYPW = $KeyPassword
    try {
        Write-PkiPemFile -Path $tmp -Pem $CertPem
        $a = (Invoke-OpenSSL -Arguments @('x509', '-in', $tmp, '-noout', '-pubkey')).StdOut.Trim()
        $b = (Invoke-OpenSSL -Arguments @('pkey', '-in', $KeyFile, '-pubout', '-passin', 'env:PKI_EXPORT_KEYPW')).StdOut.Trim()
        return (($a -replace '\s', '') -ceq ($b -replace '\s', ''))
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; Remove-Item Env:PKI_EXPORT_KEYPW -ErrorAction SilentlyContinue }
}

function New-PkiRandomPassword {
    param([int]$Length = 20)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_#@%'
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $s = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    return ('Aa1-' + $s)
}
