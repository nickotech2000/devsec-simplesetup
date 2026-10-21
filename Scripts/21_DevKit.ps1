# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 21_DevKit.ps1  -  the DevKit: ONE zip (or 7z) a developer unpacks and works with.
#   PkiTransport.ps1 -DevKit builds it:
#     * the .certpacked (CA certificates + the PKI folder with the ISSUING (intermediate) CA keys only, no root key)
#     * Install-PkiTrust.ps1 / .sh               unpack the .certpacked and put the PKI in the Local Machine store / the Ubuntu store
#     * GenerateLeafCertificate / GeneratePersonLeafCertificate / GenerateOffice365LeafCertificate / GenerateCodeSigningCertificate  (.ps1 and .sh)
#     * Make-ShExecutable.ps1 / make-executable.sh  make the .sh files executable (Windows developers: no Linux knowledge needed)
#     * devkit.env (written from the live configuration), examples, docs, START-HERE.txt
# Needs the Library module set (configuration, catalog, leaf generator, transport).

function ConvertTo-PkiShellQuoted {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "'\''") + "'"
}

function Get-PkiDevKitSourceFile {
    # a file of the project: docs\ first (4.9.5 layout), then the root, then linux\
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Name)
    foreach ($p in (Join-Path (Join-Path $Root 'docs') $Name), (Join-Path $Root $Name), (Join-Path (Join-Path $Root 'linux') $Name), (Join-Path (Join-Path $Root 'devkit') $Name)) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    return $null
}

function Write-PkiDevKitEnv {
    <#
    .SYNOPSIS
        devkit.env: everything the shell generators need from the configuration of THIS PKI (policies, CPS URLs, CRL / OCSP / AIA
        templates, subject, validity, development SAN, person / office defaults, the CA locations). Sourced by bash.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $c = $script:Pki
    $q = { param($v) ConvertTo-PkiShellQuoted ([string]$v) }
    $L = [System.Collections.Generic.List[string]]::new()
    [void]$L.Add('# devkit.env - written by PkiTransport.ps1 -DevKit from the configuration of the PKI. Sourced by the *.sh generators.')
    [void]$L.Add("# Made $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC on $([Environment]::MachineName). Do not edit by hand: rebuild the DevKit instead.")
    [void]$L.Add("PKI_KIT_VERSION=$(& $q $script:PkiGeneratorVersion)")
    [void]$L.Add("PKI_PROFILE=$(& $q $c.Profile)")
    [void]$L.Add("ORG_NAME=$(& $q (Get-PkiLeafSubjectValue 'Organization' 'O' 'Agantra Inovatif OU' 'OV'))")
    [void]$L.Add("CPS_URL=$(& $q (Get-PkiCpsUrl -Level 'OV'))")
    [void]$L.Add("CPS_URL_EV=$(& $q (Get-PkiCpsUrl -Level 'EV'))")
    foreach ($lvl in 'DV', 'OV', 'EV') {
        $pol = @(Get-PkiLeafPolicies -Level $lvl | ForEach-Object { "$($_.Oid)|$($_.Cps)" })
        [void]$L.Add("POLICIES_$lvl=$(& $q ($pol -join ' '))")
        [void]$L.Add("DAYS_$lvl=$(Get-PkiLeafDays -Level $lvl)")
        $san = [ordered]@{ Dns = @('placeholder.example.com'); Ip = @(); Email = @(); Given = $true }
        $dn = Get-PkiLeafDn -Level $lvl -San $san -CommonName '__CN__'
        [void]$L.Add("DN_$lvl=$(& $q (($dn | ForEach-Object { '{0}={1}' -f $_[0], ($_[1] -replace '\|', '/') }) -join '|'))")
    }
    [void]$L.Add("CRL_URLS=$(& $q (@($c.CrlUrls) -join ' '))")
    [void]$L.Add("OCSP_URLS=$(& $q (@($c.OcspUrls) -join ' '))")
    [void]$L.Add("CA_ISSUER_URLS=$(& $q (@($c.CaIssuerUrls) -join ' '))")
    $ls = Get-PkiLeafSan
    [void]$L.Add("LEAF_SAN_DNS=$(& $q (@($ls.Dns) -join ' '))")
    [void]$L.Add("LEAF_SAN_IP=$(& $q (@($ls.Ip) -join ' '))")
    [void]$L.Add("LEAF_SAN_EMAIL=$(& $q (@($ls.Email) -join ' '))")
    $dev = Get-PkiDevelopmentSan
    [void]$L.Add("DEV_SAN_DNS=$(& $q (@($dev.Dns) -join ' '))")
    [void]$L.Add("DEV_SAN_IP=$(& $q (@($dev.Ip) -join ' '))")
    [void]$L.Add("DEV_SAN_EMAIL=$(& $q (@($dev.Email) -join ' '))")
    $cm = if ($c.Bound.Contains('ContactEmail')) { [string]$c.Bound['ContactEmail'] } else { Get-PkiIniValue -Ini $c.Ini -Section 'subject_ov' -Key 'ContactEmail' -Default 'info@nextmantra.com' }
    [void]$L.Add("CONTACT_EMAIL=$(& $q $cm)")
    $ts = Get-PkiTimestampSettings
    [void]$L.Add("TSA_DAYS=$($ts.Days)")
    [void]$L.Add("TSA_POLICY_OID=$(& $q ([string]$ts.PolicyOid))")
    [void]$L.Add("RSA_PSS=$(if ($c.RsaPss) { 1 } else { 0 })")
    [void]$L.Add("PKI_RELEASE=$([int]$c.Release)")
    [void]$L.Add("PKI_VARIANT=$(& $q $(if ($c.NoCaRevocationInfo) { 'NoCR' } else { 'normal' }))")
    [void]$L.Add("OCSP_DAYS=$([int]$c.OcspDays)")
    foreach ($pair in @(@('PERSON_', (Get-PkiPersonSettings)), @('OFFICE_', (Get-PkiOfficeSettings)))) {
        $pre = $pair[0]; $s = $pair[1]
        foreach ($k in $s.Keys) {
            $name = $pre + (($k -creplace '([a-z])([A-Z])', '$1_$2').ToUpperInvariant())
            $v = $s[$k]; if ($v -is [bool]) { $v = $v.ToString().ToLowerInvariant() }
            [void]$L.Add("$name=$(& $q $v)")
        }
    }
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($ca in $c.Catalog) {
        if ($ca.Kind -ne 'intermediate') { continue }       # all intermediates: Classic 1-2 and Quantum 3-4 (the generators use 1-2, SignCsr also 3-4)
        $p = Get-PkiCaPaths -Ca $ca
        $base = [System.IO.Path]::Combine($ca.RelDir, $ca.Id) -replace '\\', '/'
        $fam = if ($null -ne $ca.Actual) { [string]$ca.Actual.Family } else { 'rsa' }
        $md = Get-PkiIssueMd -Kind 'intermediate' -Family $fam
        [void]$ids.Add($ca.Id)
        $slugBase = $ca.Slug -replace '(-nocr)?(-r\d+)?$', ''      # the shell adds -nocr / -rN itself, from the manifest of the PKI folder it picks
        [void]$L.Add("CA_$($ca.Id -replace '-', '_')=$(& $q "$base|$slugBase|$fam|$md")")
    }
    [void]$L.Add("CA_IDS=$(& $q ($ids -join ' '))")
    Write-Utf8NoBom -Path $Path -Content (($L -join "`n") + "`n")
}

function Copy-PkiDevKitTree {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Kit)
    Ensure-PkiDirectory -Path $Kit
    # scripts and project files the PowerShell generators and the transport need
    foreach ($f in 'PkiTransport.ps1', 'Unpack-PkiTransport.ps1', 'GenerateLeafCertificate.ps1', 'GeneratePersonLeafCertificate.ps1', 'GenerateOffice365LeafCertificate.ps1', 'GenerateCodeSigningCertificate.ps1', 'SignCsr.ps1', 'Create-WebServerConfig.ps1', 'Sign-Code.ps1',
                   'Install-DevEnvironment.ps1', (Split-Path -Leaf $script:Pki.ConfigPath), '.gitattributes') {
        $src = Join-Path $Root $f
        if (Test-Path -LiteralPath $src -PathType Leaf) { Copy-Item -LiteralPath $src -Destination $Kit -Force }
        elseif ($f -ne '.gitattributes') { throw "DevKit: $src is missing." }
    }
    # pki_tools.cnf of the kit: the PKI of this kit is its default PKI (the scripts of the kit need no -Pki)
    $tools = Join-Path $Root 'pki_tools.cnf'
    $tt = if (Test-Path -LiteralPath $tools) { [System.IO.File]::ReadAllText($tools) } else { "[ general ]`nDefaultPki = agantra`n" }
    $tt = if ($tt -match '(?im)^\s*DefaultPki\s*=') { [regex]::Replace($tt, '(?im)^(\s*DefaultPki\s*=).*$', "`$1 $($script:Pki.Profile)") } else { "[ general ]`nDefaultPki = $($script:Pki.Profile)`n" + $tt }
    Write-Utf8NoBom -Path (Join-Path $Kit 'pki_tools.cnf') -Content $tt
    foreach ($f in 'pki-transport.sh', 'Install-DevEnvironment.sh', 'Create-WebServerConfig.sh', 'Sign-Code.sh') {
        $src = Get-PkiDevKitSourceFile -Root $Root -Name $f
        if ($null -eq $src) { throw "DevKit: $f is missing." }
        Copy-Item -LiteralPath $src -Destination $Kit -Force
    }
    $sc = Join-Path $Kit 'scripts'; Ensure-PkiDirectory -Path $sc
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $Root 'scripts') -File | Where-Object { $_.Extension -eq '.ps1' -and $_.Name -ne 'PkiBackupCommon.ps1' }) { Copy-Item -LiteralPath $f.FullName -Destination $sc -Force }
    # the DevKit's own files (devkit\ in the project)
    $dk = Join-Path $Root 'devkit'
    if (-not (Test-Path -LiteralPath $dk -PathType Container)) { throw "DevKit: the folder $dk is missing." }
    foreach ($f in Get-ChildItem -LiteralPath $dk -File | Where-Object { $_.Name -ne 'START-HERE.txt' }) { Copy-Item -LiteralPath $f.FullName -Destination $Kit -Force }
    # 5.2.2: the destination tools - CSR maker and OpenSSL installer (templates in trustkit\)
    foreach ($f in 'New-PkiCsr.ps1', 'Prepare-Computer.ps1', 'new-pki-csr.sh', 'prepare-computer.sh') {
        $src = Join-Path (Join-Path $Root 'trustkit') $f
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw "DevKit: $src is missing." }
        Copy-Item -LiteralPath $src -Destination $Kit -Force
    }
    $lib = Join-Path $Kit 'lib'; Ensure-PkiDirectory -Path $lib
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $dk 'lib') -File) { Copy-Item -LiteralPath $f.FullName -Destination $lib -Force }
    # manuals
    $docs = Join-Path $Kit 'docs'; Ensure-PkiDirectory -Path $docs
    foreach ($n in 'DevKit-MANUAL.txt', 'PkiTransport-MANUAL.txt', 'GenerateLeafCertificate-MANUAL.txt', 'GeneratePersonLeafCertificate-MANUAL.txt', 'GenerateOffice365LeafCertificate-MANUAL.txt', 'GenerateCodeSigningCertificate-MANUAL.txt', 'SignCsr-MANUAL.txt', 'NewPkiCsr-MANUAL.txt', 'PrepareComputer-MANUAL.txt', 'Install-DevEnvironment-MANUAL.txt', 'Create-WebServerConfig-MANUAL.txt', 'Sign-Code-MANUAL.txt') {
        $src = Get-PkiDevKitSourceFile -Root $Root -Name $n
        if ($src) { Copy-Item -LiteralPath $src -Destination $docs -Force } else { Write-PkiLog "DevKit: manual $n not found (skipped)." 'WARN' }
    }
}

function Add-PkiDevKitServerKit {
    <#
    .SYNOPSIS
        Puts the SERVER KIT into the DevKit as the folder  server\ : server\linux\pki-server\pki-server.sh (+ the OCSP dispatcher and the time stamp service),
        server\pki\ = this PKI WITHOUT any private key (publish, CA certificates, index.txt, server\ files), the manuals and README-SERVER-PACKAGE.txt.
        It is the package of  New-PkiServerPackage.ps1  (no key is ever in it; the package is scanned) unpacked into the kit. ONE kit serves all four
        installs on Ubuntu 24.04 / 26.04:  CRL only (--crl-only), CRL + OCSP (--no-tsa), time stamp only (--tsa-only), everything (no flag).
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Kit, [Parameter(Mandatory)][string]$PkiRoot, [Parameter(Mandatory)][string]$Work)
    $np = Join-Path $Root 'New-PkiServerPackage.ps1'
    if (-not (Test-Path -LiteralPath $np -PathType Leaf)) { throw "DevKit: $np is missing (the server kit goes into the DevKit; -DevKitNoServer leaves it out)." }
    $zip = Join-Path $Work 'server-kit.zip'
    $pw = (Get-Process -Id $PID).Path
    $out = & $pw -NoProfile -File $np -PkiRoot $PkiRoot -Output $zip -RootName 'server' -Force 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $zip)) { throw "DevKit: the server kit could not be made (exit $LASTEXITCODE): $((@($out) | Select-Object -Last 3) -join ' | ')" }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $Kit)
    Remove-Item -LiteralPath $zip -Force
    Write-PkiLog 'DevKit: the server kit is in the folder server\ (pki-server.sh: CRL, OCSP, time stamping; no private key).' 'OK'
}

function ConvertTo-PkiLf {
    # shell scripts must have LF line endings: a CRLF file fails on Linux with  $'\r': command not found
    param([Parameter(Mandatory)][string]$Path)
    $t = [System.IO.File]::ReadAllText($Path)
    if ($t.Contains("`r")) { [System.IO.File]::WriteAllText($Path, ($t -replace "`r`n", "`n" -replace "`r", "`n"), [System.Text.UTF8Encoding]::new($false)) }
}

function New-PkiDevKitArchive {
    # zip (the .NET engine; unix mode 755 for *.sh, 644 for the rest - Linux honours it when the zip is made on Linux; Windows-made zips lose
    # the bit, which is why Make-ShExecutable.ps1 / make-executable.sh exist) or 7z (7-Zip, no password: the .certpacked inside is encrypted).
    param([Parameter(Mandatory)][string]$KitDirectory, [Parameter(Mandatory)][string]$OutFile, [ValidateSet('zip', '7z')][string]$Format = 'zip', [string]$SevenZipPath)
    if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }
    Ensure-PkiDirectory -Path (Split-Path -Parent $OutFile)
    $top = Split-Path -Leaf $KitDirectory
    if ($Format -eq '7z') {
        $x = Find-PkiSevenZip -Explicit $SevenZipPath
        if (-not $x) { throw '-ArchiveFormat 7z needs 7-Zip; none found (winget install 7zip.7zip, or use the default zip).' }
        $parent = Split-Path -Parent $KitDirectory
        $r = Invoke-PkiSevenZip -Exe $x -Arguments @('a', '-t7z', '-mx=9', '-bd', '-y', $OutFile, $top) -WorkingDirectory $parent
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $OutFile)) { throw "7-Zip failed (exit $($r.ExitCode))." }
        return
    }
    Add-Type -AssemblyName System.IO.Compression
    $fs = [System.IO.File]::Create($OutFile)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $rootLen = $KitDirectory.TrimEnd('\', '/').Length
            foreach ($f in Get-ChildItem -LiteralPath $KitDirectory -Recurse -File -Force | Sort-Object FullName) {
                $rel = $f.FullName.Substring($rootLen).TrimStart('\', '/') -replace '\\', '/'
                $e = $zip.CreateEntry("$top/$rel", [System.IO.Compression.CompressionLevel]::Optimal)
                $mode = if ($f.Extension -in '.sh', '.py') { 0x81ED } else { 0x81A4 }       # 100755 / 100644
                $e.ExternalAttributes = ($mode -shl 16)
                $e.LastWriteTime = [DateTimeOffset]::Now
                $in = [System.IO.File]::OpenRead($f.FullName); $outS = $e.Open()
                try { $in.CopyTo($outS) } finally { $outS.Dispose(); $in.Dispose() }
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $fs.Dispose() }
}

function New-PkiDevKit {
    <#
    .SYNOPSIS
        Builds the DevKit archive. Returns @{ Path; Folder; Files; Bytes; Package }.
    #>
    param(
        [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$Password,
        [ValidateSet('zip', '7z')][string]$KitFormat = 'zip', [ValidateSet('zip', '7z')][string]$PackageFormat = 'zip',
        [string]$SevenZipPath, [string]$Comment = '', [string]$LeafRoot, [bool]$WithKeys = $true, [switch]$NoVerify, [bool]$WithServer = $true
    )
    $c = $script:Pki
    $work = Join-Path ([System.IO.Path]::GetTempPath()) "devkit-$([guid]::NewGuid().ToString('N'))"
    $kitName = [System.IO.Path]::GetFileNameWithoutExtension($OutFile)
    $kit = Join-Path $work $kitName
    try {
        Copy-PkiDevKitTree -Root $Root -Kit $kit
        if ($WithServer) { Add-PkiDevKitServerKit -Root $Root -Kit $kit -PkiRoot ([string]$c.PkiRoot) -Work $work }
        Write-PkiDevKitEnv -Path (Join-Path $kit 'devkit.env')
        $ex = Join-Path $kit 'examples'; Ensure-PkiDirectory -Path $ex
        [void](Write-PkiPersonExample -Path (Join-Path $ex 'persons.example.json'))
        [void](Write-PkiOfficeExample -Path (Join-Path $ex 'office365.example.json'))
        # START-HERE.txt from the template
        $tpl = Join-Path (Join-Path $Root 'devkit') 'START-HERE.txt'
        if (Test-Path -LiteralPath $tpl) {
            $t = [System.IO.File]::ReadAllText($tpl).Replace('{{VERSION}}', [string]$script:PkiGeneratorVersion).Replace('{{DATE}}', [DateTime]::UtcNow.ToString('yyyy-MM-dd')).Replace('{{PACKAGE}}', "$kitName.certpacked").Replace('{{KEYS}}', $(if ($WithKeys) { 'the CA certificates AND the private keys of the ISSUING (intermediate) CAs - no root key' } else { 'the CA certificates only (no private keys): the generators cannot issue' }))
            Write-Utf8NoBom -Path (Join-Path $kit 'START-HERE.txt') -Content $t
        }
        # the package
        $pkgFile = Join-Path $kit "$kitName.certpacked"
        $cmt = if ($Comment) { $Comment } else { 'DevKit' }
        $res = New-PkiCertPackage -OutFile $pkgFile -Password $Password -ArchiveFormat $PackageFormat -ZipEncryption 'Aes256' `
            -IncludeLeafCerts:$false -IncludeCaKeys:$WithKeys -IssuingKeysOnly:$WithKeys -LeafRoot $LeafRoot -Comment $cmt -SevenZipPath $SevenZipPath -NoVerify:$NoVerify
        # line endings of every shell file, then SHA256SUMS of the kit
        foreach ($f in Get-ChildItem -LiteralPath $kit -Recurse -File | Where-Object { $_.Extension -in '.sh', '.py', '.env' }) { ConvertTo-PkiLf -Path $f.FullName }
        $sums = [System.Text.StringBuilder]::new()
        foreach ($f in Get-ChildItem -LiteralPath $kit -Recurse -File | Sort-Object FullName) {
            $rel = $f.FullName.Substring($kit.TrimEnd('\', '/').Length).TrimStart('\', '/') -replace '\\', '/'
            [void]$sums.Append("$(Get-PkiFileSha256 -Path $f.FullName)  $rel`n")
        }
        Write-Utf8NoBom -Path (Join-Path $kit 'SHA256SUMS') -Content $sums.ToString()
        New-PkiDevKitArchive -KitDirectory $kit -OutFile $OutFile -Format $KitFormat -SevenZipPath $SevenZipPath
        $n = @(Get-ChildItem -LiteralPath $kit -Recurse -File).Count
        return [ordered]@{ Path = $OutFile; Folder = $kitName; Files = $n; Bytes = ([System.IO.FileInfo]::new($OutFile)).Length; Package = $res; Format = $KitFormat }
    }
    finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
