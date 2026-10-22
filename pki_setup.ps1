# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Generates the Agantra Inovatif Enterprise PKI: Classical and Quantum-safe
    tracks, FIPS and non-FIPS quadrants, DV / OV / EV intermediates, default
    EV leaf certificates, and the Windows trust installation.
.DESCRIPTION
    Requires PowerShell 7+ and OpenSSL 4.x (the script stops with an error on
    older OpenSSL). Only native OpenSSL providers are used; the ENGINE API and
    third-party providers (oqsprovider) are not.

    Run  .\pki_setup.ps1 -Help  for the complete parameter list.
.NOTES
    Phase A of the PKI redesign. GenerateLeafCertificate.ps1, pki_reuse.ps1 and
    the transport script are updated in later phases.
#>
[CmdletBinding()]
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    # ---- configuration ----
    [string]$ConfigFile,
    [string]$PkiRoot,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig,

    # ---- hierarchy selection ----
    [ValidateSet(1, 2, 3, 4)][int[]]$Quadrant = @(1, 2, 3, 4),

    # ---- algorithms ----
    [ValidateSet(0, 1)][int]$IntermediatePathLen = 0,
    [ValidateSet(4096, 8192)][int]$QuadrantRsaBits = 4096,
    [ValidateSet('P-384', 'P-521')][string]$QuadrantCurve = 'P-384',
    [ValidateSet(4096, 8192)][int]$IntermediateRsaBits = 4096,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$IntermediateCurve = 'P-384',
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcAlgorithm = 'mldsa87',
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcLeafAlgorithm = 'mldsa65',
    [switch]$PqcFallback,
    [ValidateSet(4096, 8192)][int]$FallbackRsaBits = 8192,
    [switch]$RsaPss,

    # ---- validity ----
    [ValidateRange(1, 1000)][int]$RootYears = 1000,
    [ValidateRange(1, 1000)][int]$TrackYears = 500,
    [ValidateRange(1, 1000)][int]$QuadrantYears = 400,
    [ValidateRange(1, 1000)][int]$IntYears = 250,
    [ValidateRange(1, 397)][int]$LeafDays = 397,
    [ValidateRange(1, 100)][int]$OvLeafYears = 3,
    [ValidateRange(1, 100)][int]$DvLeafYears = 5,

    # ---- policies ----
    [ValidatePattern('^[1-9]\d{0,9}$')][string]$IanaPen,
    [ValidatePattern('^[0-2](\.(0|[1-9]\d*))+$')][string]$EvPolicyOid,

    # ---- subject values: default comes from agantra_pki.cnf ----
    [string]$Domain,
    [string]$Organization,
    [string]$OrganizationalUnit,
    [string]$Country,
    [string]$State,
    [string]$Locality,
    [string]$Street,
    [string]$PostalCode,
    [string]$Serial,
    [string]$BusinessCategory,
    [string]$JurisdictionCountry,
    [string]$JurisdictionState,
    [string]$JurisdictionLocality,
    [string]$CpsUrl,
    [string]$CpsUrlEv,
    [string]$ContactName,
    [string]$ContactEmail,
    [string]$ContactPhone,

    # ---- leaf / output ----
    [ValidateSet(2048, 3072, 4096, 8192)][int[]]$LeafSizes = @(2048),
    [string]$Password = 'Abc12345!',
    [switch]$LegacyPfx,
    [switch]$SkipLeaf,
    # ---- revocation: CRL, OCSP responder certificates, time stamping certificate (made with the PKI unless -SkipRevocation) ----
    [switch]$SkipRevocation,
    [ValidateRange(1, 3650)][int]$CrlDays,
    [ValidateRange(1, 3650)][int]$OcspDays,
    [ValidateSet(1, 2, 3, 4)][int]$TimestampQuadrant,
    [string]$TimestampPolicyOid,
    [ValidateRange(1, 36500)][int]$TimestampDays,

    # ---- Windows trust (elevated PowerShell) ----
    [switch]$InstallTrust,
    [switch]$Clean,
    [switch]$RemoveTrust,
    [switch]$RemoveAllTrust,
    [switch]$Unblock,
    [switch]$Check,
    [switch]$Verify,
    [switch]$VerifyAll,
    [switch]$ShowNames,
    [switch]$ReinstallTrust,

    # ---- Classic PKI only ----
    [switch]$ClassicPKI,

    # ---- releases and the NoCR variant (every PKI lives in pki\R1, pki\R2, pki\NoCR-R1 ...) ----
    [switch]$NoCaRevocationInfo,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NewRelease,

    # ---- Enterprise Root signed by a public CA (see docs\PUBLIC-CA-ENTERPRISE-ROOT.txt) ----
    [ValidateSet('DigiCert', 'GlobalSign', 'Sectigo', 'Other')][string]$ExternalCa,
    [switch]$EnterpriseRootCsr,
    [ValidateSet(4096, 8192)][int]$EnterpriseRootKeyBits = 8192,
    [string]$ImportEnterpriseRoot,
    [string]$ExternalChain,
    [switch]$CrossSignCsr,
    [string]$ImportCrossCert,

    [switch]$ListPki,
    [switch]$Help,
    [switch]$Version
)
# >>> PKI-VERSION-INFO (generated by tools/Update-VersionBlock.ps1 - do not edit here, edit the tool source)
$script:PkiVerNumber = '7.9.5'
$script:PkiVerDate = '2026-10-22'
function Show-PkiVersionInfo {
    # -Version: the same report in every script (.ps1 and .sh). Plain text, 100 columns, no changes to the system.
    $isWin = ([System.Environment]::OSVersion.Platform -eq 'Win32NT')
    $out = New-Object System.Collections.Generic.List[string]
    $rule = ('=' * 100); $dash = ('-' * 100)
    function Add-Row([string]$Label, [string]$Value) {
        $lines = @(($Value -split "`n"))
        $out.Add(' ' + $Label.PadRight(15) + ': ' + $lines[0])
        for ($i = 1; $i -lt $lines.Count; $i++) { $out.Add((' ' * 18) + $lines[$i]) }
    }
    function Run-Tool([string]$Exe, [string]$ArgText, [string]$LdPath) {
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Exe; $psi.Arguments = $ArgText
            $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
            if ($LdPath) { $psi.EnvironmentVariables['LD_LIBRARY_PATH'] = $LdPath }
            $p = [System.Diagnostics.Process]::Start($psi)
            $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(8000)) { try { $p.Kill() } catch { }; return '' }
            return (($o.Result + "`n" + $e.Result) -replace "`0", '').Trim()
        } catch { return '' }
    }
    function Find-Tool([string]$Name) {
        $r = @()
        foreach ($c in @(Get-Command $Name -All -ErrorAction SilentlyContinue)) { if ($c.CommandType -eq 'Application' -and $c.Source) { $r += $c.Source } }
        return @($r | Select-Object -Unique)
    }
    function First-Line([string]$T) { if (-not $T) { return '' }; return (($T -split "`r?`n")[0]).Trim() }
    function Num-Key([string]$V) { $m = [regex]::Match($V, '^\d+(\.\d+){0,3}'); if ($m.Success) { try { return [version]($m.Value + $(if ($m.Value -notmatch '\.') { '.0' } else { '' })) } catch { } }; return [version]'0.0' }
    function Get-Reg([string]$Path, [string]$Name) { try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null } }

    # ---- the operating system
    $kind = 'other'; $osName = ''; $osVer = ''; $patch = ''; $platform = ''; $arch = ''
    $uname = $env:PKI_FAKE_UNAME
    if (-not $uname -and -not $isWin) { $uname = (Run-Tool 'uname' '-s' '') }
    try { $arch = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture } catch { $arch = $env:PROCESSOR_ARCHITECTURE }
    if ($isWin) {
        $kind = 'windows'
        $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $pn = [string](Get-Reg $cv 'ProductName'); $dv = [string](Get-Reg $cv 'DisplayVersion'); if (-not $dv) { $dv = [string](Get-Reg $cv 'ReleaseId') }
        $bn = [string](Get-Reg $cv 'CurrentBuild'); $ubr = [string](Get-Reg $cv 'UBR'); $inst = [string](Get-Reg $cv 'InstallationType')
        $b = 0; [void][int]::TryParse($bn, [ref]$b)
        if ($pn -match '^Windows 10' -and $b -ge 22000) { $pn = $pn -replace '^Windows 10', 'Windows 11' }
        $osName = $pn; $osVer = $dv
        $patch = 'OS build ' + $bn + $(if ($ubr) { '.' + $ubr } else { '' })
        if ($inst -eq 'Client' -or $pn -match '^Windows 1[01]') {
            if ($b -ge 26100) { $platform = 'supported: full (Classic and Quantum)' } else { $platform = 'NOT supported (Windows 11 24H2 or newer is needed)' }
        } elseif ($pn -match 'Server') {
            if ($b -ge 26100) { $platform = 'supported: full (Classic and Quantum)' } elseif ($b -ge 20348) { $platform = 'supported: Classic track only (Windows Server 2022)' } else { $platform = 'NOT supported (Windows Server 2022 or newer is needed)' }
        } else { $platform = 'NOT supported' }
    } elseif ($uname -eq 'Darwin') {
        $kind = 'macos'; $osName = 'macOS'; $platform = 'REJECTED (macOS is not supported)'
    } elseif ($uname -eq 'Linux') {
        $kind = 'linux'
        $rel = $env:PKI_OS_RELEASE_FILE; if (-not $rel) { $rel = '/etc/os-release' }
        $id = ''; $vid = ''; $pretty = ''
        if (Test-Path -LiteralPath $rel) {
            foreach ($l in (Get-Content -LiteralPath $rel -ErrorAction SilentlyContinue)) {
                if ($l -match '^ID=(.*)$') { $id = $Matches[1].Trim('"', "'") }
                elseif ($l -match '^VERSION_ID=(.*)$') { $vid = $Matches[1].Trim('"', "'") }
                elseif ($l -match '^PRETTY_NAME=(.*)$') { $pretty = $Matches[1].Trim('"', "'") }
            }
        }
        $osName = $(if ($pretty) { $pretty } else { 'Linux' }); $osVer = $vid
        $patch = 'kernel ' + (Run-Tool 'uname' '-r' '')
        $maj = 0; [void][int]::TryParse(($vid -split '\.')[0], [ref]$maj)
        $ok = $false
        switch -Regex ($id) { '^ubuntu$' { $ok = ($maj -ge 24) } '^(centos|rhel|rocky|ol)$' { $ok = ($maj -ge 10) } '^(sles|sles_sap|sled|opensuse-leap)$' { $ok = ($maj -ge 15) } '^opensuse-tumbleweed$' { $ok = $true } }
        if ($ok) { $platform = 'supported: full (Classic and Quantum)' } else { $platform = 'NOT supported (see the platform list in the manual)' }
    } else { $osName = [string]$uname; $platform = 'NOT supported' }

    # ---- header
    $name = Split-Path -Leaf $PSCommandPath
    $out.Add($rule); $out.Add(' ' + $name + '  -  version information'); $out.Add($rule)
    $out.Add(' SCRIPT')
    Add-Row 'Name' $name
    Add-Row 'Version' ($script:PkiVerNumber + '   (build of ' + $script:PkiVerDate + ')')
    Add-Row 'Author' 'Nicko Satria Utama'
    Add-Row 'Company' ('Agantra Inovatif O' + [char]0x00DC + ' (NextMantra)')
    Add-Row 'Email' 'nicko@nextmantra.com'
    $out.Add($dash); $out.Add(' OPERATING SYSTEM')
    Add-Row 'Name' $osName
    if ($osVer) { Add-Row 'Version' $osVer }
    if ($patch) { Add-Row 'Patch/kernel' $patch }
    if ($arch) { Add-Row 'Architecture' $arch }
    Add-Row 'Platform' $platform
    if ($kind -eq 'macos') { $out.Add($dash); $out.Add(' macOS is rejected by these scripts. Nothing else is checked.'); $out.Add($rule); $out | ForEach-Object { Write-Host $_ }; exit 5 }

    # ---- .NET
    $out.Add($dash); $out.Add(' .NET')
    $dn = @(Find-Tool 'dotnet')
    if ($dn.Count -gt 0) {
        $sdk = @(); foreach ($l in ((Run-Tool $dn[0] '--list-sdks' '') -split "`r?`n")) { if ($l -match '^(\d+\.\d+\.\d+\S*)') { $sdk += $Matches[1] } }
        $rt = @{}; foreach ($l in ((Run-Tool $dn[0] '--list-runtimes' '') -split "`r?`n")) { if ($l -match '^(Microsoft\.\S+)\s+(\d+\.\d+\.\d+\S*)') { $f = $Matches[1] -replace '^Microsoft\.', ''; if (-not $rt.ContainsKey($f) -or (Num-Key $Matches[2]) -gt (Num-Key $rt[$f])) { $rt[$f] = $Matches[2] } } }
        if ($sdk.Count -gt 0) { $s = @($sdk | Sort-Object { Num-Key $_ } -Descending); $x = $s[0]; if ($s.Count -gt 1) { $x += '   (also ' + (($s[1..($s.Count - 1)]) -join ', ') + ')' }; Add-Row 'SDK (latest)' $x } else { Add-Row 'SDK (latest)' 'none installed' }
        if ($rt.Count -gt 0) { Add-Row 'Runtime' ((($rt.Keys | Sort-Object) | ForEach-Object { $_ + ' ' + $rt[$_] }) -join "`n") } else { Add-Row 'Runtime' 'none installed' }
    } else { Add-Row 'SDK (latest)' 'not found'; Add-Row 'Runtime' 'not found' }
    if ($isWin) {
        $rel = Get-Reg 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' 'Release'
        $fw = @()
        if ($rel) {
            $r = [int]$rel; $v4 = '4.5'
            foreach ($t in @(@(533320, '4.8.1'), @(528040, '4.8'), @(461808, '4.7.2'), @(461308, '4.7.1'), @(460798, '4.7'), @(394802, '4.6.2'), @(394254, '4.6.1'), @(393295, '4.6'), @(379893, '4.5.2'), @(378675, '4.5.1'))) { if ($r -ge $t[0]) { $v4 = $t[1]; break } }
            $fw += ($v4 + ' (release ' + $r + ')')
        }
        if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' 'Install') -eq 1) { $fw += '3.5' }
        if ($fw.Count -gt 0) { Add-Row 'Framework' ($fw -join ', ') } else { Add-Row 'Framework' 'not found' }
    } else { Add-Row 'Framework' 'n/a (Windows only)' }

    # ---- Node.js, Python, Java
    $out.Add($dash); $out.Add(' NODE.JS, PYTHON 3, JAVA')
    $nd = @(Find-Tool 'node'); $nv = ''; if ($nd.Count -gt 0) { $nv = First-Line (Run-Tool $nd[0] '--version' '') }
    if ($nv -match '^v?(\d+\.\d+\.\d+)') { Add-Row 'Node.js' ($Matches[1] + '   ' + $nd[0]) } else { Add-Row 'Node.js' 'not found' }
    $py = ''; $pp = ''
    foreach ($c in @('python3', 'python')) { foreach ($p in (Find-Tool $c)) { $t = First-Line (Run-Tool $p '--version' ''); if ($t -match '^Python (3\.\d+\S*)') { $py = $Matches[1]; $pp = $p; break } }; if ($py) { break } }
    if (-not $py -and $isWin) { foreach ($p in (Find-Tool 'py')) { $t = First-Line (Run-Tool $p '-3 --version' ''); if ($t -match '^Python (3\.\d+\S*)') { $py = $Matches[1]; $pp = $p + ' -3'; break } } }
    if ($py) { Add-Row 'Python 3' ($py + '   ' + $pp) } else { Add-Row 'Python 3' 'not found' }
    $jv = @(Find-Tool 'java'); $jt = ''; if ($jv.Count -gt 0) { $jt = Run-Tool $jv[0] '-XshowSettings:properties -version' '' }
    if ($jt -match 'version "([^"]+)"') {
        $jver = $Matches[1]; $jven = ''; if ($jt -match '(?m)java\.vendor = (.+)$') { $jven = '   ' + $Matches[1].Trim() }
        Add-Row 'Java runtime' ($jver + $jven)
    } else { Add-Row 'Java runtime' 'not found' }
    $jc = @(Find-Tool 'javac'); $jct = ''; if ($jc.Count -gt 0) { $jct = First-Line (Run-Tool $jc[0] '-version' '') }
    if ($jct -match '^javac (\S+)') { Add-Row 'JDK (javac)' $Matches[1] } else { Add-Row 'JDK (javac)' 'not found' }

    # ---- shells
    $out.Add($dash); $out.Add(' SHELLS')
    $ps = @()
    if ($isWin) {
        if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion') -eq '2.0') { $ps += '2.0' }
        $w5 = [string](Get-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' 'PowerShellVersion'); if ($w5) { $ps += $w5 }
        foreach ($d in @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'PowerShell') -Directory -ErrorAction SilentlyContinue)) { $x = Join-Path $d.FullName 'pwsh.exe'; if (Test-Path -LiteralPath $x) { $t = [string](Get-Item -LiteralPath $x).VersionInfo.ProductVersion; if ($t -match '^\d+\.\d+\.\d+(-[\w\.]+)?') { $ps += $Matches[0] } } }  # file version: no child PowerShell (antivirus heuristics)
    } else {
        foreach ($x in (Find-Tool 'pwsh')) { $t = Run-Tool $x '-NoProfile -Command $PSVersionTable.PSVersion.ToString()' ''; if ($t -match '^\d+\.\d+') { $ps += (First-Line $t) } }
    }
    $me = $PSVersionTable.PSVersion.ToString()
    $psl = @($ps | Where-Object { $_ } | Select-Object -Unique)
    if ($psl -notcontains $me) { $psl += $me }
    $psl = @($psl | Sort-Object { Num-Key $_ })
    Add-Row 'PowerShell' ((($psl | ForEach-Object { $_ })) -join ', ')
    if ($isWin) {
        $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'; if (Test-Path -LiteralPath $cmdExe) { Add-Row 'Cmd prompt' ((Get-Item -LiteralPath $cmdExe).VersionInfo.ProductVersion) } else { Add-Row 'Cmd prompt' 'not found' }
        $gb = ''; foreach ($g in (Find-Tool 'git')) { $cand = @((Join-Path (Split-Path -Parent (Split-Path -Parent $g)) 'bin\bash.exe'), (Join-Path (Split-Path -Parent (Split-Path -Parent $g)) 'usr\bin\bash.exe')); foreach ($c in $cand) { if (Test-Path -LiteralPath $c) { $gb = $c; break } }; if ($gb) { break } }
        if ($gb) { $t = Run-Tool $gb '--version' ''; if ($t -match 'version ([\w\.\(\)\-]+)') { Add-Row 'Git bash' ($Matches[1] + '   ' + $gb) } else { Add-Row 'Git bash' ('found   ' + $gb) } } else { Add-Row 'Git bash' 'not found' }
        $gv = ''; foreach ($g in (Find-Tool 'git')) { $gv = First-Line (Run-Tool $g '--version' ''); break }
        if ($gv) { Add-Row 'Git' ($gv -replace '^git version ', '') } else { Add-Row 'Git' 'not found' }
        $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
        if (Test-Path -LiteralPath $wsl) { $t = Run-Tool $wsl '--version' ''; $wv = ''; if ($t -match 'WSL version: *([\d\.]+)') { $wv = $Matches[1] }; $dl = (Run-Tool $wsl '-l -q' '') -split "`r?`n" | Where-Object { $_ -and $_ -notmatch 'no installed|Windows Subsystem|--install|Usage|wsl' }; Add-Row 'WSL' ($(if ($wv) { $wv } else { 'installed' }) + $(if ($dl) { '   distros: ' + ((@($dl) | ForEach-Object { $_.Trim() }) -join ', ') } else { '   no distro' })) } else { Add-Row 'WSL' 'not found' }
    } else {
        $bs = @(Find-Tool 'bash'); $bt = ''; if ($bs.Count -gt 0) { $bt = First-Line (Run-Tool $bs[0] '--version' '') }
        if ($bt -match 'version ([\w\.\(\)\-]+)') { Add-Row 'Bash' ($Matches[1] + '   ' + $bs[0]) } else { Add-Row 'Bash' 'not found' }
        $oth = @()
        foreach ($s in @('zsh', 'fish', 'tcsh', 'ksh', 'dash', 'csh')) {
            $f = @(Find-Tool $s); if ($f.Count -eq 0) { continue }
            $t = ''; if ($s -in 'zsh', 'fish', 'tcsh') { $t = First-Line (Run-Tool $f[0] '--version' '') }
            if ($s -eq 'csh' -and ($oth | Where-Object { $_ -like 'tcsh*' })) { continue }
            if ($t -match '(\d+\.\d+(\.\d+)*)') { $oth += ($s + ' ' + $Matches[1]) } else { $oth += ($s + ' (present)') }
        }
        if ($oth.Count -gt 0) { Add-Row 'Other shells' ($oth -join ', ') } else { Add-Row 'Other shells' 'none found' }
    }

    # ---- Schannel and OpenSSL
    $out.Add($dash); $out.Add(' TLS: SCHANNEL AND OPENSSL')
    if ($isWin) {
        $sc = Join-Path $env:SystemRoot 'System32\schannel.dll'
        if (Test-Path -LiteralPath $sc) { Add-Row 'Schannel' ((Get-Item -LiteralPath $sc).VersionInfo.ProductVersion + '   schannel.dll (Windows built-in TLS)') } else { Add-Row 'Schannel' 'not found' }
    } else { Add-Row 'Schannel' 'n/a (Windows only)' }
    $cand = New-Object System.Collections.Generic.List[string]
    foreach ($p in (Find-Tool 'openssl')) { $cand.Add($p) }
    $nPath = $cand.Count
    $known = @()
    if ($isWin) {
        $pf = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\') | Where-Object { $_ }
        foreach ($b in $pf) { foreach ($g in @('OpenSSL*\bin\openssl.exe', 'FireDaemon OpenSSL*\bin\openssl.exe', 'Git\usr\bin\openssl.exe', 'Git\mingw64\bin\openssl.exe', 'Shining Light*\bin\openssl.exe')) { $known += @(Get-ChildItem -Path (Join-Path $b $g) -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) } }
    } else {
        foreach ($g in @('/usr/bin/openssl', '/usr/local/bin/openssl', '/usr/local/ssl/bin/openssl', '/opt/openssl*/bin/openssl', '/opt/*/bin/openssl', '/usr/local/openssl*/bin/openssl')) { $known += @(Get-ChildItem -Path $g -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) }
    }
    $cfg = Join-Path (Split-Path -Parent $PSCommandPath) 'pki_tools.cnf'
    if (Test-Path -LiteralPath $cfg) { $sec = ''; foreach ($l in (Get-Content -LiteralPath $cfg -ErrorAction SilentlyContinue)) { if ($l -match '^\s*\[\s*(\w+)\s*\]') { $sec = $Matches[1] } elseif ($sec -eq 'openssl' -and $l -match '^\s*Path\s*=\s*(\S.*)$') { $known += $Matches[1].Trim() } } }
    foreach ($k in $known) { if ($k -and (Test-Path -LiteralPath $k)) { $cand.Add($k) } }
    $seen = @{}; $rows = @(); $idx = 0
    foreach ($p in $cand) {
        $real = $p; if (-not $isWin) { $rp = Run-Tool 'readlink' ('-f "' + $p + '"') ''; if ($rp) { $real = First-Line $rp } }
        if ($seen.ContainsKey($real)) { $idx++; continue }; $seen[$real] = 1
        $ld = ''; if (-not $isWin) { $pre = Split-Path -Parent (Split-Path -Parent $real); if ($pre -and $pre -ne '/usr') { $ld = (Join-Path $pre 'lib64') + ':' + (Join-Path $pre 'lib') } }
        $t = Run-Tool $real 'version' $ld
        if ($t -notmatch '(OpenSSL|LibreSSL)\s+(\d+\.\d+\.\d+\S*)') { $idx++; continue }
        $ver = $Matches[2]; $lib = $Matches[1]
        $vendor = ''
        if ($real -match 'FireDaemon') { $vendor = 'FireDaemon' }
        elseif ($real -match 'Shining Light|OpenSSL-Win|\\OpenSSL\\bin|\\OpenSSL\\') { $vendor = 'Shining Light Productions (Windows build)' }
        elseif ($real -match '\\Git\\') { $vendor = 'Git for Windows (MSYS2)' }
        elseif ($real -match 'chocolatey') { $vendor = 'Chocolatey package' }
        elseif ($real -match 'scoop') { $vendor = 'Scoop package' }
        elseif ($real -match 'msys64|mingw') { $vendor = 'MSYS2' }
        elseif ($real -match 'conda') { $vendor = 'Anaconda / Conda' }
        elseif ($real -match 'Strawberry') { $vendor = 'Strawberry Perl' }
        elseif ($real -match 'vcpkg') { $vendor = 'vcpkg' }
        elseif ($lib -eq 'LibreSSL') { $vendor = 'LibreSSL project' }
        elseif (-not $isWin) {
            $own = First-Line (Run-Tool 'dpkg' ('-S "' + $real + '"') '')
            if ($own -match '^([a-z0-9][\w\.\+\-]*)(:\w+)?: /') { $vendor = 'package ' + $Matches[1] + ' (dpkg)' }
            else { $own = Run-Tool 'rpm' ('-qf "' + $real + '"') ''; if ($own -and $own -notmatch 'not owned|error|No such') { $vendor = 'package ' + (First-Line $own) + ' (rpm)' } else { $vendor = 'built from source code (openssl.org), not a package' } }
        } else { $vendor = 'unknown packager' }
        $role = $(if ($rows.Count -eq 0 -and $idx -lt $nPath) { 'Default' } else { 'Side' })
        $rows += , @($role, $ver, $real, $vendor)
        $idx++
    }
    if ($rows.Count -eq 0) { Add-Row 'OpenSSL' 'not found' }
    else {
        $ok4 = $false
        foreach ($r in $rows) { Add-Row ($r[0] + ' OpenSSL') ($r[1] + '   ' + $r[2] + "`n" + 'from: ' + $r[3]); if ($r[1] -match '^[4-9]\.') { $ok4 = $true } }
        Add-Row 'PKI needs' ($(if ($ok4) { 'OpenSSL 4.x: found' } else { 'OpenSSL 4.x: NOT found (Install-DevEnvironment can install it)' }))
    }
    $out.Add($rule)
    foreach ($l in $out) { Write-Host $l }
}
if ($Version) { Show-PkiVersionInfo; exit 0 }
# <<< PKI-VERSION-INFO


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-PkiHelp {
    @'
====================================================================================================
 pki_setup.ps1  -  build your own private PKI
 Version 7.9.5
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = stop.
 Manual : docs\pki_setup-MANUAL.txt        Words : docs\GLOSSARY.txt
 Also   : html\index.html  (the same documents as web pages)

 1  WHAT IT DOES
----------------------------------------------------------------------------------------------------
 It builds a private PKI in the folder .\pki : root CAs, intermediate CAs, one test certificate
 for each quadrant, the CRL files and a manifest. It can install the CA certificates in Windows.

 It does NOT make the certificates for your servers and people. Use GenerateLeafCertificate.ps1.

 2  QUICK START
----------------------------------------------------------------------------------------------------
   .\pki_setup.ps1 -Check              1. Is this computer ready? Changes nothing.
   .\pki_setup.ps1 -InstallTrust       2. Build the PKI and trust it in Windows (administrator).
   .\pki_setup.ps1 -Verify             3. Check what was built. Changes nothing.
   .\pki_setup.ps1 -VerifyAll          3b. The same for all built PKIs.

 You need: PowerShell 7 and OpenSSL 4. OpenSSL 3 is refused. To install OpenSSL, run as
 administrator:   .\Install-DevEnvironment.ps1 -Only OpenSSL,7Zip    then open a NEW window.

 3  COMMON COMMANDS
----------------------------------------------------------------------------------------------------
   .\pki_setup.ps1 -Check                       is this computer ready?
   .\pki_setup.ps1 -ShowNames                   show the names of all CAs. Builds nothing.
   .\pki_setup.ps1                              build all four quadrants
   .\pki_setup.ps1 -Quadrant 1,3                build the non-FIPS quadrants (no FIPS module)
   .\pki_setup.ps1 -ClassicPKI                  build the small Classic PKI only
   .\pki_setup.ps1 -InstallTrust                build, then trust in Windows (administrator)
   .\pki_setup.ps1 -InstallTrust                run again: builds the NEXT release (R2, R3 ...)
   .\pki_setup.ps1 -Release 8 -InstallTrust     build release 8. Stops if R8 already exists.
   .\pki_setup.ps1 -NoCaRevocationInfo -InstallTrust    NoCR PKI (CA certificates without CRL)
   .\pki_setup.ps1 -Pki raksaka -InstallTrust   the PKI of another company (New-PkiConfig.ps1)
   .\pki_setup.ps1 -ListPki                     list the PKIs and their folders
   .\pki_setup.ps1 -Verify                      check an existing PKI
   .\pki_setup.ps1 -VerifyAll                   check ALL built PKIs, show every result
   .\pki_setup.ps1 -ReinstallTrust              trust an existing PKI again. No rebuild.
   .\pki_setup.ps1 -Clean -InstallTrust         remove the old release first, then build it again
   .\pki_setup.ps1 -RemoveTrust -Release 2      take release 2 out of Windows. Files stay.
   .\pki_setup.ps1 -RemoveAllTrust              remove EVERY PKI, everywhere, and delete .\pki
   .\pki_setup.ps1 -OpenSslPath 'C:\path\openssl.exe'      use this OpenSSL
   .\pki_setup.ps1 -FipsModuleConfig C:\openssl\ssl\fipsmodule.cnf
   .\pki_setup.ps1 -Unblock                     unblock files, list the programs that hold them
   .\pki_setup.ps1 -Verbose                     show every OpenSSL command
   .\pki_setup.ps1 -Help                        this text
   .\pki_setup.ps1 -Version                     version, author, OS and tool versions
   .\pki_remove.ps1 -List                       list and remove PKIs (see its -Help)

 4  WHAT IS BUILT
----------------------------------------------------------------------------------------------------
 Folder: .\pki\pki-default-01 for Agantra. Another company: .\pki\pki-<name>-01.

   Enterprise Root CA                 RSA 8192  SHA-512   1000 years   pathlen 3
   |- Classic Track Root              RSA 8192  SHA-512    500 years   pathlen 2
   |   |- Quadrant 1 Root  no FIPS    RSA 4096  SHA-384    400 years   pathlen 1
   |   |    `- DV / OV / EV CAs       RSA 4096  SHA-256    250 years   pathlen 0
   |   `- Quadrant 2 Root  FIPS       ECDSA P-384 SHA-384  400 years   pathlen 1
   |        `- DV / OV / EV CAs       ECDSA P-384 SHA-384  250 years   pathlen 0
   `- Quantum Track Root              ML-DSA-87            500 years   pathlen 2
       |- Quadrant 3 Root  no FIPS    ML-DSA-87            400 years   pathlen 1
       |    `- DV / OV / EV CAs       ML-DSA-87            250 years   pathlen 0
       `- Quadrant 4 Root  FIPS       ML-DSA-87            400 years   pathlen 1
            `- DV / OV / EV CAs       ML-DSA-87            250 years   pathlen 0

 Quadrant numbers (used by -Quadrant and in folders):
     1 = Classic, no FIPS     2 = Classic, FIPS     3 = Quantum, no FIPS     4 = Quantum, FIPS
 Test certificate (EV): quadrant 1 RSA 2048, quadrant 2 ECDSA P-256, quadrants 3 and 4 ML-DSA-65.
 Only the quadrants you choose with -Quadrant are built. The Enterprise Root and the Track Roots
 that they need are always built.

 Fixed key rules (not configurable): the Enterprise Root and the Track Roots are RSA 8192 with
 SHA-512. The strongest key and digest are used where the algorithm is not RSA:
     RSA 8192 / SHA-512     ECDSA P-521 / SHA-512     ML-DSA-87 (no separate digest)
 Quadrant roots: Q1 RSA 4096 / SHA-384, Q2 ECDSA P-384 / SHA-384.
 -QuadrantRsaBits 8192 and -QuadrantCurve P-521 make them stronger.

 5  WHERE IT RUNS
----------------------------------------------------------------------------------------------------
   Full      Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Enterprise),
             Windows Server 2025, Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+,
             Oracle Linux 10+, SLES / SLED 15+, openSUSE.
   Classic   Windows Server 2022: quadrants 1 and 2 only (no Quantum, no ML-DSA).
   Refused   Windows 10 and older, Windows 11 before 24H2, macOS, and the China, Government, IoT,
             SE and Embedded editions. The script prints an error and exits with code 5.
 Installing trust (-InstallTrust and the remove options) works on Windows only. For other systems
 install root.crt by hand: see the manual, section 7.

 6  WHAT YOU NEED
----------------------------------------------------------------------------------------------------
 PowerShell 7 or newer and OpenSSL 4.x. When several OpenSSL programs exist, the newest 4.x is
 used. An older one first in the PATH (Git, a package) is skipped and named in the output.
 A machine-wide OPENSSL_CONF is ignored: this script always uses its own configuration.
 Before it builds, the script tests that OpenSSL can make ML-DSA keys (quadrants 3, 4) and can load
 the FIPS provider (quadrants 2, 4). If not, it stops and says why.
 OpenSSL 4 has no ENGINE. This PKI uses the native providers:
     no FIPS :  -provider default
     FIPS    :  -provider fips -provider base     (needs fipsmodule.cnf, see -FipsModuleConfig)

 7  THE QUANTUM TRACK
----------------------------------------------------------------------------------------------------
 ML-DSA is used at EVERY level of the Quantum track. If OpenSSL cannot make an ML-DSA key, the
 script STOPS. A quiet downgrade would defeat the purpose.
 -PqcFallback uses an RSA key instead. It prints a warning for each key, marks it with * in the
 summary and in pki-manifest.json. Such a certificate is NOT quantum safe.

 Where ML-DSA certificates work (status of mid-2026, test on your builds):
   Certificate store, chain check   Windows 11 24H2+ and Windows Server 2025. Not Windows 10.
   TLS server certificate           OpenSSL 3.5+ (nginx, Apache, Node.js, Python, curl, Kestrel on
                                    Linux). NOT Windows Schannel (IIS, Kestrel on Windows), NOT
                                    Java 25, NOT the browsers.
 So: Quantum certificates for OpenSSL services and mutual TLS between your own systems.
 Classic certificates (quadrants 1, 2) for sites that browsers or Windows servers must serve.
 Every browser and Windows 11 also negotiates the hybrid key exchange X25519MLKEM768 with the
 Classic ones.

 8  OPTIONS
----------------------------------------------------------------------------------------------------
 Rule: a command line option wins over the configuration file, and the file wins over the default.

 WHICH PKI
   -Pki <name>              the company. Default agantra (or DefaultPki in pki_tools.cnf).
                            Names: .\pki_setup.ps1 -ListPki. Make a new one: New-PkiConfig.ps1.
   -ListPki                 list the PKIs: names, companies, folders, releases.
   -ConfigFile <file>       a configuration file. Default: <name>_pki.cnf next to this script.
                            It holds validity, algorithms, CA subject, CRL / OCSP / CA Issuers
                            URLs ({ca} = the issuing CA), SAN names, subject fields, policies and
                            the CA names ([ ca_names ]).
   -PkiRoot <folder>        write to exactly this folder.
                            Default: .\pki\pki-<name>-<NN>   (NoCR: pki-<name>-nocr-<NN>)
   -ClassicPKI              build the Classic PKI only (section 13). Not with -Quadrant.
   -Quadrant <1..4>         the quadrants to build. Default 1,2,3,4. Windows Server 2022: 1,2.

 OPENSSL
   -OpenSslPath <exe>       the openssl to use. It must be 4.x. Default: PATH, then common folders.
   -FipsModuleConfig <f>    the fipsmodule.cnf made by "openssl fipsinstall". Needed for quadrants
                            2 and 4. Default: searched next to OpenSSL.

 KEYS AND ALGORITHMS
   -QuadrantRsaBits <n>     quadrant 1 root key: 4096 | 8192 (SHA-384).           Default 4096
   -QuadrantCurve <c>       quadrant 2 root curve: P-384 | P-521 (SHA-384).       Default P-384
   -IntermediateRsaBits <n> quadrant 1 intermediates: 4096 | 8192.                Default 4096
   -IntermediateCurve <c>   quadrant 2 intermediates: P-256 | P-384 | P-521.      Default P-384
   -PqcAlgorithm <a>        Quantum intermediates: mldsa44 | mldsa65 | mldsa87.   Default mldsa87
   -PqcLeafAlgorithm <a>    Quantum test certificates: mldsa44 | mldsa65 | mldsa87.  Default mldsa65
   -PqcFallback             RSA instead of ML-DSA when ML-DSA fails. NOT quantum safe.
   -FallbackRsaBits <n>     RSA size for -PqcFallback: 4096 | 8192.               Default 8192
   -RsaPss                  sign RSA CA certificates with RSASSA-PSS. Old chain engines may
                            refuse PSS. Test first.
   -IntermediatePathLen <n> 0 = an intermediate signs end certificates only (default).
                            1 = it may sign another private CA (SignExternalCa.ps1).

 VALIDITY (from the moment of the build; each level is shorter than the one above)
   Root 1000 years > Track 500 > Quadrant 400 > Intermediate 250 > test certificate
   -RootYears <n>     Default 1000        -TrackYears <n>    Default 500
   -QuadrantYears <n> Default 400         -IntYears <n>      Default 250
   -LeafDays <n>      EV certificate. Default 397 (the maximum).
   -OvLeafYears <n>   OV certificate. Default 3.      -DvLeafYears <n>   DV certificate. Default 5.
 This script makes EV test certificates. The OV and DV defaults are used by GenerateLeafCertificate.

 POLICIES
   -IanaPen <number>        your IANA Private Enterprise Number (optional).
   -EvPolicyOid <oid>       the EV policy. Default 2.23.140.1.1
   Level policies (CA/B Forum defaults): EV 2.23.140.1.1   OV 2.23.140.1.2.2   DV 2.23.140.1.2.1
   Change them in agantra_pki.cnf, section [ policy_oids ]. EV, OV and DV must differ. An empty
   value uses the default, so EV is always present.
   Which CA carries which policy:
     Enterprise Root, Track Roots   all issuance policies (anyPolicy) and EV. Nothing else.
                                    No extended key usage.
     Quadrant Roots                 EV, OV, DV, and the PEN and custom policies.
     Intermediates                  their own level, and the PEN and custom policies.
     Leaves                         their own level, the PEN and custom policies, and -Policy of the
                                    leaf generators.
   With a PEN the certificates also carry
     1.3.6.1.4.1.<PEN>.1     company policy   (Quadrant Roots, intermediates, ALL leaves)
     1.3.6.1.4.1.<PEN>.1.1   company EV       1.3.6.1.4.1.<PEN>.1.2   company OV
     1.3.6.1.4.1.<PEN>.1.3   company DV
   The PEN is NOT in the Enterprise Root and the Track Roots. A PKI built before you set the PEN
   does not have these policies: build it again (-Clean). More policies: [ custom_policies ].

 COMPANY DATA (for the CA subjects and, where it fits, the test certificates)
   -Organization <text>        O.           Default: Agantra Inovatif OU
   -OrganizationalUnit <text>  OU of the test certificates.
   -Country <cc>               C.           Default: EE
   -State <text>               ST.          Default: Tallinn
   -Locality <text>            L.           Default: Tallinn
   -Street <text>              street address.
   -PostalCode <text>          postal code. Default: 15199
   -Serial <text>              serialNumber. CA default EEARIREG.17344131, certificate 17344131
   -BusinessCategory <text>    Private Organization | Government Entity | Business Entity |
                               Non-Commercial Entity
   -JurisdictionCountry <cc>   Default EE.       -JurisdictionState <text>  Default Tallinn.
   -JurisdictionLocality <t>   optional.
   -Domain <name>              the test certificate name and its first DNS name (adds www.<name>)
   -CpsUrl <url>               CPS address on DV and OV policies.
                               Default https://nextmantra.com/security/certs
   -CpsUrlEv <url>             CPS address on EV policies.
                               Default https://nextmantra.com/security/certs/ev-cps.pdf
   -ContactName / -ContactEmail / -ContactPhone     contact fields.
                               Test certificate defaults: BizDevSecOps Administrator,
                               info@nextmantra.com, (+372)53194019.

 TEST CERTIFICATES AND OUTPUT
   -LeafSizes <int[]>       RSA sizes of the quadrant 1 certificate: 2048 | 3072 | 4096 | 8192.
                            Default 2048. Below 2048 is refused.
   -Password <text>         PFX password, 8 or more characters. Default Abc12345!
                            Change it for real use.
   -LegacyPfx               old PFX encryption (3DES, SHA-1) for very old software.
   -SkipLeaf                build the CAs only.

 CRL, OCSP AND TIME STAMPING (made with the PKI, unless you use -SkipRevocation)
   Made after the CAs: one OCSP responder certificate for each Classic intermediate (pki\ocsp),
   one time stamp certificate (pki\tsa, quadrant 1, 1825 days, policy 1.3.6.1.4.1.67096.1.4),
   the CRLs (folder publish), and revocation-info.json with REVOCATION-INFO.txt.
   -SkipRevocation          do not make them.
   -CrlDays <n>             CRL validity. Default 365.
   -OcspDays <n>            OCSP responder certificate validity. Default 365.
   -TimestampQuadrant <n>   1 | 2 | 3 | 4. Default 1 (Classic, no FIPS).
   -TimestampPolicyOid <o>  policy of the time stamp certificate (default: PEN arc .4).
   -TimestampDays <n>       its validity. Default 1825.
   Later: PkiRevocation.ps1 -Help.  E-mail certificates carry emailProtection AND clientAuth.
   File names of CRL and CA files follow the CA names, for example agantra-root-g1.crl,
   agantra-q1-ov-g1.crl (NoCR adds -nocr, release 2 adds -r2).

 9  NAMES OF THE CAs
----------------------------------------------------------------------------------------------------
   Enterprise Root   Agantra Root CA G1
   Track Roots       Agantra Classic Root CA G1          Agantra PQC Root CA G2
   Quadrant Roots    Agantra Classic Q1 Root CA G1       (quadrant 1, no FIPS)
                     Agantra Classic Q2 Root CA G1       (quadrant 2, FIPS)
                     Agantra PQC Q1 Root CA G2           (quadrant 3, no FIPS)
                     Agantra PQC Q2 Root CA G2           (quadrant 4, FIPS)
   Intermediates     Agantra <EV|OV|DV> <algorithm> <G1|G2> CA
                     Example: Agantra OV ECDSA-P384 FIPS G1 CA
 G1 = Classic track. G2 = Quantum track. In names a quadrant is only Q1 (no FIPS) or Q2 (FIPS).
 The numbers 1 to 4 stay in -Quadrant and in the folders.
 Names come from templates. Defaults: scripts\01b_CaNaming.ps1. Override them in
 agantra_pki.cnf section [ ca_names ]. Tokens:
     {Prefix} {QuantumLabel} {Gen} {N} {Level} {Algorithm} {Track} {Id}
 Rules: at most 64 characters, every CA a different name. The script stops and says why.
 See all names first:  .\pki_setup.ps1 -ShowNames

 10  RELEASES AND THE NoCR VARIANT
----------------------------------------------------------------------------------------------------
 Every PKI has its own folder in .\pki :
     pki\pki-default-01  pki\pki-default-02 ...        normal PKI, WITH CRL / OCSP / CA Issuers
     pki\pki-default-nocr-01 ...                       NoCR PKI, WITHOUT them
     pki\pki-raksaka-01  pki\pki-raksaka-nocr-01 ...   the same for another company
 A PKI made by an older version (pki\R1, pki\NoCR-R1 or directly in .\pki) belongs to the default
 PKI and keeps working.
   -NoCaRevocationInfo   build the NoCR PKI. The Enterprise Root, the Track Roots, the Quadrant
                         Roots and the intermediates have no CDP, no OCSP and no caIssuers.
                         For programs that wait for an unreachable CA address (for example
                         signatures in Office). Leaves keep their own revocation settings; use
                         -NoRevocationInfo on the leaf generators to drop them too.
                         NoCR is a SEPARATE set of roots. Leaves of the normal PKI do not chain
                         to it. Remove the trust of the normal PKI, install this one.
   -Release <n>          release 1 to 99, to build, check, reinstall or remove.
                         If R<n> exists (as a folder OR in the Windows store) nothing is built and
                         the script says "R<n> already exists". To replace it: -Clean -Release n.
   -NewRelease           build the next release. This is also the DEFAULT: run the script again
                         without -Release and without -Clean and you get the next free number.
                         Old releases are not touched. Old certificates keep working.
 Names: release 1 has no suffix. From release 2 every CA name ends in " R2", " R3" ...
 NoCR adds " (NoCR)":   Agantra Root CA G1   |   ... G1 R2   |   ... G1 (NoCR) R2
 File names get -nocr and -r2:  agantra-q1-ov-g1-nocr-r2. A name longer than 64 characters uses
 "PQC" for the Quantum word. Leaf names are not changed.
 The other scripts use the LATEST release. -Release <n> picks one. If that release no longer
 exists, they use the latest and print a warning.

 11  WINDOWS TRUST  (administrator PowerShell; other modes need no elevation)
----------------------------------------------------------------------------------------------------
   -InstallTrust      every ROOT to LocalMachine\Root, every INTERMEDIATE to LocalMachine\CA, the
                      test certificate PFX files to LocalMachine\My (only the leaf is imported).
                      Afterwards the script READS THE STORES BACK and prints how many roots and
                      intermediates are in place. A certificate in the wrong store is an error.
                      An Enterprise Root signed by a public CA is an intermediate: it goes to CA.
                      A CA certificate that cannot be installed stops the run. A PFX that Windows
                      cannot import is a warning.
   -ReinstallTrust    install an existing PKI again. No rebuild, no OpenSSL. Moves certificates
                      that are in the wrong store. Use it after an update.
   -Clean             remove the trust and the folder of the release being built, then build.
   -RemoveTrust       remove ONE release or variant from Root, CA and My (files stay). With
                      several releases installed, -Release <n> is required.
   -RemoveAllTrust    remove EVERY certificate with 'Agantra Inovatif' or 'NextMantra' in subject
                      or issuer from Root, CA and My, then delete the .\pki folder.
 A certificate that is already gone is ignored.

 12  CHECK, VERIFY, UNBLOCK  (read only, except -Unblock)
----------------------------------------------------------------------------------------------------
   -Check       preflight. Tests PowerShell, the operating system, OpenSSL 4.x, the default
                provider, the FIPS module (when quadrant 2 or 4 is chosen), blocked files, rights
                and the output folder. Runs a real mini CA with the same OpenSSL options as the
                build. Ends with READY or NOT READY.
   -Verify      checks the PKI in the output folder against pki-manifest.json: keys, digests,
                pathlen, policies, chains, PFX. On Windows it also reports which CA certificates
                are installed.
   -VerifyAll   -Verify for EVERY built PKI in the pki folder (all companies, all releases, normal
                and NoCR), one after the other. Shows each output and a summary (PASSED / FAILED).
                -Pki <name> limits it to one company. Exit code 0 = all passed, 1 = one failed.
   -ShowNames   prints the name templates and every resulting name. Builds nothing.
   -Unblock     removes the "downloaded from the Internet" mark and the read-only attribute from
                every file below the script folder, the PKI folder and the leafcerts folder. Then
                lists the programs that hold files open. Nothing is killed: close the program.
 Every start does the same for its own folder. A script that is blocked the very first time needs:
     Get-ChildItem -Path . -Recurse -File | Unblock-File

 13  CLASSIC PKI AND A PUBLIC CA ROOT
----------------------------------------------------------------------------------------------------
 -ClassicPKI builds only: Enterprise Root, Classic Track Root, Quadrant 1 Root, DV / OV / EV
 intermediates and the quadrant 1 test certificate. RSA only, no FIPS module, no ML-DSA.
 It is the smallest and most compatible PKI, and the shape to use under a public CA.

 Let DigiCert, GlobalSign or Sectigo sign the Enterprise Root. Full text:
 docs\PUBLIC-CA-ENTERPRISE-ROOT.txt
   Model A  The Enterprise Root becomes a subordinate CA of the public CA.
     -EnterpriseRootCsr         make the root key and the request (pki\...\root\root.csr), stop.
     -ExternalCa <name>         DigiCert | GlobalSign | Sectigo | Other. Names the CA in the sheet.
     -EnterpriseRootKeyBits <n> 4096 | 8192. Default 8192. Public CAs rarely accept 8192.
     -ImportEnterpriseRoot <f>  the signed certificate (PEM or DER). It is checked, then ALL CAs
                                are built under it.
     -ExternalChain <file>      the chain of the CA (intermediates and root, PEM).
   Model B  Cross-sign the existing Enterprise Root. Nothing below it changes.
     -CrossSignCsr              the request for the same key and subject (pki\...\cross-sign\).
     -ImportCrossCert <file>    the cross certificate (with -ExternalChain).
 Checks on import: CA:TRUE, pathlen 3 or more, keyCertSign, the certificate is for YOUR key, not
 expired, EKU has serverAuth and clientAuth when present, the chain verifies.
 Never use -Clean together with -ImportEnterpriseRoot. It deletes the key.

 14  OUTPUT  (.\pki\pki-<name>-<NN>)
----------------------------------------------------------------------------------------------------
   root\root.crt .key .pfx                Enterprise Root (public CA: external-chain.pem,
                                          external-request.txt, cross-sign\)
   classical\root\  quantum\root\         Track Roots
   classical\q1\{root,dv,ov,ev}\ ...      quantum\q4\{root,dv,ov,ev}\    one folder for each CA:
                                          <id>.crt .key .pfx .cnf <id>-chain.crt, index.txt,
                                          serial, crlnumber, issued\
   leaf\                                  the test certificates: <name>.crt .key -fullchain.crt
                                          .pfx (and -fips.pfx for FIPS certificates)
   publish\                               root.crt, ca-bundle.crt, <name>.crt .crl .pem, README.txt
   server\                                for the CRL / OCSP server (no key): server-info.json,
                                          ca-list.tsv, server.env, expected-urls.tsv,
                                          DNS-RECORDS.txt
   provider-default.cnf, provider-fips.cnf    the provider configuration
   pki-manifest.json, telemetry.json          what was built

 15  LIMITS  (details: docs\PKI-Design-with-FIPS-and-PQC.txt, section 9)
----------------------------------------------------------------------------------------------------
 * Private PKI. Install the Enterprise Root on every client. No browser shows the EV company
   name for a private root.
 * ML-DSA certificates are not accepted for HTTPS by Windows Schannel, Java 25 and the browsers.
   They work in the Windows store and with OpenSSL 3.5+.
 * ML-DSA needs OpenSSL 3.5 or newer (4.x here). The FIPS quadrant needs a FIPS module that
   contains ML-DSA.
 * ML-DSA signatures are large (about 3.3 KB for ML-DSA-65, 4.6 KB for ML-DSA-87). A full chain
   is tens of KB. Some proxies and servers limit header or handshake size.
 * Dates after 2038 can fail on 32 bit systems.
 * RSA 8192 CA keys are slow. Some TLS stacks restrict P-521 (test certificates are P-256).
 * UC Browser and QQ Browser are not verified.
 * The CRL, OCSP and CA Issuers URLs help only when the files of the folder publish are served
   there.
 * OpenSSL 4.0 has short support (about May 2027). OpenSSL 3.5 LTS runs to 2030. Only this
   script needs 4.x.
 * A public CA signs only what it accepts: it may refuse RSA 8192 or P-521, limit the pathlen
   below 3, ask for an HSM, add name constraints and limit the validity (public TLS: 398 days).
   Tested with a stand-in CA, not with DigiCert, GlobalSign or Sectigo.

 16  RELATED SCRIPTS
----------------------------------------------------------------------------------------------------
   GenerateLeafCertificate.ps1 -Help    certificates for every purpose and format
   PkiTransport.ps1 -Help               move the PKI, or make a DevKit      (docs\DevKit-MANUAL.txt)
   PkiRevocation.ps1 -Help              CRL, revoke, OCSP, time stamp
   New-PkiServerPackage.ps1 -Help       Ubuntu server for CRL, OCSP, time stamp
   Export-PkiCa.ps1 -Help               CA files for CDNs
   Create-WebServerConfig.ps1 -Help     nginx and Apache configuration
   Sign-Code.ps1 -Help                  sign your software
   pki_remove.ps1 -Help                 list and remove PKIs
   Setup-GitRepo.ps1 -Help              the private Git repository (execute bit, hooks, LF)
   Settings shared by all scripts (optional): pki_tools.cnf

 EXIT CODES   0 ok    1 error    5 this operating system is not supported
====================================================================================================
'@ | Write-Host
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

if ($Help) {
    Invoke-PagedHelp { Show-PkiHelp }
    exit 0
}

# Where may this script run? (Windows 11 24H2+, Windows Server 2025 / 2022, supported Linux) - error and exit 5 otherwise
. (Join-Path $script:ScriptRoot 'scripts/00a_Platform.ps1'); Assert-PkiPlatform

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

# ------------------------------------------------------------------------------------------------------------
# STANDARD BOOTSTRAP of every main script: UNBLOCK + UNLOCK the whole script folder, children and recursive,
# BEFORE any other script of the folder is loaded (a blocked script cannot be loaded). Same text in
# GenerateLeafCertificate.ps1.
#   unblock = remove the Windows "downloaded from the Internet" mark    unlock = remove the Read-only attribute
# ------------------------------------------------------------------------------------------------------------
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

try {
    # All modules come from ONE loader (scripts\PkiModules.ps1); later scripts load them the same way.
    $PkiModuleSet = 'All'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')
    if ($ListPki) { Show-PkiList -ScriptRoot $script:ScriptRoot; exit 0 }
    if ($VerifyAll) {
        # -VerifyAll = -Verify for EVERY built PKI (all companies, all releases, normal and NoCR), one after the other.
        # -Pki <name> narrows it to one company. Read only. Exit 0 = all passed, 1 = at least one failed or none found.
        $all = @(Get-PkiInstalledPkis -ScriptRoot $script:ScriptRoot -Profile $PkiProfile)
        if ($all.Count -eq 0) { Write-Host '[ERROR] No built PKI found in the pki folder. Build one first (.\pki_setup.ps1 -InstallTrust).' -ForegroundColor Red; exit 1 }
        $me = (Get-Process -Id $PID).Path; $results = @()
        foreach ($p in $all) {
            Write-Host ''; Write-Host ('=' * 100) -ForegroundColor Cyan
            Write-Host (' VERIFY {0} of {1}:  {2}   ({3}, PKI "{4}")' -f ($results.Count + 1), $all.Count, $p.Name, $p.Label, $p.Profile) -ForegroundColor Cyan
            Write-Host ('=' * 100) -ForegroundColor Cyan
            $a = @('-NoProfile', '-File', $PSCommandPath, '-Pki', $p.Profile, '-Release', [string]$p.Release, '-Verify')
            if ($p.NoCr) { $a += '-NoCaRevocationInfo' }
            if ($VerbosePreference -eq 'Continue') { $a += '-Verbose' }
            & $me @a
            $results += [pscustomobject]@{ Name = $p.Name; Label = $p.Label; Profile = $p.Profile; Code = $LASTEXITCODE }
        }
        Write-Host ''; Write-Host ('=' * 100) -ForegroundColor Cyan; Write-Host ' VERIFY ALL - SUMMARY' -ForegroundColor Cyan; Write-Host ('=' * 100) -ForegroundColor Cyan
        foreach ($r in $results) { Write-Host (' {0,-8} {1,-26} {2,-10} {3}' -f $(if ($r.Code -eq 0) { 'PASSED' } else { 'FAILED' }), $r.Name, $r.Label, $r.Profile) -ForegroundColor $(if ($r.Code -eq 0) { 'Green' } else { 'Red' }) }
        $bad = @($results | Where-Object { $_.Code -ne 0 }).Count
        Write-Host ('' + ' {0} PKI(s) checked, {1} passed, {2} failed.' -f $results.Count, ($results.Count - $bad), $bad)
        exit $(if ($bad -gt 0) { 1 } else { 0 })
    }

    # which PKI folder: building a PKI = (variant, release) exactly; -RemoveTrust must name the release when several exist;
    # the other administration modes take the requested release or the latest
    $rootMode = if ($RemoveTrust) { 'Strict' }
                elseif ($Verify -or $ReinstallTrust -or $CrossSignCsr -or $ImportCrossCert) { 'Exact' }
                else { 'Generate' }
    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:($VerbosePreference -eq 'Continue') -RootMode $rootMode
    Invoke-PkiMain
    exit 0
}
catch {
    $failure = $_
    if (Get-Command Write-PkiFatalError -ErrorAction SilentlyContinue) {
        try { Write-PkiFatalError -ErrorRecord $failure }
        catch { Write-Host "[FATAL] $($failure.Exception.Message)" -ForegroundColor Red }
    }
    else { Write-Host "[ERROR] $($failure.Exception.Message)" -ForegroundColor Red }
    exit 1
}
finally {
    if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment }
}
