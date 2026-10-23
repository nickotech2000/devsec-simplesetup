# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Issues leaf certificates (DV, OV or EV) from the Agantra Inovatif Enterprise PKI that pki_setup.ps1
    built: Classic or Quantum (ML-DSA), FIPS or non-FIPS. By default ONE RUN makes a certificate for EVERY
    purpose (ServerAuth, ClientAuth, CodeSigning, EmailProtection, TimeStamping, OcspSigning), each in EVERY
    format (PEM, DER, CER, CERT, P7B, RFC 7468, PFX).

.DESCRIPTION
    Uses the shared modules of the scripts folder (scripts\PkiModules.ps1, set 'Library'), the same leaf
    generator as pki_setup.ps1 and the same naming configuration (agantra_pki.cnf [ leaf_names ]).
    The leaf folders are written to  <script folder>\leafcerts  (NOT inside pki). If a folder exists a NEW
    folder with the date and time is created, nothing is overwritten.
    Before anything is made, the script checks that OpenSSL is 4.x WITH the FIPS module and ML-DSA; if
    not it says so and suggests running Install-DevEnvironment.ps1.
    At every start the script UNBLOCKS and UNLOCKS its folder, children and recursive.

    Full help:  .\GenerateLeafCertificate.ps1 -Help      Manual: docs\GenerateLeafCertificate-MANUAL.txt

.EXAMPLE
    .\GenerateLeafCertificate.ps1 -DnsName www.example.com
        EV, Classic (Q1), RSA 2048: six certificates (one per purpose), every format, one go.
.EXAMPLE
    .\GenerateLeafCertificate.ps1 -OV -Quantum -FIPS -DnsName mtls.example.com -ExcludePurpose TimeStamping,OcspSigning
.EXAMPLE
    .\GenerateLeafCertificate.ps1 -OV -Purpose DocumentSigning,DocumentSigningAdobe,1.3.6.1.4.1.99999.1 -Format PFX
        (5.3.7) one document signing certificate: Microsoft Office, Adobe PDF and a custom EKU OID.
    .\GenerateLeafCertificate.ps1 -DV -DnsName a.example.com -Purpose ServerAuth,ClientAuth -Format PFX
        ONE certificate with exactly these purposes, only the PFX.
#>
# No [CmdletBinding()]: it would reserve -EV and -OV (aliases of -ErrorVariable / -OutVariable), the names of the
# levels. -Verbose is declared below instead.
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    # ---- level and quadrant (default: -EV, -Classic, non-FIPS) ----
    [switch]$DV,
    [switch]$OV,
    [switch]$EV,
    [switch]$Classic,
    [switch]$Quantum,
    [switch]$FIPS,

    # ---- purposes: none given = ONE CERTIFICATE PER PURPOSE (the set) ----
    [switch]$AllPurposes,
    [ArgumentCompleter({ param($cmd, $par, $word) 'ServerAuth', 'ClientAuth', 'ServerClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning', 'DocumentSigning', 'DocumentSigningAdobe' | Where-Object { $_ -like "$word*" } })]
    [string[]]$Purpose,
    [ValidateSet('ServerAuth', 'ClientAuth', 'ServerClientAuth', 'CodeSigning', 'EmailProtection', 'TimeStamping', 'OcspSigning', 'DocumentSigning', 'DocumentSigningAdobe')][string[]]$ExcludePurpose,

    # ---- names ----
    [string[]]$DnsName,
    [string[]]$IpAddress,
    [string[]]$EmailAddress,
    [string]$CommonName,
    [switch]$AddDevelopmentSAN,

    # ---- revocation information (4.9.5) ----
    [switch]$NoCrl,
    [switch]$NoOcsp,
    [switch]$NoRevocationInfo,
    [Alias('CodesignCompany')][string]$CodeSigningCompany,

    # ---- key and signature ----
    [ValidateSet('RSA', 'ECDSA', 'MLDSA')][string]$KeyType,
    [int]$KeyBits,
    [ValidateSet('P-256', 'P-384', 'P-521')][string]$Curve,
    [ValidatePattern('^(?i)ml-?dsa-?(44|65|87)$')][string]$PqcAlgorithm,
    [string]$Hash,

    # ---- validity and policies ----
    [ValidateRange(1, 36500)][int]$Days,
    # ---- time stamping: Classic non-FIPS (Quadrant 1) by default; the parameters prepare another one ----
    [ValidateSet(1, 2, 3, 4)][int]$TimestampQuadrant,
    [string]$TimestampPolicyOid,
    [ValidateRange(1, 36500)][int]$TimestampDays,
    [ValidateRange(1, 3650)][int]$OcspDays,
    [string[]]$Policy,
    [string]$CpsUrl,
    [string]$CpsUrlEv,

    # ---- subject values: default comes from agantra_pki.cnf ----
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
    [string]$Duns,
    [string]$ContactName,
    [string]$ContactEmail,
    [string]$ContactPhone,

    # ---- output ----
    [ValidateSet('PEM', 'DER', 'CER', 'CERT', 'P7B', 'RFC7468', 'PFX', 'ALL')][string[]]$Format = @('ALL'),
    [ValidateSet('sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-384', 'sha3-512', 'None')][string[]]$HashFile = @('sha256', 'sha512'),
    [string]$OutputRoot,
    [string]$Password = 'Abc12345!',
    [switch]$LegacyPfx,
    [switch]$NoGuidance,
    [switch]$InstallPfx,

    # ---- information, unblock / unlock ----
    [switch]$List,
    [switch]$Check,
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose,

    # ---- environment ----
    [string]$ConfigFile,
    [string]$PkiRoot,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [string]$OpenSslPath,
    [string]$FipsModuleConfig,
    [switch]$Version
)
# >>> PKI-VERSION-INFO (generated by tools/Update-VersionBlock.ps1 - do not edit here, edit the tool source)
$script:PkiVerNumber = '7.9.11'
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


$ErrorActionPreference = 'Stop'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:PkiHashFileAlgs = @($HashFile)      # 6.4.2: <name>.sha256 / .sha512 next to every certificate

function Show-PkiLeafHelp {
    @'
====================================================================================================
 GenerateLeafCertificate.ps1  -  make the certificates of the Agantra Inovatif Enterprise PKI
 Version 7.9.11
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\GenerateLeafCertificate-MANUAL.txt        Words : docs\GLOSSARY.txt
 Linux  : GenerateLeafCertificate.sh (DevKit). It needs bash and openssl only.

WHAT IT DOES
  One command makes SEVEN certificates, each in all file formats, and checks every one:
      .\GenerateLeafCertificate.ps1 -DnsName www.example.com
  Files go to  .\leafcerts\<name>\<purpose>\   (never into the pki folder).
  Nothing is overwritten. A second run makes a new folder: <name>_<yyyyMMdd>-<HHmmss>.
  A set is all or nothing. If one certificate fails, the new folder is removed.

QUICK START
  1. Check OpenSSL ........ .\GenerateLeafCertificate.ps1 -Check
  2. Make the set ......... .\GenerateLeafCertificate.ps1 -DnsName www.example.com
  3. See what was made .... .\GenerateLeafCertificate.ps1 -List
  Defaults: EV level, Classic track, no FIPS, RSA 2048 (code signing RSA 4096), 397 days.

BEFORE YOU START
  * The PKI exists (pki_setup.ps1 was run).     * PowerShell 7 or newer.
  * OpenSSL 4.x with the FIPS module and ML-DSA. A missing part that THIS run needs stops the
    script. Fix: .\Install-DevEnvironment.ps1 -Only OpenSSL,7Zip, then open a NEW window.
  * Files from a zip may be blocked. Every start unblocks and unlocks the script folders.
    -Unblock does only that.

THE SEVEN CERTIFICATES
  ServerAuth         TLS server                    folder serverauth
  ClientAuth         TLS client (mutual TLS)       folder clientauth
  ServerClientAuth   TLS server AND client         folder serverauth-clientauth
  CodeSigning        sign programs and scripts     folder codesigning
  EmailProtection    S/MIME e-mail + client login  folder emailprotection
  TimeStamping       RFC 3161 time stamp server    folder timestamping
  OcspSigning        OCSP responder                folder ocspsigning
  Each one has its own key. The three TLS ones are three separate certificates.

CHOOSE PURPOSES
  -ExcludePurpose <list>  Leave purposes out of the set, for example TimeStamping,OcspSigning.
  -AllPurposes            The set. This is the default. The switch only says it out loud.
  -Purpose <list>         NOT a set. ONE certificate with exactly these purposes, for example
                          ServerAuth,EmailProtection. Do not combine it with -ExcludePurpose.
                          TimeStamping and OcspSigning must stand alone.
                          ServerAuth,ClientAuth (nothing else) makes the three TLS certificates.
                          Extra purposes, only with -Purpose:
                            DocumentSigning       Word, Excel, PowerPoint, Microsoft 365
                            DocumentSigningAdobe  Adobe Acrobat and Reader PDF
                            1.3.6.1.4.1.99999.1.2 your own purpose, a dotted number (custom EKU)
                          Both document purposes in one certificate:
                          -Purpose DocumentSigning,DocumentSigningAdobe

LEVEL AND QUADRANT   (defaults: -EV, -Classic, no -FIPS)
  -DV | -OV | -EV         Domain / Organization / Extended validation. Picks the intermediate CA.
  -Classic | -Quantum     Classic = RSA or ECDSA. Quantum = ML-DSA.
  -FIPS                   Use the FIPS provider.
  Quadrant numbers:       -Classic = 1,  -Classic -FIPS = 2,  -Quantum = 3,  -Quantum -FIPS = 4.
  In file names the digit is Q1 = no FIPS and Q2 = FIPS, in both tracks.
  Use Classic for browsers, IIS, Kestrel and Java. Use Quantum for OpenSSL services only.
  A quadrant the PKI does not have is refused, with the way to build it.

NAMES
  -DnsName <a,b>     -IpAddress <a,b>     -EmailAddress <a,b>     -CommonName <text>
  The first DNS name is the CN and the folder name. Wildcards (*.example.com) are allowed.
  With no names, the [ leaf_san ] list of agantra_pki.cnf is used.
  ServerAuth and ClientAuth need a DNS name or an IP. EmailProtection needs an e-mail address.
  -CommonName replaces the CN of the TLS certificates.

SUBJECT   (DV: CN.  OV: company and address.  EV: OV plus business fields.)
  -Organization -OrganizationalUnit -Country -State -Locality -Street -PostalCode
  -Serial -BusinessCategory -JurisdictionCountry -JurisdictionState -JurisdictionLocality
  -Duns <number>      EV: organizationIdentifier = DUNS+<number> (a private convention)
  -ContactName -ContactEmail -ContactPhone       Defaults: [ subject_ov ] / [ subject_ev ].
  CODE SIGNING SUBJECT: always short:  C = EE  ST = Tallinn  L = Tallinn  O = CN = <company>.
      -CodeSigningCompany <name>   (alias -CodesignCompany). Empty = your organization.
      -Country / -State / -Locality change C, ST, L. The name may have 64 characters at most.

KEYS, HASHES AND VALIDITY   (weak values are REJECTED, not corrected)
  -KeyType RSA|ECDSA|MLDSA     Default: Q1 RSA, Q2 ECDSA, Q3 and Q4 MLDSA.
  -KeyBits 2048|3072|4096|8192 Default 2048.
  -Curve P-256|P-384|P-521     Default P-256.
  -PqcAlgorithm mldsa44|65|87  Default mldsa65.
  -Hash sha256|sha384|sha512   Default: the issuer's. SHA-1, SHA-224 and MD5 are rejected.
  Code signing is raised: RSA 4096, ECDSA P-384, ML-DSA 65, SHA-256 or stronger.
  -Days <n>                    EV 397 days, OV 3 years, DV 5 years. Never longer than the issuer.
  -Policy <list>               Extra policies: "OID" or "OID|CPS-URL".
  -CpsUrl <url>                CPS pointer for DV and OV
                               (default https://nextmantra.com/security/certs).
  -CpsUrlEv <url>              CPS pointer for EV (default .../security/certs/ev-cps.pdf).
  Every leaf has the level policy and the company policies. Every OV leaf also has High Assurance.

TIME STAMPING AND OCSP
  The TimeStamping leaf IS the RFC 3161 time stamp server certificate (critical, stands alone).
  -TimestampQuadrant 1|2|3|4   Default 1 (Classic, no FIPS). 3 and 4 are for the future.
  -TimestampPolicyOid <oid>    The TSA policy OID.
  -TimestampDays <n>           Default 1825.            -OcspDays <n>   Default 365.
  Config: [ timestamp ] in agantra_pki.cnf.

FILES YOU GET   (-Format <list>, default ALL)
  Always:  <name>.crt  .key (PKCS#8, PRIVATE)  .pub  .pub.der  -fullchain.crt  -chain.crt  .cnf
  Formats: PEM .pem   DER .der   CER .cer   CERT .cert   P7B .p7b   RFC7468 .rfc7468.pem
           PFX .pfx (key + chain + password). A FIPS leaf also gets <name>-fips.pfx.
  Also in every folder: convert-formats.ps1, leaf-info.json and, for ServerAuth and ClientAuth,
  tls-guidance.txt. In the set folder: leaf-set.json.
  -Password <text>     PFX password. Default Abc12345! (the lab password).
  -LegacyPfx           3DES / SHA-1 PFX for very old software.
  -NoGuidance          Do not write convert-formats.ps1 and tls-guidance.txt.
  -InstallPfx          Windows: also import the leaf PFX files into LocalMachine\My (administrator).
  -OutputRoot <path>   Where the leaf folders go. Default .\leafcerts.

HASH FILES
  -HashFile <list>   A hash file for every certificate: <name>.sha256 and <name>.sha512 (default).
                     Values: sha256 sha384 sha512 sha3-256 sha3-384 sha3-512 None.
  Each line is "<hash>  <file>". It covers .crt .pem .cer .cert .der .p7b .rfc7468.pem .pfx.
  Check:  sha256sum -c <name>.sha256      (Windows: Get-FileHash <file> -Algorithm SHA256)

REVOCATION SWITCHES
  -NoCrl             No CRL address in the certificates.
  -NoOcsp            No OCSP address. The CA issuer address stays.
  -NoRevocationInfo  Both. For offline or development systems. The certificate then cannot be
                     checked or revoked by CRL or OCSP.
  -NoCaRevocationInfo  Sign with the NoCR family of CAs. Without a NoCR PKI the script stops;
                     build one: .\pki_setup.ps1 -NoCaRevocationInfo -InstallTrust

DEVELOPMENT SAN   (-AddDevelopmentSAN, DEVELOPMENT ONLY)
  Adds 21 DNS names, 603 IP addresses and 4 e-mail addresses after your own names.
  ServerAuth, ClientAuth, ServerClientAuth: everything. EmailProtection: e-mails only.
  CodeSigning, TimeStamping, OcspSigning: nothing.
  With -EV the EV SAN rules are NOT applied. A warning is printed. leaf-info.json says
  developmentSan = true. A public CA would never issue such a certificate.
  Change the list in [ development_san ] of agantra_pki.cnf (a range: 1024 addresses at most).
  The e-mail certificate then uses ECDSA P-384 / SHA-512 by default.

WHICH PKI
  -Pki <name>          The company. File <name>_pki.cnf. Default: agantra.
                       List them: .\pki_setup.ps1 -ListPki
  -PkiRoot <path>      One PKI folder. Default: the latest release in .\pki\.
  -Release <n>         Use release n. A deleted release = the latest, with a warning.
  -ConfigFile <path>   The configuration file. Default agantra_pki.cnf.
  -OpenSslPath <path>  Use this openssl (4.x).     -FipsModuleConfig <path>   fipsmodule.cnf.

INFORMATION
  -List      Leaf certificates made so far.        -Check    OpenSSL readiness only.
  -Unblock   Unblock and unlock the folders, then stop.
  -Verbose   Show every OpenSSL command.           -Help     This text.
  -Version   Show version, author, OS and tool versions.

FILE NAMES   (agantra_pki.cnf [ leaf_names ])
  Example:  leafcerts\www.example.com\serverauth\www.example.com-server-ev-q1-rsa2048.crt
  Tokens: {Name} {Level} {Quadrant} {Tag} {Algorithm} {Track} {Fips} {Purpose} {PurposeName}
          {Date} {Time}. An unknown token stops the script at the start.

RECIPES
  .\GenerateLeafCertificate.ps1 -OV -DnsName shop.example.com `
        -ExcludePurpose TimeStamping,OcspSigning
  .\GenerateLeafCertificate.ps1 -OV -DnsName shop.example.com `
        -Purpose ServerClientAuth -Format PFX
  .\GenerateLeafCertificate.ps1 -OV -Purpose CodeSigning -CodeSigningCompany "Example Ltd"
  .\GenerateLeafCertificate.ps1 -DV -Purpose EmailProtection -EmailAddress user@example.com
  .\GenerateLeafCertificate.ps1 -OV -Classic -FIPS -DnsName api.example.com `
        -KeyType ECDSA -Curve P-384
  .\GenerateLeafCertificate.ps1 -EV -Quantum -DnsName mtls.example.com
  .\GenerateLeafCertificate.ps1 -EV -DnsName api.nextmantra.com -AddDevelopmentSAN
  .\GenerateLeafCertificate.ps1 -OV -DnsName lab.example.com -NoRevocationInfo

LIMITS
  * ML-DSA leaves (-Quantum): Windows Schannel, Java 25 and browsers do not accept them for HTTPS.
  * Private PKI: wildcard and internal names work here. A public CA would refuse some.
  * EV leaves are capped at 397 days. -AddDevelopmentSAN leaves are not EV-conformant.
  * Protect the folder: it holds private keys and the PFX password. Never e-mail a .key file.
  * Leaves of version 4.6 are in pki\leafcerts. They are not moved.

WHERE IT RUNS
  Windows 11 24H2 or newer, Windows Server 2025, and Windows Server 2022 (Classic track only).
  Linux with pwsh. Refused (exit 5): Windows 10, older Windows 11, macOS and special editions.

EXIT CODES
  0 done       1 error or not ready       5 this system is refused
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

if ($Help) {
    Invoke-PagedHelp { Show-PkiLeafHelp }
    exit 0
}

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

# ------------------------------------------------------------------------------------------------------------
# STANDARD BOOTSTRAP of every main script: UNBLOCK + UNLOCK the whole script folder, children and recursive,
# BEFORE any other script of the folder is loaded (a blocked script cannot be loaded). Same text in pki_setup.ps1.
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

$script:LeafFolderCreated = $null
try {
    # The same shared modules as pki_setup.ps1 (the 'Library' set: everything except the pki_setup orchestration).
    $PkiModuleSet = 'Library'
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    # ---------------- selection ----------------
    if (@($DV, $OV, $EV | Where-Object { $_ }).Count -gt 1) { throw 'Use only one of -DV, -OV and -EV.' }
    if ($Classic -and $Quantum) { throw 'Use only one of -Classic and -Quantum.' }
    if ($Purpose) { foreach ($pn in @($Purpose)) { if (-not (Test-PkiPurposeName -Name $pn)) { throw "Unknown purpose '$pn'. Use ServerAuth, ClientAuth, ServerClientAuth, CodeSigning, EmailProtection, TimeStamping, OcspSigning, DocumentSigning, DocumentSigningAdobe, or a custom EKU as a dotted OID (for example 1.3.6.1.4.1.99999.1.2)." } } }
    if ($Purpose -and ($AllPurposes -or $ExcludePurpose)) { throw '-Purpose makes ONE certificate with exactly those purposes; it cannot be combined with -AllPurposes or -ExcludePurpose (the set).' }
    $level = if ($DV) { 'DV' } elseif ($OV) { 'OV' } else { 'EV' }
    $track = if ($Quantum) { 'Quantum' } else { 'Classic' }
    $quadrant = if ($Quantum) { if ($FIPS) { 4 } else { 3 } } else { if ($FIPS) { 2 } else { 1 } }

    Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
    if ([bool]$script:Pki.ClassicOnly -and $Quantum) { throw 'This computer is Windows Server 2022: only the CLASSIC track can be issued (Quadrant 1 and 2; FIPS and non-FIPS; DV / OV / EV). The Quantum track (-Quantum, ML-DSA) needs Windows 11 24H2 or newer / Windows Server 2025.' }
    $c = $script:Pki
    Test-PkiLeafNaming
    $leafRoot = Get-PkiLeafRoot

    # ---------------- -Unblock: UNBLOCK + UNLOCK, children and recursive ----------------
    if ($Unblock) {
        Write-PkiLog 'UNBLOCK + UNLOCK (children and recursive)'
        Write-PkiLog "Start-up bootstrap of this script: $($script:BootstrapUnlocked) read-only item(s) unlocked in $($script:ScriptRoot) (the Internet mark is removed on Windows)."
        [void](Invoke-PkiUnblockUnlock -Path @($script:ScriptRoot, $c.PkiRoot, $leafRoot))
        exit 0
    }
    if ($List) { Show-PkiLeafIndex -Root $leafRoot; exit 0 }

    if (-not ($DV -or $OV -or $EV)) { Write-PkiLog 'No -DV / -OV / -EV given: using -EV.' }
    if (-not ($Classic -or $Quantum)) { Write-PkiLog 'No -Classic / -Quantum given: using -Classic.' }
    if (-not $FIPS) { Write-PkiLog 'No -FIPS given: non-FIPS quadrant.' }
    # ServerAuth + ClientAuth asked together (and nothing else) = THREE certificates: server only, client only, server + client.
    $threeTls = $false
    if ($Purpose) {
        $pu = @($Purpose | Select-Object -Unique)
        if (($pu -contains 'ServerAuth') -and ($pu -contains 'ClientAuth') -and (@($pu | Where-Object { $_ -notin 'ServerAuth', 'ClientAuth', 'ServerClientAuth' }).Count -eq 0)) { $threeTls = $true }
    }
    $setMode = (-not [bool]$Purpose) -or $threeTls
    $purposes = @(if (-not [bool]$Purpose) { $script:PkiPurposeProfiles.Keys | Where-Object { @($ExcludePurpose) -notcontains $_ -and -not $script:PkiPurposeProfiles[$_].Contains('NotInSet') } } elseif ($threeTls) { @('ServerAuth', 'ClientAuth', 'ServerClientAuth') } else { $Purpose })
    if ($setMode -and $purposes.Count -eq 0) { throw '-ExcludePurpose removed every purpose: nothing to make.' }
    Write-PkiLog "Leaf: $level, $track$(if ($FIPS) { ' FIPS' }) = Quadrant $quadrant, issuer q$quadrant-$($level.ToLowerInvariant())"
    Write-PkiLog $(if ($setMode) { "Set: one certificate for each of $($purposes.Count) purposes ($($purposes -join ', ')), every format, in one go." } else { "One certificate with the purposes: $($Purpose -join ', ')." })
    if (($purposes -contains 'ServerAuth') -and ($purposes -contains 'ClientAuth') -and $setMode) { Write-PkiLog 'TLS: ServerAuth and ClientAuth are made as THREE certificates: server only, client only, and one with both (ServerClientAuth).' }
    Write-PkiLog "Output folder: $leafRoot"
    $oldLeaf = Join-Path $c.PkiRoot 'leafcerts'
    if ((Test-Path -LiteralPath (Join-Path $oldLeaf 'leaf-index.json')) -and ($oldLeaf -ne $leafRoot)) {
        Write-PkiLog "Leaf folders of version 4.6 are still in $oldLeaf (they are not moved)." 'INFO'
    }

    # ---------------- OpenSSL 4.x with FIPS and quantum: BEFORE anything is made ----------------
    Initialize-OpenSSL
    if ($Check) {
        $ready = $true
        try { [void](Assert-PkiLeafOpenSslReady -NeedFips $true -NeedPqc $true) }
        catch { $ready = $false; Write-Host ''; foreach ($l in ($_.Exception.Message -split "`r?`n")) { Write-Host $l -ForegroundColor Yellow } }
        Write-Host ''
        if ($ready) { Write-Host 'READY: OpenSSL 4.x with the FIPS provider and ML-DSA.' -ForegroundColor Green; exit 0 }
        Write-Host 'NOT READY: see above (run Install-DevEnvironment.ps1 as suggested).' -ForegroundColor Red
        exit 1
    }
    [void](Assert-PkiLeafOpenSslReady -NeedFips ([bool]$FIPS) -NeedPqc ([bool]$Quantum))

    # ---------------- the existing PKI ----------------
    $m = Import-PkiExisting -SkipProviders
    if ($c.Quadrants -notcontains $quadrant) {
        $have = ($c.Quadrants | ForEach-Object { "Q$_" }) -join ', '
        throw "This PKI has no Quadrant $quadrant ($track$(if ($FIPS) { ' FIPS' })); it contains: $have.`nUse another quadrant, or build the missing ones: .\pki_setup.ps1 -Clean -Quadrant 1,2,3,4 (a new PKI)."
    }
    $issuer = Get-PkiCa -Id "q$quadrant-$($level.ToLowerInvariant())"
    Write-PkiLog "Issuer: $($issuer.Id)  [$($c.Built[$issuer.Id].commonName)]"

    $base = @{
        Level = $level; Quadrant = $quadrant; DnsName = $DnsName; IpAddress = $IpAddress; EmailAddress = $EmailAddress
        CommonName = $CommonName; KeyType = $KeyType; KeyBits = $KeyBits; Curve = $Curve
        PqcAlgorithm = $PqcAlgorithm; Hash = $Hash; Days = $Days; Policy = $Policy; Format = $Format
        AddDevelopmentSan = [bool]$AddDevelopmentSAN; CodeSigningCompany = $CodeSigningCompany
        NoCrl = [bool]($NoCrl -or $NoRevocationInfo); NoOcsp = [bool]($NoOcsp -or $NoRevocationInfo)
    }
    if ($base.NoCrl -or $base.NoOcsp) { Write-PkiLog ('Revocation information left OUT of every generated certificate: ' + $(if ($base.NoCrl) { 'no CRL distribution point' }) + $(if ($base.NoCrl -and $base.NoOcsp) { ', ' }) + $(if ($base.NoOcsp) { 'no OCSP URL' }) + '. These certificates cannot be revoked by CRL/OCSP; development / Office use only.') 'WARN' }
    if ($purposes -contains 'CodeSigning') {
        $csDn = Get-PkiCodeSigningDn -Company $CodeSigningCompany -Level $level
        Write-PkiLog ('Code signing subject: ' + (($csDn | ForEach-Object { '{0}={1}' -f $_[0], $_[1] }) -join ', '))
    }
    if ($AddDevelopmentSAN) {
        $devList = Get-PkiDevelopmentSan
        Write-PkiLog "-AddDevelopmentSAN: $($devList.Dns.Count) DNS names, $($devList.Ip.Count) IP addresses and $($devList.Email.Count) e-mail addresses ($($devList.Source)) are added to the SAN of the TLS certificates (S/MIME: the e-mail addresses only; code signing, time stamping and OCSP carry no SAN)." 'WARN'
        if ($level -eq 'EV') { Write-PkiLog 'EV: the SAN rules of EV certificates (no wildcard, no IP address, no internal name, no e-mail address) are deliberately NOT applied. The subject, the EV policy and the 397-day limit stay. For development only; no public CA would issue this.' 'WARN' }
    }
    if ($purposes -contains 'TimeStamping') {
        $ts = Get-PkiTimestampSettings
        Write-PkiLog ("Time stamping certificate: Quadrant {0} ({1}{2}), policy OID {3}, valid {4} days (Classic non-FIPS is the default; -TimestampQuadrant, -TimestampPolicyOid, -TimestampDays change it)." -f $ts.Quadrant, $(if ($ts.Quadrant -in 3, 4) { 'Quantum' } else { 'Classic' }), $(if ($ts.Quadrant -in 2, 4) { ' FIPS' } else { ' non-FIPS' }), $(if ($ts.PolicyOid) { $ts.PolicyOid + $(if ($ts.Derived) { ' (from your IANA PEN)' }) } else { '(none: set one)' }), $ts.Days)
        if ($ts.Quadrant -in 3, 4) { Write-PkiLog 'A quantum time stamping certificate cannot be used by the PKI server kit yet (openssl ts signs with RSA / ECDSA).' 'WARN' }
    }
    $items = [System.Collections.Generic.List[hashtable]]::new()
    $setFolder = $null
    $setName = ''

    if ($setMode) {
        # ---------------- the SET: decide everything first, then write ----------------
        $specs = New-PkiLeafSetSpecs -Base $base -Purposes $purposes
        $script:LeafFolderCreated = $null          # Invoke-PkiLeafSet removes its own folder when it fails
        $res = Invoke-PkiLeafSet -Specs $specs -LeafRoot $leafRoot -Guidance:(-not $NoGuidance)
        $setFolder = $res.Folder
        $setName = $setFolder.Name
        foreach ($it in $res.Items) { [void]$items.Add($it) }
    }
    else {
        # ---------------- ONE certificate with the given purposes ----------------
        $one = $base.Clone(); $one.Eku = @(Resolve-PkiPurposeEku -Purpose $Purpose)
        $spec = New-PkiLeafSpec -Options $one
        $folder = New-PkiUniqueFolder -Root $leafRoot -Name $spec.Folder -SuffixTemplate $spec.UniqueSuffix
        $script:LeafFolderCreated = $folder.Path
        $spec.OutDir = $folder.Path
        if ($folder.Renamed) { Write-PkiLog "The folder '$($spec.Folder)' exists already: a NEW folder was created: $($folder.Name)" 'WARN' }
        $r = New-PkiLeafCertificate -Spec $spec
        $validation = Test-PkiLeafResult -Spec $spec -R $r
        Write-PkiLog 'Validation passed: chain, key, purpose, policies and every file.' 'OK'
        foreach ($oid in $validation.UnsupportedPolicies) {
            Write-PkiLog "Policy $oid is in the leaf but the issuing CA does not carry it: a policy-processing client will not see it asserted by the chain." 'WARN'
        }
        if (-not $NoGuidance) { [void](Write-PkiLeafGuidance -Spec $spec -R $r) }
        $r.Files = @(@(Get-ChildItem -LiteralPath $r.Dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name }) + @('leaf-info.json') | Sort-Object -Unique)
        $setFolder = $folder; $setName = ''
        [void]$items.Add(@{ Spec = $spec; Result = $r; Relative = $folder.Name })
        $script:LeafFolderCreated = $null
    }

    # ---------------- index, per-leaf info, set info ----------------
    foreach ($it in $items) {
        $entry = Add-PkiLeafIndex -Root $leafRoot -Spec $it.Spec -R $it.Result -FolderName $it.Relative -Set $setName
        Write-Utf8NoBom -Path (Join-Path $it.Result.Dir 'leaf-info.json') -Content ($entry | ConvertTo-Json -Depth 6)
    }
    if ($setMode) {
        $setInfo = [ordered]@{
            set = $setName; path = $setFolder.Path; level = $level; quadrant = $quadrant; track = $track; fips = [bool]$FIPS
            purposes = @($items | ForEach-Object { $_.Spec.Eku -join '+' }); developmentSan = [bool]$AddDevelopmentSAN; formats = @($items[0].Spec.Formats)
            createdUtc = [DateTime]::UtcNow.ToString('o'); generator = "GenerateLeafCertificate.ps1 $($script:PkiGeneratorVersion)"
            certificates = @($items | ForEach-Object { [ordered]@{ purpose = ($_.Spec.Eku -join '+'); folder = $_.Relative; stem = $_.Result.Stem; keyAlgorithm = $_.Result.Actual.Algorithm; notAfter = $_.Result.NotAfter; sha1 = $_.Result.Sha1 } })
        }
        Write-Utf8NoBom -Path (Join-Path $setFolder.Path 'leaf-set.json') -Content ($setInfo | ConvertTo-Json -Depth 6)
    }

    # ---------------- UNBLOCK + UNLOCK what was written ----------------
    [void](Unblock-PkiTree -Path @($setFolder.Path)); [void](Unlock-PkiTree -Path @($setFolder.Path))

    # ---------------- Windows: leaf PFX into My ----------------
    if ($InstallPfx) {
        if (-not $IsWindows) { Write-PkiLog '-InstallPfx is for Windows; skipped.' 'WARN' }
        else {
            Assert-Administrator
            foreach ($it in $items) {
                if (-not $it.Result.Pfx) { Write-PkiLog "-InstallPfx: no PFX for $($it.Result.Stem) (add PFX to -Format); skipped." 'WARN'; continue }
                $res2 = Install-PkiLeafPfx -Leaf ([ordered]@{ name = $it.Result.Stem; pfx = $it.Result.Pfx; sha1 = $it.Result.Sha1 })
                if ($res2.Status -eq 'failed') { Write-PkiLog "The PFX of $($it.Result.Stem) could not be imported: $($res2.Message)" 'WARN' }
            }
        }
    }

    # ---------------- summary ----------------
    Write-Host ''
    Write-Host $(if ($setMode) { 'LEAF CERTIFICATE SET' } else { 'LEAF CERTIFICATE' }) -ForegroundColor Cyan
    Write-Host ("  Folder     : {0}" -f $setFolder.Path)
    Write-Host ("  Level      : {0}   Quadrant {1} ({2}{3})   Issuer {4}" -f $level, $quadrant, $track, $(if ($FIPS) { ' FIPS' } else { '' }), $issuer.Id)
    Write-Host ("  Formats    : {0}" -f ($items[0].Spec.Formats -join ', '))
    if ($AddDevelopmentSAN) { Write-Host ("  Dev SAN    : {0} DNS, {1} IP, {2} e-mail in the TLS certificates{3}" -f $devList.Dns.Count, $devList.Ip.Count, $devList.Email.Count, $(if ($level -eq 'EV') { ' (EV SAN rules NOT applied)' } else { '' })) -ForegroundColor Yellow }
    Write-Host ''
    Write-Host ('  {0,-16} {1,-12} {2,-6} {3,-11} {4}' -f 'PURPOSE', 'KEY', 'DAYS', 'EXPIRES', 'SUBJECT CN / FOLDER') -ForegroundColor Cyan
    foreach ($it in $items) {
        $cn = (@($it.Spec.DnPairs | Where-Object { $_[0] -eq 'CN' }) | Select-Object -First 1)[1]
        Write-Host ('  {0,-16} {1,-12} {2,-6} {3,-11} {4}' -f ($it.Spec.Eku -join '+'), $it.Result.Actual.Algorithm, $it.Result.Days, $it.Result.NotAfter, $cn)
        Write-Host ('  {0,-16} {1}' -f '', $it.Relative) -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  Files in every purpose folder:'
    Write-Host ('      ' + (($items[0].Result.Files | ForEach-Object { $_.Replace($items[0].Result.Stem, '<name>') }) -join '   '))
    Write-Host '      (<name> = the certificate name of that folder: the key <name>.key and the public key <name>.pub are in EVERY purpose folder)'
    Write-Host ''
    Write-PkiLog "$($items.Count) certificate(s) ready in $($setFolder.Path)" 'OK'
    if (-not $NoGuidance) { Write-PkiLog 'convert-formats.ps1 (every format) in each folder; tls-guidance.txt for ServerAuth / ClientAuth.' 'INFO' }
    exit 0
}
catch {
    $failure = $_
    # a folder this run created for a leaf that failed is removed (it is new and holds nothing else)
    if ($script:LeafFolderCreated -and (Test-Path -LiteralPath $script:LeafFolderCreated)) {
        if (Get-Command Unlock-PkiTree -ErrorAction SilentlyContinue) { [void](Unlock-PkiTree -Path @($script:LeafFolderCreated)) }
        Remove-Item -LiteralPath $script:LeafFolderCreated -Recurse -Force -ErrorAction SilentlyContinue
    }
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
