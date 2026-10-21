# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Carries the Agantra Inovatif Enterprise PKI to other machines as a password-protected ".certpacked" file
    (SOURCE: -Pack) and, on a Windows 11 24H2 or newer (Windows Server 2025 / 2022) destination, unpacks it and installs the trust (-Install).

.DESCRIPTION
    A .certpacked file is a zip or 7z archive with a password under another name.
    -Pack     makes it from the pki folder (and, if you say so, the leafcerts folder).
    -Install  DESTINATION, Windows 11 24H2 or newer (Windows Server 2025 / 2022) only: scans the machine (Windows version, OpenSSL 4.0.1+),
              and only when the scan passes unpacks the package and installs the CAs in the Windows stores.
    -DevKit   SOURCE: ONE zip (or 7z) for the developers: the .certpacked (CA certificates + the keys of the ISSUING CAs, no root key),
              Install-PkiTrust.ps1 / .sh, the leaf / person / Office 365 generators and SignCsr as .ps1 and .sh, Make-ShExecutable.ps1 /
              make-executable.sh, devkit.env, the manuals, and the folder server\ (the SERVER KIT, no private key: server\linux\pki-server\pki-server.sh + the PKI public data:
              CRL, OCSP and time stamp server on Ubuntu 24.04 / 26.04; -DevKitNoServer leaves it out). Manual: docs\DevKit-MANUAL.txt
    -Server   SOURCE: ONE zip for the CRL / OCSP / time stamp server on Ubuntu 24.04 / 26.04 (pki-server.sh, the PKI WITHOUT any private key, the
              server\ files of the PKI: hosts, CA list, expected URLs). Built by New-PkiServerPackage.ps1. Manual: docs\PKI-SERVER-MANUAL.txt
    -CrlServer SOURCE: ONE small zip for a CRL / CA-certificate server ONLY on Ubuntu 24.04 / 26.04 (no OCSP, no time stamping, no OpenSSL 4, no key): pki-server.sh +
              pki\publish + pki\server. On Ubuntu:  sudo ./linux/pki-server/pki-server.sh install --crl-only --source ./pki
    -CrlOcspServer SOURCE: ONE zip for a CRL + OCSP server on Ubuntu 24.04 / 26.04 WITHOUT time stamping (pki-server.sh, the PKI without keys, OCSP dispatcher).
              On Ubuntu:  sudo ./linux/pki-server/pki-server.sh install --no-tsa --source ./pki
    -TimestampServer SOURCE: ONE zip for a TIME STAMP server only (RFC 3161) on Ubuntu 24.04 / 26.04 (pki-server.sh, the PKI without keys, the TSA service).
              On Ubuntu:  sudo ./linux/pki-server/pki-server.sh install --tsa-only --source ./pki
    Unpack only (any machine with PowerShell 7):  Unpack-PkiTransport.ps1.   Linux and macOS:  pki-transport.sh.

    Full help:  .\PkiTransport.ps1 -Help        Manual: docs\PkiTransport-MANUAL.txt

.EXAMPLE
    .\PkiTransport.ps1 -Pack -GeneratePassword
        CA certificates only, zip + AES-256, written to .\transport\agantra-pki-<date>.certpacked
.EXAMPLE
    .\PkiTransport.ps1 -Pack -IncludeLeafCerts -Out D:\share\dev.certpacked -Kit
.EXAMPLE
    .\PkiTransport.ps1 -Install -Package .\dev.certpacked
.EXAMPLE
    .\PkiTransport.ps1 -DevKit -GeneratePassword
        The developer kit: agantra-pki-devkit-<date>.zip (the password of the .certpacked inside is shown once)
#>
# No [CmdletBinding()]: it would reserve short aliases of common parameters. -Verbose is declared below.
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    # ---- what to do ----
    [switch]$Pack,
    [switch]$DevKit,
    [switch]$Server,
    [switch]$CrlServer,
    [switch]$CrlOcspServer,
    [switch]$TimestampServer,
    [switch]$Install,
    [switch]$Check,
    [switch]$List,
    [switch]$RemoveTrust,

    # ---- the package ----
    [string]$Package,
    [string]$Out,
    [Alias('Password')][string]$PackagePassword,
    [switch]$GeneratePassword,
    [switch]$AllowWeakPassword,
    [ValidateSet('zip', '7z')][string]$ArchiveFormat = 'zip',
    [ValidateSet('Aes256', 'ZipCrypto')][string]$ZipEncryption = 'Aes256',
    [string]$SevenZipPath,
    [string]$Comment,
    [switch]$NoVerify,

    # ---- what goes in (source) ----
    [switch]$IncludeLeafCerts,
    [string[]]$LeafName,
    [switch]$IncludeCaKeys,
    [switch]$Kit,
    [switch]$DevKitNoKeys,
    [switch]$DevKitNoServer,
    [switch]$Tar,
    [switch]$IncludeServiceKeys,
    [ValidateSet('zip', '7z')][string]$KitArchiveFormat = 'zip',

    # ---- what comes out (destination) ----
    [string]$Destination,
    [ValidateSet('roots', 'intermediates', 'chains', 'ca', 'leafcerts', 'pki', 'all', 'fullchain')][string[]]$Extract,
    [switch]$InstallLeafPfx,
    [string]$PfxPassword = 'Abc12345!',
    [switch]$Force,
    [switch]$SkipOpenSslCheck,
    [switch]$InstallMissing,

    # ---- environment ----
    [string]$ConfigFile,
    [string]$PkiRoot,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [string]$OpenSslPath,

    # ---- information, unblock / unlock ----
    [switch]$Unblock,
    [switch]$Help,
    [switch]$Verbose,
    [switch]$Version
)
# >>> PKI-VERSION-INFO (generated by tools/Update-VersionBlock.ps1 - do not edit here, edit the tool source)
$script:PkiVerNumber = '7.6.8'
$script:PkiVerDate = '2026-10-21'
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

function Show-PkiTransportHelp {
    @'
====================================================================================================
 PkiTransport.ps1  -
 carry the PKI to other machines (.certpacked), build the DevKit and server zips
 Version 7.6.8
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OÜ (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 On a terminal: SPACE = next page, ENTER = next line, Q = quit.
 Manual : docs\PkiTransport-MANUAL.txt        Words : docs\GLOSSARY.txt
 Needs  : PowerShell 7+. Source: the PKI made by pki_setup.ps1.

WHAT IT DOES
  SOURCE (the computer with the PKI):
    -Pack              A password-protected .certpacked from the PKI.
    -DevKit            ONE zip for developers: the .certpacked, installers, generators, manuals.
    -Server            ONE zip for the Ubuntu CRL + OCSP + time stamp server. No password, no key.
    -CrlServer         A small zip: CRL and CA certificates only.
    -CrlOcspServer     A zip: CRL + OCSP, no time stamping.
    -TimestampServer   A zip: time stamp server (RFC 3161) only.
  DESTINATION (Windows 11 24H2+, Windows Server 2025 / 2022):
    -Install           Scans the computer. Only if the scan passes: unpacks and installs the CAs.
    -Check             The scan only. Nothing is changed.
    -RemoveTrust       Removes the CAs of a package from the Windows stores (administrator).
  ANY MODE:
    -List              Shows what is inside a package.
    -Unblock           Unblocks and unlocks the folders, then stops.
  The other two scripts of the transport:
    Unpack-PkiTransport.ps1   Any computer with PowerShell 7. Only unpacks.
    pki-transport.sh          Linux. Unpacks and installs the trust in the system store.

QUICK START
  1. Source ........ .\PkiTransport.ps1 -Pack -GeneratePassword -Kit
                     (the password is shown ONCE; send it by another way)
  2. Copy the .certpacked and the <name>-kit folder to the destination.
  3. Destination ... .\PkiTransport.ps1 -Install -Package .\name.certpacked
                     (PowerShell 7 as administrator, in the kit folder)

THE PACKAGE
  A .certpacked IS an archive: rename it to .zip or .7z and 7-Zip opens it with the password.
    zip + AES-256 (default)  Made and read by this script. Nothing to install on Windows.
    zip + ZipCrypto          Weak. Only for packages WITHOUT private keys. "unzip -P" reads it.
    7z  + AES-256            File names hidden too. Needs 7-Zip to make and to read.
  The package always holds: ca\roots, ca\intermediates, ca\ca-bundle-roots.crt,
  ca\ca-bundle-all.crt, ca\chains, ca\publish, certpack.json, certpack.tsv, SHA256SUMS, README.txt.
  Every file has its SHA-256 listed.

PACK   (source)
  .\PkiTransport.ps1 -Pack -GeneratePassword                      CA certificates only
  .\PkiTransport.ps1 -Pack -IncludeLeafCerts
  + the leafcerts folders (leaf KEYS)
  .\PkiTransport.ps1 -Pack -IncludeLeafCerts -LeafName www.example.com,api*     only these sets
  .\PkiTransport.ps1 -Pack -IncludeCaKeys                         + the WHOLE pki folder with ALL CA
                                                                  KEYS (the destination can issue)
  .\PkiTransport.ps1 -Pack -Out D:\share\dev.certpacked -ArchiveFormat 7z -Kit
  -Out <file>            Default .\transport\agantra-pki-<yyyyMMdd-HHmmss>.certpacked. The extension
                         is always .certpacked (.zip or .7z is changed).
  -PackagePassword <t>   (alias -Password). Not given: the variable PKI_TRANSPORT_PASSWORD, else a
                         prompt. 12+ printable ASCII characters, 3 of 4 classes.
  -AllowWeakPassword     Relaxes the length and classes. Never the ASCII rule.
  -GeneratePassword      A 20-character password, shown ONCE at the end. Write it down.
  -ArchiveFormat zip|7z  Default zip.      -ZipEncryption Aes256|ZipCrypto   Default Aes256.
                         ZipCrypto is refused when private keys are included.
  -SevenZipPath <exe>    7-Zip, for 7z.
  -IncludeLeafCerts      Add leafcerts\ (contains private keys).   -LeafName <wildcards>
  only those.
  -IncludeCaKeys         Add pki\ with the CA private keys. Only for a machine that must issue.
  -Kit                   Also write <name>-kit\ : the transport scripts, the bootstrap scripts
                         (Install-DevEnvironment), the modules, the CSR tools, the manuals. The
                         destination then needs nothing else.
  -Comment <text>        Stored in the package.        -NoVerify   Do not read the package back.
  -PkiRoot <path>  -ConfigFile <path>   As in pki_setup.ps1.

INSTALL   (destination: Windows 11 24H2+, Server 2025 / 2022)
  .\PkiTransport.ps1 -Install -Package .\dev.certpacked
  1. SCAN. Windows 11 24H2 (build 26100) or newer, Server 2025, Server 2022 (Classic certificates
     only). Windows 10, older Windows 11, older Server and special editions are refused (exit 2 /
       5).
     OpenSSL 4.0.1+: when missing it is INSTALLED if you agree or give -InstallMissing; otherwise
     the script stops (exit 4). Administrator PowerShell.
  2. Only then: the package is decrypted, every SHA-256 is checked, the selection is written.
  3. Every ROOT goes to Trusted Root Certification Authorities, every INTERMEDIATE to Intermediate
     Certification Authorities. The stores are read back. OpenSSL proves the chains.
  -Package <file>        The .certpacked.         -PackagePassword / the prompt, as for -Pack.
  -Destination <folder>  Default .\certpacked-received\<package name>.
  -Extract <list>        roots | intermediates | chains | ca | leafcerts | pki | all. Default ca.
  -InstallLeafPfx        Also import the leaf PFX files into LocalMachine\My (leaf only).
  -PfxPassword <text>    The PFX password. Default Abc12345!.
  -Force                 Overwrite files that exist and differ.
  -InstallMissing        Install 7-Zip and OpenSSL 4.0.1+ when they are missing (needs
                         Install-DevEnvironment.ps1 next to this script; the kit has it).
  -OpenSslPath <exe>     Use this openssl.        -SkipOpenSslCheck   Go on without OpenSSL 4.
  -SevenZipPath <exe>    7-Zip, for a 7z package.
  -NoVerify              Skip the OpenSSL chain check at the end.

OTHER COMMANDS
  -Check [-Package <f>]  The scan (with -Package: does the password open the file?).
  -List -Package <f>     Scope, CAs, leaves and files of the package.
  -RemoveTrust -Package <f>   Remove the CAs of the package from the Windows stores.
  -Unblock               Unblock (Internet mark) and unlock (Read-only) the script folder and
                         -Destination, then stop. This is also done at every start.
  -Verbose               Show detail.          -Help   This text.
  -Version               Show version, author, OS and tool versions.

DEVKIT   (-DevKit)
  .\PkiTransport.ps1 -DevKit -GeneratePassword
  zip + the .certpacked with the ISSUING CA keys
  .\PkiTransport.ps1 -DevKit -Out D:\share\devkit.zip -KitArchiveFormat 7z -ArchiveFormat 7z
  .\PkiTransport.ps1 -DevKit -DevKitNoKeys              Trust only. The generators cannot issue.
  .\PkiTransport.ps1 -DevKit -DevKitNoServer            Without the server\ folder.
  The kit holds: the .certpacked (NO root key; no OCSP / TSA key; no old leaf key),
  Install-PkiTrust, the Generate*Certificate scripts, SignCsr, Make-ShExecutable, START-HERE.txt,
  devkit.env, examples, docs, SHA256SUMS. Each PowerShell script has a .sh twin.
  -KitArchiveFormat zip|7z   The outer archive. Default zip, not encrypted.
  -ArchiveFormat zip|7z      The .certpacked inside (AES-256).
  -DevKitNoKeys              No private keys at all.      -DevKitNoServer   Leave out server\.
  Certificates issued from a DevKit copy are NOT in the CRL / OCSP database of the master PKI.
  Manual: docs\DevKit-MANUAL.txt

SERVER PACKAGES   (no password, no private key; Ubuntu 24.04 / 26.04)
  .\PkiTransport.ps1 -CrlServer            CRL and CA certificates only (nginx)
  .\PkiTransport.ps1 -CrlOcspServer        CRL + OCSP, no time stamping
  .\PkiTransport.ps1 -TimestampServer      Time stamp server only
  .\PkiTransport.ps1 -Server               All three
  Options: -Out <file.zip>  -Force  -Tar (also .tar.gz)  -Release  -NoCaRevocationInfo  -PkiRoot
           -IncludeServiceKeys (LAB ONLY: the OCSP / time stamp keys; a CA key is never packed;
           -CrlServer and -TimestampServer refuse it). The modes cannot be combined.
  The package is opened again and scanned. One private key inside = deleted, exit 5.
  On Ubuntu (CRL server):
     unzip agantra-pki-crl-server-*.zip && cd agantra-pki-crl-server
     sudo ./linux/pki-server/pki-server.sh install --crl-only --source ./pki
     ./linux/pki-server/pki-server.sh dns
  CRL + OCSP or time stamping: make the keys ON the server and sign them here.
     sudo ./linux/pki-server/pki-server.sh csr --no-tsa --source ./pki --out ./csr
     PkiRevocation.ps1 -Action SignCsr -For Ocsp            (time stamping: -For Tsa -Ca <ca>)
     sudo ./linux/pki-server/pki-server.sh import-cert --cert ./signed/ocsp-<ca>.crt
     sudo ./linux/pki-server/pki-server.sh install --no-tsa --source ./pki
  New CRL later: PkiRevocation.ps1 -Action NewCrl, build the package again, copy, unzip, then
     pki-server.sh update --crl-only --source ./pki
  Manual: docs\PKI-SERVER-MANUAL.txt

WHICH PKI
  -Release <n>             Release R<n>. Default: the LATEST. A missing release = the latest, with a
                           warning.
  -NoCaRevocationInfo      The NoCR family (CAs without CRL / OCSP addresses).
  -PkiRoot <folder>        Exactly this folder.
  -Pki <name>              The company (file <name>_pki.cnf). Default agantra.
                           List: .\pki_setup.ps1 -ListPki
  ONE PKI per package: the kit of release 2 holds R2 only.

LIMITS
  * A package with leaf certificates or CA keys holds PRIVATE KEYS. Send it over a channel you
    trust, send the password by another one, delete the package and the extracted files when done.
  * 7-Zip gets the password as an argument. It is visible in the process list while it runs.
  * Not tested on a real Windows: -Install and -RemoveTrust. The rest is tested on Linux.

EXIT CODES
  0 done   1 error   2 Windows not supported   3 not Windows (use pki-transport.sh)
  4 OpenSSL 4.0.1+ missing   5 this system is refused, or a key was found in a server package

WHERE IT RUNS
  Windows 11 24H2 or newer, Windows Server 2025, Windows Server 2022 (Classic track only), Linux
  with pwsh. Refused (exit 5): Windows 10, older Windows 11, macOS and special editions.
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

if ($Help) { Invoke-PagedHelp { Show-PkiTransportHelp }; exit 0 }

# Where may this script run? Windows 11 24H2+ / Server 2025 / Server 2022 (classic only), supported Linux. Error and exit 5 otherwise.
$__pf = Join-Path $PSScriptRoot 'scripts/00a_Platform.ps1'
if (-not (Test-Path -LiteralPath $__pf)) { [Console]::Error.WriteLine('[ERROR] scripts/00a_Platform.ps1 is missing: the operating system cannot be checked. Nothing was done.'); exit 5 }
. $__pf; Assert-PkiPlatform
. (Join-Path $PSScriptRoot 'scripts/00b_Profiles.ps1')
# defaults from pki_tools.cnf [ transport ] (only when the parameter was not given on the command line)
if (-not $PSBoundParameters.ContainsKey('ArchiveFormat')) { $ArchiveFormat = (Get-PkiToolSetting -Section 'transport' -Key 'ArchiveFormat' -Default 'zip').ToLowerInvariant() }
if (-not $PSBoundParameters.ContainsKey('ZipEncryption')) { $ZipEncryption = Get-PkiToolSetting -Section 'transport' -Key 'ZipEncryption' -Default 'Aes256' }

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'
Write-Host ''

# ------------------------------------------------------------------------------------------------------------
# STANDARD BOOTSTRAP of every main script: UNBLOCK + UNLOCK the whole script folder, children and recursive,
# BEFORE any other script of the folder is loaded (a blocked script cannot be loaded).
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

$script:PackageOpened = $null
try {
    # ---------------- what is asked ----------------
    $modes = @($Pack, $DevKit, $Server, $CrlServer, $CrlOcspServer, $TimestampServer, $Install, $Check, $List, $RemoveTrust, $Unblock | Where-Object { $_ })
    if ($modes.Count -eq 0) { throw 'Say what to do: -Pack, -DevKit, -Server, -CrlServer, -CrlOcspServer, -TimestampServer, -Install, -Check, -List, -RemoveTrust or -Unblock. See .\PkiTransport.ps1 -Help.' }
    if ($modes.Count -gt 1 -and -not ($Check -and ($Install -or $List)) ) { throw 'Use only one of -Pack, -DevKit, -Server, -CrlServer, -CrlOcspServer, -TimestampServer, -Install, -Check, -List, -RemoveTrust and -Unblock.' }
    if ($IncludeCaKeys -and -not $Pack) { throw '-IncludeCaKeys is a -Pack option (-DevKit packs the issuing CA keys by itself).' }
    if ($Pack -and ($Install -or $RemoveTrust)) { throw '-Pack cannot be combined with -Install or -RemoveTrust.' }

    # =========================================================================================== -Server (no module needed: New-PkiServerPackage.ps1 does the work)
    if ($Server -or $CrlServer -or $CrlOcspServer -or $TimestampServer) {
        $what = if ($CrlServer) { '-CrlServer' } elseif ($CrlOcspServer) { '-CrlOcspServer' } elseif ($TimestampServer) { '-TimestampServer' } else { '-Server' }
        if (@($Server, $CrlServer, $CrlOcspServer, $TimestampServer | Where-Object { $_ }).Count -gt 1) { throw 'Use only one of -Server, -CrlServer, -CrlOcspServer and -TimestampServer.' }
        if ($TimestampServer -and $IncludeServiceKeys) { throw '-TimestampServer carries no keys at all: -IncludeServiceKeys is not allowed with it.' }
        if ($Server -and $CrlServer) { throw 'Use only one of -Server, -CrlServer and -CrlOcspServer.' }
        if ($CrlServer -and $IncludeServiceKeys) { throw '-CrlServer carries no keys at all: -IncludeServiceKeys is not allowed with it. Use -Server for the OCSP / time stamp server.' }
        if ($Pack -or $DevKit -or $Install -or $Check -or $List -or $RemoveTrust -or $Unblock) { throw "$what cannot be combined with another mode." }
        $np = Join-Path $script:ScriptRoot 'New-PkiServerPackage.ps1'
        if (-not (Test-Path -LiteralPath $np)) { throw "New-PkiServerPackage.ps1 not found next to this script: $np" }
        $outZip = if ($Out) { $Out } else { Join-Path (Get-PkiTransportFolder -Root $script:ScriptRoot) ("{0}-{1}.zip" -f $(if ($CrlServer) { "$(Get-PkiFileStem -Name $PkiProfile)-crl-server" } elseif ($CrlOcspServer) { "$(Get-PkiFileStem -Name $PkiProfile)-crl-ocsp-server" } elseif ($TimestampServer) { "$(Get-PkiFileStem -Name $PkiProfile)-timestamp-server" } else { "$(Get-PkiFileStem -Name $PkiProfile)-server" }), (Get-Date -Format 'yyyyMMdd-HHmmss')) }
        if ([System.IO.Path]::GetExtension($outZip).ToLowerInvariant() -ne '.zip') { $outZip += '.zip' }
        $outZip = [System.IO.Path]::GetFullPath($outZip)
        $na = @('-NoProfile', '-File', $np, '-Output', $outZip)
        if ($PkiRoot) { $na += @('-PkiRoot', $PkiRoot) }
        if ($Release -gt 0) { $na += @('-Release', [string]$Release) }
        if ($PkiProfile) { $na += @('-PkiProfile', $PkiProfile) }
        if ($NoCaRevocationInfo) { $na += '-NoCaRevocationInfo' }
        if ($CrlServer) { $na += '-CrlOnly' }
        if ($CrlOcspServer) { $na += '-NoTsa' }
        if ($TimestampServer) { $na += '-TsaOnly' }
        if ($Tar) { $na += '-Tar' }
        if ($IncludeServiceKeys) { $na += '-IncludeServiceKeys' }
        if ($Force) { $na += '-Force' }
        $sw = Get-Item -LiteralPath (Get-Process -Id $PID).Path
        & $sw.FullName @na
        $rc = $LASTEXITCODE
        if ($rc -ne 0) { exit $rc }
        $h = (Get-FileHash -LiteralPath $outZip -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "  SHA-256     : $h   (compare it after the transfer)" -ForegroundColor Gray
        if ($CrlServer) { Write-Host '  The CRL server package holds NO private key. Ubuntu: unzip; sudo ./linux/pki-server/pki-server.sh install --crl-only --source ./pki ; then  pki-server.sh dns' -ForegroundColor Gray }
        elseif ($TimestampServer) { Write-Host '  The time stamp package holds NO private key. Ubuntu: unzip; csr --tsa-only, sign (-For Tsa), import-cert, then  sudo ./linux/pki-server/pki-server.sh install --tsa-only --source ./pki  (README-TIMESTAMP-SERVER.txt)' -ForegroundColor Gray }
        elseif ($CrlOcspServer) { Write-Host '  The CRL + OCSP package holds NO private key. Ubuntu: unzip; csr --no-tsa, sign, import-cert, then  sudo ./linux/pki-server/pki-server.sh install --no-tsa --source ./pki  (README-CRL-OCSP-SERVER.txt)' -ForegroundColor Gray }
        else { Write-Host '  The server package holds NO private key (a CA key never). Ubuntu: unzip; sudo ./linux/pki-server/pki-server.sh install --source ./pki' -ForegroundColor Gray }
        exit 0
    }

    # module set: pack needs the whole library, everything else only the small destination kit
    $PkiModuleSet = if ($Pack -or $DevKit) { 'Library' } else { 'Transport' }
    . (Join-Path $script:ScriptRoot 'scripts/PkiModules.ps1')

    # =========================================================================================== -Unblock
    if ($Unblock) {
        Initialize-PkiMinimalContext -PkiRoot (Join-Path $script:ScriptRoot 'pki')
        Write-PkiLog 'UNBLOCK + UNLOCK (children and recursive)'
        Write-PkiLog "Start-up bootstrap of this script: $($script:BootstrapUnlocked) read-only item(s) unlocked in $($script:ScriptRoot) (the Internet mark is removed on Windows)."
        $paths = @($script:ScriptRoot); if ($Destination) { $paths += $Destination }
        [void](Invoke-PkiUnblockUnlock -Path $paths)
        exit 0
    }

    # ---------------- the password (shared by every mode) ----------------
    $getPassword = {
        param([bool]$ForPack)
        $pw = $PackagePassword
        if ([string]::IsNullOrEmpty($pw)) { $pw = $env:PKI_TRANSPORT_PASSWORD }
        $generated = $false
        if ($ForPack -and [string]::IsNullOrEmpty($pw) -and $GeneratePassword) { $pw = New-PkiPackagePassword; $generated = $true }
        if ([string]::IsNullOrEmpty($pw)) { $pw = Read-PkiPackagePassword -Confirm:$ForPack }
        if ($ForPack) {
            $problems = Test-PkiPackagePassword $pw
            if ($AllowWeakPassword) { $problems = @($problems | Where-Object { $_ -like '*ASCII*' -or $_ -like '*empty*' }) }
            if ($problems.Count -gt 0) { throw ("The package password is not accepted: " + ($problems -join '; ') + '. Use -GeneratePassword for a strong one.') }
        }
        return [ordered]@{ Password = $pw; Generated = $generated }
    }

    # =========================================================================================== -DevKit
    if ($DevKit) {
        Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
        $c = $script:Pki
        [void](Import-PkiExisting -SkipProviders)
        Write-PkiLog "PKI of the kit: release R$([int]$c.Release)$(if ($c.NoCaRevocationInfo) { ' (NoCR: CA certificates without revocation information)' })  $($c.PkiRoot)" 'INFO'
        $leafRoot = Get-PkiLeafRoot
        if ($ArchiveFormat -eq '7z' -or $KitArchiveFormat -eq '7z') {
            if (-not (Find-PkiSevenZip -Explicit $SevenZipPath)) {
                $doInstall = [bool]$InstallMissing
                if (-not $doInstall) { $doInstall = Confirm-PkiInstall '7-Zip is needed for a 7z archive and was not found. Install it now?' }
                if ($doInstall) { [void](Install-PkiSevenZip) }
            }
            if (-not (Find-PkiSevenZip -Explicit $SevenZipPath)) { throw '7z needs 7-Zip and none was found (winget install 7zip.7zip, or -SevenZipPath). The default zip needs nothing.' }
        }
        if (-not $DevKitNoKeys) { Write-PkiLog 'The DevKit will contain the PRIVATE KEYS OF THE ISSUING (intermediate) CAs (inside the encrypted .certpacked). No root key. Whoever opens it can issue certificates your clients trust, until you revoke the intermediates.' 'WARN' }
        $pw = & $getPassword $true
        $kitFile = if ($Out) { $Out } else { Join-Path (Get-PkiTransportFolder -Root $script:ScriptRoot) ("{0}-devkit-{1}" -f (Get-PkiFileStem -Name $PkiProfile), (Get-Date -Format 'yyyyMMdd-HHmmss')) }
        $want = if ($KitArchiveFormat -eq '7z') { '.7z' } else { '.zip' }
        $ext = [System.IO.Path]::GetExtension($kitFile)
        if ($ext -ne $want) { $kitFile = $(if ($ext -in '.zip', '.7z', '.certpacked') { [System.IO.Path]::ChangeExtension($kitFile, $want) } else { $kitFile + $want }) }
        $kitFile = [System.IO.Path]::GetFullPath($kitFile)
        Write-PkiLog "Building the DevKit -> $kitFile  (kit: $KitArchiveFormat, .certpacked inside: $ArchiveFormat AES-256)"
        $r = New-PkiDevKit -Root $script:ScriptRoot -OutFile $kitFile -Password $pw.Password -KitFormat $KitArchiveFormat -PackageFormat $ArchiveFormat `
            -SevenZipPath $SevenZipPath -Comment ([string]$Comment) -LeafRoot $leafRoot -WithKeys:(-not $DevKitNoKeys) -NoVerify:$NoVerify -WithServer:(-not $DevKitNoServer)
        $sha = Get-PkiFileSha256 -Path $r.Path
        Write-Host ''
        Write-Host 'DEVKIT' -ForegroundColor Cyan
        Write-Host ("  File        : {0}" -f $r.Path)
        Write-Host ("  Size        : {0:N0} bytes, {1} files in folder {2}\" -f $r.Bytes, $r.Files, $r.Folder)
        Write-Host ("  Contains    : the .certpacked ({0}, {1}) with {2}" -f $r.Package.Format, $r.Package.Encryption, $(if ($DevKitNoKeys) { 'the CA certificates only' } else { 'the CA certificates + the issuing CA keys (no root key)' }))
        Write-Host ("                Install-PkiTrust.ps1 / .sh, Generate{Leaf,PersonLeaf,Office365Leaf}Certificate + SignCsr .ps1 / .sh, Make-ShExecutable.ps1, make-executable.sh, docs, START-HERE.txt$(if (-not $DevKitNoServer) { ", server\ (the server kit: pki-server.sh for CRL / OCSP / time stamping, no private key)" })")
        Write-Host ("  SHA-256     : {0}   (of the kit file: compare it after the transfer)" -f $sha)
        if ($pw.Generated) {
            Write-Host ''
            Write-Host '  PASSWORD of the .certpacked inside (shown once; send it by another channel than the kit):' -ForegroundColor Yellow
            Write-Host "      $($pw.Password)" -ForegroundColor Yellow
        }
        Write-Host ''
        Write-PkiLog 'Next: send the kit to the developer. Windows: unzip, open PowerShell 7 as Administrator in the folder, run .\Install-PkiTrust.ps1. Ubuntu: unzip, bash make-executable.sh, ./Install-PkiTrust.sh.' 'INFO'
        exit 0
    }

    # =========================================================================================== -Pack
    if ($Pack) {
        Initialize-PkiConfiguration -ScriptRoot $script:ScriptRoot -Bound $PSBoundParameters -VerboseOutput:([bool]$Verbose)
        $c = $script:Pki
        [void](Import-PkiExisting -SkipProviders)
        $leafRoot = Get-PkiLeafRoot
        if ($ZipEncryption -eq 'ZipCrypto' -and ($IncludeLeafCerts -or $IncludeCaKeys)) { throw '-ZipEncryption ZipCrypto is weak and is refused for a package with private keys (-IncludeLeafCerts, -IncludeCaKeys). Use Aes256.' }
        if ($ArchiveFormat -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) {
            $doInstall = [bool]$InstallMissing
            if (-not $doInstall) { $doInstall = Confirm-PkiInstall '7-Zip is needed for a 7z package and was not found. Install it now?' }
            if ($doInstall) { [void](Install-PkiSevenZip) }
        }
        if ($ArchiveFormat -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) { throw "-ArchiveFormat 7z needs 7-Zip and none was found. Install it (winget install 7zip.7zip) or give -SevenZipPath. The default zip format needs nothing." }
        if ($ArchiveFormat -eq 'zip' -and $ZipEncryption -eq 'ZipCrypto') { Write-PkiLog 'ZipCrypto is the old PKWARE encryption: weak against known-plaintext attacks. It is fine for CA certificates (public), not for anything secret.' 'WARN' }
        if ($IncludeLeafCerts) { Write-PkiLog "The package will contain the LEAF CERTIFICATES of $leafRoot WITH THEIR PRIVATE KEYS." 'WARN' }
        if ($IncludeCaKeys) { Write-PkiLog "The package will contain the WHOLE PKI of $($c.PkiRoot) WITH THE CA PRIVATE KEYS: whoever opens it can issue certificates your clients trust." 'WARN' }

        $pw = & $getPassword $true
        $name = if ($Out) { $Out } else { Join-Path (Get-PkiTransportFolder -Root $script:ScriptRoot) ("{0}-{1}.certpacked" -f (Get-PkiFileStem -Name $PkiProfile), (Get-Date -Format 'yyyyMMdd-HHmmss')) }
        $ext = [System.IO.Path]::GetExtension($name)
        if ($ext -in '.zip', '.7z') { Write-PkiLog "The extension $ext is changed to .certpacked (the package is not meant to look like an archive)." 'WARN'; $name = [System.IO.Path]::ChangeExtension($name, '.certpacked') }
        elseif ($ext -ne '.certpacked') { $name = $name + '.certpacked' }
        $name = [System.IO.Path]::GetFullPath($name)

        Write-PkiLog "Packing $($c.PkiRoot) -> $name  ($ArchiveFormat$(if ($ArchiveFormat -eq 'zip') { ', ' + $ZipEncryption }))"
        $res = New-PkiCertPackage -OutFile $name -Password $pw.Password -ArchiveFormat $ArchiveFormat -ZipEncryption $ZipEncryption `
            -IncludeLeafCerts:([bool]$IncludeLeafCerts) -IncludeCaKeys:([bool]$IncludeCaKeys) -LeafName @($LeafName | Where-Object { $_ }) -LeafRoot $leafRoot `
            -Comment ([string]$Comment) -SevenZipPath $SevenZipPath -NoVerify:$NoVerify
        $sha = Get-PkiFileSha256 -Path $res.Path
        Write-Host ''
        Write-Host 'PACKAGE' -ForegroundColor Cyan
        Write-Host ("  File        : {0}" -f $res.Path)
        Write-Host ("  Size        : {0:N0} bytes, {1} files" -f $res.Bytes, $res.Files)
        Write-Host ("  Archive     : {0}, {1}" -f $res.Format, $res.Encryption)
        Write-Host ("  Contains    : CA certificates{0}{1}" -f $(if ($IncludeLeafCerts) { ' + leafcerts (private keys)' } else { '' }), $(if ($IncludeCaKeys) { ' + the whole PKI (CA private keys)' } else { '' }))
        Write-Host ("  CAs         : {0} ({1} roots, {2} intermediates)" -f @($res.Manifest.certificateAuthorities).Count, @($res.Manifest.certificateAuthorities | Where-Object { $_.kind -ne 'intermediate' }).Count, @($res.Manifest.certificateAuthorities | Where-Object { $_.kind -eq 'intermediate' }).Count)
        Write-Host ("  SHA-256     : {0}   (of the .certpacked file: compare it after the transfer)" -f $sha)
        if (-not $NoVerify) { Write-Host '  Read back   : every entry decrypted and authenticated' }
        if ($pw.Generated) {
            Write-Host ''
            Write-Host '  PASSWORD (shown once; send it by another channel than the file):' -ForegroundColor Yellow
            Write-Host "      $($pw.Password)" -ForegroundColor Yellow
        }
        if ($Kit) {
            $kitDir = Join-Path (Split-Path -Parent $res.Path) (([System.IO.Path]::GetFileNameWithoutExtension($res.Path)) + '-kit')
            $kf = Write-PkiTransportKit -Root $script:ScriptRoot -KitDirectory $kitDir
            Write-Host ''
            Write-Host ("  Kit         : {0}   ({1} files: the transport scripts, Install-DevEnvironment.ps1 / .sh, the modules, the manuals)" -f $kitDir, $kf.Count)
        }
        Write-Host ''
        Write-PkiLog 'Next: copy the .certpacked (and the kit) to the destination.  Windows 11 24H2+ / Server 2025 / 2022: .\PkiTransport.ps1 -Install -Package <file>   Linux / macOS: ./linux/pki-transport.sh --package <file>' 'INFO'
        exit 0
    }

    # =========================================================================================== destination modes
    Initialize-PkiMinimalContext -PkiRoot (Join-Path $script:ScriptRoot 'pki') -Password $PfxPassword -VerboseOutput:([bool]$Verbose)
    $script:Pki.ScriptRoot = $script:ScriptRoot

    if (($Install -or $RemoveTrust) -and -not $IsWindows) {
        Write-PkiLog 'PkiTransport.ps1 -Install installs into the Windows stores. On Linux and macOS use ./linux/pki-transport.sh.' 'ERROR'
        exit 3
    }

    # ---------------- the SCAN ----------------
    $scanOk = $true
    $showScan = [bool]($Install -or $Check -or $RemoveTrust)
    if ($showScan) { Write-Host 'SCAN OF THIS MACHINE' -ForegroundColor Cyan }
    $say = { param($n, $st, $t) if ($showScan) { Write-PkiScanLine $n $st $t } }
    $sayRaw = { param($t, $col) if ($showScan) { Write-Host $t -ForegroundColor $col } }
    $sup = Get-PkiWindowsSupport
    if ($sup.Supported) { & $say 'Operating system' 'PASS' "$($sup.Name), build $($sup.Build).$($sup.Ubr)  (required: $($sup.Required))" }
    else { & $say 'Operating system' 'FAIL' "$($sup.Name)$(if ($sup.Build) { ', build ' + $sup.Build })"; & $sayRaw "      $($sup.Reason)" 'Red'; & $sayRaw "      Required: $($sup.Required)." 'Red'; $scanOk = $false }
    & $say 'PowerShell' 'PASS' "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    $ossl = Get-PkiDestinationOpenSsl -ExplicitPath $OpenSslPath
    if ($ossl.Status -ne 'Ok' -and -not $SkipOpenSslCheck -and $Install -and $sup.Supported) {
        $doInstall = [bool]$InstallMissing
        if (-not $doInstall) { $doInstall = Confirm-PkiInstall 'OpenSSL 4.0.1+ is missing. Install it now (Install-DevEnvironment.ps1 -Only OpenSSL)?' }
        if ($doInstall) { [void](Install-PkiOpenSsl); $ossl = Get-PkiDestinationOpenSsl -ExplicitPath $OpenSslPath }
    }
    switch ($ossl.Status) {
        'Ok' {
            $script:PkiDestOpenSslText = $ossl.Best.Text.Split([char]40)[0].Trim()
            & $say 'OpenSSL' 'PASS' "$script:PkiDestOpenSslText  [$($ossl.Best.Exe)]  (required: $($ossl.Required))"
            if ($ossl.Newer) { & $say 'OpenSSL version' 'INFO' "newer than the tested range ($($script:PkiTestedOpenSslMax)); accepted" }
        }
        default {
            $script:PkiDestOpenSslText = ''
            $found = @($ossl.Found | ForEach-Object { $_.Text.Split([char]40)[0].Trim() + '   at ' + $_.Exe })
            & $say 'OpenSSL' $(if ($SkipOpenSslCheck) { 'WARN' } else { 'FAIL' }) "$(if ($ossl.Status -eq 'TooOld') { 'too old' } else { 'not found' })  (required: $($ossl.Required))"
            if (-not $SkipOpenSslCheck) {
                $scanOk = $false
                foreach ($l in ((Get-PkiOpenSslAdvice -Found $found) -split "`r?`n")) { & $sayRaw ('      ' + $l) 'Yellow' }
            }
        }
    }
    if ($IsWindows) { & $say 'Administrator' $(if (Test-IsAdministrator) { 'PASS' } else { 'INFO' }) $(if (Test-IsAdministrator) { 'elevated' } else { 'not elevated (needed for -Install and -RemoveTrust)' }) }
    $sz = Find-PkiSevenZip -Explicit $SevenZipPath
    & $say '7-Zip' 'INFO' $(if ($sz) { $sz } else { 'not found (only needed for a 7z package; zip packages need nothing)' })
    if ($showScan) { Write-Host '' }

    if ($Check -and -not $Package) {
        if ($scanOk) { Write-Host 'READY: this machine can install the package.' -ForegroundColor Green; exit 0 }
        Write-Host 'NOT READY: see above.' -ForegroundColor Red
        if (-not $sup.Supported) { exit 2 } else { exit 4 }
    }
    if (-not $sup.Supported -and ($Install -or $RemoveTrust)) {
        Write-PkiLog "This machine is not supported for installing the trust: $($sup.Reason)" 'ERROR'
        exit 2
    }
    if (-not $scanOk -and $Install) { Write-PkiLog 'The scan did not pass. Nothing was unpacked or installed.' 'ERROR'; exit 4 }
    if ($Install -or $RemoveTrust) { Assert-Administrator }       # before anything is unpacked

    # ---------------- open the package ----------------
    if (-not $Package) { throw '-Package <file> is needed.' }
    $pw = & $getPassword $false
    if ((Get-PkiArchiveType -Path $Package) -eq '7z' -and -not (Find-PkiSevenZip -Explicit $SevenZipPath)) {
        $doInstall = [bool]$InstallMissing
        if (-not $doInstall) { $doInstall = Confirm-PkiInstall 'This is a 7z package and 7-Zip was not found. Install 7-Zip now?' }
        if ($doInstall) { [void](Install-PkiSevenZip) }
    }
    Write-PkiLog "Opening $Package ($(Get-PkiArchiveType -Path $Package))"
    $script:PackageOpened = Open-PkiCertPackage -Path $Package -Password $pw.Password -SevenZipPath $SevenZipPath
    $m = $script:PackageOpened.Manifest
    Write-PkiLog "Package opened: $($script:PackageOpened.Verified) file(s), every SHA-256 matches. Made $($m['createdUtc']) on $($m['source']['machine']), $($m['archive']['encryption'])." 'OK'
    $scope = $m['scope']
    Write-PkiLog "Scope: CA certificates$(if ($scope['leafcerts']) { ' + leaf certificates (private keys)' })$(if ($scope['caPrivateKeys']) { if ($scope.Contains('issuingKeysOnly') -and $scope['issuingKeysOnly']) { ' + the PKI folder with the keys of the ISSUING (intermediate) CAs only (no root key)' } else { ' + the whole PKI (CA private keys)' } })." 'INFO'
    if ($m['comment']) { Write-PkiLog "Comment: $($m['comment'])" 'INFO' }

    if ($Check) {
        if (-not $scanOk) {
            Write-Host 'NOT READY: the password opens the package, but this machine did not pass the scan (see above).' -ForegroundColor Red
            if (-not $sup.Supported) { exit 2 } else { exit 4 }
        }
        Write-Host 'READY: the scan passed and the password opens the package.' -ForegroundColor Green; exit 0
    }

    # =========================================================================================== -List
    if ($List) {
        Write-Host ''
        Write-Host ('{0,-14} {1,-12} {2,-4} {3,-11} {4}' -f 'KIND', 'KEY', 'Q', 'EXPIRES', 'COMMON NAME') -ForegroundColor Cyan
        foreach ($ca in @($m['certificateAuthorities'])) { Write-Host ('{0,-14} {1,-12} {2,-4} {3,-11} {4}' -f $ca['kind'], $ca['keyAlgorithm'], $(if ($ca['quadrant']) { "Q$($ca['quadrant'])" } else { '' }), $ca['notAfter'], $ca['commonName']) }
        $lv = @($m['leaves'])
        if ($lv.Count -gt 0) { Write-Host ''; Write-Host "LEAF CERTIFICATES: $($lv.Count)" -ForegroundColor Cyan; foreach ($l in $lv) { Write-Host ('  {0,-48} {1} Q{2} {3} {4}' -f $l['folder'], $l['level'], $l['quadrant'], $l['keyAlgorithm'], $l['notAfter']) } }
        Write-Host ''
        Write-PkiLog "$(@($m['files']).Count) file(s) in the package; roles: $((@($m['files']) | ForEach-Object { $_['role'] } | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')" 'OK'
        exit 0
    }

    # =========================================================================================== -RemoveTrust
    if ($RemoveTrust) { Remove-PkiPackageTrustWindows -Opened $script:PackageOpened; exit 0 }

    # =========================================================================================== -Install
    $sel = if ($Extract) { @($Extract) } else { @('ca') }
    if ($IncludeLeafCerts -and $sel -notcontains 'leafcerts' -and $sel -notcontains 'all' -and $sel -notcontains 'fullchain') { $sel += 'leafcerts' }
    if ($InstallLeafPfx -and $sel -notcontains 'leafcerts' -and $sel -notcontains 'all' -and $sel -notcontains 'fullchain') { $sel += 'leafcerts' }
    if (($sel -contains 'ca') -eq $false -and ($sel -contains 'roots') -eq $false -and ($sel -contains 'all') -eq $false -and ($sel -contains 'fullchain') -eq $false) { $sel += 'ca' }     # trust needs the CAs
    $dest = if ($Destination) { $Destination } else { Join-Path (Join-Path (Get-Location).Path 'certpacked-received') ([System.IO.Path]::GetFileNameWithoutExtension($Package)) }
    $dest = [System.IO.Path]::GetFullPath($dest)
    Write-PkiLog "Unpacking ($($sel -join ', ')) to $dest"
    $written = Export-PkiPackageSelection -Opened $script:PackageOpened -Destination $dest -Select $sel -LeafName @($LeafName | Where-Object { $_ }) -Force:$Force
    Write-PkiLog "$($written.Count) file(s) written." 'OK'

    Assert-Administrator
    Install-PkiPackageWindows -Opened $script:PackageOpened -Destination $dest -InstallLeafPfx:$InstallLeafPfx -PfxPassword $PfxPassword

    if (-not $NoVerify -and $ossl.Status -eq 'Ok') {
        if (-not (Test-PkiPackageChains -Opened $script:PackageOpened -Destination $dest -OpenSslExe $ossl.Best.Exe)) { throw 'The chain check with OpenSSL failed (see above).' }
    }
    Write-Host ''
    Write-PkiLog "Done. The CA certificates are installed (roots: Trusted Root Certification Authorities, intermediates: Intermediate Certification Authorities). Files: $dest" 'OK'
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
    if (Get-Command Remove-PkiOpenedPackage -ErrorAction SilentlyContinue) { Remove-PkiOpenedPackage -Opened $script:PackageOpened }
    if (Get-Command Clear-PkiSecretEnvironment -ErrorAction SilentlyContinue) { Clear-PkiSecretEnvironment }
}
