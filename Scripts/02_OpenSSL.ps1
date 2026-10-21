# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 02_OpenSSL.ps1
#
# OpenSSL 4.x only.
#   * Version gate: OpenSSL older than 4.0 stops the script.
#   * No ENGINE API: no "openssl engine", no OPENSSL_NO_ENGINE.
#   * Native providers only, selected with -provider flags and the
#     provider sections written by 03_RuntimeConfig.ps1:
#         non-FIPS : -provider default
#         FIPS     : -provider fips -provider base -propquery fips=yes
#   * Algorithms: RSA, ECDSA and ML-DSA (native in OpenSSL 3.5 / 4.x, default and FIPS
#     providers). The Quantum quadrants use ML-DSA at every level. A failed ML-DSA key is an
#     ERROR. Only with -PqcFallback does the script create an RSA key instead (genrsa), with a
#     warning per key, so a build can continue; such a certificate is NOT quantum-safe.
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PkiOpenSslVersionOf {
    # Runs "<exe> version"; $null when it is not OpenSSL / LibreSSL or does not run.
    param([Parameter(Mandatory)][string]$Exe)
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $Exe
        [void]$psi.ArgumentList.Add('version')
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $psi.Environment['OPENSSL_CONF'] = (Get-PkiNeutralOpenSslConf)
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEnd()
        [void]$p.WaitForExit(20000)
        if ($out -match '^(?<prod>OpenSSL|LibreSSL)\s+(?<maj>\d+)\.(?<min>\d+)(\.(?<pat>\d+))?') {
            return [pscustomobject]@{
                Exe = $Exe; Product = $Matches['prod']; Major = [int]$Matches['maj']; Minor = [int]$Matches['min']
                Patch = $(if ($Matches['pat']) { [int]$Matches['pat'] } else { 0 }); Text = $out.Trim()
            }
        }
    }
    catch { }
    return $null
}

function Get-PkiOpenSslCandidates {
    # Every openssl in PATH (in PATH order), then the usual install folders (FireDaemon, Shining Light, Homebrew).
    $list = [System.Collections.Generic.List[string]]::new()
    $add = { param($p) if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p -PathType Leaf)) { $r = (Resolve-Path -LiteralPath $p).Path; if (-not ($list | Where-Object { $_ -ieq $r })) { [void]$list.Add($r) } } }
    foreach ($name in 'openssl.exe', 'openssl') {
        foreach ($cmd in @(Get-Command $name -All -CommandType Application -ErrorAction SilentlyContinue)) { & $add $cmd.Source }
    }
    if ($IsWindows) {
        $pf = $env:ProgramFiles
        foreach ($d in 'FireDaemon OpenSSL 4', 'FireDaemon OpenSSL', 'FireDaemon OpenSSL 3', 'OpenSSL-Win64', 'OpenSSL') { & $add (Join-Path $pf "$d\bin\openssl.exe") }
    }
    else {
        foreach ($p in '/opt/homebrew/opt/openssl@4/bin/openssl', '/usr/local/opt/openssl@4/bin/openssl', '/opt/homebrew/bin/openssl', '/usr/local/bin/openssl') { & $add $p }
        foreach ($g in '/opt/openssl-4*/bin/openssl', '/usr/local/openssl-4*/bin/openssl', (Join-Path $HOME '.local/openssl-4*/bin/openssl')) { foreach ($f in @(Get-ChildItem -Path $g -ErrorAction SilentlyContinue)) { & $add $f.FullName } }
    }
    return ,$list
}

function Get-PkiBootstrapCommand {
    # The command that installs OpenSSL (FireDaemon, FIPS module, fipsmodule.cnf) with the bootstrap script only.
    $boot = $null
    foreach ($root in @($(if ($null -ne $script:Pki -and $script:Pki.Contains('ScriptRoot')) { $script:Pki.ScriptRoot }), $PSScriptRoot, (Split-Path -Parent $PSScriptRoot))) {
        if ($root -and (Test-Path -LiteralPath (Join-Path $root 'Install-DevEnvironment.ps1'))) { $boot = Join-Path $root 'Install-DevEnvironment.ps1'; break }
    }
    $b = if ($boot) { $boot } else { '.\Install-DevEnvironment.ps1' }
    return "$b -Only OpenSSL,7Zip"
}

function Get-PkiOpenSslCapabilityAdvice {
    # OpenSSL 4.x is there but FIPS and / or ML-DSA do not work.
    param([string[]]$Missing, [bool]$Windows = $IsWindows)
    $head = @"
This OpenSSL cannot do: $($Missing -join ', ').
The PKI needs OpenSSL 4.x WITH the FIPS module (fipsmodule.cnf) and native ML-DSA (post-quantum).

"@
    if ($Windows) {
        $cmd = Get-PkiBootstrapCommand
        return $head + @"
HOW TO FIX (Windows)
  1. In an ELEVATED PowerShell run your bootstrap script. It installs FireDaemon OpenSSL with FIPS and
     quantum-safe support, adds it to PATH and creates fipsmodule.cnf. OpenSSL only:
         $cmd
  2. Open a NEW PowerShell window and check:  openssl version   (OpenSSL 4.x.x)
  3. Run this script again. To use one specific OpenSSL:  -OpenSslPath "C:\Program Files\FireDaemon OpenSSL 4\bin\openssl.exe"
     FIPS only:  openssl fipsinstall -out fipsmodule.cnf -module <path to fips.dll>   then  -FipsModuleConfig <path>
"@
    }
    return $head + @"
HOW TO FIX
  Run the bootstrap: it builds OpenSSL 4 as a FULL build (FIPS module, ML-DSA, ML-KEM) and proves it:
      ./linux/Install-DevEnvironment.sh --yes --only openssl        (minutes on several cores, over an hour on one core)
  Then pass it:  -OpenSslPath <prefix>/bin/openssl  -FipsModuleConfig <prefix>/ssl/fipsmodule.cnf
  (On Windows: Install-DevEnvironment.ps1 -Only OpenSSL.)
"@
}

function Get-PkiOpenSslAdvice {
    param([string[]]$Found = @(), [bool]$Windows = $IsWindows)
    $foundText = if ($Found.Count -gt 0) { "Found:`n    " + ($Found -join "`n    ") } else { 'No openssl was found.' }
    $bootCmdLine = Get-PkiBootstrapCommand
    if ($Windows) {
        return @"
This PKI needs OpenSSL 4.x (OpenSSL 3.x is not supported): the Quantum quadrants use native ML-DSA and the
FIPS quadrants use the OpenSSL 4 FIPS provider.
$foundText

HOW TO FIX
  1. In an ELEVATED PowerShell run your bootstrap script (it installs FireDaemon OpenSSL through winget,
     package FireDaemon.OpenSSL, puts it in PATH and creates fipsmodule.cnf). OpenSSL only:
         $bootCmdLine
     (or run it without the -Skip switches to prepare the whole development environment)
  2. Open a NEW PowerShell window (PATH is read at start) and check:      openssl version
     It must say OpenSSL 4.x.x. If an older OpenSSL comes first in PATH, give the new one explicitly:
         .\pki_setup.ps1 -OpenSslPath "C:\Program Files\FireDaemon OpenSSL 4\bin\openssl.exe"
"@
    }
    return @"
This PKI needs OpenSSL 4.x (OpenSSL 3.x is not supported): the Quantum quadrants use native ML-DSA and the
FIPS quadrants use the OpenSSL 4 FIPS provider.
$foundText

HOW TO FIX   Install OpenSSL 4.x (Homebrew: brew install openssl@4, or build it from source with enable-fips)
and pass it explicitly:   ./pki_setup.ps1 -OpenSslPath /path/to/openssl
"@
}

function Find-OpenSSL {
    # Best OpenSSL 4.x or newer: an explicit -OpenSslPath is used as given (its version is checked by
    # Initialize-OpenSSL); otherwise every candidate is asked for its version and the newest 4.x wins,
    # even when an older OpenSSL (Git for Windows, an old package) comes first in PATH.
    param([string]$ExplicitPath)
    $script:PkiOpenSslNotes = [System.Collections.Generic.List[string]]::new()

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            $advice = Get-PkiOpenSslAdvice
            throw ('OpenSSL executable given with -OpenSslPath was not found: ' + $ExplicitPath + [Environment]::NewLine + [Environment]::NewLine + $advice)
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($exe in (Get-PkiOpenSslCandidates)) {
        $v = Get-PkiOpenSslVersionOf -Exe $exe
        if ($null -ne $v) { [void]$found.Add($v) }
    }
    $good = @($found | Where-Object { $_.Product -eq 'OpenSSL' -and $_.Major -ge 4 })
    if ($good.Count -eq 0) {
        $lines = @($found | ForEach-Object { ($_.Text.Split('(')[0].Trim()) + '   at ' + $_.Exe })
        $advice = Get-PkiOpenSslAdvice -Found $lines
        throw ('OpenSSL 4.0 or newer was not found.' + [Environment]::NewLine + $advice)
    }
    $best = $good | Sort-Object -Property @{ Expression = 'Major'; Descending = $true }, @{ Expression = 'Minor'; Descending = $true }, @{ Expression = 'Patch'; Descending = $true } | Select-Object -First 1
    foreach ($f in $found) {
        if ($f.Exe -ine $best.Exe -and ($f.Major -lt 4 -or $f.Product -ne 'OpenSSL')) {
            $fv = $f.Text.Split([char]40)[0].Trim()
            [void]$script:PkiOpenSslNotes.Add('skipped ' + $fv + ' at ' + $f.Exe + ' (OpenSSL 4.x is required)')
        }
    }
    return $best.Exe
}

function Get-PkiNeutralOpenSslConf {
    # A minimal configuration (default provider only) for commands that need no PKI configuration,
    # such as "openssl version". Written once per user to the temp folder.
    $path = Join-Path ([System.IO.Path]::GetTempPath()) 'agantra-pki-neutral-openssl.cnf'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $text = "# Neutral OpenSSL configuration of the Agantra PKI scripts: default provider only.`nopenssl_conf = openssl_init`n`n[ openssl_init ]`nproviders = provider_sect`n`n[ provider_sect ]`ndefault = default_sect`n`n[ default_sect ]`nactivate = 1`n"
        [System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))
    }
    return $path
}

function Invoke-OpenSSL {
    <#
    .SYNOPSIS
        Runs OpenSSL with System.Diagnostics.Process (no shell quoting issues).
    .PARAMETER ConfigPath
        Set as OPENSSL_CONF for this process only, so every command (also
        those without a -config option) loads the provider sections in it.
    .PARAMETER AllowFailure
        Return the result instead of throwing when the exit code is not 0.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$ConfigPath,
        [switch]$AllowFailure
    )

    Assert-PkiFile -Path $script:Pki.OpenSslExe

    $shown = [System.Collections.Generic.List[string]]::new()
    $hide = $false
    foreach ($a in $Arguments) {
        if ($hide) { [void]$shown.Add('[REDACTED]'); $hide = $false; continue }
        [void]$shown.Add($a)
        if ($a -in '-passin', '-passout', '-pass') { $hide = $true }
    }
    Write-PkiVerbose ('openssl ' + ($shown -join ' '))

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:Pki.OpenSslExe
    foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add([string]$a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    # 7.6.4 (the fix of 6.6.19): a relative path (.\leafcerts\x.pfx) is relative to the PowerShell location, but a child process starts in
    # [Environment]::CurrentDirectory, which Set-Location does not change. Start OpenSSL where the user is.
    try { $loc = (Get-Location -PSProvider FileSystem).ProviderPath; if ($loc -and (Test-Path -LiteralPath $loc -PathType Container)) { $psi.WorkingDirectory = $loc } } catch { }
    # ALWAYS set OPENSSL_CONF. A machine-wide OPENSSL_CONF (for example a master configuration that also
    # activates the third-party oqsprovider) must never reach the PKI scripts: native providers only.
    $psi.Environment['OPENSSL_CONF'] = $(if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath } else { Get-PkiNeutralOpenSslConf })

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    try {
        [void]$process.Start()
        $errTask = $process.StandardError.ReadToEndAsync()
        $stdout = $process.StandardOutput.ReadToEnd()
        $process.WaitForExit()
        $stderr = $errTask.GetAwaiter().GetResult()
        $exit = $process.ExitCode
    }
    finally { $process.Dispose() }

    $result = [pscustomobject]@{ ExitCode = $exit; StdOut = $stdout; StdErr = $stderr }
    if ($exit -ne 0 -and -not $AllowFailure) {
        $msg = "OpenSSL exited with code $exit (openssl $($shown -join ' '))."
        if (-not [string]::IsNullOrWhiteSpace($stderr)) { $msg += "`nSTDERR:`n$($stderr.Trim())" }
        if (-not [string]::IsNullOrWhiteSpace($stdout)) { $msg += "`nSTDOUT:`n$($stdout.Trim())" }
        throw $msg
    }
    return $result
}

function Initialize-OpenSSL {
    $script:Pki.OpenSslExe = Find-OpenSSL -ExplicitPath $script:Pki.OpenSslPath
    $v = Invoke-OpenSSL -Arguments @('version')
    $text = $v.StdOut.Trim()
    $script:Pki.OpenSslVersion = $text

    $short = $text.Split('(')[0].Trim()
    $exe = $script:Pki.OpenSslExe
    if ($text -notmatch '^OpenSSL\s+(?<maj>\d+)\.(?<min>\d+)(\.(?<pat>\d+))?') {
        $advice = Get-PkiOpenSslAdvice -Found @($short + '   at ' + $exe)
        throw ('Unrecognised OpenSSL version string: ' + $text + ' (' + $exe + '). This PKI requires OpenSSL 4.0 or newer (LibreSSL and BoringSSL are not supported).' + [Environment]::NewLine + $advice)
    }
    $major = [int]$Matches['maj']
    if ($major -lt 4) {
        $advice = Get-PkiOpenSslAdvice -Found @($short + '   at ' + $exe)
        throw ('OpenSSL 4.0 or newer is required. This is ' + $short + ' (' + $exe + ').' + [Environment]::NewLine + $advice)
    }
    Write-PkiLog "OpenSSL: $text"
    Write-PkiLog "  executable: $($script:Pki.OpenSslExe)"
    if ($null -ne (Get-Variable -Name PkiOpenSslNotes -Scope Script -ErrorAction SilentlyContinue)) {
        foreach ($n in $script:PkiOpenSslNotes) { Write-PkiLog "  $n" 'INFO' }
    }

    # The default provider must load: every non-FIPS operation relies on it.
    $p = Invoke-OpenSSL -Arguments @('list', '-providers', '-provider', 'default') -AllowFailure
    if ($p.ExitCode -ne 0) {
        throw "The OpenSSL default provider could not be loaded.`n$($p.StdErr.Trim())"
    }
    Write-PkiVerbose ($p.StdOut.Trim())
}

# ------------------------------------------------------------
# Providers
# ------------------------------------------------------------
function Get-PkiProviderArgs {
    param([bool]$Fips)
    if ($Fips) { return @('-provider', 'fips', '-provider', 'base', '-propquery', 'fips=yes') }
    return @('-provider', 'default')
}

function Get-PkiProviderConfigPath {
    param([bool]$Fips)
    if ($Fips) { return (Join-Path $script:Pki.PkiRoot 'provider-fips.cnf') }
    return (Join-Path $script:Pki.PkiRoot 'provider-default.cnf')
}

function Test-PkiFipsProvider {
    # Loads the FIPS provider (runs its self-tests). Throws a clear message on failure.
    $cnf = Get-PkiProviderConfigPath -Fips $true
    $r = Invoke-OpenSSL -Arguments (@('list', '-providers') + (Get-PkiProviderArgs -Fips $true)) -ConfigPath $cnf -AllowFailure
    if ($r.ExitCode -ne 0) {
        throw @"
The OpenSSL FIPS provider could not be loaded, so FIPS quadrants (2 and 4) cannot be generated.
$($r.StdErr.Trim())

Fix one of:
  0. Run your Install-DevEnvironment.ps1 (FireDaemon OpenSSL with the FIPS module and fipsmodule.cnf), then retry
  1. Install the FIPS module and create its configuration:
       openssl fipsinstall -out fipsmodule.cnf -module <path to fips.dll>
     then run again with  -FipsModuleConfig <path to fipsmodule.cnf>
  2. Generate only the non-FIPS quadrants:  -Quadrant 1,3
"@
    }
    Write-PkiLog 'FIPS provider loaded.' 'OK'
}

# ------------------------------------------------------------
# Key protection (Windows ACL): owner, SYSTEM and Administrators only
# ------------------------------------------------------------
function Protect-PkiKeyFile {
    param([Parameter(Mandatory)][string]$Path)
    if ($IsWindows) {
        try {
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            & icacls.exe $Path /inheritance:r /grant:r "${user}:(F)" 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null
        }
        catch { Write-PkiLog "Could not restrict key file ACL: $Path ($($_.Exception.Message))" 'WARN' }
    }
    else {
        try { & chmod 600 $Path } catch { }
    }
}

# ------------------------------------------------------------
# Private key generation (PKCS#8 PEM)
#   Family rsa   : genpkey -algorithm RSA  -pkeyopt rsa_keygen_bits:N
#   Family ecdsa : genpkey -algorithm EC   -pkeyopt ec_paramgen_curve:<curve>
#   Family pqc   : genpkey -algorithm mldsa87 | mldsa65 | mldsa44
# Returns @{ Family; Bits; Curve; Algorithm; Fallback }
# ------------------------------------------------------------
function New-PkiPrivateKey {
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][ValidateSet('rsa', 'ecdsa', 'pqc')][string]$Family,
        [int]$Bits = 0,
        [string]$Curve = 'P-384',
        [bool]$Fips = $false,
        [string]$Label = 'key',
        [string]$PqcAlgorithm,
        [int]$FallbackBits = 0
    )
    if ([string]::IsNullOrWhiteSpace($PqcAlgorithm)) { $PqcAlgorithm = $script:Pki.PqcAlgorithm }
    if ($FallbackBits -le 0) { $FallbackBits = $script:Pki.FallbackRsaBits }

    $prov = Get-PkiProviderArgs -Fips $Fips
    $cnf  = Get-PkiProviderConfigPath -Fips $Fips
    Ensure-PkiDirectory -Path (Split-Path -Parent $KeyPath)
    if (Test-Path -LiteralPath $KeyPath) { Remove-Item -LiteralPath $KeyPath -Force }

    $info = $null
    switch ($Family) {
        'rsa' {
            [void](Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('genpkey', '-algorithm', 'RSA', '-pkeyopt', "rsa_keygen_bits:$Bits", '-out', $KeyPath) + $prov))
            $info = [ordered]@{ Family = 'rsa'; Bits = $Bits; Curve = $null; Algorithm = "RSA-$Bits"; Fallback = $false }
        }
        'ecdsa' {
            [void](Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('genpkey', '-algorithm', 'EC', '-pkeyopt', "ec_paramgen_curve:$Curve", '-pkeyopt', 'ec_param_enc:named_curve', '-out', $KeyPath) + $prov))
            $info = [ordered]@{ Family = 'ecdsa'; Bits = 0; Curve = $Curve; Algorithm = "ECDSA-$($Curve -replace '-','')"; Fallback = $false }
        }
        'pqc' {
            try {
                [void](Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('genpkey', '-algorithm', $PqcAlgorithm, '-out', $KeyPath) + $prov))
                $info = [ordered]@{ Family = 'pqc'; Bits = 0; Curve = $null; Algorithm = (Get-PkiPqcDisplayName $PqcAlgorithm); Fallback = $false }
            }
            catch {
                $reason = ($_.Exception.Message -split "`n" | Where-Object { $_ -match 'error|unsupported|unknown|not found|fail|initializ' } | Select-Object -First 1)
                if ([string]::IsNullOrWhiteSpace($reason)) { $reason = ($_.Exception.Message -split "`n")[0] }
                if (Test-Path -LiteralPath $KeyPath) { Remove-Item -LiteralPath $KeyPath -Force -ErrorAction SilentlyContinue }
                $mode = if ($Fips) { 'FIPS provider' } else { 'default provider' }
                if (-not $script:Pki.PqcFallback) {
                    throw @"
ML-DSA key generation failed for '$Label' ($PqcAlgorithm, $mode).
Reason: $reason
The Quantum quadrants must use a post-quantum algorithm, so the script stops instead of creating an
RSA key. Use OpenSSL 4.x with native ML-DSA (and, for FIPS, a FIPS module that includes ML-DSA).
To build anyway with RSA-$FallbackBits keys in their place (NOT quantum-safe), add -PqcFallback.
"@
                }
                Write-PkiLog "ML-DSA key '$Label' ($PqcAlgorithm, $mode) failed: $reason" 'WARN'
                Write-PkiLog "  -PqcFallback: creating a classical RSA-$FallbackBits key instead (genrsa). This certificate is NOT quantum-safe." 'WARN'
                [void](Invoke-OpenSSL -ConfigPath $cnf -Arguments (@('genrsa', '-out', $KeyPath) + $prov + @([string]$FallbackBits)))
                $info = [ordered]@{ Family = 'rsa'; Bits = $FallbackBits; Curve = $null; Algorithm = "RSA-$FallbackBits"; Fallback = $true }
                [void]$script:Pki.PqcFallbacks.Add([ordered]@{ Label = $Label; RequestedAlgorithm = $PqcAlgorithm; UsedAlgorithm = "RSA-$FallbackBits"; Fips = $Fips; Reason = $reason })
            }
        }
    }

    if (-not (Test-Path -LiteralPath $KeyPath -PathType Leaf) -or (Get-Item -LiteralPath $KeyPath).Length -lt 64) {
        throw "OpenSSL reported success but did not write a key for '$Label': $KeyPath"
    }
    if ((Get-Content -LiteralPath $KeyPath -TotalCount 1) -ne '-----BEGIN PRIVATE KEY-----') {
        throw "Key for '$Label' is not PKCS#8 PEM: $KeyPath"
    }
    Protect-PkiKeyFile -Path $KeyPath
    return $info
}

# Signature digest / options -------------------------------------------------
function Get-PkiIssueMd {
    # Digest used when a CA signs the certificates it issues.
    param([string]$Kind, [string]$Family)
    if ($Family -eq 'pqc') { return 'default' }          # ML-DSA is a pure signature: no external digest
    if ($Kind -in 'root', 'track') { return 'sha512' }
    if ($Kind -eq 'quadrant') { return $script:PkiQuadDigest }     # Quadrant Roots sign the intermediates with SHA-384
    if ($Family -eq 'ecdsa') { return 'sha384' }
    return 'sha256'
}

function Get-PkiSigOpts {
    # RSA-PSS (optional shield). Not used for ECDSA / ML-DSA.
    param([string]$Family, [string]$Md)
    if ($script:Pki.RsaPss -and $Family -eq 'rsa' -and $Md -ne 'default') {
        return @('-sigopt', 'rsa_padding_mode:pss', '-sigopt', "rsa_mgf1_md:$Md", '-sigopt', 'rsa_pss_saltlen:digest')
    }
    return @()
}

function Get-PkiOwnMd {
    # Digest of a CA's own CSR (proof of possession). Root-level CAs: SHA-512.
    param([string]$Kind, [string]$Family)
    if ($Family -eq 'pqc') { return 'default' }
    if ($Kind -in 'root', 'track') { return 'sha512' }
    if ($Kind -eq 'quadrant') { return $script:PkiQuadDigest }
    if ($Family -eq 'ecdsa') { return 'sha384' }
    return 'sha256'
}

function Get-PkiMdArgs {
    # -sha512 for req (not for pure-signature keys)
    param([string]$Md)
    if ($Md -eq 'default') { return @() }
    return @("-$Md")
}
