<#------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------#>

<#
.SYNOPSIS
    Builds the Agantra PKI proxy (all *.cs files in this folder) for Windows, Linux and macOS.
.DESCRIPTION
    No project file is kept in this folder: a throw-away csproj is generated under %TEMP%, compiles the *.cs files
    from here, and is deleted afterwards. Output goes next to this script with the usual names:
      agantra-inovatif-crl-ocsp-proxy-win64.exe / -linux64 / -mac
.PARAMETER Rid
    Runtime identifiers to build. Default: win-x64, linux-x64, osx-arm64.
.PARAMETER BaseName
    First part of the output file names. Default agantra-inovatif-crl-ocsp-proxy; for example
    -BaseName agantra-inovatif-tinydns-proxy gives agantra-inovatif-tinydns-proxy-win64.exe / -linux64 / -mac.
.PARAMETER Aot
    Native AOT instead of ReadyToRun + trimming (smaller memory, faster start). Native AOT cannot cross-compile, so it only
    works for the OS you are on (needs the C++ build tools on Windows); other runtime identifiers are skipped.
.PARAMETER KeepTemp
    Keep the generated project folder (for troubleshooting).
.PARAMETER Smoke
    After the build, start the binary for this OS once with --help and --env-report (both read-only, nothing is changed)
    to prove it starts. Skipped when the binary for this OS was not built.
.PARAMETER SumsOnly
    Do not build: only write SHA256SUMS-proxy.txt for the binaries that are already in this folder. Use it after you have
    code-signed the binaries, because signing changes the hash.
.PARAMETER Sums
    Write SHA256SUMS-proxy.txt next to the binaries (hash of every built file and of appsettings.json). Give this file to the
    customer's administrator together with the security hand-over text, so the files can be verified and allow-listed.
.EXAMPLE
    .\build-me.ps1
    .\build-me.ps1 -Rid win-x64
    .\build-me.ps1 -Rid win-x64 -Aot
#>
[CmdletBinding()]
param(
    [ValidateSet('win-x64', 'linux-x64', 'osx-arm64')]
    [string[]]$Rid = @('win-x64', 'linux-x64', 'osx-arm64'),
    [string]$BaseName = 'agantra-inovatif-tinydns-proxy',
    [switch]$Aot,
    [switch]$KeepTemp,
    [switch]$Smoke,
    [switch]$Sums,
    [switch]$SumsOnly
)

$ErrorActionPreference = 'Stop'

Write-Host '-------------------------------------------------' -ForegroundColor Cyan
Write-Host 'Author  : Nicko Satria Utama' -ForegroundColor Cyan
Write-Host 'Company : Agantra Inovatif OU' -ForegroundColor Cyan
Write-Host 'Email   : nicko@nextmantra.com' -ForegroundColor Cyan
Write-Host '-------------------------------------------------' -ForegroundColor Cyan

$ProjectDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($ProjectDir)) { $ProjectDir = (Get-Location).Path }

$sources = @(Get-ChildItem -Path $ProjectDir -Filter '*.cs' -File)
if ($sources.Count -eq 0) { Write-Error "No .cs files found in $ProjectDir"; return }
Write-Host ("Sources : " + (($sources | ForEach-Object Name) -join ', ')) -ForegroundColor Gray

# These files make up the proxy; a missing one would compile into a program without the tiny DNS or the test switches.
$required = 'Config.cs', 'Program.cs', 'Http.cs', 'Handlers.cs', 'Installer.cs', 'Dns.cs', 'DnsTest.cs', 'DnsOsSetup.cs', 'EnvReport.cs', 'SecurityInfo.cs'
$missing = @($required | Where-Object { $sources.Name -notcontains $_ })
if ($missing.Count -gt 0) { Write-Error ("Missing source file(s): " + ($missing -join ', ') + ". Copy the complete set into $ProjectDir."); return }

if ($SumsOnly) { $Sums = [switch]$true }
else {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { Write-Error 'dotnet SDK not found on PATH.'; return }
    $sdk = (& dotnet --version) 2>$null
    if ($sdk -and ([version]($sdk -replace '[-+].*$', '')).Major -lt 10) { Write-Error ".NET SDK 10 or newer is required (found $sdk)."; return }
    Write-Host "SDK     : $sdk" -ForegroundColor Gray
}

$Targets = @{
    'win-x64'   = @{ Ext = '.exe'; Suffix = '-win64' }
    'linux-x64' = @{ Ext = '';     Suffix = '-linux64' }
    'osx-arm64' = @{ Ext = '';     Suffix = '-mac' }
}

# Native AOT only builds for the OS it runs on.
$hostRid = if ($IsLinux) { 'linux-x64' } elseif ($IsMacOS) { 'osx-arm64' } else { 'win-x64' }

$work = Join-Path ([IO.Path]::GetTempPath()) ("pkiproxy-build-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

# Compile items are absolute paths, so nothing is created inside this folder (obj/bin live in $work).
$compile = ($sources | ForEach-Object { '    <Compile Include="' + $_.FullName + '" />' }) -join "`n"
$aotFlag = if ($Aot) { 'true' } else { 'false' }
$csproj = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>pkiproxy</AssemblyName>
    <RootNamespace>PkiProxy</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <InvariantGlobalization>true</InvariantGlobalization>
    <UseSystemResourceKeys>true</UseSystemResourceKeys>
    <DebugType>none</DebugType>
    <DebugSymbols>false</DebugSymbols>
    <GenerateDocumentationFile>false</GenerateDocumentationFile>
    <JsonSerializerIsReflectionEnabledByDefault>false</JsonSerializerIsReflectionEnabledByDefault>
    <ServerGarbageCollector>false</ServerGarbageCollector>
    <ConcurrentGarbageCollection>false</ConcurrentGarbageCollection>
    <TieredPGO>false</TieredPGO>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
    <NoWarn>`$(NoWarn);CA1416</NoWarn>
    <SelfContained>true</SelfContained>
    <PublishSingleFile>true</PublishSingleFile>
    <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
    <PublishAot>$aotFlag</PublishAot>
    <PublishTrimmed>true</PublishTrimmed>
    <TrimMode>full</TrimMode>
    <PublishReadyToRun Condition="'`$(PublishAot)' != 'true'">true</PublishReadyToRun>
    <MetadataUpdaterSupport>false</MetadataUpdaterSupport>
    <EventSourceSupport>false</EventSourceSupport>
  </PropertyGroup>
  <ItemGroup>
$compile
  </ItemGroup>
  <ItemGroup>
    <RuntimeHostConfigurationOption Include="System.GC.HeapHardLimit" Value="134217728" />
    <RuntimeHostConfigurationOption Include="System.GC.RetainVM" Value="false" />
  </ItemGroup>
</Project>
"@
Set-Content -Path (Join-Path $work 'pkiproxy.csproj') -Value $csproj -Encoding UTF8

$errors = 0
try {
    foreach ($r in $(if ($SumsOnly) { @() } else { $Rid })) {
        $t = $Targets[$r]
        $final = "$BaseName$($t.Suffix)$($t.Ext)"
        if ($Aot -and $r -ne $hostRid) {
            Write-Host "`n[-] $r skipped: native AOT cannot cross-compile (run without -Aot, or build on that OS)." -ForegroundColor DarkYellow
            continue
        }

        Write-Host "`n========================================================" -ForegroundColor Yellow
        Write-Host "[>] $r  ->  $final  ($(if ($Aot) { 'native AOT' } else { 'ReadyToRun + trimmed' }))" -ForegroundColor Yellow
        Write-Host '========================================================' -ForegroundColor Yellow

        $out = Join-Path $work "out-$r"
        & dotnet publish (Join-Path $work 'pkiproxy.csproj') -c Release -r $r -o $out --nologo -v:q -p:TreatWarningsAsErrors=false
        if ($LASTEXITCODE -ne 0) { Write-Host "[!] build failed for $r" -ForegroundColor Red; $errors++; continue }

        $built = Get-ChildItem -Path $out -File | Where-Object { $_.BaseName -eq 'pkiproxy' -and $_.Extension -eq $t.Ext } | Select-Object -First 1
        if (-not $built) { Write-Host "[!] no output binary found for $r" -ForegroundColor Red; $errors++; continue }

        # A running copy of the proxy, or the antivirus scanning the previous file, can lock the target for a moment.
        $copied = $false
        for ($try = 1; $try -le 8 -and -not $copied; $try++) {
            try { Copy-Item -Path $built.FullName -Destination (Join-Path $ProjectDir $final) -Force -ErrorAction Stop; $copied = $true }
            catch { if ($try -eq 8) { Write-Host "[!] cannot overwrite ${final}: $($_.Exception.Message)  (is the proxy still running? use: $final --stop)" -ForegroundColor Red } else { Start-Sleep -Seconds 2 } }
        }
        if (-not $copied) { $errors++; continue }
        $mb =[Math]::Round((Get-Item (Join-Path $ProjectDir $final)).Length / 1MB, 2)
        Write-Host "[+] $final ($mb MB)" -ForegroundColor Green
    }
}
finally {
    if ($KeepTemp) { Write-Host "`nKept build folder: $work" -ForegroundColor Gray }
    else { Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue }
}

$built = @(Get-ChildItem -Path $ProjectDir -File | Where-Object { $_.Name -like "$BaseName*" -and $_.Name -notlike '*.txt' })

if ($Sums -and $built.Count -gt 0) {
    $lines = @($built + @(Get-Item (Join-Path $ProjectDir 'appsettings.json') -ErrorAction SilentlyContinue) | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name })
    [IO.File]::WriteAllText((Join-Path $ProjectDir 'SHA256SUMS-proxy.txt'), (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
    Write-Host '[+] SHA256SUMS-proxy.txt written' -ForegroundColor Green
}

if ($Smoke) {
    $mine = Join-Path $ProjectDir ("$BaseName$($Targets[$hostRid].Suffix)$($Targets[$hostRid].Ext)")
    if (Test-Path -LiteralPath $mine) {
        Write-Host "`n[smoke] $([IO.Path]::GetFileName($mine))" -ForegroundColor Yellow
        $env:DOTNET_gcServer = '0'
        foreach ($sw in @('--help'), @('--env-report')) {
            $out = & $mine @sw 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0 -and $out.Length -gt 0) { Write-Host ("  ok   " + ($sw -join ' ')) -ForegroundColor Green }
            else { Write-Host ("  FAIL " + ($sw -join ' ') + " (exit $LASTEXITCODE)") -ForegroundColor Red; $errors++ }
        }
    } else { Write-Host "`n[smoke] skipped: no binary for $hostRid was built." -ForegroundColor DarkYellow }
}

Write-Host "`n========================================================" -ForegroundColor Green
if ($errors -eq 0) { Write-Host '[+] BUILD COMPLETE' -ForegroundColor Green }
else { Write-Host "[-] BUILD FINISHED WITH $errors ERROR(S)" -ForegroundColor Red }
Get-ChildItem -Path $ProjectDir -File | Where-Object { $_.Name -like "$BaseName*" -or $_.Name -eq 'appsettings.json' -or $_.Name -like 'SHA256SUMS-proxy*' } |
    Select-Object Name, @{ Name = 'Size (MB)'; Expression = { [Math]::Round($_.Length / 1MB, 2) } } | Format-Table -AutoSize
Write-Host 'Binaries are not signed here. For a customer: sign them, run .\build-me.ps1 -SumsOnly, then send the binary, SHA256SUMS-proxy.txt and SECURITY-HANDOVER.txt.' -ForegroundColor Gray
Write-Host 'On the customer machine the administrator runs:  <binary> --security-info --admin-script   (see SECURITY-HANDOVER.txt)' -ForegroundColor Gray
Write-Host '========================================================' -ForegroundColor Green
if ($errors -gt 0) { exit 1 }

# SIG # Begin signature block
# MIJEJwYJKoZIhvcNAQcCoIJEGDCCRBQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB3e/DlwbLg5Y12
# jsLJsXBROm1Lfju+nRxauViE1IaxG6CCPIIwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzCCCFEwggY5oAMCAQICEDC+rVhO7O1QAJ/4rgkZXskwDQYJKoZIhvcNAQEL
# BQAwggEHMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYDVQQFExFFRUFSSVJFRy4x
# NzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoM
# E0FnYW50cmEgSW5vdmF0aWYgT1UxGDAWBgNVBAsMD0ludGVybWVkaWF0ZS1DQTEi
# MCAGA1UEAwwZQWdhbnRyYSBFViBSU0EtNDA5NiBHMSBDQTEbMBkGA1UEKQwSTmlj
# a28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFudHJh
# LmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQwMTkwHhcNMjYxMTExMTI1MjE4WhcN
# MjcxMjExMTI1MjE4WjCBzjEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24x
# EzARBgsrBgEEAYI3PAIBAxMCSUQxGDAWBgsrBgEEAYI3PAIBAgwHVGFsbGlubjER
# MA8GA1UEBRMIMTczNDQxMzExCzAJBgNVBAYTAkVFMRAwDgYDVQQIDAdUYWxsaW5u
# MRAwDgYDVQQHDAdUYWxsaW5uMRwwGgYDVQQKDBNBZ2FudHJhIElub3ZhdGlmIE9V
# MRwwGgYDVQQDDBNBZ2FudHJhIElub3ZhdGlmIE9VMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAnE8Uxs2SRMoPlMzLQfouz/xCs/tauFe/5eARagKMwn/t
# ymidvwxBUowv9svmAtAuG8vAQeDA+4W0SwjZ/qtwoGLgGR10m2+IxEFxuf6HcOkH
# DQlmopdjrgnXEtnuBMHUCXrOuhL6bbc6hOkrkixeiTd4yrkHqAzS/ws+50moyf7c
# ojuTZWc45pJ/SzM5N0F7xlY4zMEcBB3Sf5ARQd0CcUPVunuSwc94FMHWnjyD0KZJ
# xDqPpJvq404ZAD4m8Bg3UKskBZyPWiYF0Y2xwunLMkgXWVz1UqVDybJuHCg3+Pti
# GEi/YzAFb9v9FMDjRN5ysASfWzExeCFOpzIyGJzs+PHbJAkf4uTN1LOp47aV+GBi
# +oiOOo5B/kTEAEbBw8/pG6R8klO8RhXqDWTtRGL+w/CGlrqk+hSUxQ03Ibp+7Kfn
# K8P1iGQkOAVrMsmNl6tg/Ad3iKMr4xEexB4sXrjl1DMWNO79Tq+d0jURuBHEJnoH
# M/Kpsp0cVdtmrf7gdgXya2EeNZz/Jo/qfqBuKloNQ7fNdEXRa/iLLjTiv7PUQ7tT
# fGULjV8jMweMrtsrt36k/9mJ0lV72yRE7O41tKeqpVq1AUi8edZsf4KoKgkWjmxo
# MkJdmcgI2lhtFMUu46umF89WWj1Yusg7EFEpeCTep49BJc8155D+OSTOp4Q4qwEC
# AwEAAaOCAe0wggHpMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRS0syUGQFoU3d+BcSztogonuuiODAf
# BgNVHSMEGDAWgBS7XhtjedSjX1QqQpZ+nVG9eNIRTDCBrwYDVR0gBIGnMIGkMEsG
# CSsGAQQBhIwYATA+MDwGCCsGAQUFBwIBFjBodHRwczovL25leHRtYW50cmEuY29t
# L3NlY3VyaXR5L2NlcnRzL2V2LWNwcy5wZGYwTAYKKwYBBAGEjBgBATA+MDwGCCsG
# AQUFBwIBFjBodHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzL2V2
# LWNwcy5wZGYwBwYFZ4EMAQMwRAYDVR0fBD0wOzA5oDegNYYzaHR0cDovL2NybC5u
# ZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEtcTEtZXYtZzEuY3JsMHwGCCsGAQUF
# BwEBBHAwbjArBggrBgEFBQcwAYYfaHR0cDovL29jc3AubmV4dG1hbnRyYS5pbnRl
# cm5hbDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC5uZXh0bWFudHJhLmludGVybmFs
# L2FnYW50cmEtcTEtZXYtZzEuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQA6yygwfvga
# YHQn2Wiv90I8ckuMe78ndnVmhdlf6+020kdbwL9iCXnHqgd7110BgUmxkHjdAJWY
# OPOmg751c7JJEe+wTe8hW8RWhi5vGe/kraxvgLnSFrKQiPx+8t7YPEB8DhnpHzkt
# itrzGmVrdvccQfG6ASG3NURD1qNK5OYY9W6BnrPDQQE3X6UdjMfGvDM0cxhFiXTF
# ZcfN9ZJelco0TDi2oBPvrB1++J/+b70YcEw9wq2Qy5TB3ldQWNiGPakh42lhc/sp
# DQpCZr9UH/DqN8StXjQBa5iS1Aqn8aqFwWmykia+VWB97IhMN6RVgaBiVe8tgL+s
# l1YcsoNECSh5n5Q85YrOMJElhwcKp707NGsO+I3eaoP4ZM8z5ZoIngTaTVnENrkE
# bTppnuzQQp4xYsgg6wqb1I4Xo1ULOJXNvoLWOtUy5pogXCSZi6cHfYtKEhOg3NiZ
# 3jli/xZ6NO1c36M3TW9CGPcv6Fs+VyDIYaj6M7J6EpqTXD9kW3aFa0FukNg5/DSl
# UkdrYWWWCQFU24klaJTA+HDDtg54iX09vVSKv67hrMOUj6q8A+5oMCj5VqyP1F6i
# 3fL/s4nZgUVwheJN51BlmXGJjCYOjhEJ4YxSN+NiKxL151fggUxQvZwz1t9xlKkX
# jNN9CF6om4NpiJ5sEmqNxS/mZ+LOYHnzejCCCMUwggatoAMCAQICEHZimyX5IwmB
# Zyo8wC5dFrIwDQYJKoZIhvcNAQEMBQAwggEKMRMwEQYLKwYBBAGCNzwCAQMTAkVF
# MRowGAYDVQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNV
# BAcMB1RhbGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYgT1UxFzAVBgNV
# BAsMDlF1YWRyYW50LVJvb3RzMSYwJAYDVQQDDB1BZ2FudHJhIENsYXNzaWMgUTEg
# Um9vdCBDQSBHMTEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZI
# hvcNAQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMx
# OTQwMTkwIBcNMjYxMTEwMTI0NDQyWhgPMjI3NjExMTAxMjQ0NDJaMIIBBzETMBEG
# CysGAQQBgjc8AgEDEwJFRTEaMBgGA1UEBRMRRUVBUklSRUcuMTczNDQxMzExCzAJ
# BgNVBAYTAkVFMRAwDgYDVQQHDAdUYWxsaW5uMRwwGgYDVQQKDBNBZ2FudHJhIElu
# b3ZhdGlmIE9VMRgwFgYDVQQLDA9JbnRlcm1lZGlhdGUtQ0ExIjAgBgNVBAMMGUFn
# YW50cmEgRVYgUlNBLTQwOTYgRzEgQ0ExGzAZBgNVBCkMEk5pY2tvIFNhdHJpYSBV
# dGFtYTEjMCEGCSqGSIb3DQEJARYUbmlja29AbmV4dG1hbnRyYS5jb20xFzAVBgNV
# BBQMDigrMzcyKTUzMTk0MDE5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA0LWE8ceQhWdJJNBbr2Yn/LpfI0quOINctaKCmqGUBypAAzT9LK5WlvittZbJ
# Vg0tlOhhD5gP7F7mRxJCsslPVZG87L+VGEoGPG0SF28PAZsCksA/aQvUiFWbfMFb
# 9AY6cKCrcFTbBC0Uul/EC9CnnCrT8CPX3+0CIEFg7Ya5qW+h57BBQmvnRy3TfBrE
# RAhThHXc0sgF1LRs2pvfRJ5Abnmjwhz/McCHN10zwQVrGIiSPa+X1ugU/brMi1q6
# tBQjAKD41cTdIWPbBL8o4WMEP+0QDwOFVM3Sbac9Ci7oufmrAwu8FgOCGnifx7Mr
# BhJUjl3CIU0FFzYry4HUEbd8E+shujKYNvmV/moqchNODCdhY4EUJN0az8s3SD0v
# WJ90Zb0d+PJK+spqVxb6dY4ezx9v0pZV19hfGR9rif1YjsOV5SITzj+Vt1YdhZG8
# urJbZeES/47ZVDTMoUMHWpw3NtJdZVUBgwuvyhiWHgOnLTAYsbUa3WOa7/2O+n5d
# ov7Gzd6p3gIiWTwXlFtwliWtrxY6gAdQ1b9SYdefM3lOBGTatUhm7rIEg175qGmd
# NvCt2PM6wdtshTgFNRBjob4VYqmJUeexQaWefnicDPvqqVCbezbvTJX/QimZCiqT
# cOlyHI/Vx1+CdOAooswYBhxsqCZKLtxC1qbAJKybtayjH7UCAwEAAaOCAiIwggIe
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBS7
# XhtjedSjX1QqQpZ+nVG9eNIRTDAfBgNVHSMEGDAWgBRzZ3r0UiTfRpDHfoRIWmvD
# 2LgKhjCB7wYDVR0gBIHnMIHkMEcGBWeBDAEBMD4wPAYIKwYBBQUHAgEWMGh0dHBz
# Oi8vbmV4dG1hbnRyYS5jb20vc2VjdXJpdHkvY2VydHMvZXYtY3BzLnBkZjBLBgkr
# BgEEAYSMGAEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9z
# ZWN1cml0eS9jZXJ0cy9ldi1jcHMucGRmMEwGCisGAQQBhIwYAQEwPjA8BggrBgEF
# BQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0cy9ldi1j
# cHMucGRmMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwubmV4dG1hbnRyYS5p
# bnRlcm5hbC9hZ2FudHJhLXExLXJvb3QtZzEuY3JsMH4GCCsGAQUFBwEBBHIwcDAr
# BggrBgEFBQcwAYYfaHR0cDovL29jc3AubmV4dG1hbnRyYS5pbnRlcm5hbDBBBggr
# BgEFBQcwAoY1aHR0cDovL2NydC5uZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEt
# cTEtcm9vdC1nMS5jcnQwDQYJKoZIhvcNAQEMBQADggIBALvIqYtQTbtFzFhTVUpo
# FbQrcUfDO1baQSgxNXIqjUle5ELB3giyrBxbWwh8HHwkkZuvVOE9bJ91ImcOfdFZ
# D5jqvkuAVUBcuGqE+dEM09tY3jWQlTNb52ZbVOcC9sSZx7cTuh93NhsH/muyY8qj
# 58Oy+WwGxazbOo4uQeMp5rr6NRnv2nIVTbVeL8CmU9Or9ESTpgzIjVx65sNZCLOp
# F4PaR0psc2paqWYkBLLXLo6GjHgGT+vUoWncD6b4vA3a9RVz6fAqZoUrDB53z9Q2
# egQjkBFzlGf4zqWnJswnykd8QnwJhR/Dd4HMLTQiQBSPdpxV2bBSkwmuHfdQeV9K
# h0MoILMKUoGz0nhgjbWBD62YXBDGcD8E1tIjqY8j9W9E157Y+oMTiKzqjwtBxw5N
# soUApa0oelPCyalQ8xVFyJvT+RdoPdDzO4FKS8LubXmkYwyvseI2vHFTI4tjSSUU
# 8iGj2UW+mWjcx6McI+A4vJm0D6kUMfmPUjT9spn+ulJvqBb7Drj1m8Tla2+aj61g
# dul8sWTPbZOMOUGm0fZcQEobAFaWrbYvhcLYMDUrNN9t1JdOsTNBu3YLOdJSSj3R
# CWmbHmfHhj5dhwPWUrhys7Doo/btMaAsNyor83UjmW0q0hWLdQ/R2a4P+WX3ZdMw
# RpuPp8jvrm5Bt2fCxua3tJ0yMIIMDDCCB/SgAwIBAgIQYNJyHEujv8+hmUk4ZqRU
# lzANBgkqhkiG9w0BAQ0FADCCAQQxEzARBgsrBgEEAYI3PAIBAxMCRUUxGjAYBgNV
# BAUTEUVFQVJJUkVHLjE3MzQ0MTMxMQswCQYDVQQGEwJFRTEQMA4GA1UEBwwHVGFs
# bGlubjEcMBoGA1UECgwTQWdhbnRyYSBJbm92YXRpZiBPVTEUMBIGA1UECwwLVHJh
# Y2stUm9vdHMxIzAhBgNVBAMMGkFnYW50cmEgQ2xhc3NpYyBSb290IENBIEcxMRsw
# GQYDVQQpDBJOaWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0BCQEWFG5pY2tv
# QG5leHRtYW50cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAxOTAgFw0yNjEx
# MTAxMjQ0MzhaGA8yNDI2MTExMDEyNDQzOFowggEKMRMwEQYLKwYBBAGCNzwCAQMT
# AkVFMRowGAYDVQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMCRUUxEDAO
# BgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYgT1UxFzAV
# BgNVBAsMDlF1YWRyYW50LVJvb3RzMSYwJAYDVQQDDB1BZ2FudHJhIENsYXNzaWMg
# UTEgUm9vdCBDQSBHMTEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJ
# KoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIp
# NTMxOTQwMTkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDdLri07O62
# CiFnt8EPJRSgEu+r3v+hTgSAxWltLcpcRxo9vh/OusTMWv57f56rDRW5ciPAVAPf
# pOHmeQBA52PU4s8OLMSD+0V07NyPlqbh5ny3FGtm7cYqJAoOB4l4ArlOM9jGiwIS
# v6HhKTCyqqd0R8efbfSR9Szk1yfLhVUSEO1sYsD5GIZ9LCkHcPT+EZOuyOo4dOKF
# uhldgtnkt8Sqr8BM1IzQuaAnZg06YFSgFtmMZNCNLc+bWmqr67P6FIwu71BGnib3
# 8dKKrhfIKi9LEK73ryIF99GnseDtDjCvXG8Ld7D61vj9ZzVmA9mY3K5GJOJepSJ1
# hOgy4W57rD1BLPcS2wVx9eNeqrvt77w40GJ6NhwuRNigXhuvaCSZ/uwfy8OnW/Ra
# IRogBQkVSAGLhI314s63KkK0UyVikTifv2HNf0RDPm+Sj7u5g+J+O/rpCK0lB1Ay
# ZFp+6Lcz6hwaXCiLB40SthJeQcnjA6vpenpGP294lT5ZBZHE1LWfF5tzxOu1WFR8
# X8HaN7yStistsQk0UbWqUU9yN4gWzzUjT7TH99B36Hm3VYR4ZK22gUsu4NDpwWSI
# bP4eYPWALOUhCLjq0KKfRzP7YnyvIcYQCh+dK/wPKAsT6CQQI/MAX2nmvpBVJ/9F
# C7j6e9Dk5jylrZychbsqsODVUi0Yqr3ABQIDAQABo4IDbDCCA2gwEgYDVR0TAQH/
# BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHNnevRSJN9GkMd+
# hEhaa8PYuAqGMB8GA1UdIwQYMBaAFOZgQnEy/gO3Db/I7zf2rAiud3SxMIICLQYD
# VR0gBIICJDCCAiAwRwYFZ4EMAQEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0
# bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0cy9ldi1jcHMucGRmMD0GBmeBDAECAjAz
# MDEGCCsGAQUFBwIBFiVodHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2Nl
# cnRzMD0GBmeBDAECATAzMDEGCCsGAQUFBwIBFiVodHRwczovL25leHRtYW50cmEu
# Y29tL3NlY3VyaXR5L2NlcnRzMEAGCSsGAQQBhIwYATAzMDEGCCsGAQUFBwIBFiVo
# dHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzMEwGCisGAQQBhIwY
# AQEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0
# eS9jZXJ0cy9ldi1jcHMucGRmMEEGCisGAQQBhIwYAQIwMzAxBggrBgEFBQcCARYl
# aHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0czBBBgorBgEEAYSM
# GAEDMDMwMQYIKwYBBQUHAgEWJWh0dHBzOi8vbmV4dG1hbnRyYS5jb20vc2VjdXJp
# dHkvY2VydHMwQQYKKwYBBAGEjBgBBTAzMDEGCCsGAQUFBwIBFiVodHRwczovL25l
# eHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzMEsGA1UdHwREMEIwQKA+oDyGOmh0
# dHA6Ly9jcmwubmV4dG1hbnRyYS5pbnRlcm5hbC9hZ2FudHJhLWNsYXNzaWMtcm9v
# dC1nMS5jcmwwgYMGCCsGAQUFBwEBBHcwdTArBggrBgEFBQcwAYYfaHR0cDovL29j
# c3AubmV4dG1hbnRyYS5pbnRlcm5hbDBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5u
# ZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEtY2xhc3NpYy1yb290LWcxLmNydDAN
# BgkqhkiG9w0BAQ0FAAOCBAEAMHgU5rdeN9ASSLLAyJPxtMM5v3s0hpdBqqknms6N
# zJgRgTHrVJ8gpwrNc0wrSYKOKt3tKpjO9Fiq3GbrIykaTz+XlRwckZ0jWc5C43Y7
# Vzl71b02ppzWMmMYlvEKlP43n45n61o/IQZzaxMcDl/RlLhJCs+EWb/saB9Dq2DT
# uRwQ+vGKuOkEM+SqnMDDK0TPRGBK08Qfcf2iyIEUJIc8oJmpwK7gRUQ8MfnuFyWM
# oInX6R5OXvfTs07YxQfXk8x4S6FYU3YZqZatFD5ZfdBFUvZfGDawjZLIK0JUDq5n
# hcOQrtvbY4Aa18YdtZPDikKEeztxvhABFWuHbc/2YBibudZC7ZmNJ6H9os2jN8u/
# oB7N4H+I6h8J3sFaDOnoSbu1obn7280OKbTHCQJw4eGhXQj4n+DOc6OTBgWjIIY8
# v5ggH8p4NgkHDS2RhLnJCKSP4xgDjKK+ceisRNU1u8iN6SfFV94gGDqN04oVHJJm
# I+936fJ0qCGOfo4UdMUCq1RPoQXtUQ5O3+zXuqU4ft1y1/betbCNbp1pLz/vVWQ6
# FeWaD7tzhqIt9ddMZEaERZr9SkM8XNdYJcs53ZsqRFqcBRvlNBgCCQaW5ssG6kbL
# 38ITe7JYniAAXlkYnKq//L2cxel2+6g7yE5vgwT510xY6z4f5/K9l8+WADWkOfvj
# XqxYoGZrDX/21AWKYcOkZBlUMJvaXuQNNth+f+Oq5kCL3bmMtUY6tHxfFhnObxsC
# T+OrrZ01hfH8QLlfw4xLQj+AUInCV++Th2gia18lQGPtjTfIwmVyQtAMXO9fQsX6
# /PP3s65U1SQOKpEpyBMDaECzAgntIYICeNpsy7uFOSxgMbXKb36ejHQfBZJCtxKi
# M1x6FK/qC5p1Rc50okvmEsuWIgVa2X8o+o7yPv51mxG/RRF9uObkaW5o+F68UPcJ
# wDsfkMwZ2jkQYuW3gD1ycHR3NdMRKcY6qlwrLOxHRMjaFce2Xr+uScg6aLaSrHJ7
# mx7reaKZi8IrU6lpEuVCDdhgbvRobSqf6eDieubH6gVA/b003MYrjpLzgSWIZfCI
# NdTvoBfHTx+TUATiDkT8p5W3mZldAhoPxdSwXc8OhzEKjrxt1dwcGE5QgkS8/JG6
# kaQRuD6M8aMnzMyaz211SQxhCslUFKkHyrNSf0cKeHH6Q83TWKJ9sSNY2YEL6zAW
# zVoG+OGsyHwYpVF/7kV/jel/XmeLfhinwHlzq9U38zlzY+hXIb1QrkU3cfT2wvVD
# qzkUv+OPAKgtS3XvC+dQup1EE9aYYOCsmqvktEAn1YsTHzkb1Zqh99+L9Lv0glyH
# fhTo3e69McqfSZb48R3QmUpqXAXhEdEAQNxXV8uMFZ/K/zCCDBYwggf+oAMCAQIC
# EBtgCP/Kbm8A12oQovKK3nMwDQYJKoZIhvcNAQENBQAwgfsxEzARBgsrBgEEAYI3
# PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVHLjE3MzQ0MTMxMQswCQYDVQQGEwJF
# RTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdhbnRyYSBJbm92YXRpZiBP
# VTETMBEGA1UECwwKUm9vdC1DZXJ0czEbMBkGA1UEAwwSQWdhbnRyYSBSb290IENB
# IEcxMRswGQYDVQQpDBJOaWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0BCQEW
# FG5pY2tvQG5leHRtYW50cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAxOTAg
# Fw0yNjExMTAxMjQ0MzdaGA8yNTI2MTExMDEyNDQzN1owggEEMRMwEQYLKwYBBAGC
# NzwCAQMTAkVFMRowGAYDVQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMC
# RUUxEDAOBgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYg
# T1UxFDASBgNVBAsMC1RyYWNrLVJvb3RzMSMwIQYDVQQDDBpBZ2FudHJhIENsYXNz
# aWMgUm9vdCBDQSBHMTEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJ
# KoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIp
# NTMxOTQwMTkwggQiMA0GCSqGSIb3DQEBAQUAA4IEDwAwggQKAoIEAQCl6FIemmC0
# 6Oio87GeihhWXgga3temk6QE3682h8tgKNDWK/tk40k4wVJDNVi+47fMwV5KZqSv
# fB7SFjpePtpdVlkYz5as1CEl0cINE28go7Ma1uLsw8X+eDUsba3r/6tjC11CnMIi
# dXEAa5PfWQ+3V2yd/BOXwHo0bmO9wMus+51h5gnIdjOHlI+y2u9q8VgHHen7wXzt
# c2zZq2zDwO4oVuhg5iqbRlLy0LWk7Alj0oSG+0FBlyT8SbzV2tx8i4AbnS6BRyqB
# IqJzEzPxXLE+iHAWkB5iZ/4Z+hQCLtKIaaHrXVMQbTdGoejeqOWTnoQ+e8N8SM+g
# 8uyKPdzjOmbYYtFJJ8j84iZdsw697mg6Z3DETpW0LpYMa0T1knObG/bGYcXvXo73
# w6SNdg+PnnzYY6yO6cOiw1gzvHOtF/vqTNZKLkOOHKKbukag5zzksYnvz8E0I9lv
# kfRbHhGCnoyXYoXLlnTkjMlSDDa97NMUN2L2aHD4nWa+wX9OzcEXAGsVbCr7padz
# Wu6Acj3aeTQlhkNMq1DBDKZuy7gxs4PSaw4krFAXtaKpY/Oa0kXnwjkwkithLrGD
# OGeY3CNHppmIpvV/xu1FSeYfvuNQ3mBuIuuL3LkwVgdlMDvn6AhqYsi/wd28sI1W
# TAKjz9LAAyUIejMjckC4X7+9DX3V1Ag5bwd9DuRiVvySzTQ+ptx06+ZM2BwSgt/2
# Z6d7lezgoNg2PhFrP6GqtCN2ZSrlhjvmCmfk+AijqZpBmK9K3XkEJzSiifHEWa8S
# S/tHRP821x6YK7xsWzLjGzNdE0KiZ/qEJ+kBQ6LMQlMPKx7iVaogIyVbXW2DdLSk
# OGhXGoRExRM11yNvd8ZsMY4WJcy0OcRht2smMmPsMPnXscVxSCxvGT6wnFTxbdMN
# 6HEMo86gOFxJ93dAX62lckjpGmJi92BQPOnERXws2iA+AobxkMWYFYQmBPdGwmIU
# dFIyNAAhjJFT5EYqfXiRyIqHkS3RLMjd6hrrqq8RBtAjRNoS3SXSmrX4A2qySOnF
# hBkVoQGKBmcUzkiYXD7FojmnSA8yODegsDgf8jjgwZdIG/L1X+rreESepxYq4q9U
# 6lIy7TvO5pgXNWnpcvweZf5n4y2AmGfzZVeRjxKgTST776V/AiV0X2jetUCRfQL+
# QrT7A0oz+QWF5zk1oaFtG2z9NlGKbVqezhvMmgCTWwBSxUIOJdz1TOzqCOlaDQSm
# kR4PM1Gz3N++/oq3+HlfT2r5NjwR791Y9LTMZC+mjSLyk5AdoJW8WQ1EuZGeY9Nc
# zqYAAfYegNeWimoZKZ0ynt7/J1nGLrGHuWuw0BtqNpxeHjgudfiAACX2SvWgTYNQ
# JaTZx7qj6C6PAgMBAAGjggGGMIIBgjASBgNVHRMBAf8ECDAGAQH/AgECMA4GA1Ud
# DwEB/wQEAwIBBjAdBgNVHQ4EFgQU5mBCcTL+A7cNv8jvN/asCK53dLEwHwYDVR0j
# BBgwFoAUQBVqU/qpoI6JzR/XDIrFyFps0XAwWgYDVR0gBFMwUTAGBgRVHSAAMEcG
# BWeBDAEBMD4wPAYIKwYBBQUHAgEWMGh0dHBzOi8vbmV4dG1hbnRyYS5jb20vc2Vj
# dXJpdHkvY2VydHMvZXYtY3BzLnBkZjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8v
# Y3JsLm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1yb290LWcxLmNybDB7Bggr
# BgEFBQcBAQRvMG0wKwYIKwYBBQUHMAGGH2h0dHA6Ly9vY3NwLm5leHRtYW50cmEu
# aW50ZXJuYWwwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQubmV4dG1hbnRyYS5pbnRl
# cm5hbC9hZ2FudHJhLXJvb3QtZzEuY3J0MA0GCSqGSIb3DQEBDQUAA4IEAQACyf2J
# GugvORSsiwf8WU3SV3wby6d547UZYdRGqIcHolLU7A5HihzuqVx2Kuy3D/IzGUtP
# o8h+CwCtkavQvQgoBrAk66A/f6sbogNrM3eRUsq5h7L35t9y5JdkwQFj/+aGrUpq
# 7C7gPAxJgg4ZO+qDzKI/EUjNKVvGksG9C4nnuKCqvRfqRI7MjJNcmMwEmBbgGhYC
# EtSXwSuOqnYNBBmBpR1/+lZz5XI6SzJNlTjU1GDiMlAIGLyj8E8npviG7pa1tdMJ
# agPubJxRCoZMju5ZUhV2FCDoNMpcVbZtBQht5/JENCi7fy5OkHQ4cOHR0uCK6mz8
# bb92o3ItxBd9uVY5t5ZQtVqrXx1Ta+6mML8RogxtRw9Xs8rFOxYyZBGxMnnjjl8c
# AbJOGg0QZWu6IHPnVubo8TUKND477LFkhKbMLs1YR7bMcD/M4yHWkOuC9Ff7sP9Z
# HEJV3NihA4UczhC5j+uGrGF0nVh9qgStqU121Q6HkKWP5sW66m94S8AuMEum13+9
# KbT4haRIlU3ndKHIpWBBfl3GVdRRGTRizr5rHxMev3CwCJMrCFWZ0c2fGsjzXbqI
# WvqgtusiizEJwAFmhMM//nHk2HlcBDaYRm0ayMpfZVVcirtQpXXuvfZDdxnv2Ud1
# kwYsP9hHvmOUwoehBB1tago6Xysn4a5LXe2o+pn4EuRGSQAJ3l8s9FjJF2gZFxk+
# aUrpn3lzr5EAQ3h0/Tb55BcWImuO8tR+RngQQ1Tb6dAUGndsDo78ezlhurHiDN86
# vu4dFzXReOOM8oHq+yE7mMBeAQozT0J1xKtyqIzlL7TybRI3PH7PxQ4fYdZ0wuJH
# BWQ4ZrQ0yGkxV7blw6rlNzIA82HA+qLKc5h32jkF6eZrbvrWwVilsJfH+WdFHBYJ
# HomLnb5oVH5B9CRuCNGhoS5rRZ7SJO9J6K9mFd0GvID9n3AAbEhnd0a2yIOV4t71
# DUkgRQsECxUY+9/apFuszCNbYY00Ecpij7ajWNHK0bCDnTu1gTHVSlQCqTBBEPtN
# 5934xhWs3FOLco4SWUp9Pho6otg9uxor0jSwIyXl5aZXl7Na+ywokgDGFA4xlQy5
# /N8i4PjmnqaItjS3PDDyNFh0vmWoePBv7I98g0Po4XNs8nOv4zc8r/wVCO7+969+
# ///I9L30mjJry7WxvdgYjJeb9Jhb7UderM8NqdHbhXIgufXIEPyzFdctnWRqhNU2
# lTQ5zdoFrs6Cc+pwkbbCPLVrIG2vXaPULn7eAtBUlf8Kk72VFESRIhuzFELfrSSH
# wbRm8oMR5aEEb7AnfHRF2107KeIqfLh5dH1FnnszjgBKaQKBaR3JHHgwFGpzs3mZ
# U4dJ1cvXH6hD/mTWMYIG+zCCBvcCAQEwggEdMIIBBzETMBEGCysGAQQBgjc8AgED
# EwJFRTEaMBgGA1UEBRMRRUVBUklSRUcuMTczNDQxMzExCzAJBgNVBAYTAkVFMRAw
# DgYDVQQHDAdUYWxsaW5uMRwwGgYDVQQKDBNBZ2FudHJhIElub3ZhdGlmIE9VMRgw
# FgYDVQQLDA9JbnRlcm1lZGlhdGUtQ0ExIjAgBgNVBAMMGUFnYW50cmEgRVYgUlNB
# LTQwOTYgRzEgQ0ExGzAZBgNVBCkMEk5pY2tvIFNhdHJpYSBVdGFtYTEjMCEGCSqG
# SIb3DQEJARYUbmlja29AbmV4dG1hbnRyYS5jb20xFzAVBgNVBBQMDigrMzcyKTUz
# MTk0MDE5AhAwvq1YTuztUACf+K4JGV7JMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKww
# e3ZoxnjB3RlJWkWViggbGeHUrUzStfjo6JjJoVLtMA0GCSqGSIb3DQEBAQUABIIC
# AETam0BTAK16xQbHsn2GZO7WP9/9xX2EO6iGboud1EjczoL/zTbvpb9h6t7uzSke
# bJBBK6jciXGpfxLsv4M3ZacUuZzM3U8wFmTVqCxXCnz+1d4UfKDFrzGhQfZ7MKNa
# lmRH4v6YbOm4iz8Hsk/5Q5G84u1Qe57lgBrjEGCI+lMBNnBWuHkaW+/cvufgBd53
# V15Yd+ovwR51/nS03P+z+Hbso+GDlfrf7KbrjtbUi3lqRFk7+wM3Z9J6Kolf5YjL
# ussKx1+zp78ELIWQoCzwc+TrqDsxNKu9ddERsudCnstoWHIVUlQKJ6A0x/9A40uV
# WDU1Ik/zRWMJK3ixSJWbxFSGsWT/YM0lEUIyp7+NQ/F86Wp3hRs490+UH1+x0Vi1
# e3KeCIX//8MuqEfbSihe6fk7ZHAS2YKhs35GsraNkLg4MeKv2k6APwoH94XO4JLx
# gyO34QsTSH50vIMQdSoB7ys0L7nTcdW4l5f1UXrMntRK7vDUgIrWTa03RHrml8mh
# q1PGTHlxNGWF+XAm0wlNfowK5SoTUJipzxJ5aEFDk/UsZYHEMnpo+x2X1JRRuTx1
# 7E06VNpQD/1T7dFiYOD+K90LIJTwaUQtvq1HbK0FNUZbpupe6fXXgg1qvEigfC6x
# Jck+M9PiUYvT6My0lTrhNz7zePUE62Y/8D0pDqEDYgJHoYIDJjCCAyIGCSqGSIb3
# DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFt
# cGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTAN
# BglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTI2MTExMTEzMDM0MlowLwYJKoZIhvcNAQkEMSIEIMPyokNH0etA
# /o1WzwiSZTSyT/KABrzU8BrPO6hho/hrMA0GCSqGSIb3DQEBAQUABIICADcszgaw
# E4j3jFSAZ/mqqnqtAsKAb9IPBbGOsHH/rzGIu5ubfPdAiRuxBynXJsJZhm77XgzJ
# PYJotAZ+u97B7FnGt1Ikr5NpJLMi8ruqJVCF97VXVBf7Tw5P9IlWGJqCEwm4gU8y
# jnXmgygrqEr7pYw+U0lfoX9St6v47979xrA9foyI1DrN9iKOLOwzI3Yq26CHBBb3
# FAJxKVXcoheREOS9RAV9PBFrRjeeGrWocVXnwp/yFaLx5IWgyi9FLKAOXMX0ywSk
# tsJINN+ArsnJZxigbT1u4toB1NwD+TtC+hagVS5fMW6bzQOuveoG60hH+Cuxcg+4
# kA5S0yCuMAIu3sDkzHy0aZ5OHlp+g/vOYrgbarTQIaA7TWwoEsNq9SqQT0Gs32WR
# eS8v3HagEZIPbBo1f9lUiDxiTg7hACeYRkHkdltSs6JZ2V4tw0CcvXECX1qh4z+x
# lTa7pJC2c9yn9PFmrE/r6Gtsgo8T35VGnUJagjKCHm89FEKTgBRM59wabcMhezO3
# QZ8tPxa7PypL7Fm2LE7V7HMBpcGE69VHDVOoSv2Bo0V1rl6atzRwnsxsl3Bz7zds
# wf3z6mEb4e1yvo1lnpcQl6jeAn3BeDAiHextEvUQaSw8LTctg2Tro4KtAjRGa+Rm
# PltCh6mY5TwkQ7EXDCNWaevRXbQ8kqi1Nj0D
# SIG # End signature block
