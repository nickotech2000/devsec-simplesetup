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
