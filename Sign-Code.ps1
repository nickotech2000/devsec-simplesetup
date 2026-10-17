# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# Version: 6.4.1
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Signs code (Windows files, .NET, Java, Android APK, Office VBA, NuGet) with a private-PKI leaf or a public OV/EV
    code-signing certificate. Works on a developer PC and in a build pipeline (Azure DevOps, GitHub Actions, AWS, Alibaba,
    Google Cloud, Visual Studio 2026 / MSBuild). Full help: .\Sign-Code.ps1 -Help     Manual: docs\Sign-Code-MANUAL.txt
.EXAMPLE
    .\Sign-Code.ps1 -Pfx .\codesign.pfx -File .\app.exe -File .\app.dll
.EXAMPLE
    .\Sign-Code.ps1 -Ci -PfxBase64Env SIGN_PFX_B64 -Folder .\bin\Release
#>
param(
    [string[]]$File,
    [string[]]$Folder,
    [string[]]$Include,
    [string[]]$Exclude,
    [switch]$NoRecurse,
    [ValidateSet('Auto', 'PrivatePki', 'PublicCa')][string]$CertSource = 'Auto',
    [ValidateSet('Local', 'AzureKeyVault', 'AzureTrustedSigning', 'AwsKms', 'GcpKms', 'Pkcs11', 'DigiCertKeyLocker')][string]$Provider = 'Local',
    [string]$Pfx,
    [string]$PfxPasswordEnv = 'SIGN_PFX_PASSWORD',
    [string]$PfxBase64Env,
    [string]$Thumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$StoreLocation = 'CurrentUser',
    [string]$CertPem,
    [string]$KeyPem,
    [string]$KeyPasswordEnv = 'SIGN_KEY_PASSWORD',
    [string]$ChainFile,
    [string]$CertFile,
    [string]$ProviderArg,
    [string]$Timestamp = 'DigiCert',
    [string]$TimestampUrl,
    [ValidateSet('sha256', 'sha384', 'sha512')][string]$Digest = 'sha256',
    [string]$Description,
    [string]$DescriptionUrl,
    [string]$OutFolder,
    [switch]$SkipSigned,
    [ValidateSet('Winget', 'Chocolatey', 'None')][string]$Installer = 'Winget',
    [switch]$CheckOnly,
    [switch]$Ci,
    [switch]$Strict,
    [ValidateSet('github', 'azure', 'aws', 'gcp', 'alibaba', 'msbuild', 'all')][string]$Template,
    [switch]$ShowCertificate,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
$script:ToolVersion = '6.4.1'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-SignCodeHelp {
@'
====================================================================================================
 Sign-Code.ps1 - sign your code with a code-signing certificate
 Version 6.4.1
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 Manual : docs\Sign-Code-MANUAL.txt        Linux / macOS twin: Sign-Code.sh
 Runs on: Windows 11 (all editions), Windows Server 2022 and 2025 (all editions), PowerShell 7+.
          Windows build agents: Azure DevOps (windows-latest), GitHub Actions (windows-latest), AWS
          CodeBuild (Windows), Alibaba Cloud Yunxiao Flow, Google Cloud Build (Windows worker),
          Visual Studio 2026 / MSBuild.

WHAT IT DOES (in plain words)
  1. Reads the code-signing certificate and CHECKS it. A certificate that does not follow the
     code-signing rules is REFUSED and the script stops before any file is touched (exit code 2).
  2. CHECKS the timestamp server: it must answer, and its own certificate must still be valid (exit
     3).
  3. Finds the tools it needs. If one is missing it INSTALLS it with winget (default) or Chocolatey.
  4. Signs every file you listed (and every supported file inside the folders you listed), with a
     timestamp.
  5. Verifies each signature, writes <file>-signed.sha256 and <file>-signed.sha512 next to it,
     and prints the certificate contents.

WHAT YOU GIVE: THE FILES
  -File <path>        One file. Repeat it:  -File .\app.exe -File .\app.dll -File .\build.ps1
  -Folder <path>      One folder (all supported files inside, sub-folders too). Repeat it:
                      -Folder e:\build\a -Folder e:\build\b
  -NoRecurse          Do not go into sub-folders.
  -Include / -Exclude Wildcards on the file name, e.g. -Include "MyCompany.*" -Exclude "*.Tests.dll"
  -OutFolder <path>   Sign COPIES in this folder. The originals stay untouched. Default: sign in
                      place.
  -SkipSigned         Do not sign a file that already has a valid signature.

  Supported files
    Windows        exe dll sys ocx scr cpl efi ax drv winmd xll msi msp cab cat msix appx vbs js wsf
    PowerShell     ps1 psm1 psd1 ps1xml psc1 cdxml
    .NET           the dll / exe built by .NET Framework (Windows) and .NET (any platform); NuGet
                   packages nupkg snupkg
    Java           jar war ear (jarsigner)         Android  apk (apksigner), aab (jarsigner)
    Office VBA     docm xlsm pptm dotm xlam ppam xltm potm  doc xls ppt dot xla  (needs Microsoft
                   Office or the Office SIP on this PC: Windows only)
  Not supported: Linux native packages (rpm, deb, ELF programs). Use GPG / rpm --addsign for them.

WHAT YOU GIVE: THE CERTIFICATE  (choose ONE way)
  -Pfx <file>                A .pfx / .p12 file. Password: environment variable named by
                             -PfxPasswordEnv (default SIGN_PFX_PASSWORD). If it is not set and you
                             are at a console, you are asked.
  -PfxBase64Env <name>       The name of an environment variable (a pipeline SECRET) that holds the
                             .pfx file as base64. The script writes it to a temporary file and
                             deletes it at the end.
  -Thumbprint <hex>          A certificate that is already in the Windows certificate store (also a
                             hardware token / smart card / HSM key). -StoreLocation CurrentUser
                             (default) or LocalMachine.
  -CertPem <file> -KeyPem <file>   Your private PKI leaf as PEM files (made by
                                   GenerateLeafCertificate.ps1 with
                             -Purpose CodeSigning). Key password: environment variable
                             -KeyPasswordEnv.
  -Provider <name>           Keys that live in a cloud / HSM service and never leave it (best for
                             pipelines):
                               AzureKeyVault        via AzureSignTool          (-ProviderArg
                                            "vault-url|cert-name")
                               AzureTrustedSigning  Azure Artifact Signing
                                                     (-ProviderArg "endpoint|account|profile")
                               AwsKms               via Jsign                  (-ProviderArg
                                            "region|key-alias")
                               GcpKms               via Jsign                  (-ProviderArg
                                            "keyring-path|key-alias")
                               Pkcs11               via Jsign, any HSM         (-ProviderArg
                                            "pkcs11.cfg")
                               DigiCertKeyLocker    via smctl                  (-ProviderArg
                                            "key-pair-alias")
                             Secrets (tokens, API keys) are read from the environment variables the
                             tool expects; they are never put in the command line by this script.
                             See the manual.
  -CertFile <file>           With -Provider: the PUBLIC certificate (PEM or .cer) so that the checks
                             can run.
  -CertSource <x>            PrivatePki | PublicCa | Auto (default). Auto = "PublicCa" when the
                             certificate chains to
                             a root that Windows trusts. PublicCa is stricter (RSA 3072+, trusted
                             chain).
  -ChainFile <file>          CA certificates of your private PKI (ca-bundle.pem) to check the chain.

TIMESTAMP  (a signature without a timestamp dies when the certificate expires - always use one)
  -Timestamp <name>          DigiCert (default), GlobalSign, Certum, Sectigo, SSLcom, Entrust
  -TimestampUrl <url>        Any RFC 3161 server address. It wins over -Timestamp.
  -Digest sha256|sha384|sha512   File digest and timestamp digest. Default sha256.

OTHER
  -Description <text> -DescriptionUrl <url>   The name and web page shown in the Windows security
  prompt.
  -Installer Winget|Chocolatey|None           How missing tools are installed (default Winget).
  -CheckOnly           Run the certificate and timestamp checks and stop. No file is signed.
  -ShowCertificate     Print the certificate contents (also printed after signing).
  -Strict              A file that is skipped or cannot be signed makes the whole run fail (exit 6).
  -Ci                  Pipeline mode: never asks a question, writes pipeline annotations (GitHub
                       Actions, Azure DevOps), writes a summary, removes every temporary secret file
                       at the end.
  -Template github|azure|aws|gcp|alibaba|msbuild|all
                       Writes ready-to-edit pipeline files into transport\signing-ci_<time>\ and
                       stops.

BUILD ENVIRONMENT SETUP  (for DevSecOps)
  Azure DevOps Services / Server, GitHub Actions, AWS CodeBuild, Alibaba Cloud Yunxiao,
  Google Cloud Build, Azure / GCP build VMs, Visual Studio 2026 / MSBuild.
  The agent needs
    * PowerShell 7+ on a Windows build agent (Windows 11, Server 2022 / 2025). Hosted images already
      have it.
    * Outbound HTTP (port 80) to the timestamp server, and HTTPS to the package sources of the
      tools.
    * Missing tools are installed for you. On a locked-down or offline agent put the tools in the
      image and add -Installer None; use your own RFC 3161 server with -TimestampUrl <url>.
  Secrets (never in the repository, never on the command line)
    * Private PKI leaf: store the .pfx as BASE64 in a secret and its password in a second secret.
      Map them to environment variables, then  -Ci -PfxBase64Env <NAME>.
      Make the base64:  [Convert]::ToBase64String([IO.File]::ReadAllBytes("codesign.pfx"))
    * Public OV / EV certificate: the key must be in hardware, so use -Provider
      (Key Vault, KMS, Artifact Signing, KeyLocker, HSM) - the key never reaches the agent.
    * Cloud login: use the identity of the pipeline (service connection, OIDC, managed identity,
      workload identity), not a stored password.
  Steps to follow
    1. pwsh -File Sign-Code.ps1 -Ci -CheckOnly ...   once, to prove the secret, the certificate and
       the timestamp work.
    2. Put the real step AFTER the build and BEFORE publishing the artifact.
    3. Sign the files you ship (exe, dll, msi, ps1, jar, apk, nupkg), not obj\ or test files:
       -Folder <publish folder>  with  -Exclude "*.Tests.dll".
    4. A result other than 0 stops the pipeline. Keep sign-report_*.json and the *-signed.sha256 /
       *-signed.sha512 files as artifacts: they are your proof.
  Ready-made pipeline files:  -Template github | azure | aws | gcp | alibaba | msbuild | all
    msbuild = a .targets file for Visual Studio 2026 / MSBuild:  dotnet build -p:SignCode=true

EXAMPLES
  .\Sign-Code.ps1 -Pfx .\codesign.pfx -File .\app.exe -File .\app.dll -File .\deploy.ps1
  .\Sign-Code.ps1 -CertPem .\cs.crt -KeyPem .\cs.key -ChainFile .\ca-bundle.pem -Folder e:\a `
        -Folder e:\b
  .\Sign-Code.ps1 -Thumbprint 3A1F... -Timestamp GlobalSign -Folder .\bin\Release -Exclude `
        "*.Tests.dll"
  .\Sign-Code.ps1 -Ci -Provider AzureKeyVault -ProviderArg `
        "https://myvault.vault.azure.net|codesign" -CertFile .\codesign.cer -Folder .\out
  .\Sign-Code.ps1 -Pfx .\codesign.pfx -CheckOnly
  .\Sign-Code.ps1 -Template all

EXIT CODES  0 ok   1 error   2 certificate refused   3 timestamp server failed
            4 tool missing / install failed   5 wrong platform   7 no file to sign
            6 some files skipped or failed (with -Strict, or any failure)
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

if ($Help) { Invoke-PagedHelp { Show-SignCodeHelp }; exit 0 }

# ---------------------------------------------------------------- small helpers
$script:Ci = [bool]$Ci
$script:Env = if ($env:GITHUB_ACTIONS -eq 'true') { 'github' } elseif ($env:TF_BUILD -eq 'True') { 'azure' } elseif ($env:CODEBUILD_BUILD_ID) { 'aws' } elseif ($env:CLOUD_BUILD_ID -or ($env:BUILD_ID -and $env:PROJECT_ID)) { 'gcp' } else { 'local' }
$script:Temp = [System.Collections.Generic.List[string]]::new()
$script:Cleanup = [System.Collections.Generic.List[scriptblock]]::new()
function Write-Say {
    param([string]$Level, [string]$Text)
    $c = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { $null } }
    if ($c) { Write-Host "[$Level] $Text" -ForegroundColor $c } else { Write-Host "[$Level] $Text" }
    if ($script:Ci) {
        if ($script:Env -eq 'github' -and $Level -in 'ERROR', 'WARN') { Write-Host "::$(if ($Level -eq 'ERROR') { 'error' } else { 'warning' })::$Text" }
        if ($script:Env -eq 'azure' -and $Level -in 'ERROR', 'WARN') { Write-Host "##vso[task.logissue type=$(if ($Level -eq 'ERROR') { 'error' } else { 'warning' })]$Text" }
    }
}
class SignExit : System.Exception { [int]$Code; SignExit([int]$c, [string]$m) : base($m) { $this.Code = $c } }
function Stop-Sign { param([int]$Code, [string]$Text) throw [SignExit]::new($Code, $Text) }
function Get-Secret { param([string]$EnvName, [string]$Prompt)
    $v = [Environment]::GetEnvironmentVariable($EnvName)
    if ($v) { return $v }
    if ($script:Ci -or [Console]::IsInputRedirected) { return $null }
    $s = Read-Host -AsSecureString $Prompt
    return [System.Net.NetworkCredential]::new('', $s).Password
}
function New-TempFile { param([string]$Ext = '.tmp')
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("signcode-" + [Guid]::NewGuid().ToString('N') + $Ext)
    [void]$script:Temp.Add($p); return $p
}

# ---------------------------------------------------------------- the file types
$script:Kinds = @{}
foreach ($e in 'exe dll sys ocx scr cpl efi ax drv winmd xll msi msp cab cat msix appx msixbundle appxbundle vbs js wsf'.Split(' ')) { $script:Kinds[$e] = 'authenticode' }
foreach ($e in 'ps1 psm1 psd1 ps1xml psc1 cdxml'.Split(' ')) { $script:Kinds[$e] = 'powershell' }
foreach ($e in 'docm xlsm pptm dotm xlam ppam xltm potm doc xls ppt dot xla'.Split(' ')) { $script:Kinds[$e] = 'office' }
foreach ($e in 'jar war ear aab'.Split(' ')) { $script:Kinds[$e] = 'java' }
$script:Kinds['apk'] = 'apk'
foreach ($e in 'nupkg snupkg'.Split(' ')) { $script:Kinds[$e] = 'nuget' }

$script:TsaTable = [ordered]@{
    'digicert'   = 'http://timestamp.digicert.com'
    'globalsign' = 'http://timestamp.globalsign.com/tsa/r6advanced1'
    'certum'     = 'http://time.certum.pl'
    'sectigo'    = 'http://timestamp.sectigo.com'
    'sslcom'     = 'http://ts.ssl.com'
    'entrust'    = 'http://timestamp.entrust.net/TSS/RFC3161sha2TS'
}

# ---------------------------------------------------------------- templates for pipelines
function Write-PipelineTemplates {
    param([string]$Which)
    $dir = Join-Path (Join-Path $script:ScriptRoot 'transport') ("signing-ci_" + (Get-Date).ToString('yyyyMMdd-HHmmss'))
    [void](New-Item -ItemType Directory -Path $dir -Force)
    $t = [ordered]@{}
    $t['github-actions.yml'] = @'
# GitHub Actions: sign after the build. Secrets: SIGN_PFX_B64 (the .pfx as base64) and SIGN_PFX_PASSWORD.
# Public OV/EV certificates: use a cloud signing service (see the manual) instead of a .pfx secret.
name: build-and-sign
on: [push]
jobs:
  build:
    runs-on: windows-latest          # Windows Server 2025 image; use ubuntu-latest + Sign-Code.sh for Linux
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with: { dotnet-version: '9.0.x' }
      - run: dotnet build -c Release -o out
      - name: Sign
        shell: pwsh
        env:
          SIGN_PFX_B64: ${{ secrets.SIGN_PFX_B64 }}
          SIGN_PFX_PASSWORD: ${{ secrets.SIGN_PFX_PASSWORD }}
        run: ./Sign-Code.ps1 -Ci -PfxBase64Env SIGN_PFX_B64 -Folder out -Timestamp DigiCert
      - uses: actions/upload-artifact@v4
        with: { name: signed, path: out }
'@
    $t['azure-pipelines.yml'] = @'
# Azure DevOps (service or server). Library variables: SIGN_PFX_B64, SIGN_PFX_PASSWORD (mark them secret).
# A secret variable is NOT visible to a script by itself: map it with env: as shown.
trigger: [ main ]
pool: { vmImage: windows-latest }      # self-hosted agent: Windows 11 / Server 2022 / 2025 with PowerShell 7
steps:
  - task: UseDotNet@2
    inputs: { version: 9.x }
  - script: dotnet build -c Release -o $(Build.ArtifactStagingDirectory)\out
  - pwsh: ./Sign-Code.ps1 -Ci -PfxBase64Env SIGN_PFX_B64 -Folder "$(Build.ArtifactStagingDirectory)\out"
    displayName: Sign code
    env:
      SIGN_PFX_B64: $(SIGN_PFX_B64)
      SIGN_PFX_PASSWORD: $(SIGN_PFX_PASSWORD)
  # Key in Azure Key Vault instead (no secret in the pipeline, use a service connection / managed identity):
  # - pwsh: ./Sign-Code.ps1 -Ci -Provider AzureKeyVault -ProviderArg "https://myvault.vault.azure.net|codesign" -CertFile codesign.cer -Folder out
  - publish: $(Build.ArtifactStagingDirectory)\out
    artifact: signed
'@
    $t['aws-codebuild-buildspec.yml'] = @'
# AWS CodeBuild (Linux image with PowerShell, or a Windows image). Secrets from Secrets Manager / Parameter Store.
# Keys in AWS KMS: -Provider AwsKms (Jsign needs Java). The build role needs kms:Sign and kms:DescribeKey.
version: 0.2
env:
  secrets-manager:
    SIGN_PFX_B64: codesign/pfx:pfx_base64
    SIGN_PFX_PASSWORD: codesign/pfx:password
phases:
  build:
    commands:
      - dotnet build -c Release -o out
      - bash ./Sign-Code.sh --ci --pfx-base64-env SIGN_PFX_B64 --folder out
      # KMS example:
      # - bash ./Sign-Code.sh --ci --provider awskms --provider-arg "eu-central-1|alias/codesign" --cert-file codesign.cer --folder out
artifacts:
  files: [ 'out/**/*' ]
'@
    $t['google-cloudbuild.yaml'] = @'
# Google Cloud Build. Secrets from Secret Manager. Keys in Cloud KMS: --provider gcpkms (Jsign needs Java).
steps:
  - name: 'mcr.microsoft.com/dotnet/sdk:9.0'
    entrypoint: bash
    args: ['-c', 'dotnet build -c Release -o out']
  - name: 'mcr.microsoft.com/dotnet/sdk:9.0'
    entrypoint: bash
    args: ['-c', './Sign-Code.sh --ci --pfx-base64-env SIGN_PFX_B64 --folder out']
    secretEnv: ['SIGN_PFX_B64', 'SIGN_PFX_PASSWORD']
availableSecrets:
  secretManager:
    - { versionName: projects/$PROJECT_ID/secrets/sign-pfx-b64/versions/latest, env: SIGN_PFX_B64 }
    - { versionName: projects/$PROJECT_ID/secrets/sign-pfx-password/versions/latest, env: SIGN_PFX_PASSWORD }
'@
    $t['alibaba-yunxiao-flow.yml'] = @'
# Alibaba Cloud Yunxiao (Apsara DevOps) Flow - a GENERIC example: copy the two commands into a "Run shell" step
# of your pipeline (Linux build) or "Run PowerShell" step (Windows build). Keep the .pfx (base64) and its password
# in the Flow "Variables" marked secret, or fetch them from KMS Secrets Manager into the two environment variables.
# Alibaba KMS has no code-signing API: use the .pfx secret (private PKI) or a PKCS#11 HSM (-Provider Pkcs11).
stages:
  - name: sign
    steps:
      - run: |
          export SIGN_PFX_B64="$SIGN_PFX_B64" SIGN_PFX_PASSWORD="$SIGN_PFX_PASSWORD"
          bash ./Sign-Code.sh --ci --pfx-base64-env SIGN_PFX_B64 --folder ./out
'@
    $t['Sign-Code.targets'] = @'
<Project>
  <!--
    Visual Studio 2026 / MSBuild: sign the build output after the build.
    1. Put Sign-Code.ps1 in the repository (for example in /build) and import this file in Directory.Build.targets:
         <Import Project="build\Sign-Code.targets" />
    2. Developer PC: nothing happens (SignCode is false). Build agent: dotnet build -p:SignCode=true
       with the secret variables SIGN_PFX_B64 and SIGN_PFX_PASSWORD set.
    3. -p:SignTimestamp=GlobalSign changes the timestamp server.
  -->
  <PropertyGroup>
    <SignCode Condition="'$(SignCode)' == ''">false</SignCode>
    <SignTimestamp Condition="'$(SignTimestamp)' == ''">DigiCert</SignTimestamp>
    <SignCodeScript Condition="'$(SignCodeScript)' == ''">$(MSBuildThisFileDirectory)Sign-Code.ps1</SignCodeScript>
  </PropertyGroup>
  <Target Name="SignCodeAfterBuild" AfterTargets="CopyFilesToOutputDirectory" Condition="'$(SignCode)' == 'true'">
    <Exec Command="pwsh -NoProfile -File &quot;$(SignCodeScript)&quot; -Ci -PfxBase64Env SIGN_PFX_B64 -Timestamp $(SignTimestamp) -File &quot;@(IntermediateAssembly->'%(FullPath)')&quot;" />
  </Target>
</Project>
'@
    $sel = if ($Which -eq 'all') { @($t.Keys) } else { @(switch ($Which) { 'github' { 'github-actions.yml' } 'azure' { 'azure-pipelines.yml' } 'aws' { 'aws-codebuild-buildspec.yml' } 'gcp' { 'google-cloudbuild.yaml' } 'alibaba' { 'alibaba-yunxiao-flow.yml' } 'msbuild' { 'Sign-Code.targets' } }) }
    foreach ($n in $sel) { [System.IO.File]::WriteAllText((Join-Path $dir $n), (($t[$n] -replace "`r", '') + "`n"), [System.Text.UTF8Encoding]::new($false)); Write-Say 'OK' "Written: $(Join-Path $dir $n)" }
    Write-Say 'INFO' 'These are starting points. Edit the names, paths and secret names. They were not run on a real pipeline.'
}
if ($Template) { Write-PipelineTemplates -Which $Template; exit 0 }

# ---------------------------------------------------------------- the platform
function Test-SigningPlatform {
    if ($env:PKI_FAKE_OS) { Write-Say 'WARN' 'PKI_FAKE_OS is set: platform check skipped (test only).'; return }
    if (-not $IsWindows) { Stop-Sign 5 'Sign-Code.ps1 runs on Windows. On Linux or macOS use Sign-Code.sh.' }
    $v = [System.Environment]::OSVersion.Version
    $build = $v.Build
    $isServer = $false
    try { $isServer = ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) } catch { }
    $ok = if ($isServer) { $build -ge 20348 } else { $build -ge 22000 }
    if (-not $ok) { Stop-Sign 5 "This Windows (build $build) is not supported. Needed: Windows 11, Windows Server 2022 or 2025." }
    Write-Say 'INFO' "Windows build $build ($(if ($isServer) { 'Server' } else { 'client' })): supported."
}

# ---------------------------------------------------------------- tools: find, install
function Update-PathFromRegistry {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine'); $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = (@($m, $u, $env:Path) | Where-Object { $_ }) -join ';'
}
function Find-Tool {
    param([string]$Name)
    switch ($Name) {
        'signtool' {
            $c = Get-Command signtool.exe -ErrorAction SilentlyContinue; if ($c) { return $c.Source }
            $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin") | Where-Object { Test-Path $_ }
            $f = foreach ($r in $roots) { Get-ChildItem -Path $r -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\x64\\' } }
            if ($f) { return ($f | Sort-Object { [version]($_.FullName -replace '.*\\bin\\(\d+\.\d+\.\d+\.\d+)\\.*', '$1') } -ErrorAction SilentlyContinue | Select-Object -Last 1).FullName }
        }
        'jarsigner' {
            $c = Get-Command jarsigner.exe -ErrorAction SilentlyContinue; if ($c) { return $c.Source }
            if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\jarsigner.exe")) { return "$env:JAVA_HOME\bin\jarsigner.exe" }
            $f = Get-ChildItem -Path "$env:ProgramFiles\Microsoft", "$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Java" -Filter jarsigner.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($f) { return $f.FullName }
        }
        'apksigner' {
            $c = Get-Command apksigner.bat, apksigner -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { return $c.Source }
            foreach ($h in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, "$env:LOCALAPPDATA\Android\Sdk", "$env:ProgramData\chocolatey\lib\android-sdk\tools") | Where-Object { $_ }) {
                $f = Get-ChildItem -Path "$h\build-tools" -Filter apksigner.bat -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
                if ($f) { return $f.FullName }
            }
        }
        'dotnet' { $c = Get-Command dotnet -ErrorAction SilentlyContinue; if ($c) { return $c.Source } }
        'jsign' { $c = Get-Command jsign, jsign.bat, jsign.cmd -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { return $c.Source } }
        'azuresigntool' {
            $c = Get-Command AzureSignTool -ErrorAction SilentlyContinue; if ($c) { return $c.Source }
            $p = Join-Path $env:USERPROFILE '.dotnet\tools\AzureSignTool.exe'; if (Test-Path $p) { return $p }
        }
        'smctl' { $c = Get-Command smctl -ErrorAction SilentlyContinue; if ($c) { return $c.Source } }
    }
    return $null
}
# winget id / chocolatey id. Package names can change: if one fails, install by hand and run again.
$script:InstallTable = @{
    signtool      = @{ Winget = 'Microsoft.WindowsSDK.10.0.26100'; Choco = 'windows-sdk-10-version-2004-all'; Label = 'Windows SDK (signtool)' }
    jarsigner     = @{ Winget = 'Microsoft.OpenJDK.21'; Choco = 'microsoft-openjdk21'; Label = 'JDK 21 (jarsigner)' }
    dotnet        = @{ Winget = 'Microsoft.DotNet.SDK.9'; Choco = 'dotnet-sdk'; Label = '.NET SDK' }
    jsign         = @{ Winget = $null; Choco = 'jsign'; Label = 'Jsign (needs Java)' }
    apksigner     = @{ Winget = $null; Choco = 'android-sdk'; Label = 'Android SDK build-tools (apksigner)' }
    azuresigntool = @{ Winget = $null; Choco = $null; Label = 'AzureSignTool (dotnet tool)' }
    smctl         = @{ Winget = $null; Choco = $null; Label = 'DigiCert smctl (KeyLocker client tools)' }
}
function Install-SigningTool {
    param([string]$Name)
    $e = $script:InstallTable[$Name]
    Write-Say 'WARN' "$($e.Label) was not found."
    if ($Installer -eq 'None') { Stop-Sign 4 "$($e.Label) is missing and -Installer None was given. Install it and run again." }
    if ($Name -eq 'azuresigntool') {
        if (-not (Find-Tool 'dotnet')) { Install-SigningTool 'dotnet' }
        Write-Say 'INFO' 'dotnet tool install --global AzureSignTool'
        & dotnet tool install --global AzureSignTool 2>&1 | ForEach-Object { Write-Host "  $_" }
        $env:Path += ";$env:USERPROFILE\.dotnet\tools"
    }
    elseif ($Name -eq 'smctl') { Stop-Sign 4 'smctl (DigiCert KeyLocker client tools) must be installed by you: https://docs.digicert.com/ (software trust manager). Add it to PATH and run again.' }
    else {
        $order = if ($Installer -eq 'Winget') { @('Winget', 'Choco') } else { @('Choco', 'Winget') }
        $done = $false
        foreach ($m in $order) {
            $id = $e[$m]; if (-not $id) { continue }
            if ($m -eq 'Winget' -and (Get-Command winget -ErrorAction SilentlyContinue)) {
                Write-Say 'INFO' "winget install --id $id"
                & winget install --id $id --exact --silent --accept-package-agreements --accept-source-agreements 2>&1 | ForEach-Object { Write-Host "  $_" }
                $done = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335189); if ($done) { break }
            }
            if ($m -eq 'Choco' -and (Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Say 'INFO' "choco install $id -y"
                & choco install $id -y --no-progress 2>&1 | ForEach-Object { Write-Host "  $_" }
                $done = ($LASTEXITCODE -eq 0); if ($done) { break }
            }
        }
        if (-not $done) { Stop-Sign 4 "Could not install $($e.Label) (winget and Chocolatey: not found, no package or failed). Install it by hand, then run again." }
        if ($Name -eq 'apksigner') {
            $sm = Get-ChildItem -Path "$env:ProgramData\chocolatey\lib\android-sdk" -Filter sdkmanager.bat -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sm) { & $sm.FullName --install 'build-tools;35.0.0' 2>&1 | ForEach-Object { Write-Host "  $_" } }
        }
    }
    Update-PathFromRegistry
    if (-not (Find-Tool $Name)) { Stop-Sign 4 "$($e.Label) was installed but is still not found. Open a new console (so PATH is refreshed) and run again." }
    Write-Say 'OK' "$($e.Label) is ready."
}
function Get-SigningTool { param([string]$Name) $p = Find-Tool $Name; if (-not $p) { Install-SigningTool $Name; $p = Find-Tool $Name }; return $p }

# ---------------------------------------------------------------- the certificate
function Get-OidFriendly { param([string]$Oid) switch ($Oid) {
    '1.3.6.1.5.5.7.3.3' { 'Code Signing' } '1.3.6.1.5.5.7.3.8' { 'Time Stamping' } '1.3.6.1.5.5.7.3.1' { 'Server Authentication' }
    '1.3.6.1.5.5.7.3.2' { 'Client Authentication' } '1.3.6.1.4.1.311.10.3.13' { 'Lifetime Signing' } '1.3.6.1.5.5.7.3.4' { 'Email' } default { $Oid } } }

function Test-CodeSigningCertificate {
    <# Returns @{ Errors; Warnings; Info } - Errors non-empty = refuse. #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$Source, [string]$Chain)
    $err = [System.Collections.Generic.List[string]]::new(); $warn = [System.Collections.Generic.List[string]]::new()
    $now = [DateTime]::UtcNow
    if ($Cert.NotBefore.ToUniversalTime() -gt $now) { [void]$err.Add("The certificate is not valid yet (starts $($Cert.NotBefore.ToString('yyyy-MM-dd HH:mm')))." ) }
    if ($Cert.NotAfter.ToUniversalTime() -lt $now) { [void]$err.Add("The certificate has EXPIRED ($($Cert.NotAfter.ToString('yyyy-MM-dd')))." ) }
    elseif (($Cert.NotAfter.ToUniversalTime() - $now).TotalDays -lt 30) { [void]$warn.Add("The certificate expires in less than 30 days ($($Cert.NotAfter.ToString('yyyy-MM-dd'))). Signatures with a timestamp stay valid after that.") }
    # extended key usage
    $eku = $Cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | Select-Object -First 1
    if (-not $eku) { [void]$err.Add('The certificate has no Extended Key Usage. A code-signing certificate must have "Code Signing" (1.3.6.1.5.5.7.3.3).') }
    else {
        $oids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
        if ($oids -notcontains '1.3.6.1.5.5.7.3.3') { [void]$err.Add("The certificate is not for Code Signing. Its purposes: $(($oids | ForEach-Object { Get-OidFriendly $_ }) -join ', ').") }
        $bad = @($oids | Where-Object { $_ -in '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.4', '1.3.6.1.5.5.7.3.8', '2.5.29.37.0' })
        if ($bad.Count -gt 0) { [void]$warn.Add("The certificate also has other purposes ($(($bad | ForEach-Object { Get-OidFriendly $_ }) -join ', ')). Public CAs forbid this for code signing; use a dedicated certificate.") }
    }
    # key usage
    $ku = $Cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] } | Select-Object -First 1
    if ($ku -and -not ($ku.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)) { [void]$err.Add('Key Usage does not include Digital Signature.') }
    if (-not $ku) { [void]$warn.Add('The certificate has no Key Usage extension (it should say Digital Signature).') }
    # basic constraints
    $bc = $Cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | Select-Object -First 1
    if ($bc -and $bc.CertificateAuthority) { [void]$err.Add('This is a CA certificate (CA:TRUE). A CA must never sign code. Use a leaf certificate.') }
    # key
    $alg = $Cert.PublicKey.Oid.Value
    $bits = 0; $keyText = $alg
    if ($alg -eq '1.2.840.113549.1.1.1') { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert); $bits = $rsa.ExportParameters($false).Modulus.Length * 8; $keyText = "RSA-$bits"
        if ($bits -lt 2048) { [void]$err.Add("RSA-$bits is too weak. At least RSA-2048 (public CAs: RSA-3072).") }
        elseif ($bits -lt 3072 -and $Source -eq 'PublicCa') { [void]$err.Add("A public code-signing certificate must have RSA-3072 or larger (CA/Browser Forum). This one is RSA-$bits.") }
        elseif ($bits -lt 3072) { [void]$warn.Add("RSA-$bits works, but RSA-3072 or ECDSA P-384 is recommended.") }
        if ($bits -gt 4096) { [void]$warn.Add("RSA-$bits is larger than 4096: some signing tools and Windows components refuse it.") }
    }
    elseif ($alg -eq '1.2.840.10045.2.1') { $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert); $ecBits = $ec.ExportParameters($false).Q.X.Length * 8; $keyText = "ECDSA-$ecBits"
        if ($ecBits -lt 256) { [void]$err.Add("ECDSA key size $ecBits is too small (P-256 or larger).") }
        if ($ecBits -gt 384) { [void]$warn.Add('ECDSA P-521 is not accepted by every signing tool. P-256 or P-384 is safest.') }
    }
    elseif ($alg -like '2.16.840.1.101.3.4.3.*') { [void]$err.Add('An ML-DSA (quantum) certificate cannot sign code yet: Authenticode, jarsigner, apksigner and NuGet do not support it. Use an RSA or ECDSA code-signing leaf.') }
    else { [void]$err.Add("Key type $alg is not supported for code signing.") }
    # signature algorithm
    $sa = $Cert.SignatureAlgorithm.FriendlyName
    if ($sa -match 'md5|sha1') { [void]$err.Add("The certificate is signed with a weak algorithm ($sa).") }
    # self-signed
    if ($Cert.Subject -eq $Cert.Issuer) { [void]$warn.Add('The certificate is self-signed. Every computer that checks the signature must trust it by hand.') }
    # chain
    $ch = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $ch.ChainPolicy.RevocationMode = 'NoCheck'
    $trusted = $false
    if ($Chain -and (Test-Path -LiteralPath $Chain)) {
        $ch.ChainPolicy.TrustMode = 'CustomRootTrust'
        $txt = [System.IO.File]::ReadAllText($Chain)
        foreach ($m in [regex]::Matches($txt, '-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----')) {
            $c2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($m.Value)
            if ($c2.Subject -eq $c2.Issuer) { [void]$ch.ChainPolicy.CustomTrustStore.Add($c2) } else { [void]$ch.ChainPolicy.ExtraStore.Add($c2) }
        }
    }
    $ch.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
    $trusted = $ch.Build($Cert)
    $statuses = @($ch.ChainStatus | Where-Object { $_.Status -ne 'NoError' } | ForEach-Object { $_.Status.ToString() })
    return [pscustomobject]@{ Errors = @($err); Warnings = @($warn); KeyText = $keyText; ChainTrusted = $trusted; ChainStatus = $statuses; ChainLength = $ch.ChainElements.Count }
}
function Get-CertPolicyText {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $p = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.32' } | Select-Object -First 1
    if (-not $p) { return '' }
    return $p.Format($true)
}
function Show-CertificateContents {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [string]$KeyText = '')
    Write-Host ''
    Write-Host '----- CERTIFICATE USED FOR SIGNING ------------------------------------------------------'
    Write-Host ("  Subject      : " + $Cert.Subject)
    Write-Host ("  Issuer       : " + $Cert.Issuer)
    Write-Host ("  Serial       : " + $Cert.SerialNumber)
    Write-Host ("  Valid        : " + $Cert.NotBefore.ToString('yyyy-MM-dd HH:mm') + '  to  ' + $Cert.NotAfter.ToString('yyyy-MM-dd HH:mm'))
    Write-Host ("  Public key   : " + $KeyText + '; signature ' + $Cert.SignatureAlgorithm.FriendlyName)
    Write-Host ("  Thumbprint   : " + $Cert.Thumbprint + ' (SHA-1)')
    Write-Host ("  SHA-256      : " + [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Cert.RawData)))
    foreach ($x in $Cert.Extensions) {
        if ($x -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) { Write-Host ("  Purposes     : " + (($x.EnhancedKeyUsages | ForEach-Object { (Get-OidFriendly $_.Value) + ' (' + $_.Value + ')' }) -join '; ')) }
        elseif ($x -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) { Write-Host ("  Key usage    : " + $x.KeyUsages) }
    }
    $pol = (((Get-CertPolicyText $Cert) -split "`n") | Where-Object { $_ -match 'Policy Identifier' } | ForEach-Object { ($_ -replace '.*=', '').Trim() }) -join '; '
    if ($pol) { Write-Host ("  Policies     : " + $pol) }
    Write-Host '-----------------------------------------------------------------------------------------'
}

# ---------------------------------------------------------------- the timestamp server check
function Test-TimestampServer {
    param([string]$Url)
    $nonce = [byte[]]::new(8); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce); $nonce[0] = $nonce[0] -band 0x7F
    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes("signcode-check-" + [Guid]::NewGuid()))
    $req = [System.Collections.Generic.List[byte]]::new()
    $req.AddRange([byte[]](0x30, 0x43, 0x02, 0x01, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))
    $req.AddRange($hash); $req.AddRange([byte[]](0x02, 0x08)); $req.AddRange($nonce); $req.AddRange([byte[]](0x01, 0x01, 0xFF))
    $hc = [System.Net.Http.HttpClient]::new(); $hc.Timeout = [TimeSpan]::FromSeconds(20)
    try {
        $content = [System.Net.Http.ByteArrayContent]::new($req.ToArray()); $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/timestamp-query')
        $resp = $hc.PostAsync($Url, $content).GetAwaiter().GetResult()
        if (-not $resp.IsSuccessStatusCode) { Stop-Sign 3 "The timestamp server $Url answered HTTP $([int]$resp.StatusCode). Choose another with -Timestamp or -TimestampUrl." }
        $bytes = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
    }
    catch [SignExit] { throw }
    catch { Stop-Sign 3 "The timestamp server $Url cannot be reached from this computer: $($_.Exception.GetBaseException().Message). Check the network / proxy / firewall (outbound HTTP to the server), or choose another with -Timestamp." }
    finally { $hc.Dispose() }
    try {
        $r = [System.Formats.Asn1.AsnReader]::new([ReadOnlyMemory[byte]]$bytes, [System.Formats.Asn1.AsnEncodingRules]::DER)
        $seq = $r.ReadSequence(); $si = $seq.ReadSequence(); $status = [int]$si.ReadInteger()
        if ($status -gt 1) { Stop-Sign 3 "The timestamp server $Url refused the request (status $status)." }
        $tokBytes = $seq.ReadEncodedValue()
        $tok = $null; $read = 0
        if (-not [System.Security.Cryptography.Pkcs.Rfc3161TimestampToken]::TryDecode($tokBytes, [ref]$tok, [ref]$read)) { Stop-Sign 3 "The answer of $Url is not a valid RFC 3161 timestamp." }
        $tsa = $tok.AsSignedCms().SignerInfos[0].Certificate
        if (-not $tsa) { $tsa = $tok.AsSignedCms().Certificates | Select-Object -First 1 }
    }
    catch [SignExit] { throw }
    catch { Stop-Sign 3 "The answer of $Url could not be read as a timestamp: $($_.Exception.Message)" }
    $now = [DateTime]::UtcNow
    if ($tsa.NotAfter.ToUniversalTime() -lt $now) { Stop-Sign 3 "The certificate of the timestamp server expired on $($tsa.NotAfter.ToString('yyyy-MM-dd')). Choose another server." }
    if ($tsa.NotBefore.ToUniversalTime() -gt $now) { Stop-Sign 3 'The certificate of the timestamp server is not valid yet.' }
    $left = [int]($tsa.NotAfter.ToUniversalTime() - $now).TotalDays
    $drift = [Math]::Abs(($tok.TokenInfo.Timestamp.UtcDateTime - $now).TotalMinutes)
    if ($drift -gt 5) { Write-Say 'WARN' "The clock of this computer differs from the timestamp server by $([int]$drift) minutes. Fix the time (NTP)." }
    Write-Say 'OK' "Timestamp server answers: $Url"
    Write-Say 'OK' "Timestamp certificate: $($tsa.Subject)  valid until $($tsa.NotAfter.ToString('yyyy-MM-dd')) ($left days left)"
    if ($left -lt 30) { Write-Say 'WARN' "The timestamp certificate expires in $left days." }
}

# ---------------------------------------------------------------- the files
function Resolve-SigningFiles {
    $list = [System.Collections.Generic.List[string]]::new(); $skipped = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @($File | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Stop-Sign 1 "File not found: $f" }
        $full = (Resolve-Path -LiteralPath $f).Path
        if (-not $script:Kinds.ContainsKey(([System.IO.Path]::GetExtension($full).TrimStart('.').ToLowerInvariant()))) { [void]$skipped.Add($full); continue }
        if (-not $list.Contains($full)) { [void]$list.Add($full) }
    }
    foreach ($d in @($Folder | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $d -PathType Container)) { Stop-Sign 1 "Folder not found: $d" }
        $items = Get-ChildItem -LiteralPath $d -File -Recurse:(-not $NoRecurse)
        foreach ($i in $items) {
            $ext = $i.Extension.TrimStart('.').ToLowerInvariant()
            if (-not $script:Kinds.ContainsKey($ext)) { continue }
            if ($Include -and -not ($Include | Where-Object { $i.Name -like $_ })) { continue }
            if ($Exclude -and ($Exclude | Where-Object { $i.Name -like $_ })) { continue }
            if (-not $list.Contains($i.FullName)) { [void]$list.Add($i.FullName) }
        }
    }
    return [pscustomobject]@{ Files = @($list); Skipped = @($skipped) }
}
function Write-SignedHashFiles {
    param([string]$Path)
    $dir = Split-Path -Parent $Path; $name = Split-Path -Leaf $Path; $written = @()
    foreach ($a in 'sha256', 'sha512') {
        $h = [Convert]::ToHexString([System.Security.Cryptography.HashAlgorithm]::Create($a.ToUpperInvariant()).ComputeHash([System.IO.File]::ReadAllBytes($Path))).ToLowerInvariant()
        $out = Join-Path $dir "$name-signed.$a"
        [System.IO.File]::WriteAllText($out, "$h  $name`n", [System.Text.UTF8Encoding]::new($false)); $written += $out
    }
    return $written
}
function Test-AlreadySigned {
    param([string]$Path, [string]$Kind)
    if ($Kind -in 'authenticode', 'powershell') { try { return ((Get-AuthenticodeSignature -LiteralPath $Path).Status -eq 'Valid') } catch { return $false } }
    return $false
}

# ---------------------------------------------------------------- main
$exit = 0
$ctx = [ordered]@{}
try {
    Write-Host '============================================================'
    Write-Host 'Author : Nicko Satria Utama'
    Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
    Write-Host 'Email  : nicko@nextmantra.com'
    Write-Host '============================================================'
    Write-Host ''
    Write-Say 'INFO' "Sign-Code.ps1 version $script:ToolVersion$(if ($script:Ci) { "  (pipeline mode, $script:Env)" })"
    Test-SigningPlatform

    # ---- the files first: no point checking a certificate when there is nothing to sign
    $sel = Resolve-SigningFiles
    foreach ($s in $sel.Skipped) { Write-Say 'WARN' "Not a supported file type, skipped: $s" }
    if (-not $CheckOnly -and $sel.Files.Count -eq 0) { Stop-Sign 7 'No file to sign. Give -File and / or -Folder (supported types: see -Help).' }
    Write-Say 'INFO' "$($sel.Files.Count) file(s) to sign."

    # ---- the certificate (public part), and a way to sign with it
    $cert = $null; $sigThumb = $null; $pfxPath = $null; $pfxPass = $null; $importedThumb = $null
    $nSrc = @($Pfx, $PfxBase64Env, $Thumbprint, $CertPem) | Where-Object { $_ }
    if ($Provider -eq 'Local') {
        if (@($nSrc).Count -ne 1) { Stop-Sign 1 'Give exactly ONE certificate source: -Pfx, -PfxBase64Env, -Thumbprint or -CertPem/-KeyPem (or use -Provider).' }
    }
    elseif (-not $CertFile) { Stop-Sign 1 "-Provider $Provider needs -CertFile <the public certificate> so that the certificate checks can run." }

    $X = [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
    if ($Provider -ne 'Local') { $cert = $X::new($CertFile) }
    elseif ($Thumbprint) {
        $loc = [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
        $st = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $loc); $st.Open('ReadOnly')
        $cert = $st.Certificates | Where-Object { $_.Thumbprint -eq ($Thumbprint -replace '\s', '').ToUpperInvariant() } | Select-Object -First 1; $st.Close()
        if (-not $cert) { Stop-Sign 1 "No certificate with thumbprint $Thumbprint in the $StoreLocation\My store." }
        if (-not $cert.HasPrivateKey) { Write-Say 'WARN' 'The store certificate shows no private key (a hardware token may only show it when plugged in).' }
        $sigThumb = $cert.Thumbprint
    }
    else {
        if ($Pfx) { if (-not (Test-Path -LiteralPath $Pfx -PathType Leaf)) { Stop-Sign 1 "PFX file not found: $Pfx" }; $pfxPath = (Resolve-Path -LiteralPath $Pfx).Path }
        elseif ($PfxBase64Env) {
            $b64 = [Environment]::GetEnvironmentVariable($PfxBase64Env); if (-not $b64) { Stop-Sign 1 "The environment variable $PfxBase64Env is empty or not set. In a pipeline, map the secret to it." }
            $pfxPath = New-TempFile '.pfx'; [System.IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String(($b64 -replace '\s', '')))
        }
        if ($pfxPath) {
            $pfxPass = Get-Secret $PfxPasswordEnv 'PFX password'
            try { $cert = $X::new($pfxPath, $pfxPass, $flags::EphemeralKeySet -bor $flags::Exportable) } catch { Stop-Sign 1 "The PFX could not be opened (wrong password in ${PfxPasswordEnv}?): $($_.Exception.Message)" }
        }
        else {
            if (-not $KeyPem) { Stop-Sign 1 '-CertPem needs -KeyPem as well.' }
            $kp = Get-Secret $KeyPasswordEnv 'Private key password (empty = none)'
            $pem = [System.IO.File]::ReadAllText($CertPem)
            $cert = if ($kp) { $X::CreateFromEncryptedPemFile($CertPem, $kp, $KeyPem) } else { $X::CreateFromPemFile($CertPem, $KeyPem) }
            # a PEM pair has no PFX: make a temporary one for the signing tools
            $pfxPath = New-TempFile '.pfx'; $pfxPass = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
            [System.IO.File]::WriteAllBytes($pfxPath, $cert.Export('Pfx', $pfxPass))
            $cert = $X::new($pfxPath, $pfxPass, $flags::EphemeralKeySet -bor $flags::Exportable)
        }
        if ($script:Env -eq 'github' -and $pfxPass) { Write-Host "::add-mask::$pfxPass" }
    }

    # ---- classify and CHECK
    $src = $CertSource
    $chainFile = if ($ChainFile) { $ChainFile } else { $null }
    if ($src -eq 'Auto') {
        $probe = Test-CodeSigningCertificate -Cert $cert -Source 'PrivatePki' -Chain $null
        $src = if ($probe.ChainTrusted -and $cert.Subject -ne $cert.Issuer) { 'PublicCa' } else { 'PrivatePki' }
    }
    Write-Say 'INFO' "Certificate source: $src"
    $res = Test-CodeSigningCertificate -Cert $cert -Source $src -Chain $chainFile
    $polText = Get-CertPolicyText $cert
    $isEv = $polText -match '2\.23\.140\.1\.3\b'; $isCsbr = $polText -match '2\.23\.140\.1\.4\.1\b'
    if ($src -eq 'PublicCa') {
        if (-not $res.ChainTrusted) { $res.Errors += "The chain does not end at a root that Windows trusts ($($res.ChainStatus -join ', '))." }
        if (-not ($isEv -or $isCsbr)) { $res.Warnings += 'No CA/Browser Forum code-signing policy (2.23.140.1.4.1 or EV 2.23.140.1.3) found in the certificate.' }
    }
    elseif (-not $res.ChainTrusted) { $res.Warnings += "The chain is not complete / not trusted here ($($res.ChainStatus -join ', ')). Give -ChainFile <ca-bundle.pem> to check it against your private root." }
    foreach ($w in $res.Warnings) { Write-Say 'WARN' $w }
    if ($res.Errors.Count -gt 0) {
        foreach ($e in $res.Errors) { Write-Say 'ERROR' $e }
        Show-CertificateContents $cert $res.KeyText
        Stop-Sign 2 'The certificate does NOT comply with the code-signing rules. Nothing was signed.'
    }
    Write-Say 'OK' "Certificate complies: $($res.KeyText), $(if ($isEv) { 'EV code signing' } elseif ($isCsbr) { 'OV code signing (CA/B Forum)' } else { 'code signing' }), valid until $($cert.NotAfter.ToString('yyyy-MM-dd')), chain length $($res.ChainLength)."

    # ---- the timestamp server
    $tsUrl = if ($TimestampUrl) { $TimestampUrl } elseif ($script:TsaTable.Contains($Timestamp.ToLowerInvariant())) { $script:TsaTable[$Timestamp.ToLowerInvariant()] } elseif ($Timestamp -match '^https?://') { $Timestamp } else { Stop-Sign 1 "Unknown timestamp name '$Timestamp'. Use: $($script:TsaTable.Keys -join ', ') or -TimestampUrl <url>." }
    Test-TimestampServer -Url $tsUrl
    if ($CheckOnly) { Show-CertificateContents $cert $res.KeyText; Write-Say 'OK' 'Checks finished (-CheckOnly): nothing was signed.'; exit 0 }

    # ---- the tools needed for THIS job
    $kinds = @($sel.Files | ForEach-Object { $script:Kinds[[System.IO.Path]::GetExtension($_).TrimStart('.').ToLowerInvariant()] } | Sort-Object -Unique)
    $tool = @{}
    if ($Provider -eq 'Local') {
        if ($kinds -contains 'authenticode' -or $kinds -contains 'office') { $tool.signtool = Get-SigningTool 'signtool' }
        if ($kinds -contains 'java') { $tool.jarsigner = Get-SigningTool 'jarsigner' }
        if ($kinds -contains 'apk') { $tool.apksigner = Get-SigningTool 'apksigner'; if (-not (Find-Tool 'jarsigner')) { $tool.jarsigner = Get-SigningTool 'jarsigner' } }
        if ($kinds -contains 'nuget') { $tool.dotnet = Get-SigningTool 'dotnet' }
    }
    else {
        switch ($Provider) {
            'AzureKeyVault' { $tool.azuresigntool = Get-SigningTool 'azuresigntool' }
            'AzureTrustedSigning' { $tool.signtool = Get-SigningTool 'signtool' }
            'DigiCertKeyLocker' { $tool.smctl = Get-SigningTool 'smctl' }
            default { $tool.jsign = Get-SigningTool 'jsign' }
        }
        $bad = @($kinds | Where-Object { $_ -in 'java', 'apk', 'nuget', 'office' })
        if ($bad.Count -gt 0) { Write-Say 'WARN' "-Provider $Provider signs Windows files and PowerShell scripts only. Skipped kinds: $($bad -join ', '). Use -Provider Local with an exported key for them." }
    }

    # ---- sign with a certificate in a temporary store (no password on any command line)
    $tmpStoreThumb = $null
    if ($Provider -eq 'Local' -and -not $sigThumb -and ($kinds | Where-Object { $_ -in 'authenticode', 'powershell', 'office' })) {
        $st = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser'); $st.Open('ReadWrite')
        $imp = $X::new($pfxPath, $pfxPass, $flags::PersistKeySet -bor $flags::Exportable)
        $st.Add($imp); $st.Close(); $tmpStoreThumb = $imp.Thumbprint; $sigThumb = $tmpStoreThumb
        $script:Cleanup.Add({ $s2 = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser'); $s2.Open('ReadWrite'); $c = $s2.Certificates | Where-Object { $_.Thumbprint -eq $tmpStoreThumb }; if ($c) { $s2.RemoveRange($c) }; $s2.Close() })
    }

    # ---- sign
    $report = [System.Collections.Generic.List[object]]::new(); $failed = 0
    $workRoot = $null
    if ($OutFolder) { $workRoot = $OutFolder; [void](New-Item -ItemType Directory -Path $workRoot -Force) }
    $common = @{}
    $i = 0
    foreach ($src0 in $sel.Files) {
        $i++
        $ext = [System.IO.Path]::GetExtension($src0).TrimStart('.').ToLowerInvariant(); $kind = $script:Kinds[$ext]
        $target = $src0
        if ($workRoot) { $target = Join-Path $workRoot (Split-Path -Leaf $src0); Copy-Item -LiteralPath $src0 -Destination $target -Force }
        $row = [ordered]@{ file = $target; kind = $kind; status = 'signed'; message = '' }
        if ($SkipSigned -and (Test-AlreadySigned $target $kind)) { $row.status = 'skipped'; $row.message = 'already signed'; [void]$report.Add([pscustomobject]$row); Write-Say 'INFO' "[$i/$($sel.Files.Count)] already signed, skipped: $target"; continue }
        Write-Host "[$i/$($sel.Files.Count)] $target  ($kind)"
        try {
            $out = ''
            if ($Provider -eq 'Local') {
                switch ($kind) {
                    'authenticode' {
                        $a = @('sign', '/fd', $Digest, '/tr', $tsUrl, '/td', $Digest, '/sha1', $sigThumb)
                        if ($StoreLocation -eq 'LocalMachine' -and $Thumbprint) { $a += '/sm' }
                        if ($Description) { $a += @('/d', $Description) }; if ($DescriptionUrl) { $a += @('/du', $DescriptionUrl) }
                        $a += $target
                        $out = (& $tool.signtool @a 2>&1) -join "`n"; if ($LASTEXITCODE -ne 0) { throw $out }
                        $v = (& $tool.signtool verify /pa $target 2>&1) -join "`n"
                        if ($LASTEXITCODE -ne 0 -and $src -eq 'PublicCa') { throw "verify failed: $v" }
                        if ($LASTEXITCODE -ne 0) { $row.message = 'signature written; the root is not trusted on this PC (normal for a private PKI)' }
                    }
                    'office' {
                        $a = @('sign', '/fd', $Digest, '/tr', $tsUrl, '/td', $Digest, '/sha1', $sigThumb, $target)
                        $out = (& $tool.signtool @a 2>&1) -join "`n"; if ($LASTEXITCODE -ne 0) { throw "$out`n(VBA signing needs Microsoft Office or the Office SIP installed on this PC.)" }
                    }
                    'powershell' {
                        $c0 = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $sigThumb } | Select-Object -First 1
                        $r = Set-AuthenticodeSignature -LiteralPath $target -Certificate $c0 -TimestampServer $tsUrl -HashAlgorithm $Digest.ToUpperInvariant()
                        if ($r.Status -notin 'Valid', 'UnknownError') { throw "Set-AuthenticodeSignature: $($r.Status) $($r.StatusMessage)" }
                        if ($r.Status -eq 'UnknownError') { $row.message = 'signature written; the root is not trusted on this PC (normal for a private PKI)' }
                    }
                    'java' {
                        $pw = 'SIGNCODE_JS_PASS'; [Environment]::SetEnvironmentVariable($pw, $pfxPass)
                        $kt = Get-Command keytool -ErrorAction SilentlyContinue
                        $aliasName = $null
                        if ($kt) { $l = (& $kt.Source -list -keystore $pfxPath -storetype PKCS12 -storepass:env $pw 2>&1) -join "`n"; $m = [regex]::Match($l, '(?m)^([^,\r\n]+),.*PrivateKeyEntry'); if ($m.Success) { $aliasName = $m.Groups[1].Value.Trim() } }
                        if (-not $aliasName) { throw 'Could not read the key alias from the PFX (keytool missing?).' }
                        $out = (& $tool.jarsigner -keystore $pfxPath -storetype PKCS12 -storepass:env $pw -digestalg $Digest.ToUpperInvariant().Replace('SHA', 'SHA-') -tsa $tsUrl -tsadigestalg $Digest.ToUpperInvariant().Replace('SHA', 'SHA-') $target $aliasName 2>&1) -join "`n"
                        if ($LASTEXITCODE -ne 0) { throw $out }
                        $v = (& $tool.jarsigner -verify $target 2>&1) -join "`n"; if ($LASTEXITCODE -ne 0) { throw "verify failed: $v" }
                    }
                    'apk' {
                        $pw = 'SIGNCODE_APK_PASS'; [Environment]::SetEnvironmentVariable($pw, $pfxPass)
                        $out = (& $tool.apksigner sign --ks $pfxPath --ks-type PKCS12 --ks-pass "env:$pw" $target 2>&1) -join "`n"; if ($LASTEXITCODE -ne 0) { throw $out }
                        $v = (& $tool.apksigner verify $target 2>&1) -join "`n"; if ($LASTEXITCODE -ne 0) { throw "verify failed: $v" }
                        $row.message = 'APK signed without a timestamp (the Android format has none)'
                    }
                    'nuget' {
                        $a = @('nuget', 'sign', $target, '--certificate-path', $pfxPath, '--timestamper', $tsUrl, '--timestamp-hash-algorithm', $Digest, '--hash-algorithm', $Digest, '--overwrite')
                        if ($pfxPass) { $a += @('--certificate-password', $pfxPass) }
                        $out = (& $tool.dotnet @a 2>&1) -join "`n"; if ($LASTEXITCODE -ne 0) { throw $out }
                    }
                }
            }
            else {
                if ($kind -notin 'authenticode', 'powershell') { $row.status = 'skipped'; $row.message = "kind $kind is not signed by -Provider $Provider"; [void]$report.Add([pscustomobject]$row); continue }
                $pa = @($ProviderArg -split '\|')
                switch ($Provider) {
                    'AzureKeyVault' {
                        # secrets: AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID or a managed identity (-kvm)
                        $a = @('sign', '-kvu', $pa[0], '-kvc', $pa[1], '-fd', $Digest, '-tr', $tsUrl, '-td', $Digest)
                        if ($env:AZURE_CLIENT_ID -and $env:AZURE_CLIENT_SECRET -and $env:AZURE_TENANT_ID) { $a += @('-kvi', $env:AZURE_CLIENT_ID, '-kvs', $env:AZURE_CLIENT_SECRET, '-kvt', $env:AZURE_TENANT_ID) } else { $a += '-kvm' }
                        $a += $target
                        $out = (& $tool.azuresigntool @a 2>&1) -join "`n"
                    }
                    'AzureTrustedSigning' {
                        $dlib = $env:AZURE_CODESIGNING_DLIB; if (-not $dlib -or -not (Test-Path $dlib)) { throw 'Set AZURE_CODESIGNING_DLIB to the full path of Azure.CodeSigning.Dlib.dll (NuGet package Microsoft.Trusted.Signing.Client).' }
                        $meta = New-TempFile '.json'; [System.IO.File]::WriteAllText($meta, (@{ Endpoint = $pa[0]; CodeSigningAccountName = $pa[1]; CertificateProfileName = $pa[2] } | ConvertTo-Json))
                        $out = (& $tool.signtool sign /v /debug /fd $Digest /tr 'http://timestamp.acs.microsoft.com' /td $Digest /dlib $dlib /dmdf $meta $target 2>&1) -join "`n"
                    }
                    'DigiCertKeyLocker' { $out = (& $tool.smctl sign --keypair-alias $pa[0] --input $target 2>&1) -join "`n" }
                    { $_ -in 'AwsKms', 'GcpKms', 'Pkcs11' } {
                        # the secret goes through an environment variable, never on the command line
                        switch ($Provider) {
                            'AwsKms' { $env:JSIGN_STOREPASS = "$($env:AWS_ACCESS_KEY_ID)|$($env:AWS_SECRET_ACCESS_KEY)$(if ($env:AWS_SESSION_TOKEN) { '|' + $env:AWS_SESSION_TOKEN })"; $stype = 'AWS' }
                            'GcpKms' { $env:JSIGN_STOREPASS = (& gcloud auth print-access-token 2>$null); $stype = 'GOOGLECLOUD' }
                            'Pkcs11' { $env:JSIGN_STOREPASS = $env:SIGN_PKCS11_PIN; $stype = 'PKCS11' }
                        }
                        $out = (& $tool.jsign --storetype $stype --keystore $pa[0] --alias $pa[1] --storepass 'env:JSIGN_STOREPASS' --certfile $CertFile --alg $Digest --tsaurl $tsUrl --tsmode RFC3161 $target 2>&1) -join "`n"
                    }
                }
                if ($LASTEXITCODE -ne 0) { throw $out }
            }
            $h = Write-SignedHashFiles -Path $target
            $row.hashFiles = @($h | ForEach-Object { Split-Path -Leaf $_ })
            Write-Say 'OK' "signed: $(Split-Path -Leaf $target)   -> $(($row.hashFiles) -join ', ')"
        }
        catch {
            $failed++; $row.status = 'failed'; $row.message = ($_.Exception.Message -replace '\s+', ' ').Trim()
            if ($pfxPass) { $row.message = $row.message.Replace($pfxPass, '***') }
            Write-Say 'ERROR' "FAILED: $target : $($row.message)"
        }
        [void]$report.Add([pscustomobject]$row)
    }

    # ---- what happened
    $okN = @($report | Where-Object status -eq 'signed').Count; $skN = @($report | Where-Object status -eq 'skipped').Count
    Show-CertificateContents $cert $res.KeyText
    $repDir = if ($workRoot) { $workRoot } else { Join-Path $script:ScriptRoot 'transport' }
    [void](New-Item -ItemType Directory -Path $repDir -Force)
    $repFile = Join-Path $repDir ("sign-report_" + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.json')
    ([ordered]@{ version = $script:ToolVersion; time = (Get-Date).ToString('o'); certificate = $cert.Subject; thumbprint = $cert.Thumbprint; timestamp = $tsUrl; digest = $Digest; provider = $Provider
        signed = $okN; skipped = $skN; failed = $failed; files = $report } | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $repFile -Encoding utf8
    Write-Say 'INFO' "Report: $repFile"
    Write-Say $(if ($failed) { 'ERROR' } else { 'OK' }) "Signed $okN, skipped $skN, failed $failed (of $($sel.Files.Count))."
    if ($script:Ci -and $env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value "### Sign-Code`nSigned **$okN**, skipped $skN, failed **$failed**. Certificate: ``$($cert.Subject)``, timestamp $tsUrl" }
    if ($script:Ci -and $script:Env -eq 'azure') { Write-Host "##vso[task.setvariable variable=SignCode.Signed]$okN" }
    if ($failed -gt 0) { $exit = 6 } elseif ($Strict -and ($skN -gt 0 -or $sel.Skipped.Count -gt 0)) { Write-Say 'ERROR' '-Strict: some files were skipped.'; $exit = 6 }
}
catch [SignExit] {
    Write-Say 'ERROR' $_.Exception.Message
    $exit = $_.Exception.Code
}
catch {
    Write-Say 'ERROR' $_.Exception.Message
    $exit = 1
}
finally {
    foreach ($cb in $script:Cleanup) { try { & $cb } catch { } }
    foreach ($t in $script:Temp) { if (Test-Path -LiteralPath $t) { try { Remove-Item -LiteralPath $t -Force } catch { } } }
}
exit $exit
