#!/usr/bin/env bash
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# Version: 6.4.1
# ============================================================
# Sign-Code.sh - sign code with a code-signing certificate (Linux build machines and pipelines).
# Bash twin of Sign-Code.ps1. Needs bash 4+, OpenSSL and curl. Manual: docs/Sign-Code-MANUAL.txt
set -u
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then echo "[ERROR] bash 4 or newer is needed." >&2; exit 1; fi
VERSION=6.4.1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

help_pager() {  # help text: one screen at a time on a terminal (Space = next page, q = quit); everything when piped
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -FRXK; elif [ -t 1 ] && command -v more >/dev/null 2>&1; then more; else cat; fi
}
show_help() {
cat <<'HELP_EOF'
====================================================================================================
 Sign-Code.sh - sign your code with a code-signing certificate (Linux / macOS build machines)
 Version 6.4.1
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 Manual : docs/Sign-Code-MANUAL.txt         Windows twin: Sign-Code.ps1
 Runs on: Ubuntu 24.04 / 25.x, CentOS Stream 10, RHEL 10, Rocky Linux 10, Oracle Linux 10 (bash 4+).
          Build services: GitHub Actions (ubuntu), Azure DevOps (ubuntu), AWS CodeBuild, Alibaba
          Cloud
          Yunxiao Flow, Google Cloud Build, and any Linux container or VM.

WHAT IT DOES (in plain words)
  1. Reads the code-signing certificate and CHECKS it. A certificate that does not follow the
     code-signing rules is REFUSED and the script stops before any file is touched (exit code 2).
  2. CHECKS the timestamp server: it must answer, and its own certificate must still be valid (exit
     3).
  3. Finds the tools it needs. If one is missing it INSTALLS it from the package manager (apt or
     dnf), from a PPA / COPR you name, or (Jsign) from Maven Central.
  4. Signs every file you listed (and every supported file inside the folders you listed).
  5. Verifies each signature, writes <file>-signed.sha256 and <file>-signed.sha512 next to it,
     and prints the certificate contents.

WHAT YOU GIVE: THE FILES
  --file <path>         One file. Repeat it:  --file app.exe --file app.dll --file build.ps1
  --folder <path>       One folder (all supported files inside, sub-folders too). Repeat it:
                        --folder /build/a --folder /build/b
  --no-recurse          Do not go into sub-folders.
  --include <glob> / --exclude <glob>   Wildcards on the file name (repeatable), e.g. --exclude
                                        '*.Tests.dll'
  --out-folder <path>   Sign COPIES in this folder. The originals stay untouched. Default: sign in
                        place.
  --skip-signed         (accepted for the same command line as Sign-Code.ps1)

  Supported on Linux
    Windows files  exe dll sys ocx scr cpl efi msi cab cat msix appx   (osslsigncode)
    PowerShell     ps1 psm1 psd1 ps1xml psc1 cdxml                      (osslsigncode)
    .NET           dll / exe of .NET apps (any platform) = Windows files above; NuGet nupkg snupkg
                   (dotnet)
    Java           jar war ear (jarsigner)         Android  apk (apksigner), aab (jarsigner)
  Not signed on Linux (skipped with a message): MS Office VBA, vbs, js, wsf (need Windows), and
  Linux native packages (rpm, deb, ELF) - use GPG / rpm --addsign for those.

WHAT YOU GIVE: THE CERTIFICATE  (choose ONE way)
  --pfx <file>               A .pfx / .p12 file. Password: the environment variable named by
                             --pfx-password-env (default SIGN_PFX_PASSWORD). Not set + a terminal =
                             you are asked.
  --pfx-base64-env <name>    The name of an environment variable (a pipeline SECRET) that holds the
                             .pfx as base64. It is written to a temporary file and deleted at the
                             end.
  --cert-pem <file> --key-pem <file>   Your private PKI leaf as PEM files (made by
                                       GenerateLeafCertificate
                             with --purpose CodeSigning). Key password: variable --key-password-env.
  --provider <name>          Keys that live in a cloud / HSM service (best for pipelines):
                               azurekeyvault         via Jsign   --provider-arg
                                            "vault-name|cert-name"
                               azuretrustedsigning   via Jsign   --provider-arg
                                            "endpoint-host|account/profile"
                               awskms                via Jsign   --provider-arg "region|key-alias"
                               gcpkms                via Jsign   --provider-arg
                                            "keyring-path|key-alias"
                               pkcs11                via Jsign   --provider-arg "pkcs11.cfg|alias"
                                                       (PIN: SIGN_PKCS11_PIN)
                               digicertkeylocker     via smctl   --provider-arg "key-pair-alias"
                             Tokens are taken from the CLI of the cloud (az, gcloud) or the usual
                             environment variables (AWS_ACCESS_KEY_ID ...) and passed through an
                             environment variable.
  --cert-file <file>         With --provider: the PUBLIC certificate (PEM) so the checks can run.
  --cert-source <x>          privatepki | publicca | auto (default). auto = "publicca" when the
                             chain ends at a
                             root of this computer's trust store. publicca is stricter (RSA 3072+).
  --chain-file <file>        CA certificates of your private PKI (ca-bundle.pem) to check the chain.

TIMESTAMP  (a signature without a timestamp dies when the certificate expires - always use one)
  --timestamp <name>         digicert (default), globalsign, certum, sectigo, sslcom, entrust
  --timestamp-url <url>      Any RFC 3161 server address. It wins over --timestamp.
  --digest sha256|sha384|sha512     File digest and timestamp digest. Default sha256.

INSTALLING TOOLS
  --installer auto|none      auto (default): apt on Ubuntu, dnf on CentOS Stream / RHEL / Rocky /
                             Oracle.
  --ppa ppa:owner/name       Ubuntu: add this PPA before installing. (dotnet falls back to
                             ppa:dotnet/backports.)
  --copr owner/project       RHEL family: enable this COPR before installing.
  osslsigncode on RHEL family comes from EPEL: it is enabled for you (CentOS Stream: crb +
  epel-release,
  Rocky: crb + epel-release, Oracle: oracle-epel-release-el10).

OTHER
  --description <text> --description-url <url>   Shown to people who open the signature details.
  --check-only        Run the certificate and timestamp checks and stop. No file is signed.
  --show-certificate  Print the certificate contents (also printed after signing).
  --strict            A file that is skipped or cannot be signed makes the whole run fail (exit 6).
  --ci                Pipeline mode: never asks a question, writes pipeline annotations (GitHub
                      Actions, Azure DevOps), writes a summary, removes every temporary secret file
                      at the end.
  --template github|azure|aws|gcp|alibaba|msbuild|all
                      Writes ready-to-edit pipeline files into transport/signing-ci_<time>/ and
                      stops.

BUILD ENVIRONMENT SETUP  (for DevSecOps)
  Azure DevOps Services / Server, GitHub Actions, AWS CodeBuild, Alibaba Cloud Yunxiao,
  Google Cloud Build, Azure / GCP build VMs, Visual Studio 2026 / MSBuild.
  The agent needs
    * bash 4+, openssl and curl on a Linux build agent (hosted Ubuntu images already have them).
    * Outbound HTTP (port 80) to the timestamp server, and HTTPS to the package sources of the
      tools.
    * Missing tools are installed for you. On a locked-down or offline agent put the tools in the
      image and add --installer none; use your own RFC 3161 server with --timestamp-url <url>.
  Secrets (never in the repository, never on the command line)
    * Private PKI leaf: store the .pfx as BASE64 in a secret and its password in a second secret.
      Map them to environment variables, then  --ci --pfx-base64-env <NAME>.
      Make the base64:  base64 -w0 codesign.pfx
    * Public OV / EV certificate: the key must be in hardware, so use --provider
      (Key Vault, KMS, Artifact Signing, KeyLocker, HSM) - the key never reaches the agent.
    * Cloud login: use the identity of the pipeline (service connection, OIDC, managed identity,
      workload identity), not a stored password.
  Steps to follow
    1. bash Sign-Code.sh --ci --check-only ...   once, to prove the secret, the certificate and the
       timestamp work.
    2. Put the real step AFTER the build and BEFORE publishing the artifact.
    3. Sign the files you ship (exe, dll, msi, ps1, jar, apk, nupkg), not obj\ or test files:
       --folder <publish folder>  with  --exclude "*.Tests.dll".
    4. A result other than 0 stops the pipeline. Keep sign-report_*.json and the *-signed.sha256 /
       *-signed.sha512 files as artifacts: they are your proof.
  Ready-made pipeline files:  --template github | azure | aws | gcp | alibaba | msbuild | all
    msbuild = a .targets file for Visual Studio 2026 / MSBuild:  dotnet build -p:SignCode=true

EXAMPLES
  ./Sign-Code.sh --pfx codesign.pfx --file app.dll --file tool.jar --file app.apk
  ./Sign-Code.sh --cert-pem cs.crt --key-pem cs.key --chain-file ca-bundle.pem --folder /b/a \
        --folder /b/b
  ./Sign-Code.sh --timestamp globalsign --pfx codesign.pfx --folder ./publish --exclude \
        '*.Tests.dll'
  ./Sign-Code.sh --ci --provider awskms --provider-arg "eu-central-1|alias/codesign" --cert-file \
        cs.crt --folder out
  ./Sign-Code.sh --pfx codesign.pfx --check-only
  ./Sign-Code.sh --template all

EXIT CODES  0 ok   1 error   2 certificate refused   3 timestamp server failed
            4 tool missing / install failed   5 wrong platform   7 no file to sign
            6 some files skipped or failed (with --strict, or any failure)
====================================================================================================
HELP_EOF
}
template_text() {
  case "$1" in
    github-actions.yml)
cat <<'TPL_EOF'
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
TPL_EOF
;;
    azure-pipelines.yml)
cat <<'TPL_EOF'
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
TPL_EOF
;;
    aws-codebuild-buildspec.yml)
cat <<'TPL_EOF'
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
TPL_EOF
;;
    google-cloudbuild.yaml)
cat <<'TPL_EOF'
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
TPL_EOF
;;
    alibaba-yunxiao-flow.yml)
cat <<'TPL_EOF'
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
TPL_EOF
;;
    Sign-Code.targets)
cat <<'TPL_EOF'
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
TPL_EOF
;;
  esac
}

# ---------------------------------------------------------------- helpers
CI=0; ENVKIND=local
[ "${GITHUB_ACTIONS:-}" = true ] && ENVKIND=github
[ "${TF_BUILD:-}" = True ] && ENVKIND=azure
[ -n "${CODEBUILD_BUILD_ID:-}" ] && ENVKIND=aws
[ -n "${CLOUD_BUILD_ID:-}" ] && ENVKIND=gcp
TMPFILES=(); CLEANUPS=()
say() {
  local l="$1"; shift
  printf '[%s] %s\n' "$l" "$*"
  if [ $CI = 1 ]; then
    case "$ENVKIND:$l" in
      github:ERROR) printf '::error::%s\n' "$*";; github:WARN) printf '::warning::%s\n' "$*";;
      azure:ERROR) printf '##vso[task.logissue type=error]%s\n' "$*";; azure:WARN) printf '##vso[task.logissue type=warning]%s\n' "$*";;
    esac
  fi
}
fail() { say ERROR "$2"; EXIT=$1; exit $1; }
tmpfile() { local f; f=$(mktemp "${TMPDIR:-/tmp}/signcode.XXXXXX$1"); chmod 600 "$f"; TMPFILES+=("$f"); printf '%s' "$f"; }
cleanup() { local f; for f in "${TMPFILES[@]:-}"; do [ -n "$f" ] && rm -f -- "$f"; done; }
trap cleanup EXIT
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
get_secret() {  # env-name prompt  -> value on stdout (may be empty)
  local v="${!1:-}"; if [ -n "$v" ]; then printf '%s' "$v"; return; fi
  if [ $CI = 1 ] || [ ! -t 0 ]; then return; fi
  read -r -s -p "$2: " v; echo >&2; printf '%s' "$v"
}
hexhash() { # alg file
  case "$1" in
    sha256) if command -v sha256sum >/dev/null; then sha256sum "$2" | cut -d' ' -f1; else shasum -a 256 "$2" | cut -d' ' -f1; fi;;
    sha512) if command -v sha512sum >/dev/null; then sha512sum "$2" | cut -d' ' -f1; else shasum -a 512 "$2" | cut -d' ' -f1; fi;;
  esac
}
SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null && SUDO="sudo"

declare -A KIND
for e in exe dll sys ocx scr cpl efi msi cab cat msix appx; do KIND[$e]=authenticode; done
for e in ps1 psm1 psd1 ps1xml psc1 cdxml; do KIND[$e]=powershell; done
for e in jar war ear aab; do KIND[$e]=java; done
KIND[apk]=apk; KIND[nupkg]=nuget; KIND[snupkg]=nuget
for e in docm xlsm pptm dotm xlam ppam xltm potm doc xls ppt dot xla vbs js wsf appxbundle msixbundle winmd xll ax drv; do KIND[$e]=windows-only; done
declare -A TSA=( [digicert]=http://timestamp.digicert.com [globalsign]=http://timestamp.globalsign.com/tsa/r6advanced1
  [certum]=http://time.certum.pl [sectigo]=http://timestamp.sectigo.com [sslcom]=http://ts.ssl.com [entrust]=http://timestamp.entrust.net/TSS/RFC3161sha2TS )

# ---------------------------------------------------------------- templates
write_templates() {
  local which="$1" dir="$SCRIPT_DIR/transport/signing-ci_$(date +%Y%m%d-%H%M%S)" n
  mkdir -p "$dir"
  local -a all=(github-actions.yml azure-pipelines.yml aws-codebuild-buildspec.yml google-cloudbuild.yaml alibaba-yunxiao-flow.yml Sign-Code.targets)
  local -a sel
  case "$which" in all) sel=("${all[@]}");; github) sel=(github-actions.yml);; azure) sel=(azure-pipelines.yml);; aws) sel=(aws-codebuild-buildspec.yml);; gcp) sel=(google-cloudbuild.yaml);; alibaba) sel=(alibaba-yunxiao-flow.yml);; msbuild) sel=(Sign-Code.targets);; *) die 1 "--template '$which' is not github, azure, aws, gcp, alibaba, msbuild or all.";; esac
  for n in "${sel[@]}"; do template_text "$n" > "$dir/$n"; say OK "Written: $dir/$n"; done
  say INFO 'These are starting points. Edit the names, paths and secret names. They were not run on a real pipeline.'
}
die() { say ERROR "$2"; exit "$1"; }

# ---------------------------------------------------------------- platform and tools
OSID=unknown; PKGMGR=""
check_platform() {
  if [ -n "${PKI_FAKE_OS:-}" ]; then say WARN 'PKI_FAKE_OS is set: platform check skipped (test only).'; else
    [ "$(uname -s)" = Linux ] || die 5 'Sign-Code.sh runs on Linux (Ubuntu 24+, CentOS Stream 10, RHEL 10, Rocky 10, Oracle Linux 10). On Windows use Sign-Code.ps1.'
  fi
  local id="" ver="" like=""
  if [ -r /etc/os-release ]; then id=$(. /etc/os-release; echo "${ID:-}"); ver=$(. /etc/os-release; echo "${VERSION_ID:-}"); like=$(. /etc/os-release; echo "${ID_LIKE:-}"); fi
  OSID="$id"; local major=${ver%%.*}
  case "$id" in
    ubuntu) PKGMGR=apt; [ "${major:-0}" -ge 24 ] 2>/dev/null || say WARN "Ubuntu $ver: version 24.04 or newer is supported.";;
    centos|rhel|rocky|ol|almalinux) PKGMGR=dnf; [ "${major:-0}" -ge 10 ] 2>/dev/null || say WARN "$id $ver: version 10 or newer is supported.";;
    debian) PKGMGR=apt; say WARN 'Debian is not in the supported list; the Ubuntu steps are used.';;
    *) case " $like " in *" rhel "*|*" fedora "*) PKGMGR=dnf;; *" debian "*|*" ubuntu "*) PKGMGR=apt;; esac
       [ -n "$PKGMGR" ] && say WARN "Linux '$id' is not in the supported list; using $PKGMGR." || { [ -n "${PKI_FAKE_OS:-}" ] || die 5 "Linux '$id' is not supported (Ubuntu 24+, CentOS Stream 10, RHEL 10, Rocky 10, Oracle Linux 10)."; };;
  esac
  say INFO "Linux $id $ver ($PKGMGR): supported."
}
JSIGN_JAR_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/signcode"
find_tool() {
  case "$1" in
    osslsigncode|jarsigner|keytool|dotnet|smctl|curl|openssl|az|gcloud) command -v "$1";;
    apksigner) command -v apksigner || { local h f; for h in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Android/Sdk" /opt/android-sdk; do [ -n "$h" ] && f=$(ls -1 "$h"/build-tools/*/apksigner 2>/dev/null | sort | tail -1) && [ -n "$f" ] && { echo "$f"; return; }; done; };;
    jsign) command -v jsign || { [ -f "$JSIGN_JAR_DIR/jsign.sh" ] && echo "$JSIGN_JAR_DIR/jsign.sh"; };;
  esac
}
pkg_install() {  # packages...
  [ "$INSTALLER" = none ] && return 1
  if [ "$PKGMGR" = apt ]; then $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >&2
  else $SUDO dnf install -y "$@" >&2; fi
}
apt_update_once() { [ -n "${APT_UPDATED:-}" ] || { [ "$PKGMGR" = apt ] && $SUDO apt-get update -y >&2; APT_UPDATED=1; }; }
enable_epel() {
  case "$OSID" in
    ol) $SUDO dnf install -y oracle-epel-release-el10 >&2;;
    rhel) $SUDO dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm" >&2;;
    *) $SUDO dnf config-manager --set-enabled crb >&2 2>/dev/null || true; $SUDO dnf install -y epel-release >&2;;
  esac
}
add_extra_repo() {
  if [ "$PKGMGR" = apt ] && [ -n "$PPA" ]; then $SUDO apt-get install -y software-properties-common >&2; $SUDO add-apt-repository -y "$PPA" >&2; APT_UPDATED=""; apt_update_once; fi
  if [ "$PKGMGR" = dnf ] && [ -n "$COPR" ]; then $SUDO dnf install -y dnf-plugins-core >&2; $SUDO dnf copr enable -y "$COPR" >&2; fi
}
install_jsign() {
  find_tool java >/dev/null 2>&1 || command -v java >/dev/null || install_tool jarsigner
  command -v curl >/dev/null || { apt_update_once; pkg_install curl ca-certificates; }
  mkdir -p "$JSIGN_JAR_DIR"
  local ver jar
  ver=$(curl -fsSL https://repo1.maven.org/maven2/net/jsign/jsign/maven-metadata.xml | sed -n 's/.*<release>\(.*\)<\/release>.*/\1/p') || true
  [ -n "$ver" ] || die 4 'Could not read the Jsign version from Maven Central (network?). Install Jsign by hand (https://ebourg.github.io/jsign/) and run again.'
  jar="$JSIGN_JAR_DIR/jsign-$ver.jar"
  curl -fsSL -o "$jar" "https://repo1.maven.org/maven2/net/jsign/jsign/$ver/jsign-$ver.jar" || die 4 'Jsign download failed.'
  local want got; want=$(curl -fsSL "https://repo1.maven.org/maven2/net/jsign/jsign/$ver/jsign-$ver.jar.sha1") || true
  got=$(sha1sum "$jar" | cut -d' ' -f1)
  [ -n "$want" ] && [ "${want%% *}" = "$got" ] || { rm -f "$jar"; die 4 'The Jsign download does not match the SHA-1 published on Maven Central. Not used.'; }
  printf '#!/bin/sh\nexec java -jar "%s" "$@"\n' "$jar" > "$JSIGN_JAR_DIR/jsign.sh"; chmod +x "$JSIGN_JAR_DIR/jsign.sh"
}
install_tool() {
  local t="$1"
  say WARN "$t was not found."
  [ "$INSTALLER" = none ] && die 4 "$t is missing and --installer none was given. Install it and run again."
  [ -n "$PKGMGR" ] || die 4 "No package manager known: install $t by hand."
  add_extra_repo
  apt_update_once
  case "$t" in
    osslsigncode) [ "$PKGMGR" = dnf ] && enable_epel; pkg_install osslsigncode || die 4 'osslsigncode could not be installed.';;
    jarsigner|keytool) if [ "$PKGMGR" = apt ]; then pkg_install default-jdk-headless; else pkg_install java-21-openjdk-devel || pkg_install java-17-openjdk-devel; fi || die 4 'The JDK could not be installed.';;
    apksigner) if [ "$PKGMGR" = apt ]; then pkg_install apksigner || die 4 'apksigner could not be installed.'; else
         die 4 "apksigner has no RPM package. Install the Android command-line tools, run  sdkmanager 'build-tools;35.0.0'  and set ANDROID_HOME (or use --copr owner/project with an apksigner package)."; fi;;
    dotnet) if [ "$PKGMGR" = apt ]; then pkg_install dotnet-sdk-9.0 || pkg_install dotnet-sdk-8.0 || { $SUDO apt-get install -y software-properties-common >&2; $SUDO add-apt-repository -y ppa:dotnet/backports >&2; APT_UPDATED=""; apt_update_once; pkg_install dotnet-sdk-9.0 || pkg_install dotnet-sdk-8.0; }
            else pkg_install dotnet-sdk-9.0 || pkg_install dotnet-sdk-8.0; fi || die 4 'The .NET SDK could not be installed.';;
    jsign) install_jsign;;
    curl|openssl) pkg_install "$t" ca-certificates || die 4 "$t could not be installed.";;
    smctl) die 4 'smctl (DigiCert KeyLocker client tools) must be installed by you: https://docs.digicert.com/ . Add it to PATH and run again.';;
    az|gcloud) die 4 "$t (the cloud CLI) must be installed by you and logged in.";;
  esac
  hash -r
  [ -n "$(find_tool "$t")" ] || die 4 "$t was installed but is still not found."
  say OK "$t is ready."
}
need_tool() { local p; p=$(find_tool "$1"); if [ -z "$p" ]; then install_tool "$1"; p=$(find_tool "$1"); fi; printf '%s' "$p"; }

# ---------------------------------------------------------------- certificate checks (openssl)
oidname() { case "$1" in 1.3.6.1.5.5.7.3.3) echo 'Code Signing';; *) echo "$1";; esac; }
CERT_ERR=(); CERT_WARN=()
check_certificate() {   # pem-file source chain
  local pem="$1" source="$2" chain="$3" t
  CERT_ERR=(); CERT_WARN=()
  t=$("$OSSL" x509 -in "$pem" -noout -text -nameopt RFC2253 2>/dev/null) || { CERT_ERR+=("OpenSSL cannot read the certificate."); return; }
  CERT_TEXT="$t"
  "$OSSL" x509 -in "$pem" -noout -checkend 0 >/dev/null || CERT_ERR+=("The certificate has EXPIRED ($("$OSSL" x509 -in "$pem" -noout -enddate | cut -d= -f2)).")
  if ! "$OSSL" x509 -in "$pem" -noout -checkend -0 >/dev/null 2>&1; then :; fi
  local nb now_ok; nb=$("$OSSL" x509 -in "$pem" -noout -startdate | cut -d= -f2)
  [ "$(date -d "$nb" +%s 2>/dev/null || echo 0)" -le "$(date +%s)" ] || CERT_ERR+=("The certificate is not valid yet (starts $nb).")
  "$OSSL" x509 -in "$pem" -noout -checkend $((30*86400)) >/dev/null || { "$OSSL" x509 -in "$pem" -noout -checkend 0 >/dev/null && CERT_WARN+=("The certificate expires in less than 30 days. Signatures with a timestamp stay valid after that."); }
  # purposes
  if ! printf '%s' "$t" | grep -q 'X509v3 Extended Key Usage'; then CERT_ERR+=('The certificate has no Extended Key Usage. A code-signing certificate must have "Code Signing" (1.3.6.1.5.5.7.3.3).')
  else
    local eku; eku=$(printf '%s\n' "$t" | sed -n '/X509v3 Extended Key Usage/{n;p}' | sed 's/^ *//')
    printf '%s' "$eku" | grep -q 'Code Signing' || CERT_ERR+=("The certificate is not for Code Signing. Its purposes: $eku.")
    printf '%s' "$eku" | grep -qE 'TLS Web|E-mail Protection|Time Stamping|Any Extended' && CERT_WARN+=("The certificate also has other purposes ($eku). Public CAs forbid this for code signing; use a dedicated certificate.")
  fi
  if printf '%s' "$t" | grep -q 'X509v3 Key Usage'; then
    printf '%s\n' "$t" | sed -n '/X509v3 Key Usage/{n;p}' | grep -q 'Digital Signature' || CERT_ERR+=('Key Usage does not include Digital Signature.')
  else CERT_WARN+=('The certificate has no Key Usage extension (it should say Digital Signature).'); fi
  printf '%s' "$t" | grep -q 'CA:TRUE' && CERT_ERR+=('This is a CA certificate (CA:TRUE). A CA must never sign code. Use a leaf certificate.')
  # key
  local alg bits; alg=$(printf '%s\n' "$t" | sed -n 's/^ *Public Key Algorithm: *//p' | head -1)
  CERT_KEYTEXT="$alg"
  if printf '%s' "$alg" | grep -qi 'rsaEncryption\|^rsa'; then
    bits=$(printf '%s\n' "$t" | sed -n 's/^ *Public-Key: *(\([0-9]*\) bit).*/\1/p' | head -1); CERT_KEYTEXT="RSA-$bits"
    if [ "$bits" -lt 2048 ]; then CERT_ERR+=("RSA-$bits is too weak. At least RSA-2048 (public CAs: RSA-3072).")
    elif [ "$bits" -lt 3072 ] && [ "$source" = publicca ]; then CERT_ERR+=("A public code-signing certificate must have RSA-3072 or larger (CA/Browser Forum). This one is RSA-$bits.")
    elif [ "$bits" -lt 3072 ]; then CERT_WARN+=("RSA-$bits works, but RSA-3072 or ECDSA P-384 is recommended."); fi
    [ "$bits" -gt 4096 ] && CERT_WARN+=("RSA-$bits is larger than 4096: some signing tools and Windows components refuse it.")
  elif printf '%s' "$alg" | grep -qi 'ec'; then
    bits=$(printf '%s\n' "$t" | sed -n 's/^ *Public-Key: *(\([0-9]*\) bit).*/\1/p' | head -1); CERT_KEYTEXT="ECDSA-$bits"
    [ "$bits" -lt 256 ] && CERT_ERR+=("ECDSA key size $bits is too small (P-256 or larger).")
    [ "$bits" -gt 384 ] && CERT_WARN+=('ECDSA P-521 is not accepted by every signing tool. P-256 or P-384 is safest.')
  elif printf '%s' "$alg" | grep -qiE 'ml-dsa|mldsa|slh-dsa'; then CERT_ERR+=('An ML-DSA (quantum) certificate cannot sign code yet: Authenticode, jarsigner, apksigner and NuGet do not support it. Use an RSA or ECDSA code-signing leaf.')
  else CERT_ERR+=("Key type $alg is not supported for code signing."); fi
  printf '%s\n' "$t" | sed -n 's/^ *Signature Algorithm: *//p' | head -1 | grep -qiE 'md5|sha1' && CERT_ERR+=("The certificate is signed with a weak algorithm.")
  local subj iss; subj=$(printf '%s\n' "$t" | sed -n 's/^ *Subject: *//p' | head -1); iss=$(printf '%s\n' "$t" | sed -n 's/^ *Issuer: *//p' | head -1)
  [ "$subj" = "$iss" ] && CERT_WARN+=('The certificate is self-signed. Every computer that checks the signature must trust it by hand.')
  # chain
  CERT_CHAIN_OK=0
  local vargs=(-purpose codesigning)
  if [ -n "$chain" ] && [ -f "$chain" ]; then vargs+=(-no-CApath -no-CAfile -CAfile "$chain" -untrusted "$chain"); else [ -n "$CHAIN_UNTRUSTED" ] && vargs+=(-untrusted "$CHAIN_UNTRUSTED"); fi
  CERT_VERIFY=$("$OSSL" verify "${vargs[@]}" "$pem" 2>&1) && CERT_CHAIN_OK=1
  CERT_POLICY=""; printf '%s' "$t" | grep -q '2\.23\.140\.1\.3\b' && CERT_POLICY=EV
  [ -z "$CERT_POLICY" ] && printf '%s' "$t" | grep -q '2\.23\.140\.1\.4\.1\b' && CERT_POLICY=CSBR
}
show_certificate() {
  local pem="$1"
  echo; echo '----- CERTIFICATE USED FOR SIGNING ------------------------------------------------------'
  "$OSSL" x509 -in "$pem" -noout -subject -issuer -serial -dates -nameopt RFC2253 | sed 's/^/  /'
  echo "  Public key   : ${CERT_KEYTEXT:-?}"
  echo "  SHA-1        : $("$OSSL" x509 -in "$pem" -noout -fingerprint -sha1 | cut -d= -f2)"
  echo "  SHA-256      : $("$OSSL" x509 -in "$pem" -noout -fingerprint -sha256 | cut -d= -f2)"
  "$OSSL" x509 -in "$pem" -noout -ext extendedKeyUsage,keyUsage 2>/dev/null | sed 's/^/  /'
  echo '-----------------------------------------------------------------------------------------'
}

# ---------------------------------------------------------------- timestamp check
check_timestamp() {
  local url="$1" q r tok certs tsa nd
  q=$(tmpfile .tsq); r=$(tmpfile .tsr); tok=$(tmpfile .der); certs=$(tmpfile .pem)
  "$OSSL" ts -query -digest "$(printf 'signcode-check-%s' "$RANDOM$RANDOM$$" | sha256sum | cut -d' ' -f1)" -sha256 -cert -out "$q" 2>/dev/null || die 3 'OpenSSL could not build a timestamp request.'
  local codef errf code err; codef=$(tmpfile .code); errf=$(tmpfile .err)
  curl -sS --max-time 20 -H 'Content-Type: application/timestamp-query' --data-binary "@$q" -o "$r" -w '%{http_code}' "$url" > "$codef" 2>"$errf" || true
  code=$(cat "$codef" 2>/dev/null); err=$(cat "$errf" 2>/dev/null)
  case "$code" in 200) ;; ''|000) die 3 "The timestamp server $url cannot be reached from this computer: ${err:-no answer}. Check the network / proxy / firewall, or choose another with --timestamp.";; *) die 3 "The timestamp server $url answered HTTP $code. Choose another with --timestamp or --timestamp-url.";; esac
  local txt; txt=$("$OSSL" ts -reply -in "$r" -text 2>&1) || die 3 "The answer of $url is not a valid RFC 3161 timestamp."
  printf '%s' "$txt" | grep -qE 'Status: (Granted|Granted with modifications)' || die 3 "The timestamp server $url refused the request: $(printf '%s' "$txt" | sed -n 's/^Status: *//p' | head -1)"
  "$OSSL" ts -reply -in "$r" -token_out -out "$tok" 2>/dev/null
  "$OSSL" pkcs7 -inform DER -in "$tok" -print_certs -out "$certs" 2>/dev/null
  [ -s "$certs" ] || { say WARN "The timestamp answer has no certificate inside; its validity cannot be checked."; say OK "Timestamp server answers: $url"; return; }
  tsa=$(awk '/BEGIN CERTIFICATE/{n++} n==1{print} /END CERTIFICATE/{if(n==1) exit}' "$certs")
  # the TSA certificate is the one with the timeStamping purpose
  local one i=0 found=""
  while true; do
    i=$((i+1)); one=$(awk -v k=$i '/BEGIN CERTIFICATE/{n++} n==k{print} /END CERTIFICATE/{if(n==k) exit}' "$certs"); [ -n "$one" ] || break
    if printf '%s\n' "$one" | "$OSSL" x509 -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'Time Stamping'; then found="$one"; break; fi
  done
  [ -n "$found" ] && tsa="$found"
  printf '%s\n' "$tsa" | "$OSSL" x509 -noout -checkend 0 >/dev/null || die 3 "The certificate of the timestamp server has expired. Choose another server."
  nd=$(printf '%s\n' "$tsa" | "$OSSL" x509 -noout -enddate | cut -d= -f2)
  local left=$(( ( $(date -d "$nd" +%s) - $(date +%s) ) / 86400 ))
  say OK "Timestamp server answers: $url"
  say OK "Timestamp certificate: $(printf '%s\n' "$tsa" | "$OSSL" x509 -noout -subject -nameopt RFC2253 | sed 's/^subject=//')  valid until $nd ($left days left)"
  [ $left -lt 30 ] && say WARN "The timestamp certificate expires in $left days."
  return 0
}

# ---------------------------------------------------------------- files
FILES=(); SKIPPED=()
add_file() {
  local f="$1" ext k
  ext=$(lc "${f##*.}"); k="${KIND[$ext]:-}"
  if [ -z "$k" ]; then SKIPPED+=("$f (not a supported file type)"); return; fi
  if [ "$k" = windows-only ]; then SKIPPED+=("$f (needs Windows: use Sign-Code.ps1)"); return; fi
  local x; for x in "${FILES[@]:-}"; do [ "$x" = "$f" ] && return; done
  FILES+=("$f")
}
resolve_files() {
  local f d i name ok p
  for f in "${FILE_ARGS[@]:-}"; do [ -n "$f" ] || continue; [ -f "$f" ] || die 1 "File not found: $f"; add_file "$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"; done
  for d in "${FOLDER_ARGS[@]:-}"; do
    [ -n "$d" ] || continue; [ -d "$d" ] || die 1 "Folder not found: $d"
    d=$(cd "$d" && pwd)
    local find_args=("$d"); [ $NORECURSE = 1 ] && find_args+=(-maxdepth 1)
    while IFS= read -r -d '' i; do
      name=$(basename "$i"); local ext; ext=$(lc "${i##*.}"); [ -n "${KIND[$ext]:-}" ] || continue
      if [ ${#INCLUDE[@]} -gt 0 ]; then ok=0; for p in "${INCLUDE[@]}"; do case "$name" in $p) ok=1;; esac; done; [ $ok = 1 ] || continue; fi
      ok=0; for p in "${EXCLUDE[@]:-}"; do [ -n "$p" ] && case "$name" in $p) ok=1;; esac; done; [ $ok = 1 ] && continue
      add_file "$i"
    done < <(find "${find_args[@]}" -type f -print0 | sort -z)
  done
}
write_hashes() {  # file -> prints names
  local f="$1" dir name a h out names=""; dir=$(dirname "$f"); name=$(basename "$f")
  for a in sha256 sha512; do h=$(hexhash $a "$f"); out="$dir/$name-signed.$a"; printf '%s  %s\n' "$h" "$name" > "$out"; names="$names $(basename "$out")"; done
  printf '%s' "${names# }"
}

# ---------------------------------------------------------------- main
FILE_ARGS=(); FOLDER_ARGS=(); INCLUDE=(); EXCLUDE=(); NORECURSE=0; CERT_SOURCE=auto; PROVIDER=local; PFX=""; PFX_PASS_ENV=SIGN_PFX_PASSWORD
PFX_B64_ENV=""; CERT_PEM=""; KEY_PEM=""; KEY_PASS_ENV=SIGN_KEY_PASSWORD; CHAIN_FILE=""; CERT_FILE=""; PROVIDER_ARG=""; TIMESTAMP=digicert; TS_URL=""
DIGEST=sha256; DESCRIPTION=""; DESC_URL=""; OUT_FOLDER=""; INSTALLER=auto; CHECK_ONLY=0; STRICT=0; TEMPLATE=""; SHOW_CERT=0; PPA=""; COPR=""; OPENSSL_ARG=""
CHAIN_UNTRUSTED=""; EXIT=0
need() { [ $# -ge 2 ] || die 1 "Option $1 needs a value."; }
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) show_help | help_pager; exit 0;;
    --file) need "$@"; FILE_ARGS+=("$2"); shift;;
    --folder) need "$@"; FOLDER_ARGS+=("$2"); shift;;
    --include) need "$@"; INCLUDE+=("$2"); shift;;
    --exclude) need "$@"; EXCLUDE+=("$2"); shift;;
    --no-recurse) NORECURSE=1;;
    --cert-source) need "$@"; CERT_SOURCE=$(lc "$2"); shift;;
    --provider) need "$@"; PROVIDER=$(lc "$2"); shift;;
    --pfx) need "$@"; PFX="$2"; shift;;
    --pfx-password-env) need "$@"; PFX_PASS_ENV="$2"; shift;;
    --pfx-base64-env) need "$@"; PFX_B64_ENV="$2"; shift;;
    --cert-pem) need "$@"; CERT_PEM="$2"; shift;;
    --key-pem) need "$@"; KEY_PEM="$2"; shift;;
    --key-password-env) need "$@"; KEY_PASS_ENV="$2"; shift;;
    --chain-file) need "$@"; CHAIN_FILE="$2"; shift;;
    --cert-file) need "$@"; CERT_FILE="$2"; shift;;
    --provider-arg) need "$@"; PROVIDER_ARG="$2"; shift;;
    --timestamp) need "$@"; TIMESTAMP=$(lc "$2"); shift;;
    --timestamp-url) need "$@"; TS_URL="$2"; shift;;
    --digest) need "$@"; DIGEST=$(lc "$2"); shift;;
    --description) need "$@"; DESCRIPTION="$2"; shift;;
    --description-url) need "$@"; DESC_URL="$2"; shift;;
    --out-folder) need "$@"; OUT_FOLDER="$2"; shift;;
    --skip-signed) ;;
    --installer) need "$@"; INSTALLER=$(lc "$2"); shift;;
    --ppa) need "$@"; PPA="$2"; shift;;
    --copr) need "$@"; COPR="$2"; shift;;
    --check-only) CHECK_ONLY=1;;
    --ci) CI=1;;
    --strict) STRICT=1;;
    --template) need "$@"; TEMPLATE=$(lc "$2"); shift;;
    --show-certificate) SHOW_CERT=1;;
    --openssl) need "$@"; OPENSSL_ARG="$2"; shift;;
    *) die 1 "Unknown option: $1   (see --help)";;
  esac
  shift
done
case "$DIGEST" in sha256|sha384|sha512) ;; *) die 1 "--digest '$DIGEST' is not sha256, sha384 or sha512.";; esac
case "$INSTALLER" in auto|none) ;; *) die 1 "--installer '$INSTALLER' is not auto or none.";; esac
if [ -n "$TEMPLATE" ]; then write_templates "$TEMPLATE"; exit 0; fi

printf '%s\n' '============================================================' 'Author : Nicko Satria Utama' 'Company: Agantra Inovatif OÜ (NextMantra)' 'Email  : nicko@nextmantra.com' '============================================================' ''
say INFO "Sign-Code.sh version $VERSION$([ $CI = 1 ] && echo "  (pipeline mode, $ENVKIND)")"
check_platform
OSSL="$OPENSSL_ARG"; [ -n "$OSSL" ] || OSSL=$(command -v openssl || true)
[ -n "$OSSL" ] || { install_tool openssl; OSSL=$(command -v openssl); }
command -v curl >/dev/null || install_tool curl

resolve_files
for s in "${SKIPPED[@]:-}"; do [ -n "$s" ] && say WARN "Skipped: $s"; done
[ $CHECK_ONLY = 1 ] || [ ${#FILES[@]} -gt 0 ] || die 7 'No file to sign. Give --file and / or --folder (supported types: see --help).'
say INFO "${#FILES[@]} file(s) to sign."

# ---- certificate: make a PEM (public) and a normalized temporary PFX (alias "signcode") for the tools
PUBPEM=$(tmpfile .pem); WORKPFX=""; WORKPASS=""
if [ "$PROVIDER" = local ]; then
  n=0; for v in "$PFX" "$PFX_B64_ENV" "$CERT_PEM"; do [ -n "$v" ] && n=$((n+1)); done
  [ $n -eq 1 ] || die 1 'Give exactly ONE certificate source: --pfx, --pfx-base64-env or --cert-pem/--key-pem (or use --provider).'
  WORKPASS=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'); [ "$ENVKIND" = github ] && echo "::add-mask::$WORKPASS"
  export SIGNCODE_WORKPASS="$WORKPASS"
  WORKPFX=$(tmpfile .pfx)
  if [ -n "$PFX" ] || [ -n "$PFX_B64_ENV" ]; then
    SRCPFX="$PFX"
    if [ -n "$PFX_B64_ENV" ]; then
      [ -n "${!PFX_B64_ENV:-}" ] || die 1 "The environment variable $PFX_B64_ENV is empty or not set. In a pipeline, map the secret to it."
      SRCPFX=$(tmpfile .pfx); printf '%s' "${!PFX_B64_ENV}" | tr -d ' \n\r' | base64 -d > "$SRCPFX" || die 1 "$PFX_B64_ENV is not valid base64."
    fi
    [ -f "$SRCPFX" ] || die 1 "PFX file not found: $SRCPFX"
    export SIGNCODE_SRCPASS; SIGNCODE_SRCPASS=$(get_secret "$PFX_PASS_ENV" 'PFX password')
    [ "$ENVKIND" = github ] && [ -n "$SIGNCODE_SRCPASS" ] && echo "::add-mask::$SIGNCODE_SRCPASS"
    ALLPEM=$(tmpfile .pem)
    "$OSSL" pkcs12 -in "$SRCPFX" -nodes -passin env:SIGNCODE_SRCPASS -out "$ALLPEM" 2>/dev/null || "$OSSL" pkcs12 -legacy -in "$SRCPFX" -nodes -passin env:SIGNCODE_SRCPASS -out "$ALLPEM" 2>/dev/null || die 1 "The PFX could not be opened (wrong password in $PFX_PASS_ENV?)."
    "$OSSL" pkcs12 -in "$SRCPFX" -nokeys -clcerts -passin env:SIGNCODE_SRCPASS -out "$PUBPEM" 2>/dev/null || "$OSSL" pkcs12 -legacy -in "$SRCPFX" -nokeys -clcerts -passin env:SIGNCODE_SRCPASS -out "$PUBPEM" 2>/dev/null
    KEYTMP=$(tmpfile .key); awk '/BEGIN (ENCRYPTED |EC |RSA )?PRIVATE KEY/{p=1} p{print} /END (ENCRYPTED |EC |RSA )?PRIVATE KEY/{p=0}' "$ALLPEM" > "$KEYTMP"
    CHAINTMP=$(tmpfile .pem); "$OSSL" pkcs12 -in "$SRCPFX" -nokeys -cacerts -passin env:SIGNCODE_SRCPASS -out "$CHAINTMP" 2>/dev/null || "$OSSL" pkcs12 -legacy -in "$SRCPFX" -nokeys -cacerts -passin env:SIGNCODE_SRCPASS -out "$CHAINTMP" 2>/dev/null || true
    CHAIN_UNTRUSTED="$CHAINTMP"
  else
    [ -n "$KEY_PEM" ] || die 1 '--cert-pem needs --key-pem as well.'
    [ -f "$CERT_PEM" ] && [ -f "$KEY_PEM" ] || die 1 'Certificate or key file not found.'
    export SIGNCODE_KEYPASS; SIGNCODE_KEYPASS=$(get_secret "$KEY_PASS_ENV" 'Private key password (empty = none)')
    awk '/BEGIN CERTIFICATE/{n++} n==1{print} /END CERTIFICATE/{if(n==1) exit}' "$CERT_PEM" > "$PUBPEM"
    KEYTMP=$(tmpfile .key)
    if [ -n "$SIGNCODE_KEYPASS" ]; then "$OSSL" pkey -in "$KEY_PEM" -passin env:SIGNCODE_KEYPASS -out "$KEYTMP" 2>/dev/null || die 1 "The private key could not be opened (wrong password in $KEY_PASS_ENV?)."
    else "$OSSL" pkey -in "$KEY_PEM" -passin pass: -out "$KEYTMP" 2>/dev/null || die 1 'The private key could not be opened (is it encrypted? set the password variable).'; fi
    CHAINTMP=$(tmpfile .pem); awk '/BEGIN CERTIFICATE/{n++} n>=2{print}' "$CERT_PEM" > "$CHAINTMP"; CHAIN_UNTRUSTED="$CHAINTMP"
  fi
  [ -s "$PUBPEM" ] || die 1 'No certificate was found in the PFX / PEM.'
  # the private key must belong to the certificate
  [ "$("$OSSL" x509 -in "$PUBPEM" -noout -pubkey | tr -d ' \n')" = "$("$OSSL" pkey -in "$KEYTMP" -pubout 2>/dev/null | tr -d ' \n')" ] || die 1 'The private key does NOT belong to the certificate.'
  cf=(); [ -s "${CHAINTMP:-}" ] && cf=(-certfile "$CHAINTMP")
  "$OSSL" pkcs12 -export -inkey "$KEYTMP" -in "$PUBPEM" "${cf[@]}" -name signcode -out "$WORKPFX" -passout env:SIGNCODE_WORKPASS 2>/dev/null || die 1 'Could not prepare the signing key store.'
  rm -f "$KEYTMP"
else
  [ -n "$CERT_FILE" ] || die 1 "--provider $PROVIDER needs --cert-file <the public certificate> so that the checks can run."
  [ -f "$CERT_FILE" ] || die 1 "Certificate file not found: $CERT_FILE"
  "$OSSL" x509 -in "$CERT_FILE" -out "$PUBPEM" 2>/dev/null || "$OSSL" x509 -inform DER -in "$CERT_FILE" -out "$PUBPEM" || die 1 'The certificate file could not be read.'
fi

# ---- classify and CHECK
SRC="$CERT_SOURCE"
case "$SRC" in auto|privatepki|publicca) ;; *) die 1 "--cert-source '$SRC' is not auto, privatepki or publicca.";; esac
if [ "$SRC" = auto ]; then
  check_certificate "$PUBPEM" privatepki ""
  if [ $CERT_CHAIN_OK = 1 ] && [ "$(printf '%s' "$CERT_TEXT" | sed -n 's/^ *Subject: *//p' | head -1)" != "$(printf '%s' "$CERT_TEXT" | sed -n 's/^ *Issuer: *//p' | head -1)" ]; then SRC=publicca; else SRC=privatepki; fi
fi
say INFO "Certificate source: $SRC"
check_certificate "$PUBPEM" "$SRC" "$CHAIN_FILE"
if [ "$SRC" = publicca ]; then
  [ $CERT_CHAIN_OK = 1 ] || CERT_ERR+=("The chain does not end at a root that this computer trusts ($(printf '%s' "$CERT_VERIFY" | tail -1)).")
  [ -n "$CERT_POLICY" ] || CERT_WARN+=('No CA/Browser Forum code-signing policy (2.23.140.1.4.1 or EV 2.23.140.1.3) found in the certificate.')
elif [ $CERT_CHAIN_OK = 0 ]; then CERT_WARN+=('The chain is not complete / not trusted here. Give --chain-file <ca-bundle.pem> to check it against your private root.'); fi
for w in "${CERT_WARN[@]:-}"; do [ -n "$w" ] && say WARN "$w"; done
if [ ${#CERT_ERR[@]} -gt 0 ]; then
  for e in "${CERT_ERR[@]}"; do say ERROR "$e"; done
  show_certificate "$PUBPEM"
  die 2 'The certificate does NOT comply with the code-signing rules. Nothing was signed.'
fi
say OK "Certificate complies: $CERT_KEYTEXT, $([ "$CERT_POLICY" = EV ] && echo 'EV code signing' || { [ "$CERT_POLICY" = CSBR ] && echo 'OV code signing (CA/B Forum)' || echo 'code signing'; }), chain $([ $CERT_CHAIN_OK = 1 ] && echo verified || echo 'not verified')."

# ---- timestamp
if [ -n "$TS_URL" ]; then TSURL="$TS_URL"
elif [ -n "${TSA[$TIMESTAMP]:-}" ]; then TSURL="${TSA[$TIMESTAMP]}"
elif [[ "$TIMESTAMP" =~ ^https?:// ]]; then TSURL="$TIMESTAMP"
else die 1 "Unknown timestamp name '$TIMESTAMP'. Use: ${!TSA[*]} or --timestamp-url <url>."; fi
check_timestamp "$TSURL"
if [ $CHECK_ONLY = 1 ]; then show_certificate "$PUBPEM"; say OK 'Checks finished (--check-only): nothing was signed.'; exit 0; fi

# ---- tools needed for THIS job
declare -A KINDS_USED; for f in "${FILES[@]}"; do KINDS_USED[${KIND[$(lc "${f##*.}")]}]=1; done
TOOL_OSS=""; TOOL_JAR=""; TOOL_APK=""; TOOL_DOTNET=""; TOOL_JSIGN=""; TOOL_SMCTL=""
if [ "$PROVIDER" = local ]; then
  { [ -n "${KINDS_USED[authenticode]:-}" ] || [ -n "${KINDS_USED[powershell]:-}" ]; } && TOOL_OSS=$(need_tool osslsigncode)
  [ -n "${KINDS_USED[java]:-}" ] && TOOL_JAR=$(need_tool jarsigner)
  [ -n "${KINDS_USED[apk]:-}" ] && { TOOL_APK=$(need_tool apksigner); command -v jarsigner >/dev/null || need_tool jarsigner >/dev/null; }
  [ -n "${KINDS_USED[nuget]:-}" ] && TOOL_DOTNET=$(need_tool dotnet)
else
  case "$PROVIDER" in
    digicertkeylocker) TOOL_SMCTL=$(need_tool smctl);;
    azurekeyvault|azuretrustedsigning) TOOL_JSIGN=$(need_tool jsign); need_tool az >/dev/null;;
    gcpkms) TOOL_JSIGN=$(need_tool jsign); need_tool gcloud >/dev/null;;
    awskms|pkcs11) TOOL_JSIGN=$(need_tool jsign);;
    *) die 1 "--provider '$PROVIDER' is not azurekeyvault, azuretrustedsigning, awskms, gcpkms, pkcs11 or digicertkeylocker.";;
  esac
fi
[ -z "$OUT_FOLDER" ] || mkdir -p "$OUT_FOLDER"

# ---- sign
IFS='|' read -r PA1 PA2 PA3 <<<"$PROVIDER_ARG"
ds_up=$(printf '%s' "$DIGEST" | tr 'a-z' 'A-Z'); ds_dash="${ds_up/SHA/SHA-}"
OKN=0; SKN=${#SKIPPED[@]}; FAILN=0; REPORT=(); idx=0
for src in "${FILES[@]}"; do
  idx=$((idx+1)); tgt="$src"
  if [ -n "$OUT_FOLDER" ]; then tgt="$OUT_FOLDER/$(basename "$src")"; cp -f "$src" "$tgt"; fi
  ext=$(lc "${tgt##*.}"); kind="${KIND[$ext]}"; echo "[$idx/${#FILES[@]}] $tgt  ($kind)"
  msg=""; out=""; rc=0
  if [ "$PROVIDER" = local ]; then
    case "$kind" in
      authenticode|powershell)
        tmpout=$(tmpfile .signed); rm -f "$tmpout"
        oargs=(sign -pkcs12 "$WORKPFX" -pass "$WORKPASS" -h "$DIGEST" -ts "$TSURL" -in "$tgt" -out "$tmpout")
        [ -n "$DESCRIPTION" ] && oargs+=(-n "$DESCRIPTION"); [ -n "$DESC_URL" ] && oargs+=(-i "$DESC_URL")
        # -pass puts the one-time password of the temporary key store on the command line: it is random and only opens the temporary file
        out=$("$TOOL_OSS" "${oargs[@]}" 2>&1) || rc=$?
        if [ $rc -eq 0 ]; then
          out=$("$TOOL_OSS" verify -in "$tmpout" 2>&1); vrc=$?
          if printf '%s' "$out" | grep -q 'Signature verification: ok'; then :; elif [ "$SRC" = publicca ]; then rc=1; else msg='signature written; the root is not trusted by this machine (normal for a private PKI)'; fi
          [ $rc -eq 0 ] && cp -f "$tmpout" "$tgt"
        fi;;
      java)
        out=$("$TOOL_JAR" -keystore "$WORKPFX" -storetype PKCS12 -storepass:env SIGNCODE_WORKPASS -digestalg "$ds_dash" -tsa "$TSURL" -tsadigestalg "$ds_dash" "$tgt" signcode 2>&1) || rc=$?
        [ $rc -eq 0 ] && { out=$("$TOOL_JAR" -verify "$tgt" 2>&1) || rc=$?; };;
      apk)
        out=$("$TOOL_APK" sign --ks "$WORKPFX" --ks-type PKCS12 --ks-pass env:SIGNCODE_WORKPASS "$tgt" 2>&1) || rc=$?
        [ $rc -eq 0 ] && { out=$("$TOOL_APK" verify "$tgt" 2>&1) || rc=$?; msg='APK signed without a timestamp (the Android format has none)'; };;
      nuget)
        out=$("$TOOL_DOTNET" nuget sign "$tgt" --certificate-path "$WORKPFX" --certificate-password "$WORKPASS" --timestamper "$TSURL" --timestamp-hash-algorithm "$DIGEST" --hash-algorithm "$DIGEST" --overwrite 2>&1) || rc=$?;;
    esac
  else
    case "$kind" in authenticode|powershell) ;; *) say WARN "Skipped (kind $kind is not signed by --provider $PROVIDER): $tgt"; SKN=$((SKN+1)); REPORT+=("{\"file\":\"$tgt\",\"status\":\"skipped\"}"); continue;; esac
    case "$PROVIDER" in
      azurekeyvault) export JSIGN_STOREPASS; JSIGN_STOREPASS=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
        out=$("$TOOL_JSIGN" --storetype AZUREKEYVAULT --keystore "$PA1" --alias "$PA2" --storepass env:JSIGN_STOREPASS --alg "$DIGEST" --tsaurl "$TSURL" --tsmode RFC3161 "$tgt" 2>&1) || rc=$?;;
      azuretrustedsigning) export JSIGN_STOREPASS; JSIGN_STOREPASS=$(az account get-access-token --resource https://codesigning.azure.net --query accessToken -o tsv)
        out=$("$TOOL_JSIGN" --storetype TRUSTEDSIGNING --keystore "$PA1" --alias "$PA2" --storepass env:JSIGN_STOREPASS --alg "$DIGEST" --tsaurl http://timestamp.acs.microsoft.com --tsmode RFC3161 "$tgt" 2>&1) || rc=$?;;
      awskms) export JSIGN_STOREPASS="${AWS_ACCESS_KEY_ID:-}|${AWS_SECRET_ACCESS_KEY:-}${AWS_SESSION_TOKEN:+|$AWS_SESSION_TOKEN}"
        out=$("$TOOL_JSIGN" --storetype AWS --keystore "$PA1" --alias "$PA2" --storepass env:JSIGN_STOREPASS --certfile "$CERT_FILE" --alg "$DIGEST" --tsaurl "$TSURL" --tsmode RFC3161 "$tgt" 2>&1) || rc=$?;;
      gcpkms) export JSIGN_STOREPASS; JSIGN_STOREPASS=$(gcloud auth print-access-token)
        out=$("$TOOL_JSIGN" --storetype GOOGLECLOUD --keystore "$PA1" --alias "$PA2" --storepass env:JSIGN_STOREPASS --certfile "$CERT_FILE" --alg "$DIGEST" --tsaurl "$TSURL" --tsmode RFC3161 "$tgt" 2>&1) || rc=$?;;
      pkcs11) export JSIGN_STOREPASS="${SIGN_PKCS11_PIN:-}"
        out=$("$TOOL_JSIGN" --storetype PKCS11 --keystore "$PA1" --alias "$PA2" --storepass env:JSIGN_STOREPASS --certfile "$CERT_FILE" --alg "$DIGEST" --tsaurl "$TSURL" --tsmode RFC3161 "$tgt" 2>&1) || rc=$?;;
      digicertkeylocker) out=$("$TOOL_SMCTL" sign --keypair-alias "$PA1" --input "$tgt" 2>&1) || rc=$?;;
    esac
  fi
  if [ $rc -eq 0 ]; then
    hn=$(write_hashes "$tgt"); OKN=$((OKN+1)); say OK "signed: $(basename "$tgt")   -> ${hn// /, }"
    REPORT+=("{\"file\":\"$tgt\",\"kind\":\"$kind\",\"status\":\"signed\",\"message\":\"${msg//\"/\\\"}\"}")
  else
    FAILN=$((FAILN+1)); one=$(printf '%s' "$out" | tr '\n' ' ' | sed 's/  */ /g; s/"/'"'"'/g'); one=${one//$WORKPASS/***}
    say ERROR "FAILED: $tgt : $one"; REPORT+=("{\"file\":\"$tgt\",\"kind\":\"$kind\",\"status\":\"failed\",\"message\":\"$one\"}")
  fi
done

# ---- what happened
show_certificate "$PUBPEM"
repdir="${OUT_FOLDER:-$SCRIPT_DIR/transport}"; mkdir -p "$repdir"
rep="$repdir/sign-report_$(date +%Y%m%d-%H%M%S).json"
{ printf '{"version":"%s","time":"%s","timestamp":"%s","digest":"%s","provider":"%s","signed":%d,"skipped":%d,"failed":%d,"files":[' "$VERSION" "$(date -Is)" "$TSURL" "$DIGEST" "$PROVIDER" $OKN $SKN $FAILN
  (IFS=,; printf '%s' "${REPORT[*]:-}"); printf ']}\n'; } > "$rep"
say INFO "Report: $rep"
if [ $FAILN -gt 0 ]; then say ERROR "Signed $OKN, skipped $SKN, failed $FAILN (of ${#FILES[@]})."; else say OK "Signed $OKN, skipped $SKN, failed $FAILN (of ${#FILES[@]})."; fi
[ $CI = 1 ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '### Sign-Code\nSigned **%d**, skipped %d, failed **%d**. Timestamp %s\n' $OKN $SKN $FAILN "$TSURL" >> "$GITHUB_STEP_SUMMARY"
[ $CI = 1 ] && [ "$ENVKIND" = azure ] && echo "##vso[task.setvariable variable=SignCode.Signed]$OKN"
if [ $FAILN -gt 0 ]; then exit 6; fi
if [ $STRICT = 1 ] && [ $SKN -gt 0 ]; then say ERROR '--strict: some files were skipped.'; exit 6; fi
exit 0
