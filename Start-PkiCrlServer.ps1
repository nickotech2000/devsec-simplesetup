# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    A small CRL / CA-issuer web server for THIS machine (Windows development, no Linux needed).
    Word / Excel / Outlook say "Recoverable Signature - the signer's certificate can't be verified" when the revocation
    status of a certificate in the chain is UNKNOWN (no URL in it, or the URL cannot be reached). This script makes the
    URLs of the PKI reachable: it serves pki\pki-<name>-<NN>\publish (you point the PKI host names to 127.0.0.1 in the hosts file).
    Full help: .\Start-PkiCrlServer.ps1 -Help
.EXAMPLE
    .\Start-PkiCrlServer.ps1      (elevated PowerShell) prints the hosts-file lines, then serves; stop with Ctrl+C
#>
param(
    # which company's PKI (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string]$PkiProfile,
    [ValidateRange(1, 99)][int]$Release,
    [ValidateRange(1, 65535)][int]$Port = 80,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Help) {
    @'
============================================================
 Start-PkiCrlServer.ps1 - CRL / CA-issuer server on this machine
Version 5.3.6
 Author : Nicko Satria Utama   Company: Agantra Inovatif OÜ (NextMantra)   Email: nicko@nextmantra.com
============================================================
WHY
  Word / Excel / Outlook (XAdES document signatures) show "Recoverable Signature - the signer's certificate can't be verified,
  please try again later or check your network connection" when the REVOCATION STATUS of the chain is unknown:
     - the CA certificates have no CRL URL at all (the NoCR family: certutil says CRYPT_E_NO_REVOCATION_CHECK), or
     - the URLs are there, but the host names (crl.nextmantra.internal ...) do not resolve on this machine.
  Both end in the same message. The cure is a CRL that can be fetched.

WHAT IT DOES
  Serves every pki\R*\publish folder (CRL and CA certificate files, by file name) over HTTP, for the host names that are
  written in the certificates (read from pki\pki-<name>-<NN>\server\server.env). The host names must point to 127.0.0.1 in the
  hosts file (the script prints the lines), so this machine finds the server. OCSP requests are answered 404: Windows then uses the CRL.
  The script does NOT edit the hosts file itself (antivirus programs flag that, rightly): it prints the lines, you paste them.

STEPS (Windows 11, elevated PowerShell = "Run as administrator")
  1. Use the NORMAL PKI for the signer (its CA certificates carry the CRL URLs). Issue the certificate WITHOUT -NoRevocationInfo:
        .\GenerateOffice365LeafCertificate.ps1 -File persons.json
  2. Add the printed lines to the hosts file (Notepad as Administrator), then  .\Start-PkiCrlServer.ps1   leave the window open (Ctrl+C stops it)
  3. In another window, clear what Windows remembered about the failed downloads and check the chain: the two certutil commands are in
     docs\PKI-SERVER-MANUAL.txt (chapter 7) and docs\GenerateOffice365LeafCertificate-MANUAL.txt. This script prints no download-cache commands.
  4. Open the document in Word again. When you are done: Ctrl+C, and delete the lines from the hosts file.

OPTIONS
  -Release N       serve only this release (default: every release found in pki\)
  -Port N          default 80 (the URLs in the certificates have no port: another port only helps for a test with curl)
  -Help

NOTES
  * Real use: pki\pki-<name>-<NN>\server\ + linux\pki-server\pki-server.sh serve the same files with nginx, and the DNS records of
    server\DNS-RECORDS.txt point to that server. This script is the one-machine shortcut.
  * The CRLs are valid for the days set when the PKI was built (CRL_DAYS in server.env); renew: PkiRevocation.ps1 -Action NewCrl.
  * Windows caches downloads: after a change clear its URL cache (command in docs\PKI-SERVER-MANUAL.txt, chapter 7).

WHICH PKI  (-Pki, 5.0.0)
  -Pki <name>   the company whose PKI is used: the file <name>_pki.cnf next to the scripts. Default: agantra (or DefaultPki of pki_tools.cnf).
                The names: .\pki_setup.ps1 -ListPki  (press Tab after -Pki to see them). Make a new company: .\New-PkiConfig.ps1.
                The PKI folders are .\pki\pki-default-NN (agantra) and .\pki\pki-<name>-NN (NoCR: pki-<name>-nocr-NN).

WHERE IT RUNS  (5.0.0)
  Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022
  (Essentials, Standard, Datacenter; RTM or newer). On Windows Server 2022 only the CLASSIC track is generated or issued (no Quantum / ML-DSA);
  FIPS and non-FIPS, DV / OV / EV are available. REFUSED with an error (exit 5, nothing is done): Windows 10 and earlier, Windows 11 before 24H2,
  Windows Server before 2022, and the Chinese, Government, IoT / IoT Enterprise, SE and Embedded editions. Linux (pwsh): the distributions of the
  .sh scripts. Settings shared by all scripts (optional): pki_tools.cnf.
'@ | Write-Host
    return
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

# ---- the PKI folders: every release of every PKI (or only -Pki <name>), all folder names (pki-default-01, pki-raksaka-nocr-01 ..., old R1) ----
. (Join-Path $PSScriptRoot 'scripts/00b_Profiles.ps1')
if (-not (Get-Command Write-PkiLog -ErrorAction SilentlyContinue)) { function Write-PkiLog { param([string]$Message, [string]$Level = 'INFO') Write-Host "[$Level] $Message" } }
. (Join-Path $PSScriptRoot 'scripts/01c_Releases.ps1')
$container = Get-PkiContainer -ScriptRoot $root
if ($PkiProfile) { try { [void](Resolve-PkiProfile -ScriptRoot $root -Name $PkiProfile) } catch { throw } }
$pkis = @(Get-PkiInstalledPkis -ScriptRoot $root -Profile $PkiProfile | Where-Object { Test-Path -LiteralPath (Join-Path $_.Path 'publish') } |
        ForEach-Object { [pscustomobject]@{ Name = (Split-Path -Leaf $_.Path); Release = [int]$_.Release; Path = $_.Path } })
if ($Release -gt 0) { $pkis = @($pkis | Where-Object { $_.Release -eq $Release }) }

if ($pkis.Count -eq 0) { throw "No PKI with a publish folder in $container. Build one first:  .\pki_setup.ps1 -InstallTrust" }

# ---- host names (from server.env of every PKI) ----
$hostNames = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($p in $pkis) {
    $env1 = Join-Path $p.Path 'server\server.env'
    if (-not (Test-Path -LiteralPath $env1)) { continue }
    foreach ($l in (Get-Content -LiteralPath $env1)) {
        if ($l -match "^PKI_SRV_HOSTS_(CRL|OCSP)='(?<h>[^']*)'") { foreach ($h in ($Matches['h'] -split '\s+' | Where-Object { $_ })) { [void]$hostNames.Add($h) } }
    }
}
if ($hostNames.Count -eq 0) { throw 'No host names found in pki\pki-<name>-<NN>\server\server.env. Run  .\PkiRevocation.ps1 -Action Status  once to write it.' }

Write-Host ("PKIs served : " + (($pkis | ForEach-Object { $_.Name }) -join ', '))
Write-Host ("Host names  : " + ($hostNames -join ', '))

# The hosts file is NOT changed by this script (security software rightly flags scripts that write to it): add the lines yourself.
Write-Host ''
Write-Host 'HOSTS FILE (open Notepad as Administrator, then open the file named hosts in the Windows drivers\etc folder; add these lines, then  ipconfig /flushdns):' -ForegroundColor Cyan
foreach ($h in $hostNames) { Write-Host ("  127.0.0.1        {0}" -f $h) }
Write-Host '  (another machine on the network serves the CRLs? use its IP instead of 127.0.0.1)'
Write-Host ''

# ---- the server ----
$types = @{ '.crl' = 'application/pkix-crl'; '.crt' = 'application/pkix-cert'; '.cer' = 'application/pkix-cert'; '.pem' = 'application/x-pem-file'; '.txt' = 'text/plain' }
$folders = @($pkis | Sort-Object Release -Descending | ForEach-Object { Join-Path $_.Path 'publish' })
$listener = [System.Net.HttpListener]::new()
if ($IsWindows) { foreach ($h in $hostNames) { $listener.Prefixes.Add("http://${h}:$Port/") } }   # off Windows (tests only) the managed listener accepts localhost prefixes only
$listener.Prefixes.Add("http://localhost:$Port/"); $listener.Prefixes.Add("http://127.0.0.1:$Port/")
try { $listener.Start() }
catch {
    throw "Cannot listen on port ${Port}: $($_.Exception.Message.Split("`n")[0])`n  Port 80 needs an elevated PowerShell, and no other web server (IIS, nginx, Skype ...) may use it."
}
Write-Host "[OK] Serving CRL / CA files on port $Port. Ctrl+C stops it." -ForegroundColor Green
Write-Host '     Next: check the chain from another window (commands: docs\PKI-SERVER-MANUAL.txt, chapter 7).'
try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request; $res = $ctx.Response
        try {
            $name = [System.IO.Path]::GetFileName([Uri]::UnescapeDataString($req.Url.AbsolutePath))
            $file = $null
            if ($req.HttpMethod -eq 'GET' -and $name -match '^[A-Za-z0-9._-]+$') {
                foreach ($f in $folders) { $c = Join-Path $f $name; if (Test-Path -LiteralPath $c -PathType Leaf) { $file = $c; break } }
            }
            if ($null -ne $file) {
                $bytes = [System.IO.File]::ReadAllBytes($file)
                $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
                $res.ContentType = if ($types.ContainsKey($ext)) { $types[$ext] } else { 'application/octet-stream' }
                $res.ContentLength64 = $bytes.Length
                $res.OutputStream.Write($bytes, 0, $bytes.Length)
                Write-Host "$((Get-Date).ToString('HH:mm:ss'))  200  $($req.Url.Host)/$name  ($($bytes.Length) bytes)"
            }
            else {
                $res.StatusCode = 404
                Write-Host "$((Get-Date).ToString('HH:mm:ss'))  404  $($req.HttpMethod) $($req.Url.Host)$($req.Url.AbsolutePath)  (OCSP requests land here: Windows uses the CRL)" -ForegroundColor DarkYellow
            }
        }
        catch { Write-Host "[WARN] $($_.Exception.Message.Split("`n")[0])" -ForegroundColor Yellow }
        finally { $res.Close() }
    }
}
finally { $listener.Stop(); $listener.Close() }
