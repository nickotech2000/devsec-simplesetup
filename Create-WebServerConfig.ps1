# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Writes a secure (HTTPS only) nginx and/or Apache configuration for a leaf certificate of this PKI: TLS 1.3 by default, QUIC (HTTP/3),
    Brotli and gzip, TCP / UDP stream, ECH, a Kestrel reverse proxy. Full help: .\Create-WebServerConfig.ps1 -Help
    Manual: docs\Create-WebServerConfig-MANUAL.txt
.EXAMPLE
    .\Create-WebServerConfig.ps1 -Certificate .\leafcerts\www.example.com\www.example.com-ov-q1-rsa2048-fullchain.crt
.EXAMPLE
    .\Create-WebServerConfig.ps1 -Certificate .\site-fullchain.crt -Server nginx -Tls12 -Output Screen
#>
param(
    [string]$Certificate,
    [string]$Key,
    [ValidateSet('nginx', 'apache', 'both')][string]$Server = 'both',
    [ValidateSet('Auto', 'Ubuntu', 'RHEL')][string]$Distro = 'Auto',
    [string[]]$ServerName,
    [string]$Upstream = 'http://127.0.0.1:5000',
    [ValidateRange(1, 65535)][int]$Port = 443,
    [switch]$Tls12,
    [switch]$NoQuic,
    [ValidateSet('Brotli', 'Gzip', 'None')][string[]]$Compression = @('Brotli', 'Gzip'),
    [string[]]$TcpStream,
    [string[]]$UdpStream,
    [switch]$Ech,
    [string]$EchPublicName,
    [switch]$Fips,
    [string[]]$TlsCiphers,
    [string[]]$Tls12Ciphers,
    [string]$Groups,
    [string]$SignatureAlgorithms,
    [switch]$NoHsts,
    [int]$HstsMaxAge = 0,
    [string]$TlsDir,
    [string]$Resolver = '1.1.1.1 9.9.9.9 valid=300s',
    [string]$NginxVersion = '1.30',
    [ValidateSet('File', 'Screen', 'Both')][string]$Output = 'File',
    [string]$OutFolder,
    [switch]$Wizard,
    [string]$OpenSslPath,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
$script:ToolVersion = '6.4.7'
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Show-WebServerConfigHelp {
    @'
====================================================================================================
 Create-WebServerConfig.ps1 - nginx and Apache configuration for a leaf certificate (HTTPS only)
 Version 6.4.7
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
====================================================================================================
 Manual : docs\Create-WebServerConfig-MANUAL.txt     Shell version: Create-WebServerConfig.sh
 Needs  : PowerShell 7+ and OpenSSL (4.x best). Runs on Windows, Linux and macOS: you can make the
          files on your PC and copy them to the server. It does not need the PKI folder.

WHAT IT DOES (in plain words)
  You give it a certificate (made by GenerateLeafCertificate.ps1, or any other). It reads the
  certificate and writes a configuration for nginx and for Apache that:
    - listens on HTTPS only (there is NO port 80 server in it),
    - answers for the names inside the certificate (server_name / ServerName),
    - passes the traffic to your application behind it; by default a Kestrel (ASP.NET Core) app
      on http://127.0.0.1:5000 (change it with -Upstream),
    - uses TLS 1.3 only (add TLS 1.2 with -Tls12; TLS 1.1 and older are always refused),
    - picks ciphers and key-exchange groups that fit the certificate (RSA, ECDSA or ML-DSA,
      FIPS or not, DV / OV / EV), unless you set them yourself,
    - uses QUIC / HTTP/3 (nginx), Brotli and gzip.
  You can print the configuration on the screen and copy it, or write it to a folder.

WHICH LINUX (-Distro)
  -Distro Ubuntu    Ubuntu 24.04+ / Debian style: nginx user www-data, Apache = apache2
                    (/etc/apache2/sites-available, a2ensite, a2enmod), tools: ufw.
  -Distro RHEL      CentOS Stream 10, RHEL 10, Rocky Linux 10, Oracle Linux 10: nginx user nginx,
                    Apache = httpd (/etc/httpd/conf.d), certificates in /etc/pki/tls, SELinux and
                    firewalld commands in the README.
  -Distro Auto      (default) read /etc/os-release on Linux; on Windows / macOS: Ubuntu.
  The generated folder always has a README.txt with the exact commands for that Linux.

WHAT YOU GIVE
  -Certificate <file>   The certificate (PEM). A -fullchain.crt (leaf + intermediates) is best.
                        Not given: you are asked, step by step (the same as -Wizard).
  -Key <file>           Optional. If given it is checked that the key belongs to the certificate.
                        The key is NEVER copied. The config points to the path on the server.
  -ServerName <list>    Names for the server. Default: the DNS names (SAN) of the certificate.
  -Upstream <url>       Where your application listens. Default http://127.0.0.1:5000 (Kestrel).
                        https://... is allowed (then the proxy talks TLS to the application).
  -Port <n>             The HTTPS port. Default 443.
  -Wizard               Ask every question one by one (Enter keeps the default in [brackets]).

WHAT IT DOES FOR TLS
  -Tls12                Also allow TLS 1.2 (default is TLS 1.3 only). QUIC stays TLS 1.3.
  -Fips                 Use only FIPS-approved ciphers and groups (no ChaCha20, no X25519).
                        Switched on by itself when leaf-info.json next to the certificate says FIPS.
  -TlsCiphers <list>    TLS 1.3 cipher suites     (default by certificate, see the manual)
  -Tls12Ciphers <list>  TLS 1.2 cipher suites     (only used with -Tls12)
  -Groups <text>        Key-exchange groups, colon separated (default by certificate)
  -SignatureAlgorithms <text>   (default: set for ML-DSA only)
  -NoHsts / -HstsMaxAge <seconds>   HSTS header (default on; EV / OV 2 years, DV 1 year)
  Defaults by certificate:
    Classic RSA / ECDSA   groups X25519:secp384r1:secp256r1       (FIPS: secp384r1:secp256r1)
    Quantum (ML-DSA)      groups X25519MLKEM768:SecP384r1MLKEM1024:secp384r1 (FIPS:
                          SecP384r1MLKEM1024: SecP256r1MLKEM768:secp384r1) and signature algorithms
                          mldsa87:mldsa65
    TLS 1.3 suites        TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
                          (FIPS: the two AES-GCM suites only)

WEB FEATURES
  -NoQuic               No QUIC / HTTP/3 listener (nginx).  Apache has no QUIC: nothing is written.
  -Compression <list>   Brotli, Gzip (default both) or None. nginx needs the ngx_brotli module for
                        Brotli: the README says how to get it; without it use -Compression Gzip.
  -TcpStream <list>     TLS-terminated TCP stream (nginx only):  "8443=127.0.0.1:9000"
                        = listen on 8443 with TLS, send plain TCP to 127.0.0.1:9000. Several
                        allowed.
  -UdpStream <list>     UDP stream (nginx only):  "5353=127.0.0.1:5300"  = relay UDP 5353 to 5300.
                        UDP is relayed as it is (nginx does not terminate DTLS).
  -Ech                  Encrypted Client Hello. Makes an ECH key with OpenSSL 4 (openssl ech) and a
                        separate include file. -EchPublicName <name> = the outer name (default: the
                        parent domain of the first server name). Needs an nginx build with ECH.
                        Apache has no ECH: nothing is written.

OUTPUT
  -Output File|Screen|Both   File (default) writes the folder; Screen prints every
                             file on the screen
                             between "===== FILE: name =====" lines so you can copy and paste.
  -OutFolder <path>          Where the folder goes. Default: <script folder>\transport.
  The folder name tells what is inside, for example
      webconfig_www-example-com_ubuntu_nginx-apache_tls13_quic_20261017-113000
  -NginxVersion <x.y>        Lowest nginx version you run. Only 1.30 and newer are supported.
  -Resolver <text>           DNS resolver for OCSP stapling (nginx).  -OpenSslPath <file>   -Help

EXAMPLES
  .\Create-WebServerConfig.ps1 -Certificate .\www-fullchain.crt
  .\Create-WebServerConfig.ps1 -Certificate .\www-fullchain.crt -Server nginx -Distro RHEL -Tls12
  .\Create-WebServerConfig.ps1 -Certificate .\www-fullchain.crt -Output Screen -Server nginx
  .\Create-WebServerConfig.ps1 -Certificate .\api-fullchain.crt -Upstream http://127.0.0.1:5010 `
        -TcpStream "8883=127.0.0.1:1883" -UdpStream "5353=127.0.0.1:5300" -Ech
  .\Create-WebServerConfig.ps1 -Wizard
EXIT CODES   0 ok   1 error (the message says why)   2 the certificate does not fit
====================================================================================================
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

if ($Help) { Invoke-PagedHelp { Show-WebServerConfigHelp }; exit 0 }

function Write-Say {
    param([string]$Level, [string]$Text)
    $c = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { $null } }
    if ($c) { Write-Host "[$Level] $Text" -ForegroundColor $c } else { Write-Host "[$Level] $Text" }
}

# ---------------------------------------------------------------- OpenSSL
function Find-OpenSslExe {
    param([string]$Explicit)
    $cands = [System.Collections.Generic.List[string]]::new()
    if ($Explicit) { [void]$cands.Add($Explicit) }
    foreach ($p in @('/opt/openssl4/bin/openssl', '/opt/openssl/bin/openssl', "$env:ProgramFiles\FireDaemon OpenSSL 4\bin\openssl.exe", "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe")) { if ($p -and (Test-Path -LiteralPath $p)) { [void]$cands.Add($p) } }
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue; if ($cmd) { [void]$cands.Add($cmd.Source) }
    foreach ($x in $cands) { try { $v = (& $x version 2>$null); if ($v -match 'OpenSSL\s+(\d+)\.') { return @{ Exe = $x; Major = [int]$Matches[1]; Text = $v.Trim() } } } catch { } }
    throw 'OpenSSL was not found. Install OpenSSL 4 (run Prepare-Computer.ps1) or give -OpenSslPath.'
}
function Invoke-Ossl { param([string[]]$Arguments, [switch]$AllowFailure)
    $out = & $script:Ossl.Exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) { throw "openssl $($Arguments -join ' ') failed: $($out -join ' ')" }
    return ($out | ForEach-Object { "$_" }) -join "`n"
}

# ---------------------------------------------------------------- certificate facts
function Read-LeafCertificate {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Certificate file not found: $Path" }
    $text = [System.IO.File]::ReadAllText($Path)
    $blocks = @([regex]::Matches($text, '-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----') | ForEach-Object { $_.Value })
    if ($blocks.Count -eq 0) {
        # DER
        $bytes = [System.IO.File]::ReadAllBytes($Path); $b64 = [Convert]::ToBase64String($bytes)
        $blocks = @("-----BEGIN CERTIFICATE-----`n" + (($b64 -split '(.{1,64})' | Where-Object { $_ }) -join "`n") + "`n-----END CERTIFICATE-----")
    }
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('wsc-' + [Guid]::NewGuid().ToString('N') + '.pem')
    try {
        [System.IO.File]::WriteAllText($tmp, $blocks[0] + "`n")
        $t = Invoke-Ossl -Arguments @('x509', '-in', $tmp, '-noout', '-text', '-nameopt', 'RFC2253')
        $pub = Invoke-Ossl -Arguments @('x509', '-in', $tmp, '-noout', '-pubkey')
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $g = { param($rx) $m = [regex]::Match($t, $rx); if ($m.Success) { $m.Groups[1].Value.Trim() } else { '' } }
    $subject = & $g '(?m)^\s*Subject:\s*(.*)$'
    $cn = ''; $m = [regex]::Match($subject, '(?:^|,)CN=((?:\\,|[^,])+)'); if ($m.Success) { $cn = $m.Groups[1].Value -replace '\\,', ',' }
    $san = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($t, 'DNS:([^,\s]+)')) { if (-not $san.Contains($m.Groups[1].Value)) { [void]$san.Add($m.Groups[1].Value) } }
    $alg = & $g '(?m)Public Key Algorithm:\s*(.*)$'; $bits = & $g '(?m)Public-Key:\s*\((\d+) bit\)'; $curve = & $g '(?m)ASN1 OID:\s*(\S+)'
    $fam = if ($alg -match 'ML-DSA|mldsa') { 'mldsa' } elseif ($alg -match 'rsa') { 'rsa' } else { 'ecdsa' }
    $label = switch ($fam) { 'rsa' { "RSA-$bits" } 'mldsa' { ($alg.ToUpperInvariant()) } default { "ECDSA-$curve" } }
    $level = if ($t -match '2\.23\.140\.1\.1\b') { 'EV' } elseif ($t -match '2\.23\.140\.1\.2\.2') { 'OV' } elseif ($t -match '2\.23\.140\.1\.2\.1') { 'DV' } else { 'OV' }
    return [pscustomobject]@{
        Pem = $blocks; Subject = $subject; Cn = $cn; Dns = @($san); Family = $fam; KeyLabel = $label; Level = $level
        Ocsp = ($t -match 'OCSP - URI:'); Self = ($t -match 'Issuer:\s*(.*)$' -and $false); Pubkey = ($pub -replace '\s', ''); ChainCount = $blocks.Count
        EkuServer = ($t -match 'TLS Web Server Authentication'); Text = $t
    }
}

function Get-LeafInfoJson {
    param([string]$CertPath)
    $dir = Split-Path -Parent (Resolve-Path -LiteralPath $CertPath)
    $j = Join-Path $dir 'leaf-info.json'
    if (Test-Path -LiteralPath $j) { try { return (Get-Content -LiteralPath $j -Raw | ConvertFrom-Json) } catch { } }
    return $null
}

# ---------------------------------------------------------------- the TLS profile (what fits this certificate)
function Get-TlsProfile {
    param($Cert, $Info, [bool]$Fips, [bool]$Tls12On)
    $quantum = ($Cert.Family -eq 'mldsa')
    $suites13 = if ($Fips) { 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256' } else { 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256' }
    $suites12 = switch ($Cert.Family) {
        'rsa'   { if ($Fips) { 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256' } else { 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256' } }
        'ecdsa' { if ($Fips) { 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256' } else { 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256' } }
        default { '' }      # an ML-DSA certificate exists in TLS 1.3 only
    }
    $groups = if ($quantum) { if ($Fips) { 'SecP384r1MLKEM1024:SecP256r1MLKEM768:secp384r1' } else { 'X25519MLKEM768:SecP384r1MLKEM1024:secp384r1' } }
              else { if ($Fips) { 'secp384r1:secp256r1' } else { 'X25519:secp384r1:secp256r1' } }
    $sig = if ($quantum) { 'mldsa87:mldsa65' } else { '' }
    $hstsAge = switch ($Cert.Level) { 'DV' { 31536000 } default { 63072000 } }
    $hstsSub = ($Cert.Level -ne 'DV')
    return [pscustomobject]@{ Quantum = $quantum; Suites13 = $suites13; Suites12 = $suites12; Groups = $groups; SigAlgs = $sig; HstsAge = $hstsAge; HstsSub = $hstsSub; Tls12 = ($Tls12On -and -not $quantum) }
}

# ---------------------------------------------------------------- distro conventions
function Get-DistroInfo {
    param([string]$Name)
    if ($Name -eq 'Auto') {
        $Name = 'Ubuntu'
        if ($IsLinux -and (Test-Path /etc/os-release)) {
            $id = (Select-String -Path /etc/os-release -Pattern '^(ID|ID_LIKE)=' | ForEach-Object { $_.Line }) -join ' '
            if ($id -match 'rhel|centos|rocky|ol|fedora|almalinux') { $Name = 'RHEL' }
        }
    }
    if ($Name -eq 'RHEL') {
        return [pscustomobject]@{
            Name = 'RHEL'; Label = 'RHEL style (CentOS Stream 10, RHEL 10, Rocky 10, Oracle Linux 10)'; NginxUser = 'nginx'; NginxDir = '/etc/nginx'
            TlsDir = '/etc/pki/tls'; CertDir = '/etc/pki/tls/certs'; KeyDir = '/etc/pki/tls/private'; ApacheName = 'httpd'; ApacheConf = '/etc/httpd/conf.d'
            ApacheLog = '/var/log/httpd'; Service = 'httpd'
        }
    }
    return [pscustomobject]@{
        Name = 'Ubuntu'; Label = 'Ubuntu / Debian style (Ubuntu 24.04+)'; NginxUser = 'www-data'; NginxDir = '/etc/nginx'
        TlsDir = '/etc/ssl'; CertDir = '/etc/ssl/certs'; KeyDir = '/etc/ssl/private'; ApacheName = 'apache2'; ApacheConf = '/etc/apache2/sites-available'
        ApacheLog = '/var/log/apache2'; Service = 'apache2'
    }
}

function ConvertTo-FileSafe { param([string]$Text, [int]$Max = 40) $t = ($Text -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant(); if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max).Trim('-') }; if (-not $t) { $t = 'site' }; return $t }

function Read-Answer {
    param([string]$Question, [string]$Default = '')
    $d = if ($Default) { " [$Default]" } else { '' }
    $a = Read-Host "$Question$d"
    if ([string]::IsNullOrWhiteSpace($a)) { return $Default }
    return $a.Trim()
}
function Read-YesNo { param([string]$Question, [bool]$Default) $d = if ($Default) { 'Y/n' } else { 'y/N' }; $a = Read-Host "$Question [$d]"; if ([string]::IsNullOrWhiteSpace($a)) { return $Default }; return ($a.Trim() -match '^(?i)y') }

# ---------------------------------------------------------------- nginx
function New-NginxFiles {
    param($P)   # the plan
    $f = [ordered]@{}
    $d = $P.Distro
    $hdr = "# Made by Create-WebServerConfig.ps1 $script:ToolVersion for $($P.Names -join ', ') - $($P.Certificate.KeyLabel), $($P.Certificate.Level), $($P.ProfileText)`n# nginx $($P.NginxMin) or newer. HTTPS only: there is no listener on port 80.`n"
    # ---- main file
    $mods = ''
    if ($P.Brotli) { $mods = "# Brotli is not inside nginx: it needs the ngx_brotli module (see README.txt). Remove these two lines and use -Compression Gzip if you do not have it.`nload_module modules/ngx_http_brotli_filter_module.so;`nload_module modules/ngx_http_brotli_static_module.so;`n" }
    $f['nginx.conf'] = @"
$hdr
user $($d.NginxUser);
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
${mods}
events { worker_connections 4096; }

http {
    include       $($d.NginxDir)/mime.types;
    default_type  application/octet-stream;
    server_tokens off;
    sendfile      on;
    keepalive_timeout 65;
    log_format main '`$remote_addr - `$remote_user [`$time_local] "`$request" `$status `$body_bytes_sent "`$http_referer" "`$http_user_agent" `$ssl_protocol `$ssl_cipher';
    access_log /var/log/nginx/access.log main;

    # a WebSocket / SignalR connection (Kestrel) asks for an upgrade
    map `$http_upgrade `$connection_upgrade { default upgrade; '' close; }

    include $($d.NginxDir)/conf.d/*.conf;
}
$(if ($P.Stream) { "`n# TCP / UDP streams (not HTTP)`nstream {`n    include $($d.NginxDir)/stream.d/*.conf;`n}" })
"@
    # ---- TLS snippet (valid in http and stream)
    $tls = [System.Text.StringBuilder]::new()
    [void]$tls.AppendLine($hdr.TrimEnd())
    [void]$tls.AppendLine("# TLS settings. Protocols: $(if ($P.Tls12) { 'TLS 1.3 and TLS 1.2' } else { 'TLS 1.3 only' }) (TLS 1.1 and older are refused).")
    [void]$tls.AppendLine("ssl_protocols $(if ($P.Tls12) { 'TLSv1.2 TLSv1.3' } else { 'TLSv1.3' });")
    [void]$tls.AppendLine("ssl_conf_command Ciphersuites $($P.Suites13);")
    if ($P.Tls12) { [void]$tls.AppendLine("ssl_ciphers $($P.Suites12);"); [void]$tls.AppendLine('ssl_prefer_server_ciphers off;') }
    [void]$tls.AppendLine("ssl_ecdh_curve $($P.Groups);")
    if ($P.SigAlgs) { [void]$tls.AppendLine("ssl_conf_command SignatureAlgorithms $($P.SigAlgs);") }
    [void]$tls.AppendLine('ssl_session_cache shared:SSL:10m;')
    [void]$tls.AppendLine('ssl_session_timeout 1d;')
    [void]$tls.AppendLine('ssl_session_tickets off;')
    $f['snippets/tls.conf'] = $tls.ToString()
    # ---- compression
    $cmp = [System.Text.StringBuilder]::new(); [void]$cmp.AppendLine($hdr.TrimEnd())
    $types = 'text/plain text/css text/xml text/javascript application/javascript application/json application/xml application/wasm image/svg+xml font/ttf font/otf'
    if ($P.Brotli) { [void]$cmp.AppendLine("brotli on;`nbrotli_comp_level 5;`nbrotli_types $types;") }
    if ($P.Gzip) { [void]$cmp.AppendLine("gzip on;`ngzip_comp_level 5;`ngzip_min_length 256;`ngzip_proxied any;`ngzip_vary on;`ngzip_types $types;") }
    if (-not $P.Brotli -and -not $P.Gzip) { [void]$cmp.AppendLine('# compression is off (-Compression None)') }
    $f['snippets/compression.conf'] = $cmp.ToString()
    # ---- reverse proxy to Kestrel
    $px = @"
$hdr
# Reverse proxy to the application (Kestrel). In ASP.NET Core call app.UseForwardedHeaders() to trust these headers.
proxy_http_version 1.1;
proxy_set_header Host              `$host;
proxy_set_header X-Real-IP         `$remote_addr;
proxy_set_header X-Forwarded-For   `$proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto `$scheme;
proxy_set_header X-Forwarded-Host  `$host;
proxy_set_header Upgrade           `$http_upgrade;
proxy_set_header Connection        `$connection_upgrade;
proxy_read_timeout 100s;
proxy_send_timeout 100s;
$(if ($P.UpstreamTls) { "proxy_ssl_server_name on;`n# proxy_ssl_trusted_certificate $($P.TlsDirServer)/ca.crt;`n# proxy_ssl_verify on;" })
"@
    $f['snippets/proxy-kestrel.conf'] = $px
    # ---- the server
    $up = $P.UpstreamHostPort
    $listen = [System.Text.StringBuilder]::new()
    [void]$listen.AppendLine("    listen $($P.Port) ssl;")
    [void]$listen.AppendLine("    listen [::]:$($P.Port) ssl;")
    if ($P.Quic) {
        [void]$listen.AppendLine("    listen $($P.Port) quic reuseport;          # QUIC / HTTP/3 (UDP). 'reuseport' only once per address:port in the whole nginx")
        [void]$listen.AppendLine("    listen [::]:$($P.Port) quic reuseport;")
    }
    $hsts = ''
    if ($P.Hsts) { $hsts = "    add_header Strict-Transport-Security `"max-age=$($P.HstsAge)$(if ($P.HstsSub) { '; includeSubDomains' })`" always;`n" }
    $stap = ''
    if ($P.Certificate.Ocsp) {
        $stap = "`n    # OCSP stapling (the certificate has an OCSP address)`n    ssl_stapling on;`n    ssl_stapling_verify on;`n    ssl_trusted_certificate $($P.TlsDirServer)/$($P.Base)-chain.crt;`n    resolver $($P.Resolver);`n"
    }
    $quicLines = ''
    if ($P.Quic) { $quicLines = "    http3 on;`n    quic_retry on;`n    add_header Alt-Svc 'h3=`":$($P.Port)`"; ma=86400' always;`n" }
    $ech = ''
    if ($P.Ech) { $ech = "    include $($P.Distro.NginxDir)/snippets/ech.conf;       # Encrypted Client Hello (needs an nginx build with ECH)`n" }
    $f["conf.d/$($P.Base).conf"] = @"
$hdr
upstream kestrel {
    server $up;
    keepalive 32;
}

server {
$($listen.ToString().TrimEnd())
    http2 on;
$quicLines    server_name $($P.Names -join ' ');

    ssl_certificate     $($P.TlsDirServer)/$($P.Base)-fullchain.crt;
    ssl_certificate_key $($P.TlsDirServer)/$($P.Base).key;
    include $($d.NginxDir)/snippets/tls.conf;
$stap$ech
$hsts    add_header X-Content-Type-Options nosniff always;
    include $($d.NginxDir)/snippets/compression.conf;
    client_max_body_size 50m;

    location / {
        include $($d.NginxDir)/snippets/proxy-kestrel.conf;
        proxy_pass $($P.UpstreamScheme)://kestrel;
    }
}
"@
    # ---- stream
    if ($P.Stream) {
        $sb = [System.Text.StringBuilder]::new(); [void]$sb.AppendLine($hdr.TrimEnd())
        [void]$sb.AppendLine("# Included inside the stream { } block of nginx.conf.")
        foreach ($t in $P.Tcp) {
            [void]$sb.AppendLine("`n# TCP with TLS: clients connect to port $($t.Port) with TLS, the plain TCP goes to $($t.Target)")
            [void]$sb.AppendLine("server {`n    listen $($t.Port) ssl;`n    ssl_certificate     $($P.TlsDirServer)/$($P.Base)-fullchain.crt;`n    ssl_certificate_key $($P.TlsDirServer)/$($P.Base).key;`n    include $($d.NginxDir)/snippets/tls.conf;`n    proxy_pass $($t.Target);`n    proxy_timeout 10m;`n}")
        }
        foreach ($u in $P.Udp) {
            [void]$sb.AppendLine("`n# UDP relay (no DTLS termination): port $($u.Port) -> $($u.Target)")
            [void]$sb.AppendLine("server {`n    listen $($u.Port) udp;`n    proxy_pass $($u.Target);`n    proxy_responses 1;`n    proxy_timeout 20s;`n}")
        }
        $f["stream.d/$($P.Base)-stream.conf"] = $sb.ToString()
    }
    if ($P.Ech) {
        $f['snippets/ech.conf'] = @"
$hdr
# Encrypted Client Hello. The directive names depend on the nginx build that has ECH (OpenSSL 4 with ECH): check
#   nginx -V   and the documentation of your build. If nginx says 'unknown directive', remove the include line in the server file.
# The key file was made with:  openssl ech -public_name $($P.EchName) -out $($P.EchName).pem.ech
ssl_echkeydir $($d.NginxDir)/ech;
"@
    }
    return $f
}

# ---------------------------------------------------------------- Apache
function New-ApacheFiles {
    param($P)
    $f = [ordered]@{}
    $d = $P.Distro
    $hdr = "# Made by Create-WebServerConfig.ps1 $script:ToolVersion for $($P.Names -join ', ') - $($P.Certificate.KeyLabel), $($P.Certificate.Level), $($P.ProfileText)`n# Apache HTTP Server 2.4.58 or newer with OpenSSL 3.x / 4.x. HTTPS only: there is no VirtualHost on port 80.`n"
    $proto = if ($P.Tls12) { '-all +TLSv1.2 +TLSv1.3' } else { '-all +TLSv1.3' }
    $first = $P.Names[0]; $alias = if ($P.Names.Count -gt 1) { "    ServerAlias $(($P.Names | Select-Object -Skip 1) -join ' ')`n" } else { '' }
    $types = 'text/html text/plain text/css text/xml text/javascript application/javascript application/json application/xml application/wasm image/svg+xml'
    $cmp = ''
    if ($P.Brotli) { $cmp += "    <IfModule mod_brotli.c>`n        AddOutputFilterByType BROTLI_COMPRESS $types`n    </IfModule>`n" }
    if ($P.Gzip) { $cmp += "    <IfModule mod_deflate.c>`n        AddOutputFilterByType DEFLATE $types`n    </IfModule>`n" }
    $hsts = if ($P.Hsts) { "    Header always set Strict-Transport-Security `"max-age=$($P.HstsAge)$(if ($P.HstsSub) { '; includeSubDomains' })`"`n" } else { '' }
    $stap = if ($P.Certificate.Ocsp) { "    SSLUseStapling on`n    SSLStaplingReturnResponderErrors off`n" } else { '' }
    $cn = ''
    $cn += "    SSLCipherSuite TLSv1.3 $($P.Suites13)`n"
    if ($P.Tls12) { $cn += "    SSLCipherSuite $($P.Suites12)`n    SSLHonorCipherOrder off`n" }
    $conf = "    SSLOpenSSLConfCmd Curves $($P.Groups)`n"
    if ($P.SigAlgs) { $conf += "    SSLOpenSSLConfCmd SignatureAlgorithms $($P.SigAlgs)`n" }
    $site = @"
$hdr
<VirtualHost *:$($P.Port)>
    ServerName $first
$alias    Protocols h2 http/1.1
    ErrorLog  $($d.ApacheLog)/$($P.Base)-error.log
    CustomLog $($d.ApacheLog)/$($P.Base)-access.log combined

    SSLEngine on
    SSLCertificateFile    $($P.TlsDirServer)/$($P.Base)-fullchain.crt
    SSLCertificateKeyFile $($P.TlsDirServer)/$($P.Base).key
    SSLProtocol $proto
$cn$conf    SSLSessionTickets off
$stap
$hsts    Header always set X-Content-Type-Options nosniff
$cmp
    # reverse proxy to the application (Kestrel)
    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "$($P.Port)"
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule ^/(.*)`$ $(if ($P.UpstreamScheme -eq 'https') { 'wss' } else { 'ws' })://$($P.UpstreamHostPort)/`$1 [P,L]
    ProxyPass        / $($P.UpstreamScheme)://$($P.UpstreamHostPort)/
    ProxyPassReverse / $($P.UpstreamScheme)://$($P.UpstreamHostPort)/
</VirtualHost>
"@
    $globalName = if ($d.Name -eq 'RHEL') { 'conf.d/00-ssl-global.conf' } else { 'conf-available/00-ssl-global.conf' }
    $siteName = if ($d.Name -eq 'RHEL') { "conf.d/$($P.Base).conf" } else { "sites-available/$($P.Base).conf" }
    $f[$globalName] = @"
$hdr
# Global TLS settings (outside any VirtualHost)
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
SSLSessionCache  "shmcb:logs/ssl_scache(512000)"
SSLSessionCacheTimeout 300
# (the Listen 443 line already exists: Ubuntu ports.conf, RHEL ssl.conf)
"@
    $f[$siteName] = $site
    return $f
}

# ---------------------------------------------------------------- README with the exact commands
function New-ReadmeText {
    param($P, [string[]]$Files)
    $d = $P.Distro; $b = $P.Base; $t = $P.TlsDirServer
    $r = [System.Text.StringBuilder]::new()
    [void]$r.AppendLine("Web server configuration for: $($P.Names -join ', ')")
    [void]$r.AppendLine("Made by Create-WebServerConfig.ps1 $script:ToolVersion on $((Get-Date).ToString('yyyy-MM-dd HH:mm')) for $($d.Label)")
    [void]$r.AppendLine("Certificate: $($P.Certificate.KeyLabel), level $($P.Certificate.Level). TLS: $(if ($P.Tls12) { '1.3 and 1.2' } else { '1.3 only' }). Groups: $($P.Groups). QUIC: $(if ($P.Quic) { 'yes (nginx)' } else { 'no' })")
    [void]$r.AppendLine('')
    [void]$r.AppendLine('FILES')
    foreach ($x in $Files) { [void]$r.AppendLine("  $x") }
    [void]$r.AppendLine('')
    [void]$r.AppendLine('1. COPY THE CERTIFICATE AND THE KEY TO THE SERVER  (the key is NOT in this folder; copy it yourself, safely)')
    [void]$r.AppendLine("     sudo mkdir -p $t")
    [void]$r.AppendLine("     sudo cp $b-fullchain.crt $t/$b-fullchain.crt          (the certificate + the intermediate CA)")
    [void]$r.AppendLine("     sudo cp <your key file> $t/$b.key")
    [void]$r.AppendLine("     sudo chown root:root $t/$b.key && sudo chmod 600 $t/$b.key")
    if ($P.Certificate.Ocsp) { [void]$r.AppendLine("     sudo cp $b-chain.crt $t/$b-chain.crt                  (the CA chain, for OCSP stapling)") }
    if ($d.Name -eq 'RHEL') { [void]$r.AppendLine("     sudo restorecon -Rv $t                                  (SELinux: the right label for the files)") }
    [void]$r.AppendLine('')
    if ($P.WantNginx) {
        [void]$r.AppendLine("2. NGINX $($P.NginxMin)+   (folder nginx/)")
        [void]$r.AppendLine("     sudo cp nginx/snippets/* $($d.NginxDir)/snippets/        (make the folder first: sudo mkdir -p $($d.NginxDir)/snippets)")
        [void]$r.AppendLine("     sudo cp nginx/conf.d/$b.conf $($d.NginxDir)/conf.d/")
        if ($P.Stream) { [void]$r.AppendLine("     sudo mkdir -p $($d.NginxDir)/stream.d && sudo cp nginx/stream.d/* $($d.NginxDir)/stream.d/") }
        [void]$r.AppendLine("     nginx.conf is a COMPLETE main file. If your nginx.conf already works, keep it and only add:")
        [void]$r.AppendLine("         the map `$http_upgrade `$connection_upgrade { ... } block in http { }$(if ($P.Stream) { ', and the stream { include ...; } block' })")
        [void]$r.AppendLine("     sudo nginx -t && sudo systemctl reload nginx")
        if ($P.Brotli) { [void]$r.AppendLine("     Brotli: nginx has no Brotli inside. Install the module: $(if ($d.Name -eq 'Ubuntu') { 'sudo apt install libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static' } else { 'build ngx_brotli for your nginx (github.com/google/ngx_brotli) or use a repository that has it' }). No module? Run again with -Compression Gzip.") }
        if ($P.Quic) { [void]$r.AppendLine("     QUIC needs nginx built with QUIC (nginx -V shows --with-http_v3_module) and OpenSSL 3.5+ / 4. UDP port $($P.Port) must be open (step 4).") }
        if ($P.Ech) { [void]$r.AppendLine("     ECH: copy ech/*.pem.ech to $($d.NginxDir)/ech/ (readable by the nginx user only). Publish the ECHConfig (see ech/ech-config.txt) in the HTTPS/SVCB DNS record of $($P.Names[0]).") }
        [void]$r.AppendLine('')
    }
    if ($P.WantApache) {
        [void]$r.AppendLine("3. APACHE ($($d.ApacheName))   (folder apache/)")
        if ($d.Name -eq 'Ubuntu') {
            [void]$r.AppendLine('     sudo a2enmod ssl http2 proxy proxy_http proxy_wstunnel rewrite headers deflate brotli socache_shmcb')
            [void]$r.AppendLine("     sudo cp apache/conf-available/00-ssl-global.conf /etc/apache2/conf-available/ && sudo a2enconf 00-ssl-global")
            [void]$r.AppendLine("     sudo cp apache/sites-available/$b.conf /etc/apache2/sites-available/ && sudo a2ensite $b")
            [void]$r.AppendLine('     sudo apache2ctl configtest && sudo systemctl reload apache2')
        }
        else {
            [void]$r.AppendLine('     sudo dnf install httpd mod_ssl')
            [void]$r.AppendLine("     sudo cp apache/conf.d/00-ssl-global.conf apache/conf.d/$b.conf /etc/httpd/conf.d/")
            [void]$r.AppendLine('     sudo httpd -t && sudo systemctl enable --now httpd')
            [void]$r.AppendLine('     (mod_proxy, mod_proxy_http, mod_proxy_wstunnel, mod_rewrite, mod_headers, mod_deflate, mod_brotli are loaded by /etc/httpd/conf.modules.d)')
        }
        [void]$r.AppendLine('     Apache has no QUIC / HTTP/3, no TCP / UDP stream and no ECH: nothing for them is written.')
        [void]$r.AppendLine('')
    }
    [void]$r.AppendLine('4. FIREWALL AND SELINUX')
    if ($d.Name -eq 'RHEL') {
        [void]$r.AppendLine("     sudo firewall-cmd --permanent --add-port=$($P.Port)/tcp$(if ($P.Quic) { " --add-port=$($P.Port)/udp" })$(foreach ($x in $P.Tcp) { " --add-port=$($x.Port)/tcp" })$(foreach ($x in $P.Udp) { " --add-port=$($x.Port)/udp" })")
        [void]$r.AppendLine('     sudo firewall-cmd --reload')
        [void]$r.AppendLine('     sudo setsebool -P httpd_can_network_connect 1                    (nginx / Apache may connect to Kestrel)')
        if ($P.Stream) { [void]$r.AppendLine('     for the stream ports:  sudo semanage port -a -t http_port_t -p tcp <port>   (and udp)') }
    }
    else {
        [void]$r.AppendLine("     sudo ufw allow $($P.Port)/tcp$(if ($P.Quic) { "`n     sudo ufw allow $($P.Port)/udp" })$(foreach ($x in $P.Tcp) { "`n     sudo ufw allow $($x.Port)/tcp" })$(foreach ($x in $P.Udp) { "`n     sudo ufw allow $($x.Port)/udp" })")
        [void]$r.AppendLine('     (no port 80 is opened: this configuration is HTTPS only)')
    }
    [void]$r.AppendLine('')
    [void]$r.AppendLine('5. TEST')
    [void]$r.AppendLine("     openssl s_client -connect $($P.Names[0]):$($P.Port) -servername $($P.Names[0]) -tls1_3 </dev/null | head -20")
    [void]$r.AppendLine("     curl -v --http2 https://$($P.Names[0])/        $(if ($P.Quic) { 'curl --http3 https://' + $P.Names[0] + '/   (a curl with HTTP/3)' })")
    [void]$r.AppendLine('     Your private CA must be trusted by the client (Install-PkiTrust / Install-PkiCa), or use  curl --cacert ca-bundle.pem')
    [void]$r.AppendLine('')
    [void]$r.AppendLine('NOT TESTED HERE: this folder was made by a script and checked by reading the certificate. Run the test commands above on your server.')
    return $r.ToString()
}

function ConvertTo-StreamEntry {
    param([string[]]$Text, [string]$Kind)
    foreach ($e in @($Text | Where-Object { $_ })) {
        if ($e -notmatch '^\s*(\d{1,5})\s*=\s*(\S+:\d{1,5})\s*$') { throw "-${Kind}Stream '$e' is not in the form  port=host:port  (example 8443=127.0.0.1:9000)." }
        [pscustomobject]@{ Port = [int]$Matches[1]; Target = $Matches[2] }
    }
}

try {
    $script:Ossl = Find-OpenSslExe -Explicit $OpenSslPath
    $bound = $PSBoundParameters
    Write-Host '============================================================'
    Write-Host 'Author : Nicko Satria Utama'
    Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
    Write-Host 'Email  : nicko@nextmantra.com'
    Write-Host '============================================================'
    Write-Host ''
    Write-Say 'INFO' "Create-WebServerConfig.ps1 version $script:ToolVersion   ($($script:Ossl.Text))"

    # ---- the nginx version gate: 1.30.x, 1.31.x or newer
    if ($NginxVersion -notmatch '^(\d+)\.(\d+)') { throw "-NginxVersion '$NginxVersion' is not a version (example 1.30)." }
    if (([int]$Matches[1] * 1000 + [int]$Matches[2]) -lt 1030) { throw "nginx $NginxVersion is not supported. This script writes configuration for nginx 1.30.x, 1.31.x and newer only (older versions have no 'http2 on', no stable QUIC). Update nginx." }
    $ng = Get-Command nginx -ErrorAction SilentlyContinue
    if ($ng) { try { $nv = (& $ng.Source -v 2>&1) -join ' '; if ($nv -match 'nginx/(\d+)\.(\d+)') { if (([int]$Matches[1] * 1000 + [int]$Matches[2]) -lt 1030) { Write-Say 'WARN' "nginx on THIS computer is $($nv.Trim()): too old for these files (1.30+ is needed on the server)." } } } catch { } }

    # ---- the questions, step by step
    $interactive = (-not [Console]::IsInputRedirected)
    if (-not $Certificate -and -not $interactive) { throw '-Certificate <file> is required (or run it in a console without redirected input and it will ask).' }
    if ($Wizard -or (-not $Certificate)) {
        if (-not $interactive) { throw 'The wizard needs a console. Give the parameters instead (see -Help).' }
        Write-Host 'Step by step. Press Enter to keep the value in [brackets].' -ForegroundColor Cyan
        if (-not $bound.ContainsKey('Certificate')) { $Certificate = Read-Answer '1. Certificate file (PEM, a -fullchain.crt is best)' }
        if (-not $bound.ContainsKey('Key')) { $Key = Read-Answer '2. Private key file (optional, only to check it belongs to the certificate)' }
        if (-not $bound.ContainsKey('Server')) { $Server = Read-Answer '3. Web server: nginx, apache or both' 'both' }
        if (-not $bound.ContainsKey('Distro')) { $Distro = Read-Answer '4. Linux of the server: Ubuntu or RHEL (CentOS Stream / Rocky / Oracle / RHEL)' 'Ubuntu' }
        if (-not $bound.ContainsKey('Upstream')) { $Upstream = Read-Answer '5. Where your application (Kestrel) listens' $Upstream }
        if (-not $bound.ContainsKey('Tls12')) { $Tls12 = [switch](Read-YesNo '6. Also allow TLS 1.2 (default: TLS 1.3 only)' $false) }
        if (-not $bound.ContainsKey('NoQuic')) { $NoQuic = [switch](-not (Read-YesNo '7. QUIC / HTTP/3 (nginx)' $true)) }
        if (-not $bound.ContainsKey('Compression')) { $cc = Read-Answer '8. Compression: Brotli,Gzip / Gzip / None' 'Brotli,Gzip'; $Compression = @($cc -split '[,; ]+' | Where-Object { $_ }) }
        if (-not $bound.ContainsKey('TcpStream')) { $x = Read-Answer '9. TCP stream with TLS, port=host:port (empty = none; several separated by comma)'; if ($x) { $TcpStream = @($x -split '[,; ]+' | Where-Object { $_ }) } }
        if (-not $bound.ContainsKey('UdpStream')) { $x = Read-Answer '10. UDP stream, port=host:port (empty = none)'; if ($x) { $UdpStream = @($x -split '[,; ]+' | Where-Object { $_ }) } }
        if (-not $bound.ContainsKey('Ech')) { $Ech = [switch](Read-YesNo '11. Encrypted Client Hello (ECH)' $false) }
        if (-not $bound.ContainsKey('Output')) { $Output = Read-Answer '12. Output: File, Screen or Both' 'Both' }
    }
    if (-not $Certificate) { throw '-Certificate <file> is required.' }
    if ($Server -notin 'nginx', 'apache', 'both') { throw "Web server '$Server' is not nginx, apache or both." }
    if ($Output -notin 'File', 'Screen', 'Both') { throw "Output '$Output' is not File, Screen or Both." }
    $dist = Get-DistroInfo -Name $(if ($Distro -in 'RHEL', 'Ubuntu') { $Distro } else { 'Auto' })

    # ---- the certificate
    $cert = Read-LeafCertificate -Path $Certificate
    $info = Get-LeafInfoJson -CertPath $Certificate
    if (-not $cert.EkuServer) { Write-Say 'WARN' 'The certificate has no "TLS Web Server Authentication" purpose: browsers will refuse it for a web site.' }
    if ($Key) {
        if (-not (Test-Path -LiteralPath $Key -PathType Leaf)) { throw "Key file not found: $Key" }
        $kp = (Invoke-Ossl -Arguments @('pkey', '-in', $Key, '-pubout', '-passin', 'pass:') -AllowFailure)
        if ($kp -notmatch 'BEGIN PUBLIC KEY') { throw 'The key could not be read (is it encrypted? remove the password first, or leave out -Key).' }
        if (($kp -replace '\s', '') -cne $cert.Pubkey) { throw "The key $Key does NOT belong to the certificate $Certificate. Nothing was written." }
        Write-Say 'OK' 'The private key belongs to the certificate.'
    }
    $names = @()
    if ($ServerName) { $names = @($ServerName | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    elseif ($cert.Dns.Count -gt 0) { $names = @($cert.Dns) }
    elseif ($cert.Cn -match '^[A-Za-z0-9*.-]+\.[A-Za-z]{2,}$') { $names = @($cert.Cn); Write-Say 'WARN' 'The certificate has no DNS names (SAN): the common name is used. Browsers need a SAN.' }
    if ($names.Count -eq 0) { throw 'No server name: the certificate has no DNS name. Give -ServerName.' }
    $fipsOn = [bool]$Fips
    if (-not $fipsOn -and $info -and $info.PSObject.Properties.Name -contains 'fips' -and [bool]$info.fips) { $fipsOn = $true; Write-Say 'INFO' 'leaf-info.json says this is a FIPS certificate: FIPS-approved ciphers and groups only.' }
    $quantum = ($cert.Family -eq 'mldsa')
    if ($quantum -and $Tls12) { Write-Say 'WARN' 'An ML-DSA (quantum) certificate works in TLS 1.3 only: -Tls12 is ignored.' }
    if ($quantum -and $Server -ne 'nginx') { Write-Say 'WARN' 'ML-DSA certificates need OpenSSL 3.5+ / 4 in Apache too (mod_ssl built with it).' }
    $tp = Get-TlsProfile -Cert $cert -Info $info -Fips $fipsOn -Tls12On ([bool]$Tls12)
    $base = ConvertTo-FileSafe $names[0]
    $up = $Upstream
    if ($up -notmatch '^(?<s>https?)://(?<h>[^/:]+)(:(?<p>\d+))?') { throw "-Upstream '$Upstream' is not http://host:port or https://host:port." }
    $upScheme = $Matches['s']; $upHost = $Matches['h']; $upPort = if ($Matches['p']) { $Matches['p'] } elseif ($upScheme -eq 'https') { '443' } else { '80' }
    $tcp = @(ConvertTo-StreamEntry -Text $TcpStream -Kind 'Tcp'); $udp = @(ConvertTo-StreamEntry -Text $UdpStream -Kind 'Udp')
    $wantNginx = ($Server -in 'nginx', 'both'); $wantApache = ($Server -in 'apache', 'both')
    if (($tcp.Count + $udp.Count) -gt 0 -and -not $wantNginx) { Write-Say 'WARN' 'TCP / UDP streams are an nginx feature: nothing is written for them (Apache has none).' }
    if ($Ech -and -not $wantNginx) { Write-Say 'WARN' 'ECH is not available in Apache: nothing is written for it.' }
    $echName = ''
    if ($Ech) {
        $echName = if ($EchPublicName) { $EchPublicName } else { $n0 = $names[0] -replace '^\*\.', ''; $labels = $n0 -split '\.'; if ($labels.Count -ge 3) { ($labels | Select-Object -Skip 1) -join '.' } else { $n0 } }
    }
    $comp = @($Compression | ForEach-Object { $_.ToLowerInvariant() })
    $hstsAge = if ($HstsMaxAge -gt 0) { $HstsMaxAge } else { $tp.HstsAge }
    $profText = "$(if ($quantum) { 'Quantum' } else { 'Classic' })$(if ($fipsOn) { ' FIPS' } else { '' })"
    $tlsDirServer = if ($TlsDir) { $TlsDir.TrimEnd('/') } else { "$($dist.TlsDir)/$base" }
    $suites13 = if ($TlsCiphers) { $TlsCiphers -join ':' } else { $tp.Suites13 }
    $suites12 = if ($Tls12Ciphers) { $Tls12Ciphers -join ':' } else { $tp.Suites12 }
    $plan = [pscustomobject]@{
        Names = $names; Certificate = $cert; Distro = $dist; Base = $base; TlsDirServer = $tlsDirServer; Port = $Port
        Tls12 = $tp.Tls12; Suites13 = $suites13; Suites12 = $suites12; Groups = $(if ($Groups) { $Groups } else { $tp.Groups }); SigAlgs = $(if ($SignatureAlgorithms) { $SignatureAlgorithms } else { $tp.SigAlgs })
        Hsts = (-not $NoHsts); HstsAge = $hstsAge; HstsSub = $tp.HstsSub
        Brotli = ($comp -contains 'brotli' -and $comp -notcontains 'none'); Gzip = ($comp -contains 'gzip' -and $comp -notcontains 'none')
        Quic = (-not $NoQuic); Upstream = $Upstream; UpstreamScheme = $upScheme; UpstreamTls = ($upScheme -eq 'https'); UpstreamHostPort = "${upHost}:$upPort"
        Stream = (($tcp.Count + $udp.Count) -gt 0); Tcp = $tcp; Udp = $udp; Ech = [bool]($Ech -and $wantNginx); EchName = $echName
        Resolver = $Resolver; NginxMin = $NginxVersion; WantNginx = $wantNginx; WantApache = $wantApache; ProfileText = $profText
    }
    Write-Say 'INFO' "Certificate : $($cert.KeyLabel), level $($cert.Level), $profText"
    Write-Say 'INFO' "Server names: $($names -join ', ')"
    Write-Say 'INFO' "TLS         : $(if ($plan.Tls12) { '1.3 + 1.2' } else { '1.3 only' }); groups $($plan.Groups)$(if ($plan.SigAlgs) { '; signature algorithms ' + $plan.SigAlgs })"
    Write-Say 'INFO' "Linux style : $($dist.Label)    Upstream: $Upstream"

    # ---- build the files
    $files = [ordered]@{}
    if ($wantNginx) { foreach ($k in (New-NginxFiles -P $plan).GetEnumerator()) { $files["nginx/$($k.Key)"] = $k.Value } }
    if ($wantApache) { foreach ($k in (New-ApacheFiles -P $plan).GetEnumerator()) { $files["apache/$($k.Key)"] = $k.Value } }
    $names0 = @($files.Keys)
    $files['README.txt'] = New-ReadmeText -P $plan -Files $names0

    if ($Output -in 'Screen', 'Both') {
        foreach ($k in $files.GetEnumerator()) { Write-Host ''; Write-Host "===== FILE: $($k.Key) =====" -ForegroundColor Cyan; Write-Host ($k.Value.TrimEnd()) }
        Write-Host ''
    }
    if ($Output -in 'File', 'Both') {
        $root = if ($OutFolder) { $OutFolder } else { Join-Path $script:ScriptRoot 'transport' }
        $srv = if ($wantNginx -and $wantApache) { 'nginx-apache' } elseif ($wantNginx) { 'nginx' } else { 'apache' }
        $tag = (@($base, $dist.Name.ToLowerInvariant(), $srv, $(if ($plan.Tls12) { 'tls12-13' } else { 'tls13' }), $(if ($plan.Quic -and $wantNginx) { 'quic' } else { 'noquic' })) + $(if ($plan.Stream) { 'stream' }) + $(if ($plan.Ech) { 'ech' }) + (Get-Date).ToString('yyyyMMdd-HHmmss')) -join '_'
        $out = Join-Path $root "webconfig_$tag"
        $n = 2; while (Test-Path -LiteralPath $out) { $out = Join-Path $root ("webconfig_$tag-$n"); $n++ }
        foreach ($k in $files.GetEnumerator()) {
            $p = Join-Path $out $k.Key; [void](New-Item -ItemType Directory -Path (Split-Path -Parent $p) -Force)
            [System.IO.File]::WriteAllText($p, (($k.Value -replace "`r", '').TrimEnd() + "`n"), [System.Text.UTF8Encoding]::new($false))
        }
        # the public certificate files (never the key)
        [System.IO.File]::WriteAllText((Join-Path $out "$base-fullchain.crt"), (($cert.Pem -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
        if ($cert.Pem.Count -gt 1) { [System.IO.File]::WriteAllText((Join-Path $out "$base-chain.crt"), ((@($cert.Pem | Select-Object -Skip 1)) -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false)) }
        if ($plan.Ech) {
            $ed = Join-Path $out 'ech'; [void](New-Item -ItemType Directory -Path $ed -Force)
            $ef = Join-Path $ed "$echName.pem.ech"
            if ($script:Ossl.Major -ge 4) {
                $r = Invoke-Ossl -Arguments @('ech', '-public_name', $echName, '-out', $ef) -AllowFailure
                if (Test-Path -LiteralPath $ef) { [System.IO.File]::WriteAllText((Join-Path $ed 'ech-config.txt'), "ECH key for the outer name $echName.`nThe file $echName.pem.ech holds the PRIVATE ECH key and the public ECHConfig. Keep it on the server only.`nThe ECHConfig (base64) goes into the HTTPS DNS record of the site (ech=...).`n", [System.Text.UTF8Encoding]::new($false)); Write-Say 'OK' "ECH key made: ech/$echName.pem.ech" }
                else { Write-Say 'WARN' "openssl ech did not make a key: $r" }
            }
            else { Write-Say 'WARN' 'ECH key files need OpenSSL 4 (openssl ech). The configuration was written; make the key later with: openssl ech -public_name <name> -out <name>.pem.ech' }
        }
        Write-Say 'OK' "Written: $out"
    }
    exit 0
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
