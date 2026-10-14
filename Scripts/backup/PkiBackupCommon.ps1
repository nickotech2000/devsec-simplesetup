# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# PkiBackupCommon.ps1  -  the code shared by Backup-Pki.ps1, Restore-Pki.ps1 and Test-PkiBackup.ps1  (SOURCE of the embedded copy)
#
# NOT a project module and never loaded at run time: Build-BackupScripts.ps1 pastes this file (and the zip engine of 16_CertPack.ps1) into the three scripts,
# so each of them is STANDALONE (no other .ps1 is needed, they travel alone inside a backup zip). Edit here, then run Build-BackupScripts.ps1.
#
# Provides : the platform gate (Windows 11 Home/Pro 24H2+, Windows Server 2025 Essentials/Standard/Datacenter; Intel/AMD 64 bit only;
#            Administrator only), the password policy, hashes, the checks of Prepare-Computer, opening a backup .certpacked.
# Test hooks (never needed on Windows): PKI_FAKE_OS=Kind:Build[:EditionID[:DisplayVersion]]  PKI_FAKE_ARCH=X64|Arm64|X86  PKI_FAKE_ADMIN=1
#            PKI_BACKUP_PASSWORD=<password> (unattended runs and tests: the environment of a process can be read by others, so prefer the prompt)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BkVersion = '5.3.5'
$script:BkFormat = 'agantra-pki-backup'
$script:BkFormatVersion = 1
$script:BkFolderName = 'backup-pki'

# exit codes shared by the three scripts
#   0 ok   1 error   2 not an Administrator window   3 password refused (policy / wrong)   4 Prepare-Computer.ps1 not run (PowerShell 7, OpenSSL, Python)
#   5 this system is not supported (Windows version / edition / ARM)   6 a checksum does not match (the backup is damaged or changed)

function Say {
    param([string]$Level, [string]$Text)
    $c = 'Cyan'; if ($Level -eq 'OK') { $c = 'Green' } elseif ($Level -eq 'WARN') { $c = 'Yellow' } elseif ($Level -eq 'ERROR') { $c = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Text) -ForegroundColor $c
}

function Stop-Bk {
    param([string]$Text, [int]$Code = 1)
    Say 'ERROR' $Text
    exit $Code
}

function Write-BkBanner {
    param([string]$Script, [string]$Title)
    Write-Host '============================================================'
    Write-Host " $Script - $Title"
    Write-Host ' Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com'
    Write-Host '============================================================'
    Say 'INFO' "$Script version $script:BkVersion"
}

# ------------------------------------------------------------
# The computer: Windows, version, edition, CPU, Administrator
# ------------------------------------------------------------
function Get-BkOsInfo {
    # Returns Kind (Client|Server), Build, Product, Edition, Display (24H2 ...), Slug (windows-11-24h2 | windows-server-2025), Text
    $isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $kind = ''; $build = 0; $product = ''; $ed = ''; $disp = ''
    if ($isWin) {
        try {
            $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $build = [int]$cv.CurrentBuildNumber; $product = [string]$cv.ProductName; $kind = [string]$cv.InstallationType; $ed = [string]$cv.EditionID
            if ($cv.PSObject.Properties['DisplayVersion']) { $disp = [string]$cv.DisplayVersion }
            elseif ($cv.PSObject.Properties['ReleaseId']) { $disp = [string]$cv.ReleaseId }
        }
        catch { $build = [Environment]::OSVersion.Version.Build }
    }
    if ($env:PKI_FAKE_OS) {
        $fp = $env:PKI_FAKE_OS.Split(':'); $kind = $fp[0]; $build = [int]$fp[1]; $product = 'test (PKI_FAKE_OS)'
        if ($fp.Count -gt 2 -and $fp[2]) { $ed = $fp[2] } elseif ($kind -like 'Server*') { $ed = 'ServerStandard' } else { $ed = 'Professional' }
        $disp = $(if ($fp.Count -gt 3) { $fp[3] } else { '' })
    }
    $isServer = ($kind -like 'Server*')
    if (-not $disp) { if ($build -ge 26200) { $disp = '25H2' } elseif ($build -ge 26100) { $disp = '24H2' } elseif ($build -gt 0) { $disp = "build$build" } }
    $slug = ''
    if ($isServer) { $slug = $(if ($build -ge 26100) { 'windows-server-2025' } elseif ($build -ge 20348) { 'windows-server-2022' } else { "windows-server-build$build" }) }
    elseif ($build -ge 22000) { $slug = 'windows-11-' + ($disp.ToLowerInvariant() -replace '[^a-z0-9]', '') }
    elseif ($build -gt 0) { $slug = "windows-build$build" }
    else { $slug = 'unknown-os' }
    $text = $(if ($product) { "$product (build $build)" } else { "Windows build $build" })
    if ($ed) { $text = "$text, edition $ed" }
    return [pscustomobject]@{ IsWindows = ($isWin -or [bool]$env:PKI_FAKE_OS); Kind = $kind; IsServer = $isServer; Build = $build; Product = $product; Edition = $ed; Display = $disp; Slug = $slug; Text = $text }
}

function Get-BkCpu {
    # X64 | Arm64 | X86 | Arm ... (the real computer, also when a program is emulated)
    if ($env:PKI_FAKE_ARCH) { return $env:PKI_FAKE_ARCH }
    $a = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    foreach ($v in $env:PROCESSOR_ARCHITEW6432, $env:PROCESSOR_ARCHITECTURE) { if ($v -and $v -match '(?i)ARM') { return 'Arm64' } }
    return $a
}

function Test-BkAdministrator {
    if ($env:PKI_FAKE_OS) { return ($env:PKI_FAKE_ADMIN -eq '1') }
    try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { return $false }
}

function Assert-BkHost {
    # The same gate for Backup-Pki, Restore-Pki and Test-PkiBackup. Order: Windows -> CPU -> Windows version / edition -> Administrator.
    # Returns the OS info.
    $os = Get-BkOsInfo
    if (-not $os.IsWindows) { Stop-Bk 'These scripts run on Windows only (Windows 11 Home / Pro 24H2 or newer, Windows Server 2025 Essentials / Standard / Datacenter). Nothing was done.' 5 }
    $cpu = Get-BkCpu
    if ($cpu -ne 'X64') { Stop-Bk "This computer's processor is: $cpu. Only Intel and AMD 64 bit processors (AMD64 / x86-64) are supported: ARM and 32 bit are NOT. Nothing was done." 5 }
    $name = $os.Text
    $txt = "$($os.Edition) $($os.Product)"
    if ($txt -match '(?i)china|chinese|CountrySpecific') { Stop-Bk "This computer is ${name}: a Chinese edition is NOT supported. Nothing was done." 5 }
    if ($txt -match '(?i)government|EnterpriseG\b|EnterpriseGN|\bGov\b') { Stop-Bk "This computer is ${name}: a Government edition is NOT supported. Nothing was done." 5 }
    if ($txt -match '(?i)IoT|Embedded') { Stop-Bk "This computer is ${name}: IoT and Embedded editions are NOT supported. Nothing was done." 5 }
    if ($os.IsServer) {
        if ($os.Build -lt 26100) { Stop-Bk "This computer is ${name}: only Windows Server 2025 (build 26100 or newer) is supported for backup and restore. Nothing was done." 5 }
        if ($os.Edition -and $os.Edition -notmatch '^Server(Standard|Datacenter|Solution|Essentials)(Core|Eval|ACor)?$') { Stop-Bk "This computer is ${name}: only Windows Server 2025 Essentials, Standard and Datacenter are supported. Nothing was done." 5 }
    }
    else {
        if ($os.Build -lt 22000) { Stop-Bk "This computer is ${name}: Windows 10 and earlier are NOT supported (needs Windows 11 24H2 or newer). Nothing was done." 5 }
        if ($os.Build -lt 26100) { Stop-Bk "This computer is ${name}: Windows 11 before 24H2 is NOT supported (needs 24H2 = build 26100 or newer). Nothing was done." 5 }
        if ($os.Edition -and $os.Edition -notmatch '^(Core|CoreN|CoreSingleLanguage|Professional|ProfessionalN)$') { Stop-Bk "This computer is ${name}: only Windows 11 Home and Pro are supported. Nothing was done." 5 }
    }
    Say 'INFO' "Computer: $name, $cpu (Intel / AMD 64 bit): supported."
    if (-not (Test-BkAdministrator)) { Stop-Bk 'This is not an Administrator window. Close it, right-click PowerShell 7 (pwsh) -> "Run as administrator", and start the script again. Nothing was done.' 2 }
    Say 'INFO' ("PowerShell {0}, Administrator window." -f $PSVersionTable.PSVersion)
    return $os
}

# ------------------------------------------------------------
# Prepare-Computer.ps1 must have been run (PowerShell 7, OpenSSL 4, Python 3 - all on the PATH)
# ------------------------------------------------------------
function Get-BkDotNetSdks {
    # the installed .NET SDK versions (dotnet --list-sdks); empty when dotnet is not on the PATH
    $d = Get-Command 'dotnet' -ErrorAction SilentlyContinue
    $v = [System.Collections.Generic.List[string]]::new()
    if (-not $d) { return @() }
    try { foreach ($l in @(& $d.Source --list-sdks 2>$null)) { if ("$l" -match '^(\d+\.\d+\.\d+[^\s]*)') { [void]$v.Add($Matches[1]) } } } catch { }
    return $v.ToArray()
}

function Get-BkPrerequisites {
    # what Prepare-Computer.ps1 installs: PowerShell 7, OpenSSL 4, Python 3, .NET SDK 8 and .NET SDK 10 - all found on the PATH
    $r = [ordered]@{ PowerShell = ''; OpenSsl = ''; Python = ''; DotNet = ''; Missing = [System.Collections.Generic.List[string]]::new() }
    $r.PowerShell = "PowerShell $($PSVersionTable.PSVersion)"
    if (-not (Get-Command 'pwsh' -ErrorAction SilentlyContinue)) { [void]$r.Missing.Add('PowerShell 7: pwsh is not on the PATH') }
    $o = Get-Command 'openssl' -ErrorAction SilentlyContinue
    if (-not $o) { [void]$r.Missing.Add('OpenSSL: openssl is not on the PATH') }
    else {
        $v = ''; try { $v = (& $o.Source version 2>&1 | Select-Object -First 1).ToString().Trim() } catch { }
        $r.OpenSsl = "$v ($($o.Source))"
        if ($v -notmatch '^OpenSSL (\d+)\.' -or [int]$Matches[1] -lt 4) { [void]$r.Missing.Add("OpenSSL 4 or newer is required, found: $v") }
    }
    $py = $null
    foreach ($n in 'python', 'python3') { foreach ($g in @(Get-Command $n -All -ErrorAction SilentlyContinue)) { if (-not $py -and $g.Source -and $g.Source -notmatch '\\WindowsApps\\') { $py = $g } } }
    if (-not $py) { [void]$r.Missing.Add('Python 3: python is not on the PATH (the Microsoft Store stub does not count)') }
    else {
        $v = ''; try { $v = (& $py.Source --version 2>&1 | Select-Object -First 1).ToString().Trim() } catch { }
        $r.Python = "$v ($($py.Source))"
        if ($v -notmatch '^Python 3\.') { [void]$r.Missing.Add("Python 3 is required, found: $v") }
    }
    $sdks = @(Get-BkDotNetSdks)
    $has8 = @($sdks | Where-Object { $_ -like '8.*' }).Count -gt 0
    $has10 = @($sdks | Where-Object { $_ -like '10.*' }).Count -gt 0
    $r.DotNet = ".NET SDK $((@($sdks | Where-Object { $_ -like '8.*' -or $_ -like '10.*' }) -join ', '))"
    if (-not $has8) { [void]$r.Missing.Add('.NET SDK 8: not found (dotnet --list-sdks)') }
    if (-not $has10) { [void]$r.Missing.Add('.NET SDK 10: not found (dotnet --list-sdks)') }
    return [pscustomobject]$r
}

function Assert-BkPrepared {
    # every requirement checked; ALL that are missing are listed, then: run Prepare-Computer.ps1
    param([string]$PrepareScript = '.\Prepare-Computer.ps1')
    $p = Get-BkPrerequisites
    if ($p.Missing.Count -gt 0) {
        foreach ($m in $p.Missing) { Say 'ERROR' "Missing: $m" }
        Stop-Bk ("This computer is not ready: you need to run  $PrepareScript  first (in an Administrator PowerShell; it installs the latest PowerShell 7, OpenSSL 4, Python 3 and the .NET SDK 8 and 10 and puts them on the PATH). Then open a NEW Administrator window with  pwsh  and start this script again. Nothing was done.") 4
    }
    Say 'OK' "Required software found: $($p.PowerShell); $($p.OpenSsl); $($p.Python); $($p.DotNet)"
}

# ------------------------------------------------------------
# Password
# ------------------------------------------------------------
function Test-BkPassword {
    # The policy of the backup password. Returns the list of problems (empty = fine).
    param([AllowEmptyString()][string]$Password)
    $p = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrEmpty($Password)) { [void]$p.Add('the password is empty: no password, no backup'); return ,@($p) }
    if ($Password -cnotmatch '^[\x20-\x7E]+$') { [void]$p.Add('only printable ASCII characters are allowed (letters, digits, symbols, space): no accents, no emoji') }
    if ($Password.Length -lt 12) { [void]$p.Add("it has $($Password.Length) characters; at least 12 are required") }
    if ($Password -cnotmatch '[A-Z]') { [void]$p.Add('it needs at least 1 upper case letter (A-Z)') }
    if ($Password -cnotmatch '[a-z]') { [void]$p.Add('it needs at least 1 lower case letter (a-z)') }
    if ($Password -cnotmatch '[0-9]') { [void]$p.Add('it needs at least 1 digit (0-9)') }
    if ($Password -cnotmatch '[^A-Za-z0-9]') { [void]$p.Add('it needs at least 1 special character (for example ! # % + - _ = @)') }
    return ,@($p)
}

function ConvertFrom-BkSecure {
    param([Parameter(Mandatory)][securestring]$Secure)
    return [System.Net.NetworkCredential]::new('', $Secure).Password
}

function Read-BkNewPassword {
    # Asks twice, checks the policy, shows every problem, three tries. Exit 3 when it fails.
    if ($env:PKI_BACKUP_PASSWORD) {
        $probs = Test-BkPassword $env:PKI_BACKUP_PASSWORD
        if ($probs.Count -gt 0) { foreach ($x in $probs) { Say 'ERROR' "Password policy: $x" }; Stop-Bk 'The password (from PKI_BACKUP_PASSWORD) is not allowed by the password policy.' 3 }
        return $env:PKI_BACKUP_PASSWORD
    }
    Write-Host ''
    Write-Host 'Password policy: at least 12 characters, with at least 1 upper case letter, 1 lower case letter, 1 digit and 1 special character.'
    Write-Host 'The password is NOT stored anywhere. Without it the backup can never be opened: write it down and keep it in a safe place, apart from the backup.'
    if ([Console]::IsInputRedirected) { Stop-Bk 'The password must be typed by a person at the prompt (or given in PKI_BACKUP_PASSWORD for an unattended run). No password, no backup.' 3 }
    for ($try = 1; $try -le 3; $try++) {
        $a = ConvertFrom-BkSecure (Read-Host -Prompt 'Backup password' -AsSecureString)
        $probs = Test-BkPassword $a
        if ($probs.Count -gt 0) {
            foreach ($x in $probs) { Say 'ERROR' "Password policy: $x" }
            if ($try -lt 3) { Say 'INFO' "Try again ($try of 3)." }
            continue
        }
        $b = ConvertFrom-BkSecure (Read-Host -Prompt 'Backup password (again)' -AsSecureString)
        if ($a -cne $b) { Say 'ERROR' 'The two passwords are different.'; if ($try -lt 3) { Say 'INFO' "Try again ($try of 3)." }; continue }
        return $a
    }
    Stop-Bk 'No valid password after 3 tries. No password, no backup. Nothing was done.' 3
}

function Read-BkExistingPassword {
    # For restore and the deep check: one prompt, no policy (the policy applied when the backup was made).
    param([string]$Prompt = 'Backup password')
    if ($env:PKI_BACKUP_PASSWORD) { return $env:PKI_BACKUP_PASSWORD }
    if ([Console]::IsInputRedirected) { Stop-Bk 'The password must be typed at the prompt (or given in PKI_BACKUP_PASSWORD for an unattended run). No password, no process.' 3 }
    $a = ConvertFrom-BkSecure (Read-Host -Prompt $Prompt -AsSecureString)
    if ([string]::IsNullOrEmpty($a)) { Stop-Bk 'No password was typed. No password, no process.' 3 }
    return $a
}

# ------------------------------------------------------------
# Hashes, names
# ------------------------------------------------------------
function Get-BkHash {
    # SHA-256 and SHA-512 of a file (streamed, hidden files too)
    param([Parameter(Mandatory)][string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $s256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($fs)).ToLowerInvariant()
        [void]$fs.Seek(0, [System.IO.SeekOrigin]::Begin)
        $s512 = [Convert]::ToHexString([System.Security.Cryptography.SHA512]::HashData($fs)).ToLowerInvariant()
    }
    finally { $fs.Dispose() }
    return [pscustomobject]@{ Sha256 = $s256; Sha512 = $s512 }
}

function Get-BkShortId {
    $b = [byte[]]::new(3); [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return [Convert]::ToHexString($b).ToLowerInvariant()
}

function Get-BkComputerName {
    $n = [Environment]::MachineName.ToLowerInvariant() -replace '[^a-z0-9-]', '-'
    $n = $n.Trim('-'); if (-not $n) { $n = 'computer' }
    return $n
}

function Get-BkSumsFile {
    # Parses "<hash>  <name>" lines (comment lines start with #). Returns an ordered map name -> hash.
    param([Parameter(Mandatory)][string]$Path)
    $m = [ordered]@{}
    foreach ($l in [System.IO.File]::ReadAllLines($Path)) {
        if ($l -match '^\s*#' -or [string]::IsNullOrWhiteSpace($l)) { continue }
        if ($l -match '^([0-9a-fA-F]{64}|[0-9a-fA-F]{128})\s+\*?(.+?)\s*$') { $m[$Matches[2]] = $Matches[1].ToLowerInvariant() }
    }
    return $m
}

function Write-BkTextFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function New-BkTempDirectory {
    param([string]$Prefix = 'pkibackup')
    $d = Join-Path ([System.IO.Path]::GetTempPath()) "$Prefix-$([guid]::NewGuid().ToString('N'))"
    [void][System.IO.Directory]::CreateDirectory($d)
    return $d
}

# ------------------------------------------------------------
# Opening a backup .certpacked
# ------------------------------------------------------------
function Open-BkPackage {
    # Decrypts the .certpacked into a temporary folder, reads certpack.json and checks the SHA-256 of EVERY file.
    # Returns Dir (delete it when done), Manifest. A wrong password stops with exit 3.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Password)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Bk "Backup file not found: $Path" 1 }
    $dir = New-BkTempDirectory 'pkibackup-open'
    try {
        try { [void](Expand-PkiArchive -Path $Path -Destination $dir -Password $Password) }
        catch {
            $m = $_.Exception.Message
            if ($m -like 'WRONG_PASSWORD*') { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; Stop-Bk 'The password is wrong (or the .certpacked file is damaged). Nothing was changed.' 3 }
            throw
        }
        $mf = Join-Path $dir 'certpack.json'
        if (-not (Test-Path -LiteralPath $mf)) { throw 'This archive has no certpack.json: it is not a PKI backup.' }
        $man = Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json -AsHashtable
        if ($man['format'] -ne $script:BkFormat) { throw "This .certpacked is not a PKI backup (format '$($man['format'])'). Transport packages are installed with PkiTransport.ps1, not restored." }
        if ([int]$man['formatVersion'] -gt $script:BkFormatVersion) { throw "This backup has format version $($man['formatVersion']); this script understands version $($script:BkFormatVersion). Use a newer Restore-Pki.ps1." }
        $bad = [System.Collections.Generic.List[string]]::new()
        foreach ($f in @($man['files'])) {
            $p = Join-Path $dir (([string]$f['path']) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (-not (Test-Path -LiteralPath $p)) { [void]$bad.Add("$($f['path']) is missing"); continue }
            if ((Get-BkHash -Path $p).Sha256 -ne [string]$f['sha256']) { [void]$bad.Add("$($f['path']) has a different SHA-256") }
        }
        if ($bad.Count -gt 0) { throw ("The backup does not match its own list of files:`n  - " + ($bad -join "`n  - ")) }
        return [pscustomobject]@{ Dir = $dir; Manifest = $man }
    }
    catch { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue; throw }
}

# ------------------------------------------------------------
# Certificates, private keys, the Local Machine certificate store
# ------------------------------------------------------------
function Read-BkCertificateFile {
    # A file with exactly ONE certificate (PEM or DER) -> Thumbprint (SHA-1), Subject, Issuer, IsCa, SelfSigned. Anything else -> $null.
    param([Parameter(Mandatory)][string]$Path)
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if ($fi.Length -gt 40000 -or $fi.Length -lt 100) { return $null }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($text.Contains('-----BEGIN')) {
            if ([regex]::Matches($text, '-----BEGIN CERTIFICATE-----').Count -ne 1) { return $null }
            $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($text)
        }
        else { $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes) }
        $isCa = $false
        foreach ($e in $c.Extensions) { if ($e.Oid.Value -eq '2.5.29.19') { $isCa = ([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$e).CertificateAuthority } }
        $o = [pscustomobject]@{ Thumbprint = $c.Thumbprint.ToUpperInvariant(); Subject = $c.Subject; Issuer = $c.Issuer; IsCa = $isCa; SelfSigned = ($c.Subject -eq $c.Issuer) }
        $c.Dispose()
        return $o
    }
    catch { return $null }
}

function Get-BkPublicKeyText {
    # The public key (PEM, white space removed) of a certificate or of a private key, made by OpenSSL; '' when it cannot be read.
    param([Parameter(Mandatory)][string]$Path, [ValidateSet('cert', 'key')][string]$Kind, [bool]$Der = $false)
    try {
        if ($Kind -eq 'cert') { $t = if ($Der) { & openssl x509 -inform DER -in $Path -pubkey -noout 2>$null } else { & openssl x509 -in $Path -pubkey -noout 2>$null } }
        else { $t = & openssl pkey -in $Path -pubout -passin pass:x 2>$null }
        if ($LASTEXITCODE -ne 0) { return '' }
        return (($t -join '') -replace '\s', '')
    }
    catch { return '' }
}

function Get-BkKeyInventory {
    # Looks at every certificate under the given folders and says whether its PRIVATE KEY is among the files (found by comparing the public keys).
    # Returns Certificates (Rel, Thumbprint, Subject, IsCa, SelfSigned, HasKey, KeyFile), Keys (count), NoOpenSsl.
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string[]]$Folders)
    $res = [ordered]@{ Certificates = [System.Collections.Generic.List[object]]::new(); Keys = 0; NoOpenSsl = $false }
    $files = @()
    foreach ($f in $Folders) { $d = Join-Path $Root $f; if (Test-Path -LiteralPath $d -PathType Container) { $files += @(Get-ChildItem -LiteralPath $d -Recurse -File -Force) } }
    $haveSsl = [bool](Get-Command 'openssl' -ErrorAction SilentlyContinue)
    if (-not $haveSsl) { $res.NoOpenSsl = $true }
    # private keys: public key text -> file
    $keyMap = @{}
    $pfxStems = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $files) {
        if ($f.Extension -in '.pfx', '.p12') { [void]$pfxStems.Add(($f.DirectoryName + '|' + [System.IO.Path]::GetFileNameWithoutExtension($f.Name)).ToLowerInvariant()); $res.Keys++; continue }
        if ($f.Extension -ne '.key' -and $f.Extension -ne '.pem') { continue }
        if ($f.Length -gt 20000) { continue }
        $head = [System.IO.File]::ReadAllText($f.FullName)
        if ($head -notmatch '-----BEGIN (ENCRYPTED |EC |RSA )?PRIVATE KEY-----') { continue }
        $res.Keys++
        if ($haveSsl) { $pk = Get-BkPublicKeyText -Path $f.FullName -Kind key; if ($pk) { $keyMap[$pk] = $f.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/' } }
    }
    $seen = @{}
    foreach ($f in $files) {
        if ($f.Extension -notin '.crt', '.cer', '.pem') { continue }
        if ($f.Name -like '*.crl.pem') { continue }
        $ci = Read-BkCertificateFile -Path $f.FullName
        if ($null -eq $ci) { continue }
        $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
        $der = -not ([System.IO.File]::ReadAllText($f.FullName).Contains('-----BEGIN'))
        $pub = if ($haveSsl) { Get-BkPublicKeyText -Path $f.FullName -Kind cert -Der $der } else { '' }
        $keyFile = ''
        if ($pub -and $keyMap.ContainsKey($pub)) { $keyFile = $keyMap[$pub] }
        else {
            $stem = [System.IO.Path]::GetFileNameWithoutExtension($f.Name).ToLowerInvariant() -replace '-(fullchain|chain|bundle)$', ''
            if ($pfxStems.Contains(($f.DirectoryName + '|' + $stem).ToLowerInvariant())) { $keyFile = '(inside the .pfx next to it)' }
        }
        $o = [pscustomobject]@{ Rel = $rel; Thumbprint = $ci.Thumbprint; Subject = $ci.Subject; IsCa = $ci.IsCa; SelfSigned = $ci.SelfSigned; HasKey = [bool]$keyFile; KeyFile = $keyFile }
        [void]$res.Certificates.Add($o)
    }
    return [pscustomobject]$res
}

function Get-BkLocalMachineThumbprints {
    # SHA-1 thumbprints (upper case) of LocalMachine\Root and LocalMachine\CA (Intermediate). Test hook: PKI_FAKE_STORE_FILE = a text file, one thumbprint per line.
    $set = [System.Collections.Generic.HashSet[string]]::new()
    if ($env:PKI_FAKE_STORE_FILE) {
        if (Test-Path -LiteralPath $env:PKI_FAKE_STORE_FILE) { foreach ($l in [System.IO.File]::ReadAllLines($env:PKI_FAKE_STORE_FILE)) { $t = ($l -replace '[^0-9A-Fa-f]', '').ToUpperInvariant(); if ($t) { [void]$set.Add($t) } } }
        return $set
    }
    foreach ($n in 'Root', 'CA') {
        $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($n, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try { $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly); foreach ($c in $st.Certificates) { [void]$set.Add($c.Thumbprint.ToUpperInvariant()) } }
        finally { $st.Close() }
    }
    return $set
}

function Ensure-PkiDirectory {
    # needed by 16_CertPack.ps1 (normally from 00_Common, which a backup does not load)
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { [void][System.IO.Directory]::CreateDirectory($Path) }
}
