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

$script:BkVersion = '7.8.3'
$script:BkAssumeYes = $false
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

function Clear-BkKeyBuffer {
    # Throws away keys that were typed earlier (for example an Enter pressed while a long step ran): they must not answer the next question.
    try { if (-not [Console]::IsInputRedirected) { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } } catch { }
}

function Read-BkSecret {
    # One hidden answer. An empty answer that comes back at once is a stray Enter, not an answer: it is ignored and the question is asked again.
    param([string]$Prompt)
    Clear-BkKeyBuffer
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $v = ConvertFrom-BkSecure (Read-Host -Prompt $Prompt -AsSecureString)
    if ($v -eq '' -and $sw.ElapsedMilliseconds -lt 500) {
        Clear-BkKeyBuffer
        Write-Host '(an Enter key pressed earlier was ignored - please type the password)'
        $v = ConvertFrom-BkSecure (Read-Host -Prompt $Prompt -AsSecureString)
    }
    return $v
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
        $a = Read-BkSecret 'Backup password'
        $probs = Test-BkPassword $a
        if ($probs.Count -gt 0) {
            foreach ($x in $probs) { Say 'ERROR' "Password policy: $x" }
            if ($try -lt 3) { Say 'INFO' "Try again ($try of 3)." }
            continue
        }
        $b = Read-BkSecret 'Backup password (again)'
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
    $a = Read-BkSecret $Prompt
    if ([string]::IsNullOrEmpty($a)) { Stop-Bk 'No password was typed. No password, no process.' 3 }
    return $a
}

function Read-BkYesNo {
    # A question with the answer Y as the default (Enter = Y). $true = Y, $false = N, $null = nobody can answer (unattended) - the caller then leaves things alone.
    # -Yes of the script ($script:BkAssumeYes) answers Y to everything. Test hook: PKI_RESTORE_ANSWER=Y|N.
    param([Parameter(Mandatory)][string]$Question)
    if ($script:BkAssumeYes) { Say 'INFO' "$Question  -> Y (-Yes)"; return $true }
    if ($env:PKI_RESTORE_ANSWER) { $y = ($env:PKI_RESTORE_ANSWER -match '^(?i)y'); Say 'INFO' "$Question  -> $(if ($y) { 'Y' } else { 'N' }) (PKI_RESTORE_ANSWER)"; return $y }
    if ([Console]::IsInputRedirected) { return $null }
    while ($true) {
        Clear-BkKeyBuffer
        $a = (Read-Host -Prompt "$Question [Y/n]").Trim()
        if ($a -eq '' -or $a -match '^(?i)y(es)?$') { return $true }
        if ($a -match '^(?i)n(o)?$') { return $false }
        Write-Host 'Please answer Y (yes, the default) or N (no).'
    }
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
function ConvertTo-BkNorm {
    # for comparing names: no accents (OÜ = OU), lower case, one space
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $d = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $d.ToCharArray()) { if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) { [void]$sb.Append($ch) } }
    return (($sb.ToString().ToLowerInvariant()) -replace '\s+', ' ').Trim()
}

function Get-BkOrgOf {
    # the O= of a distinguished name
    param([string]$Dn)
    if ($Dn -match '(?:^|,\s*)O=(?<o>"(?:[^"]|"")*"|[^,]+)') { return $Matches['o'].Trim().Trim('"').Trim() }
    return ''
}

function Get-BkOwnOrganizations {
    # THE ORGANIZATIONS OF YOUR PKI: the  Organization =  of every <company>_pki.cnf in the folder (Agantra, Raksaka ...). Only certificates of these are "yours".
    param([Parameter(Mandatory)][string]$Root)
    $set = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in @(Get-ChildItem -LiteralPath $Root -Filter '*_pki.cnf' -File -Force -ErrorAction SilentlyContinue)) {
        foreach ($l in [System.IO.File]::ReadAllLines($f.FullName)) {
            if ($l -match '^\s*Organization\s*=\s*(.+?)\s*$') { $n = ConvertTo-BkNorm ($Matches[1] -replace '\s+#.*$', ''); if ($n) { [void]$set.Add($n) } }
        }
    }
    return $set
}

function Read-BkCertificatesInFile {
    # Every certificate of a PEM file (one or a chain) or the one of a DER file -> Thumbprint (SHA-1), Subject, Issuer, SubjectOrg, IssuerOrg, IsCa, SelfSigned. None -> empty.
    param([Parameter(Mandatory)][string]$Path)
    $out = [System.Collections.Generic.List[object]]::new()
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if ($fi.Length -gt 300000 -or $fi.Length -lt 100) { return $out.ToArray() }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $certs = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        if ($text.Contains('-----BEGIN')) {
            foreach ($m in [regex]::Matches($text, '-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----')) { try { [void]$certs.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($m.Value)) } catch { } }
        }
        elseif ($fi.Length -lt 40000) { try { [void]$certs.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)) } catch { } }
        foreach ($c in $certs) {
            $isCa = $false
            foreach ($e in $c.Extensions) { if ($e.Oid.Value -eq '2.5.29.19') { $isCa = ([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$e).CertificateAuthority } }
            [void]$out.Add([pscustomobject]@{ Thumbprint = $c.Thumbprint.ToUpperInvariant(); Subject = $c.Subject; Issuer = $c.Issuer; SubjectOrg = (Get-BkOrgOf $c.Subject); IssuerOrg = (Get-BkOrgOf $c.Issuer); IsCa = $isCa; SelfSigned = ($c.Subject -eq $c.Issuer) })
            $c.Dispose()
        }
    }
    catch { }
    return $out.ToArray()
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
    # Looks at every certificate under the folders: is its PRIVATE KEY among the files (public keys compared with OpenSSL), and is the certificate YOURS?
    #   yours = issued by one of your organizations (the Organization of a <company>_pki.cnf), or a self-signed CA of yours, or a CA of yours whose key is here
    #           (a root signed by DigiCert / GlobalSign / Sectigo for YOUR key is yours; the DigiCert chain, a certificate DigiCert issued, are not).
    # Returns Certificates (Rel, Thumbprint, Subject, Issuer, IsCa, SelfSigned, HasKey, Own, Index), ExcludedFiles (HashSet of Rel: files of other CAs and their keys),
    #         ExcludedFolders (PKI folders under pki\ with no certificate of yours), Foreign (subjects of other CAs), NoOpenSsl, NoOrgs.
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string[]]$Folders, [System.Collections.Generic.HashSet[string]]$OwnOrgs)
    $res = [ordered]@{ Certificates = [System.Collections.Generic.List[object]]::new(); ExcludedFiles = [System.Collections.Generic.HashSet[string]]::new(); ExcludedFolders = [System.Collections.Generic.List[string]]::new(); Foreign = [System.Collections.Generic.List[string]]::new(); NoOpenSsl = $false; NoOrgs = $false }
    $rootT = $Root.TrimEnd('\', '/')
    $files = @()
    foreach ($f in $Folders) { $d = Join-Path $Root $f; if (Test-Path -LiteralPath $d -PathType Container) { $files += @(Get-ChildItem -LiteralPath $d -Recurse -File -Force) } }
    $haveSsl = [bool](Get-Command 'openssl' -ErrorAction SilentlyContinue)
    if (-not $haveSsl) { $res.NoOpenSsl = $true }
    if ($null -eq $OwnOrgs -or $OwnOrgs.Count -eq 0) { $res.NoOrgs = $true }
    $relOf = { param($fi) ($fi.FullName.Substring($rootT.Length).TrimStart('\', '/')) -replace '\\', '/' }

    # private keys
    $keys = [System.Collections.Generic.List[object]]::new(); $pfx = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        if ($f.Extension -in '.pfx', '.p12') { [void]$pfx.Add([pscustomobject]@{ Rel = (& $relOf $f); Key = ($f.DirectoryName + '|' + [System.IO.Path]::GetFileNameWithoutExtension($f.Name)).ToLowerInvariant() }); continue }
        if ($f.Extension -ne '.key' -and $f.Extension -ne '.pem') { continue }
        if ($f.Length -gt 20000) { continue }
        if ([System.IO.File]::ReadAllText($f.FullName) -notmatch '-----BEGIN (ENCRYPTED |EC |RSA )?PRIVATE KEY-----') { continue }
        $pub = ''; if ($haveSsl) { $pub = Get-BkPublicKeyText -Path $f.FullName -Kind key }
        [void]$keys.Add([pscustomobject]@{ Rel = (& $relOf $f); Pub = $pub })
    }
    $keyPubs = @{}; foreach ($k in $keys) { if ($k.Pub) { $keyPubs[$k.Pub] = $true } }

    # certificates
    $recs = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        if ($f.Extension -notin '.crt', '.cer', '.pem', '.der') { continue }
        if ($f.Name -like '*.crl.pem') { continue }
        $cis = @(Read-BkCertificatesInFile -Path $f.FullName)
        if ($cis.Count -eq 0) { continue }
        $rel = & $relOf $f
        $der = -not ([System.IO.File]::ReadAllText($f.FullName).Contains('-----BEGIN'))
        $pub = ''; if ($haveSsl) { $pub = Get-BkPublicKeyText -Path $f.FullName -Kind cert -Der $der }
        $i = 0
        foreach ($ci in $cis) {
            $has = ($i -eq 0 -and $pub -and $keyPubs.ContainsKey($pub))
            [void]$recs.Add([pscustomobject]@{ Rel = $rel; Dir = $f.DirectoryName; Stem = ([System.IO.Path]::GetFileNameWithoutExtension($f.Name).ToLowerInvariant() -replace '-(fullchain|chain|bundle)(-cross)?(-\d+)?$', ''); Index = $i; Pub = $(if ($i -eq 0) { $pub } else { '' }); Thumbprint = $ci.Thumbprint; Subject = $ci.Subject; Issuer = $ci.Issuer; SubjectOrg = $ci.SubjectOrg; IssuerOrg = $ci.IssuerOrg; IsCa = $ci.IsCa; SelfSigned = $ci.SelfSigned; HasKey = $has; Own = $true })
            $i++
        }
    }
    # a certificate has its key when ANY copy of it does (publish\ copies, chains)
    $keyed = @{}; foreach ($r in $recs) { if ($r.HasKey) { $keyed[$r.Thumbprint] = $true } }
    foreach ($r in $recs) {
        if (-not $r.HasKey -and $keyed.ContainsKey($r.Thumbprint)) { $r.HasKey = $true }
        if (-not $r.HasKey) {
            $pf = ($r.Dir + '|' + $r.Stem).ToLowerInvariant()
            if (@($pfx | Where-Object { $_.Key -eq $pf }).Count -gt 0) { $r.HasKey = $true }
        }
    }
    # ownership
    if (-not $res.NoOrgs) {
        foreach ($r in $recs) {
            $io = $OwnOrgs.Contains((ConvertTo-BkNorm $r.IssuerOrg)); $so = $OwnOrgs.Contains((ConvertTo-BkNorm $r.SubjectOrg))
            $r.Own = ($io -or ($r.SelfSigned -and $so) -or ($r.IsCa -and $so -and ($r.HasKey -or $res.NoOpenSsl)))
        }
    }
    foreach ($r in $recs) { [void]$res.Certificates.Add($r) }

    # what is NOT yours
    if (-not $res.NoOrgs) {
        $foreignFiles = @{}
        foreach ($g in ($recs | Group-Object Rel)) {
            if (@($g.Group | Where-Object { $_.Own }).Count -eq 0) {
                [void]$res.ExcludedFiles.Add($g.Name); $first = $g.Group[0]; $foreignFiles[($first.Dir + '|' + $first.Stem).ToLowerInvariant()] = $true
                foreach ($r in $g.Group) { if ($r.Subject -and -not $res.Foreign.Contains($r.Subject)) { [void]$res.Foreign.Add($r.Subject) } }
            }
        }
        foreach ($k in $keys) {
            $m = @($recs | Where-Object { $k.Pub -and $_.Pub -eq $k.Pub })
            if ($m.Count -gt 0 -and @($m | Where-Object { $_.Own }).Count -eq 0) { [void]$res.ExcludedFiles.Add($k.Rel) }
        }
        foreach ($pf in $pfx) { if ($foreignFiles.ContainsKey($pf.Key)) { [void]$res.ExcludedFiles.Add($pf.Rel) } }
        foreach ($g in ($recs | Where-Object { $_.Rel -like 'pki/*' } | Group-Object { ($_.Rel -split '/')[1] })) {
            if (@($g.Group | Where-Object { $_.Own }).Count -eq 0) { [void]$res.ExcludedFolders.Add($g.Name) }
        }
    }
    return [pscustomobject]$res
}

function Test-BkExcluded {
    # Rel of a file ('pki/pki-x/..', 'leafcerts/..') -> $true when it belongs to another CA
    param([string]$Rel, $Inventory)
    if ($Inventory.ExcludedFiles.Contains($Rel)) { return $true }
    if ($Rel -like 'pki/*') { $n = ($Rel -split '/')[1]; if ($Inventory.ExcludedFolders.Contains($n)) { return $true } }
    return $false
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
