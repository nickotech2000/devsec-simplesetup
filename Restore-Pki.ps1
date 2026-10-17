# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
<#
.SYNOPSIS
    Puts a PKI backup (made by Backup-Pki.ps1) back: asks for the password, checks every file, restores the PKI folders and keys.
    Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator PowerShell 7, after Prepare-Computer.ps1.
    Full help: .\Restore-Pki.ps1 -Help
.EXAMPLE
    .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps
.EXAMPLE
    .\Restore-Pki.ps1 -Package .\backup-pki\pki-payload-20261014-pc01-windows-11-25h2-a1b2c3.zip -Check
#>
param(
    [string]$Package,
    [string]$Destination,
    [switch]$Force,
    [switch]$Yes,
    [switch]$Check,
    [switch]$RestrictAccess,
    [switch]$Help
)

function Show-Help {
@'
============================================================
 Restore-Pki.ps1 - put a PKI backup back
 Version 6.4.1
 Author : Nicko Satria Utama
 Company: Agantra Inovatif OU (NextMantra)
 Email  : nicko@nextmantra.com
============================================================
ORDER OF WORK  (a restore stops at the first problem, before anything is written)
  1. The computer: Windows 11 Home/Pro 24H2+ or Windows Server 2025, Intel/AMD 64 bit, Administrator
     window. Otherwise: refused.
  2. ALL required software is checked: PowerShell 7, OpenSSL 4, Python 3, .NET SDK 8, .NET SDK 10
     (on the PATH). Whatever is missing is listed, and the script says: you need to run
     Prepare-Computer.ps1 (it installs all of them). Nothing else happens until it has been run.
  3. The checksums of the files in the backup zip (SHA256SUMS) are checked.
  4. You type the backup password (no password, no restore). Every file inside the .certpacked is
     decrypted and checked against its SHA-256.
  5. ONE BY ONE, each PKI of the backup is compared with this computer:
       - the pki folder of -Destination: every file of that PKI by SHA-256 (identical / different /
         missing);
       - the Local Machine certificate store (Root and Intermediate): every CA certificate of that
         PKI by thumbprint.
     A PKI that is in the pki folder already (all files identical), or whose CA certificates are ALL
     in the Local Machine store, is NOT restored. A PKI whose folder exists but differs is NOT
     silently skipped: you are asked "Replace it with the version from the backup? [Y/n]" and Enter
     = Y (yes). With Y the old folder is renamed to <name>.before-restore-<time> (never deleted) and
     the backup version is written. Answer n to keep the old one. Run unattended (no one to ask) the
     old one is kept, unless you give -Yes. Only what is missing is restored. If nothing is missing:
     "Nothing to restore", nothing is changed. (The store holds certificates, not private keys:
     -Force restores the keys of a PKI that is only in the store.)
  5b. ONLY YOUR PKI: certificates of other CAs (DigiCert, GlobalSign, Sectigo, ...) that may be in
  an older backup are never restored; they are listed as "Not restored".
  6. The other files (leafcerts, external-ca, csr-signed, settings) are compared file by file the
     same way.
  7. The files are written, then every restored file is checked against the backup again.
  The backup itself holds the private key of EVERY certificate: all roots, all intermediates, all
  profile / leaf certificates (Backup-Pki.ps1 checks this when it makes the backup).

USE
  .\Restore-Pki.ps1 -Destination C:\PKI-DevSecOps                 (run it from the unzipped backup `
        folder: the .certpacked is next to it)
  .\Restore-Pki.ps1 -Package <backup zip | .certpacked | folder> -Destination <folder>
  .\Restore-Pki.ps1 -Check                                          (everything except writing: `
        the password, the checksums, the one-by-one comparison, what would be restored)
  Standalone: this script needs no other .ps1. Prepare-Computer.ps1 (next to it in the backup zip)
  is only RUN by you, before.

OPTIONS
  -Package <path>      the backup zip (pki-payload-....zip), the .certpacked, or a folder that holds
                       one. Default: the .certpacked next to this script.
  -Destination <dir>   the project folder to restore into. Default: the folder of this script when
                       it is the project (it has pki_setup.ps1); otherwise you must give it.
  -Yes                 answer Y to every "replace?" question without asking (old folders/files are
                       still renamed, never deleted)
  -Force               restore anyway: a PKI folder (or file) that exists is RENAMED to
                       <name>.before-restore-<yyyymmdd-HHmmss> (never deleted), and a PKI that is
                       only in the Local Machine store is restored too
  -Check               do not write anything
  -RestrictAccess      pki\, leafcerts\, external-ca\ get access for Administrators and SYSTEM only
                       (icacls) BEFORE the keys are written
  -Help

AFTER IT
  The Windows certificate stores are not in the backup: run  pki_setup.ps1 -InstallTrust  in the
  restored folder to trust the PKI again.
  EXIT CODES   0 ok   1 error   2 not an Administrator window   3 wrong password   4 Prepare-Computer.ps1 not run   5 system not supported   6 checksum does not match
============================================================
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

if ($Help) { Invoke-PagedHelp { Show-Help }; return }
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host '[ERROR] Restore-Pki.ps1 needs PowerShell 7 or newer (this window is PowerShell' $PSVersionTable.PSVersion.ToString() '). Run Prepare-Computer.ps1 in an Administrator window to install it, then start this script with  pwsh . Nothing was done.' -ForegroundColor Red
    exit 4
}

$ErrorActionPreference = 'Stop'
#region embedded library (generated by scripts\backup\Build-BackupScripts.ps1 - do not edit here)
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

$script:BkVersion = '6.4.1'
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


# ---- zip / AES-256 engine (from scripts\16_CertPack.ps1)
# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 16_CertPack.ps1  -  the password-protected archive layer of the transport (".certpacked")
#
# A .certpacked file IS a password-protected archive under another name. Rename it to .zip or .7z and any
# 7-Zip compatible program opens it with the password. Three kinds:
#
#   zip + AES-256   (default)  WinZip AES (AE-2): PBKDF2-HMAC-SHA1, AES-256-CTR, HMAC-SHA1 authentication of every
#                              entry. Made and read by THIS module with .NET only: no 7-Zip on Windows needed.
#                              Linux / macOS: 7-Zip (7z, 7zz, 7za) reads it; pki-transport.sh installs it if it can.
#   zip + ZipCrypto (legacy)   The old PKWARE encryption: weak against known-plaintext attacks. Only for packages
#                              that carry nothing secret (CA certificates). Plain "unzip -P" reads it everywhere.
#   7z  + AES-256              LZMA2 with encrypted headers (file names hidden). Needs 7-Zip to make and to read.
#
# The kind is found from the first bytes of the file, never from the extension.
#
# Provides : Initialize-PkiZipLibrary, Get-PkiArchiveType, New-PkiAesZipArchive, Expand-PkiAesZipArchive,
#            Get-PkiAesZipEntries, Find-PkiSevenZip, New-PkiSevenZipArchive, Expand-PkiSevenZipArchive,
#            Expand-PkiArchive, Test-PkiArchivePassword
# Requires : 00_Common
# ============================================================

$script:PkiZipSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

public static class PkiZip
{
    // ---------------------------------------------------------------- CRC-32
    private static readonly uint[] CrcTable = MakeTable();
    private static uint[] MakeTable()
    {
        var t = new uint[256];
        for (uint n = 0; n < 256; n++) { uint c = n; for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1); t[n] = c; }
        return t;
    }
    public static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFFu;
        for (int i = 0; i < data.Length; i++) crc = CrcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        return ~crc;
    }
    private static uint CrcStep(uint crc, byte b) { return CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8); }

    // ---------------------------------------------------------------- WinZip AES
    private static void AesKeys(string password, byte[] salt, int keyLen, out byte[] encKey, out byte[] authKey, out byte[] pwv)
    {
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] km = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 1000, HashAlgorithmName.SHA1, 2 * keyLen + 2);
        encKey = new byte[keyLen]; authKey = new byte[keyLen]; pwv = new byte[2];
        Buffer.BlockCopy(km, 0, encKey, 0, keyLen);
        Buffer.BlockCopy(km, keyLen, authKey, 0, keyLen);
        Buffer.BlockCopy(km, 2 * keyLen, pwv, 0, 2);
    }

    // AES-CTR with a LITTLE-endian counter that starts at 1 (the WinZip way; not the OpenSSL way)
    private static byte[] AesCtr(byte[] key, byte[] data)
    {
        byte[] output = new byte[data.Length];
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
            using (var enc = aes.CreateEncryptor())
            {
                byte[] counter = new byte[16]; counter[0] = 1;
                byte[] ks = new byte[16];
                for (int pos = 0; pos < data.Length; pos += 16)
                {
                    enc.TransformBlock(counter, 0, 16, ks, 0);
                    int n = Math.Min(16, data.Length - pos);
                    for (int i = 0; i < n; i++) output[pos + i] = (byte)(data[pos + i] ^ ks[i]);
                    for (int i = 0; i < 16; i++) { if (++counter[i] != 0) break; }
                }
            }
        }
        return output;
    }

    private static byte[] Mac(byte[] authKey, byte[] cipher)
    {
        using (var h = new HMACSHA1(authKey)) { byte[] full = h.ComputeHash(cipher); byte[] t = new byte[10]; Buffer.BlockCopy(full, 0, t, 0, 10); return t; }
    }

    // ---------------------------------------------------------------- ZipCrypto (legacy)
    private sealed class ZcKeys
    {
        public uint K0 = 0x12345678u, K1 = 0x23456789u, K2 = 0x34567890u;
        public void Update(byte c)
        {
            K0 = CrcStep(K0, c);
            K1 = (K1 + (K0 & 0xFF)) * 134775813u + 1u;
            K2 = CrcStep(K2, (byte)(K1 >> 24));
        }
        public byte Next() { uint t = (K2 | 2u) & 0xFFFFu; return (byte)(((t * (t ^ 1u)) >> 8) & 0xFFu); }
        public ZcKeys(string password) { foreach (byte b in Encoding.UTF8.GetBytes(password)) Update(b); }
    }
    private static byte[] ZcEncrypt(byte[] data, string password, uint crc)
    {
        var k = new ZcKeys(password);
        byte[] header = new byte[12];
        byte[] rnd = new byte[11]; RandomNumberGenerator.Fill(rnd);
        Buffer.BlockCopy(rnd, 0, header, 0, 11);
        header[11] = (byte)(crc >> 24);
        byte[] outp = new byte[12 + data.Length];
        for (int i = 0; i < 12; i++) { byte p = header[i]; outp[i] = (byte)(p ^ k.Next()); k.Update(p); }
        for (int i = 0; i < data.Length; i++) { byte p = data[i]; outp[12 + i] = (byte)(p ^ k.Next()); k.Update(p); }
        return outp;
    }

    // ---------------------------------------------------------------- helpers
    private static void U16(Stream s, int v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
    private static void U32(Stream s, uint v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)(v >> 16)); s.WriteByte((byte)(v >> 24)); }
    private static ushort R16(byte[] b, long o) { return (ushort)(b[o] | (b[o + 1] << 8)); }
    private static uint R32(byte[] b, long o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }

    private static void DosTime(DateTime t, out ushort time, out ushort date)
    {
        if (t.Year < 1980) t = new DateTime(1980, 1, 1);
        time = (ushort)((t.Hour << 11) | (t.Minute << 5) | (t.Second / 2));
        date = (ushort)(((t.Year - 1980) << 9) | (t.Month << 5) | t.Day);
    }
    private static DateTime FromDos(ushort time, ushort date)
    {
        try { return new DateTime(((date >> 9) & 0x7F) + 1980, Math.Max(1, (date >> 5) & 0x0F), Math.Max(1, date & 0x1F), (time >> 11) & 0x1F, (time >> 5) & 0x3F, (time & 0x1F) * 2); }
        catch { return DateTime.Now; }
    }

    // ---------------------------------------------------------------- Create
    public static void Create(string archivePath, string[] sources, string[] names, string password, string encryption)
    {
        if (sources.Length != names.Length) throw new ArgumentException("sources and names differ in length");
        bool aes = !string.Equals(encryption, "ZipCrypto", StringComparison.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("A password is required");
        var central = new List<byte[]>();
        using (var fs = new FileStream(archivePath, FileMode.Create, FileAccess.Write))
        {
            for (int i = 0; i < sources.Length; i++)
            {
                byte[] data = File.ReadAllBytes(sources[i]);
                string name = names[i].Replace('\\', '/').TrimStart('/');
                byte[] nameBytes = Encoding.UTF8.GetBytes(name);
                ushort dt, dd; DosTime(File.GetLastWriteTime(sources[i]), out dt, out dd);
                uint crc = Crc32(data);

                byte[] comp; ushort actual = 8;
                using (var ms = new MemoryStream())
                {
                    using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, true)) ds.Write(data, 0, data.Length);
                    comp = ms.ToArray();
                }
                if (comp.Length >= data.Length) { comp = data; actual = 0; }

                byte[] payload, extra; ushort method, verNeeded; uint crcField;
                if (aes)
                {
                    byte[] salt = new byte[16]; RandomNumberGenerator.Fill(salt);
                    byte[] ek, ak, pwv; AesKeys(password, salt, 32, out ek, out ak, out pwv);
                    byte[] ct = AesCtr(ek, comp);
                    byte[] mac = Mac(ak, ct);
                    payload = new byte[16 + 2 + ct.Length + 10];
                    Buffer.BlockCopy(salt, 0, payload, 0, 16); Buffer.BlockCopy(pwv, 0, payload, 16, 2);
                    Buffer.BlockCopy(ct, 0, payload, 18, ct.Length); Buffer.BlockCopy(mac, 0, payload, 18 + ct.Length, 10);
                    method = 99; verNeeded = 51; crcField = 0;                    // AE-2: no CRC
                    extra = new byte[] { 0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 0x41, 0x45, 0x03, (byte)(actual & 0xFF), (byte)(actual >> 8) };
                }
                else
                {
                    payload = ZcEncrypt(comp, password, crc);
                    method = actual; verNeeded = 20; crcField = crc; extra = new byte[0];
                }
                ushort flags = 0x0801;                                          // encrypted + UTF-8 names
                long offset = fs.Position;

                U32(fs, 0x04034b50u); U16(fs, verNeeded); U16(fs, flags); U16(fs, method); U16(fs, dt); U16(fs, dd);
                U32(fs, crcField); U32(fs, (uint)payload.Length); U32(fs, (uint)data.Length);
                U16(fs, nameBytes.Length); U16(fs, extra.Length);
                fs.Write(nameBytes, 0, nameBytes.Length); fs.Write(extra, 0, extra.Length); fs.Write(payload, 0, payload.Length);

                using (var c = new MemoryStream())
                {
                    U32(c, 0x02014b50u); U16(c, 63); U16(c, verNeeded); U16(c, flags); U16(c, method); U16(c, dt); U16(c, dd);
                    U32(c, crcField); U32(c, (uint)payload.Length); U32(c, (uint)data.Length);
                    U16(c, nameBytes.Length); U16(c, extra.Length); U16(c, 0); U16(c, 0); U16(c, 0); U32(c, 0x20u); U32(c, (uint)offset);
                    c.Write(nameBytes, 0, nameBytes.Length); c.Write(extra, 0, extra.Length);
                    central.Add(c.ToArray());
                }
            }
            long cdStart = fs.Position;
            foreach (var b in central) fs.Write(b, 0, b.Length);
            long cdSize = fs.Position - cdStart;
            U32(fs, 0x06054b50u); U16(fs, 0); U16(fs, 0); U16(fs, central.Count); U16(fs, central.Count);
            U32(fs, (uint)cdSize); U32(fs, (uint)cdStart); U16(fs, 0);
        }
    }

    // ---------------------------------------------------------------- Read
    private sealed class Entry
    {
        public string Name; public ushort Flags, Method, Actual, DosT, DosD; public bool Aes; public int Version, Strength;
        public uint Crc; public long CSize, USize, Offset;
    }

    private static List<Entry> ReadDirectory(byte[] a)
    {
        long eocd = -1;
        for (long i = a.Length - 22; i >= Math.Max(0, a.Length - 22 - 65535); i--) { if (R32(a, i) == 0x06054b50u) { eocd = i; break; } }
        if (eocd < 0) throw new InvalidDataException("Not a zip archive (no end-of-directory record)");
        int count = R16(a, eocd + 10); long cdOff = R32(a, eocd + 16);
        if (cdOff == 0xFFFFFFFFu || count == 0xFFFF) throw new NotSupportedException("Zip64 archives are not supported");
        var list = new List<Entry>();
        long p = cdOff;
        for (int n = 0; n < count; n++)
        {
            if (R32(a, p) != 0x02014b50u) throw new InvalidDataException("Damaged central directory");
            var e = new Entry();
            e.Flags = R16(a, p + 8); e.Method = R16(a, p + 10); e.DosT = R16(a, p + 12); e.DosD = R16(a, p + 14);
            e.Crc = R32(a, p + 16); e.CSize = R32(a, p + 20); e.USize = R32(a, p + 24);
            int nl = R16(a, p + 28), el = R16(a, p + 30), cl = R16(a, p + 32);
            e.Offset = R32(a, p + 42);
            e.Name = Encoding.UTF8.GetString(a, (int)(p + 46), nl);
            e.Actual = e.Method;
            long x = p + 46 + nl, xe = x + el;
            while (x + 4 <= xe)
            {
                int id = R16(a, x), sz = R16(a, x + 2);
                if (id == 0x9901 && sz >= 7) { e.Aes = true; e.Version = R16(a, x + 4); e.Strength = a[x + 8]; e.Actual = R16(a, x + 9); }
                x += 4 + sz;
            }
            list.Add(e);
            p += 46 + nl + el + cl;
        }
        return list;
    }

    public static string[] ListNames(string archivePath)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        var r = new List<string>();
        foreach (var e in ReadDirectory(a)) if (!e.Name.EndsWith("/")) r.Add(e.Name);
        return r.ToArray();
    }

    public static string Describe(string archivePath)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        var l = ReadDirectory(a);
        if (l.Count == 0) return "empty";
        var e = l[0];
        if (e.Aes) return "AES-" + (e.Strength == 3 ? "256" : e.Strength == 2 ? "192" : "128");
        return (e.Flags & 1) != 0 ? "ZipCrypto" : "not encrypted";
    }

    private static byte[] Inflate(byte[] comp, long usize)
    {
        using (var src = new MemoryStream(comp))
        using (var ds = new DeflateStream(src, CompressionMode.Decompress))
        using (var dst = new MemoryStream())
        {
            ds.CopyTo(dst);
            if (dst.Length != usize) throw new InvalidDataException("Size mismatch after decompression");
            return dst.ToArray();
        }
    }

    private static byte[] ReadEntry(byte[] a, Entry e, string password)
    {
        long o = e.Offset;
        if (R32(a, o) != 0x04034b50u) throw new InvalidDataException("Damaged local header of " + e.Name);
        long start = o + 30 + R16(a, o + 26) + R16(a, o + 28);
        byte[] raw = new byte[e.CSize];
        Buffer.BlockCopy(a, (int)start, raw, 0, (int)e.CSize);
        byte[] comp;
        bool checkCrc = true;
        if ((e.Flags & 1) == 0 && !e.Aes) { comp = raw; }
        else if (e.Aes)
        {
            int keyLen = e.Strength == 3 ? 32 : e.Strength == 2 ? 24 : 16, saltLen = keyLen / 2;
            if (raw.Length < saltLen + 2 + 10) throw new InvalidDataException("Damaged AES entry " + e.Name);
            byte[] salt = new byte[saltLen]; Buffer.BlockCopy(raw, 0, salt, 0, saltLen);
            byte[] ek, ak, pwv; AesKeys(password, salt, keyLen, out ek, out ak, out pwv);
            if (raw[saltLen] != pwv[0] || raw[saltLen + 1] != pwv[1]) throw new UnauthorizedAccessException("WRONG_PASSWORD");
            int clen = raw.Length - saltLen - 2 - 10;
            byte[] ct = new byte[clen]; Buffer.BlockCopy(raw, saltLen + 2, ct, 0, clen);
            byte[] mac = new byte[10]; Buffer.BlockCopy(raw, saltLen + 2 + clen, mac, 0, 10);
            if (!CryptographicOperations.FixedTimeEquals(mac, Mac(ak, ct))) throw new InvalidDataException("AUTHENTICATION_FAILED: " + e.Name + " is damaged or was changed");
            comp = AesCtr(ek, ct);
            if (e.Version == 2) checkCrc = false;
        }
        else
        {
            if (raw.Length < 12) throw new InvalidDataException("Damaged ZipCrypto entry " + e.Name);
            var k = new ZcKeys(password);
            byte[] plain = new byte[raw.Length - 12];
            byte last = 0;
            for (int i = 0; i < raw.Length; i++)
            {
                byte p = (byte)(raw[i] ^ k.Next()); k.Update(p);
                if (i < 12) last = p; else plain[i - 12] = p;
            }
            byte expect = ((e.Flags & 8) != 0) ? (byte)(e.DosT >> 8) : (byte)(e.Crc >> 24);
            if (last != expect) throw new UnauthorizedAccessException("WRONG_PASSWORD");
            comp = plain;
        }
        byte[] data = (e.Actual == 8) ? Inflate(comp, e.USize) : comp;
        if (e.Actual != 0 && e.Actual != 8) throw new NotSupportedException("Compression method " + e.Actual + " of " + e.Name);
        if (data.Length != e.USize) throw new InvalidDataException("Size mismatch of " + e.Name);
        if (checkCrc && Crc32(data) != e.Crc) throw new UnauthorizedAccessException("WRONG_PASSWORD (or damaged data) in " + e.Name);
        return data;
    }

    private static string SafePath(string dest, string name)
    {
        string rel = name.Replace('\\', '/').TrimStart('/');
        if (rel.Length == 0 || rel.IndexOf(':') >= 0) throw new InvalidDataException("Unsafe entry name: " + name);
        foreach (string seg in rel.Split('/')) if (seg == "..") throw new InvalidDataException("Unsafe entry name (..): " + name);
        string root = Path.GetFullPath(dest);
        string full = Path.GetFullPath(Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidDataException("Unsafe entry name (outside the destination): " + name);
        return full;
    }

    // destDir == null: only test (decrypt + authenticate every entry). Returns the entry names.
    public static string[] Extract(string archivePath, string destDir, string password, string[] prefixes)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        var done = new List<string>();
        foreach (var e in ReadDirectory(a))
        {
            if (e.Name.EndsWith("/")) continue;
            if (prefixes != null && prefixes.Length > 0)
            {
                bool hit = false;
                foreach (string p in prefixes) { if (e.Name.Replace('\\', '/').StartsWith(p, StringComparison.OrdinalIgnoreCase)) { hit = true; break; } }
                if (!hit) continue;
            }
            byte[] data = ReadEntry(a, e, password);
            if (!string.IsNullOrEmpty(destDir))        // PowerShell passes $null as ""
            {
                string full = SafePath(destDir, e.Name);
                Directory.CreateDirectory(Path.GetDirectoryName(full));
                File.WriteAllBytes(full, data);
                File.SetLastWriteTime(full, FromDos(e.DosT, e.DosD));
            }
            done.Add(e.Name);
        }
        return done.ToArray();
    }

    public static string Detect(string path)
    {
        byte[] h = new byte[6];
        using (var f = new FileStream(path, FileMode.Open, FileAccess.Read)) { int n = f.Read(h, 0, 6); if (n < 4) return "unknown"; }
        if (h[0] == 0x50 && h[1] == 0x4B && (h[2] == 3 || h[2] == 5)) return "zip";
        if (h[0] == 0x37 && h[1] == 0x7A && h[2] == 0xBC && h[3] == 0xAF && h[4] == 0x27 && h[5] == 0x1C) return "7z";
        return "unknown";
    }
}
'@

function Initialize-PkiZipLibrary {
    if (-not ('PkiZip' -as [type])) { Add-Type -TypeDefinition $script:PkiZipSource -Language CSharp }
}

function Get-PkiArchiveType {
    # "zip" | "7z" | "unknown", from the first bytes of the file (the extension .certpacked says nothing).
    param([Parameter(Mandatory)][string]$Path)
    Initialize-PkiZipLibrary
    return [PkiZip]::Detect($Path)
}

function New-PkiAesZipArchive {
    <#
    .PARAMETER Files
        A list of @{ Source = <file on disk>; Entry = <name inside the archive> }
    .PARAMETER Encryption
        Aes256 (default) | ZipCrypto
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Files, [Parameter(Mandatory)][string]$Password, [ValidateSet('Aes256', 'ZipCrypto')][string]$Encryption = 'Aes256')
    Initialize-PkiZipLibrary
    $src = [string[]]@($Files | ForEach-Object { $_.Source })
    $ent = [string[]]@($Files | ForEach-Object { $_.Entry })
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    [PkiZip]::Create($Path, $src, $ent, $Password, $Encryption)
}

function Expand-PkiAesZipArchive {
    # Extracts (or, with no -Destination, only tests) a zip: AES-128/192/256 or ZipCrypto. Entry prefixes filter.
    # Wrong password: the message starts with WRONG_PASSWORD.
    param([Parameter(Mandatory)][string]$Path, [string]$Destination, [Parameter(Mandatory)][string]$Password, [string[]]$Prefix)
    Initialize-PkiZipLibrary
    $dest = if ([string]::IsNullOrWhiteSpace($Destination)) { $null } else { $Destination }
    try { return [string[]][PkiZip]::Extract($Path, $dest, $Password, [string[]]@($Prefix)) }
    catch {
        $m = $_.Exception.GetBaseException().Message
        if ($m -like 'WRONG_PASSWORD*') { throw 'WRONG_PASSWORD: the password is wrong (or the file is damaged).' }
        throw $m
    }
}

function Get-PkiAesZipEntries {
    param([Parameter(Mandatory)][string]$Path)
    Initialize-PkiZipLibrary
    return [string[]][PkiZip]::ListNames($Path)
}


function Expand-PkiArchive {
    # a backup .certpacked is always a zip with AES-256: extracts it (or only tests it when -Destination is empty)
    param([Parameter(Mandatory)][string]$Path, [string]$Destination, [Parameter(Mandatory)][string]$Password, [string[]]$Prefix)
    if ((Get-PkiArchiveType -Path $Path) -ne 'zip') { throw "$Path is not a zip archive (first bytes not recognised): it is not a PKI backup, or it is damaged." }
    return (Expand-PkiAesZipArchive -Path $Path -Destination $Destination -Password $Password -Prefix $Prefix)
}
#endregion embedded library
Set-StrictMode -Version Latest

Set-StrictMode -Version Latest

$script:BkAssumeYes = [bool]$Yes
Write-BkBanner 'Restore-Pki.ps1' 'restore a PKI backup'
$os = Assert-BkHost
$prep = $(if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Prepare-Computer.ps1')) { '.\Prepare-Computer.ps1' } else { 'Prepare-Computer.ps1 (from the backup zip or from trustkit\)' })
Assert-BkPrepared -PrepareScript $prep

$work = New-BkTempDirectory 'pkirestore'
$opened = $null
try {
    # ---------------------------------------------------------------- which backup
    $cp = $null; $checkDir = $null
    if (-not $Package) {
        $found = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.certpacked' -File -ErrorAction SilentlyContinue)
        if ($found.Count -eq 1) { $Package = $found[0].FullName }
        elseif ($found.Count -gt 1) { Stop-Bk ("There is more than one .certpacked next to this script; say which with -Package:`n  " + (($found | ForEach-Object { $_.Name }) -join "`n  ")) 1 }
        else { Stop-Bk 'No backup given. Use -Package <backup zip | .certpacked | folder>, or run this script from the unzipped backup folder. Nothing was done.' 1 }
    }
    if (-not (Test-Path -LiteralPath $Package)) { Stop-Bk "Backup not found: $Package" 1 }
    $Package = (Resolve-Path -LiteralPath $Package).Path
    if ((Get-Item -LiteralPath $Package).PSIsContainer) {
        $found = @(Get-ChildItem -LiteralPath $Package -Filter '*.certpacked' -File)
        if ($found.Count -eq 1) { $cp = $found[0].FullName; $checkDir = $Package }
        else {
            $zs = @(Get-ChildItem -LiteralPath $Package -Filter 'pki-payload-*.zip' -File | Sort-Object Name)
            if ($zs.Count -eq 1) { $Package = $zs[0].FullName }
            elseif ($zs.Count -eq 0) { Stop-Bk "No backup in $Package (no .certpacked and no pki-payload-*.zip)." 1 }
            else { Stop-Bk ("There are $($zs.Count) backups in $Package; say which one with -Package <file>:`n  " + (($zs | ForEach-Object { $_.Name }) -join "`n  ")) 1 }
        }
    }
    if (-not $cp -and $Package -like '*.zip') {
        Say 'INFO' 'Opening the backup zip ...'
        $ex = Join-Path $work 'zip'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Package, $ex)
        $inner = @(Get-ChildItem -LiteralPath $ex -Recurse -Filter '*.certpacked' -File)
        if ($inner.Count -ne 1) { Stop-Bk "The zip must hold exactly one .certpacked (found $($inner.Count))." 1 }
        $cp = $inner[0].FullName; $checkDir = $inner[0].DirectoryName
    }
    elseif (-not $cp) { $cp = $Package; $checkDir = Split-Path -Parent $Package }

    # ---------------------------------------------------------------- the checksums of the zip contents
    $sumFile = Join-Path $checkDir 'SHA256SUMS'
    if (Test-Path -LiteralPath $sumFile) {
        $sums = Get-BkSumsFile $sumFile; $badSum = 0
        foreach ($k in $sums.Keys) {
            $fp = Join-Path $checkDir ($k -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (-not (Test-Path -LiteralPath $fp)) { Say 'ERROR' "Missing: $k"; $badSum++; continue }
            if ((Get-BkHash $fp).Sha256 -ne $sums[$k]) { Say 'ERROR' "Different SHA-256: $k"; $badSum++ }
        }
        if ($badSum -gt 0) { Stop-Bk "$badSum file(s) of the backup do not match SHA256SUMS: the backup is damaged or was changed. Nothing was done." 6 }
        Say 'OK' "SHA-256 checksums: $($sums.Count) files match."
    }
    else { Say 'WARN' 'No SHA256SUMS next to the .certpacked: only the checks inside the .certpacked are done.' }

    # ---------------------------------------------------------------- where to
    if (-not $Destination) {
        if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'pki_setup.ps1')) { $Destination = $PSScriptRoot }
        else { Stop-Bk 'Say where to restore: -Destination <folder>  (for example C:\PKI-DevSecOps). Nothing was done.' 1 }
    }
    $Destination = [System.IO.Path]::GetFullPath($Destination)

    # ---------------------------------------------------------------- password, decrypt, verify
    $pw = Read-BkExistingPassword 'Backup password'
    Say 'INFO' 'Decrypting and checking every file ...'
    $opened = Open-BkPackage -Path $cp -Password $pw
    $m = $opened.Manifest
    $entries = @($m['files'] | Where-Object { ([string]$_['path']).StartsWith('data/') })
    # ONLY YOUR PKI: certificates of other CAs (DigiCert, GlobalSign, Sectigo ...) are never restored, whatever this backup holds
    $dataDir = Join-Path $opened.Dir 'data'
    $ownOrgs = @(Get-BkOwnOrganizations -Root $dataDir)
    Say 'INFO' 'Looking at every certificate and key of the backup: which are yours ...'
    $inv = Get-BkKeyInventory -Root $dataDir -Folders @('pki', 'leafcerts', 'external-ca', 'csr-signed') -OwnOrgs $ownOrgs
    if ($ownOrgs.Count -eq 0) { Say 'WARN' 'The backup holds no <company>_pki.cnf with an Organization: your PKI cannot be told from other CAs; everything is restored.' }
    else {
        $before = $entries.Count
        $entries = @($entries | Where-Object { -not (Test-BkExcluded -Rel (([string]$_['path']).Substring(5)) -Inventory $inv) })
        Say 'INFO' ("Your PKI      : organization(s) {0}. Only these are restored." -f (($ownOrgs | Sort-Object) -join ', '))
        if ($before -ne $entries.Count) {
            Say 'INFO' ("Not restored  : {0} file(s) of other CAs (not your PKI)" -f ($before - $entries.Count))
            foreach ($fs in ($inv.Foreign | Select-Object -First 8)) { Say 'INFO' "  other CA: $fs" }
        }
    }
    $pkiList = @(@($m['pkiFolders']) | Where-Object { -not $inv.ExcludedFolders.Contains([string]$_) })
    Say 'OK' ("Backup made {0} on {1} ({2}): {3} files, PKI folders: {4}" -f $m['createdUtc'], $m['source']['computer'], $m['source']['os'], $entries.Count, (@($m['pkiFolders']) -join ', '))
    if ($m.ContainsKey('keyCheck')) {
        $kc = $m['keyCheck']
        if ($kc['checked']) { Say 'INFO' ("Private keys in this backup: {0} of {1} certificates; CA certificates without a key: {2}" -f $kc['withPrivateKey'], $kc['certificates'], @($kc['caWithoutKey']).Count) }
        foreach ($c in @($kc['caWithoutKey'])) { Say 'WARN' "This backup has no private key for the CA certificate: $c" }
    }
    Say 'INFO' "Destination : $Destination"

    # ---------------------------------------------------------------- one by one: is it there already?
    # Each PKI of the backup is compared with the pki folder of the destination (file by file, SHA-256) and with the Local Machine certificate
    # store (Root + Intermediate, by thumbprint). A PKI that is there already is not restored.
    $storeSet = Get-BkLocalMachineThumbprints
    $skipPki = @{}; $restorePki = [System.Collections.Generic.List[string]]::new(); $replacePki = [System.Collections.Generic.List[string]]::new()
    Write-Host ''
    Say 'INFO' 'Comparing the PKIs of the backup with this computer, one by one ...'
    foreach ($name in $pkiList) {
        $name = [string]$name
        $mine = @($entries | Where-Object { ([string]$_['path']).StartsWith("data/pki/$name/") })
        $destDir = Join-Path (Join-Path $Destination 'pki') $name
        $same = 0; $diff = 0; $miss = 0
        if (Test-Path -LiteralPath $destDir -PathType Container) {
            foreach ($e in $mine) {
                $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
                if (-not (Test-Path -LiteralPath $to -PathType Leaf)) { $miss++ }
                elseif ((Get-BkHash $to).Sha256 -eq [string]$e['sha256']) { $same++ } else { $diff++ }
            }
        }
        else { $miss = $mine.Count }
        $folderExists = (Test-Path -LiteralPath $destDir -PathType Container)
        $folderComplete = ($folderExists -and $diff -eq 0 -and $miss -eq 0)
        Write-Host ("  PKI {0}" -f $name)
        if (-not $folderExists) { Write-Host '    pki folder    : not there' }
        elseif ($folderComplete) { Write-Host ("    pki folder    : there, all {0} files identical" -f $same) -ForegroundColor Green }
        else { Write-Host ("    pki folder    : there, but {0} identical, {1} different, {2} missing" -f $same, $diff, $miss) -ForegroundColor Yellow }
        # the CA certificates of YOUR PKI (from the decrypted files, not from a list): only these are looked for in the store
        $cas = @($inv.Certificates | Where-Object { $_.Own -and $_.IsCa -and $_.Rel -like "pki/$name/*" } | Group-Object Thumbprint | ForEach-Object { $_.Group[0] } | Sort-Object @{ Expression = { -not $_.SelfSigned } }, Subject)
        $inStore = 0
        foreach ($ca in $cas) {
            $has = $storeSet.Contains($ca.Thumbprint)
            if ($has) { $inStore++ }
            Write-Host ("    {0,-12} : {1}  {2}" -f $(if ($ca.SelfSigned) { 'root' } else { 'intermediate' }), $(if ($has) { 'in Local Machine store' } else { 'NOT in Local Machine store' }), ($ca.Subject -replace '^.*?CN=([^,]+).*$', '$1')) -ForegroundColor $(if ($has) { 'Green' } else { 'Gray' })
        }
        $storeAll = ($cas.Count -gt 0 -and $inStore -eq $cas.Count)
        if ($cas.Count -eq 0) { Write-Host '    store         : (this backup does not list the CA certificates of this PKI: store not compared)' }
        # decision
        if ($folderComplete -and -not $Force) { $skipPki[$name] = 'already in the pki folder (every file identical)'; Say 'OK' "    -> not restored: $($skipPki[$name])." }
        elseif ($folderExists -and -not $folderComplete -and -not $Force) {
            # an older version of your PKI is there: offer the version of the backup (Enter = Y)
            $ans = $true
            if ($Check) { Say 'INFO' "    -> (-Check) would ask: replace this PKI with the version in the backup? [Y/n]" }
            else { $ans = Read-BkYesNo ("    PKI {0} is in the pki folder already ({1} identical, {2} different, {3} missing). Replace it with the version in the backup? The old folder is renamed, not deleted." -f $name, $same, $diff, $miss) }
            if ($ans -eq $true) { [void]$restorePki.Add($name); [void]$replacePki.Add($name); Say 'INFO' '    -> will be replaced with the backup version (the old folder is renamed).' }
            elseif ($ans -eq $false) { $skipPki[$name] = 'you answered N: the pki folder is left as it is'; Say 'WARN' "    -> not restored: $($skipPki[$name])." }
            else { $skipPki[$name] = 'the pki folder has this PKI with different files and nobody can be asked (no keyboard): left alone; use -Yes or -Force to replace it'; Say 'WARN' "    -> not restored: $($skipPki[$name])." }
        }
        elseif ($storeAll -and -not $Force) { $skipPki[$name] = "all $($cas.Count) CA certificates are in the Local Machine certificate store"; Say 'OK' "    -> not restored: $($skipPki[$name]). (Only the certificates are in the store, not the private keys: -Force restores the keys anyway.)" }
        else { [void]$restorePki.Add($name); if ($folderExists) { [void]$replacePki.Add($name) }; Say 'INFO' "    -> will be restored$(if ($folderExists) { ' (the existing folder is renamed first)' })." }
    }

    # the other files (leafcerts, external-ca, csr-signed, *_pki.cnf ...): file by file
    $extra = @($entries | Where-Object { -not ([string]$_['path']).StartsWith('data/pki/') })
    $xReplace = 0; $xWrite = [System.Collections.Generic.List[object]]::new(); $xSame = 0; $xDiff = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $extra) {
        $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $to -PathType Leaf)) { [void]$xWrite.Add($e) }
        elseif ((Get-BkHash $to).Sha256 -eq [string]$e['sha256']) { $xSame++ }
        else { if ($Force) { [void]$xWrite.Add($e) }; [void]$xDiff.Add($e) }
    }
    if ($xDiff.Count -gt 0 -and -not $Force) {
        $ansX = $true
        if ($Check) { Say 'INFO' "(-Check) would ask: replace $($xDiff.Count) other file(s) with the backup version? [Y/n]" }
        else { $ansX = Read-BkYesNo ("{0} other file(s) (leafcerts, external-ca, csr-signed, settings) differ from the backup. Replace them with the backup version? The old files are renamed, not deleted." -f $xDiff.Count) }
        if ($ansX -eq $true) { foreach ($e in $xDiff) { [void]$xWrite.Add($e) }; $xReplace = $xDiff.Count }
        else { Say 'WARN' "$($xDiff.Count) different file(s) are left as they are." }
    }
    if ($extra.Count -gt 0) {
        Write-Host ''
        Say 'INFO' ("Other files (leafcerts, external-ca, csr-signed, settings): {0} in the backup, {1} already there and identical, {2} missing, {3} there but different{4}" -f $extra.Count, $xSame, ($xWrite.Count - $xReplace), $xDiff.Count, $(if ($xDiff.Count -gt 0) { $(if ($Force -or $xReplace -gt 0) { ' (replaced, the old files are renamed)' } else { ' (left alone)' }) } else { '' }))
    }

    $pkiFiles = @($entries | Where-Object { $p = ([string]$_['path']); $restorePki.Contains(($p.Substring(9) -split '/')[0]) -and $p.StartsWith('data/pki/') })
    $toWrite = @($pkiFiles) + @($xWrite)
    Write-Host ''
    if ($toWrite.Count -eq 0) {
        if (@($skipPki.Values | Where-Object { $_ -like 'the pki folder has this PKI*' -or $_ -like 'you answered N*' }).Count -gt 0) { Say 'WARN' 'Nothing was restored: a PKI folder differs from the backup and was left as it is (see above). -Yes or -Force replaces it (the old folder is renamed). Nothing was changed.' }
        else { Say 'OK' 'Nothing to restore: everything in the backup is there already. Nothing was changed.' }
        exit 0
    }
    Say 'INFO' ("To restore    : {0} files ({1} PKI(s): {2})" -f $toWrite.Count, $restorePki.Count, $(if ($restorePki.Count -gt 0) { $restorePki -join ', ' } else { 'none' }))
    if ($Check) { Say 'OK' '-Check: the password is right and every file is valid. Nothing was written.'; exit 0 }

    # ---------------------------------------------------------------- write
    [void][System.IO.Directory]::CreateDirectory($Destination)
    $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
    foreach ($name in $replacePki) {
        $src = Join-Path (Join-Path $Destination 'pki') $name; $new = "$src.before-restore-$ts"
        Move-Item -LiteralPath $src -Destination $new
        Say 'INFO' "Renamed: pki\$name -> $(Split-Path -Leaf $new)"
    }
    foreach ($e in @($xWrite | Where-Object { Test-Path -LiteralPath (Join-Path $Destination (([string]$_['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)) -PathType Leaf })) {
        $old = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        Move-Item -LiteralPath $old -Destination "$old.before-restore-$ts"
        Say 'INFO' "Renamed: $(([string]$e['path']).Substring(5)) -> $(Split-Path -Leaf $old).before-restore-$ts"
    }
    $lockedDirs = 'pki', 'leafcerts', 'external-ca', 'csr-signed'
    $tops = @($toWrite | ForEach-Object { (([string]$_['path']).Substring(5) -split '/')[0] } | Sort-Object -Unique)
    foreach ($t in $tops) {
        if ($t -notin $lockedDirs) { continue }
        $dir = Join-Path $Destination $t
        $fresh = -not (Test-Path -LiteralPath $dir -PathType Container)
        [void][System.IO.Directory]::CreateDirectory($dir)
        if ($RestrictAccess -and $fresh) {
            try {
                & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
                if ($LASTEXITCODE -ne 0) { Say 'WARN' "icacls could not restrict $dir (exit $LASTEXITCODE)." } else { Say 'OK' "Access to $t\ : Administrators and SYSTEM only." }
            }
            catch { Say 'WARN' "icacls could not restrict ${dir}: $($_.Exception.Message)" }
        }
        elseif ($RestrictAccess) { Say 'INFO' "$t\ existed already: its access rights were not changed." }
    }
    foreach ($dr in @($m['directories'])) {
        if (-not $dr) { continue }
        $d = [string]$dr
        if ($d.StartsWith('pki/') -and -not $restorePki.Contains(($d.Substring(4) -split '/')[0])) { continue }
        [void][System.IO.Directory]::CreateDirectory((Join-Path $Destination ($d -replace '/', [System.IO.Path]::DirectorySeparatorChar)))
    }
    $n = 0
    foreach ($e in $toWrite) {
        $rel = ([string]$e['path']).Substring(5)
        $from = Join-Path $opened.Dir (([string]$e['path']) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        $to = Join-Path $Destination ($rel -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $to))
        Copy-Item -LiteralPath $from -Destination $to -Force
        $n++
    }
    Say 'INFO' "$n files written. Checking them against the backup ..."
    $bad = 0
    foreach ($e in $toWrite) {
        $to = Join-Path $Destination (([string]$e['path']).Substring(5) -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $to) -or (Get-BkHash $to).Sha256 -ne [string]$e['sha256']) { Say 'ERROR' "Does not match: $to"; $bad++ }
    }
    if ($bad -gt 0) { Stop-Bk "$bad restored file(s) do not match the backup." 6 }
    Say 'OK' "Restored $n files into $Destination; every file matches the backup."
    foreach ($k in $skipPki.Keys) { Say 'INFO' "Not restored (already there): PKI $k - $($skipPki[$k])" }
    Write-Host ''
    Say 'INFO' 'Next: in the restored folder run  .\pki_setup.ps1 -ListPki  (the PKIs), and  .\pki_setup.ps1 -InstallTrust  to trust them again in the Windows stores.'
    if (-not $RestrictAccess) { Say 'INFO' 'The keys got the access rights of the destination folder. Use -RestrictAccess next time to limit them to Administrators and SYSTEM.' }
}
finally {
    if ($opened) { Remove-Item -LiteralPath $opened.Dir -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
