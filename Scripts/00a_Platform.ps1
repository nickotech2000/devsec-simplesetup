# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 00a_Platform.ps1  -  WHERE MAY THE SCRIPTS RUN?  (5.0.0)
#
# Every .ps1 of this project calls  Assert-PkiPlatform  before it does any work (-Help works everywhere).
#
# WINDOWS (checked from the registry: EditionID, InstallationType, build number)
#   Windows 11 24H2 or newer (build 26100 and later: 25H2, 26H2, a future Windows 12 / 13 / RC / Preview) - these editions only:
#       Home, Pro (Professional), Pro for Workstations, Education, Pro Education, Enterprise            -> FULL (classic and quantum)
#   Windows Server 2025 (build 26100 and later): Essentials, Standard, Datacenter (RTM or newer)       -> FULL
#   Windows Server 2022 (build 20348): Essentials, Standard, Datacenter (RTM or newer)                 -> CLASSIC ONLY
#       The generators build the CLASSIC track only (Enterprise Root, Classic Track Root, Q1 / Q2 roots, classic intermediates; FIPS and
#       non-FIPS; DV, OV and EV). The Quantum track (ML-DSA) is not built and a quantum leaf is refused.
#   REFUSED with an error: Windows 10 and earlier, Windows 11 before 24H2, Windows Server before 2022, Windows Server of another build
#       (for example the 23H2 Annual Channel), and these specialised editions in every version: Windows 11 / Server 2025 China (Chinese) editions,
#       Government editions, IoT and IoT Enterprise (also LTSC), SE, Embedded, and every other edition that is not in the lists above.
# LINUX (pwsh on Ubuntu / WSL ...): the same distributions as the .sh scripts: Ubuntu 24 or newer, CentOS Stream 10+, RHEL 10+, Rocky 10+,
#   Oracle Linux 10+, SLES / SLED 15+, openSUSE Leap 15+ / Tumbleweed.   macOS and anything else: refused.
#
# TEST HOOKS (never needed in daily use):  $env:PKI_FAKE_OS = 'Client:26100:Professional'  (Kind:Build:EditionID, Kind = Client | Server)
#                                          $env:PKI_OS_RELEASE_FILE = <os-release file>  (Linux)
#
# Provides : Get-PkiPlatformInfo, Assert-PkiPlatform, $script:PkiPlatform  (Tier: Full | Classic | Refused; ClassicOnly)
# ============================================================
Set-StrictMode -Version Latest

# The version of the whole tool set. Raise it together with the VERSION / 'Version' lines (see docs/PKI-Design-with-FIPS-and-PQC.txt, versioning rule 10.117).
$script:PkiToolVersion = '7.6.8'
function Get-PkiToolVersion { return $script:PkiToolVersion }

function Get-PkiPlatformInfo {
    $r = [ordered]@{ Kind = 'Other'; Tier = 'Refused'; ClassicOnly = $false; Name = ''; Build = 0; Edition = ''; Message = '' }
    $supportedWin = 'Windows 11 24H2 or newer (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and Windows Server 2022 (Essentials, Standard, Datacenter; Server 2022 builds the CLASSIC track only)'
    $fake = [string]$env:PKI_FAKE_OS
    $isWin = ($PSVersionTable.PSVersion.Major -lt 6) -or ($null -ne (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -and $IsWindows)

    if ($fake -or $isWin) {
        $r.Kind = 'Windows'
        $kind = ''; $build = 0; $edId = ''; $prod = ''
        if ($fake) {
            $fp = $fake.Split(':'); $kind = $fp[0]; $build = [int]$fp[1]
            $edId = if ($fp.Count -gt 2) { $fp[2] } elseif ($kind -like 'Server*') { 'ServerStandard' } else { 'Professional' }
            $prod = "test system (PKI_FAKE_OS=$fake)"
        }
        else {
            try {
                $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                $build = [int]$cv.CurrentBuildNumber; $prod = [string]$cv.ProductName
                $edId = [string]$cv.EditionID; $kind = [string]$cv.InstallationType
            }
            catch { $build = [int][Environment]::OSVersion.Version.Build; $kind = ''; $edId = '' }
            # ProductName of Windows 11 can still say "Windows 10" in the registry: the build number decides
            if ($build -ge 22000 -and $prod -like 'Windows 10*') { $prod = $prod -replace 'Windows 10', 'Windows 11' }
        }
        $isServer = ($kind -like 'Server*')
        $r.Build = $build; $r.Edition = $edId
        $r.Name = ("{0} [edition {1}, build {2}]" -f $(if ($prod) { $prod } else { 'Windows' }), $(if ($edId) { $edId } else { '?' }), $build)

        # 1. specialised editions: refused in every version
        $text = "$edId $prod"
        $bad = $null
        if ($text -match '(?i)china|chinese|CountrySpecific') { $bad = 'a Chinese edition' }
        elseif ($text -match '(?i)government|EnterpriseG\b|EnterpriseGN|\bGov\b') { $bad = 'a Government edition' }
        elseif ($text -match '(?i)IoT') { $bad = 'an IoT / IoT Enterprise edition' }
        elseif ($text -match '(?i)Embedded') { $bad = 'an Embedded edition' }
        elseif ($edId -match '(?i)^Cloud' -or $prod -match '(?i)\bSE\b') { $bad = 'Windows 11 SE' }
        if ($bad) { $r.Message = "This is $bad ($($r.Name)). The PKI scripts do not run on specialised Windows editions (Chinese, Government, IoT / IoT Enterprise, SE, Embedded). Supported: $supportedWin."; return [pscustomobject]$r }

        if ($isServer) {
            if ($edId -and $edId -notmatch '^Server(Standard|Datacenter|Solution|Essentials)(Core|Eval|ACor)?$') { $r.Message = "This Windows Server edition is not supported ($($r.Name)). Supported: Essentials, Standard and Datacenter of Windows Server 2022 / 2025."; return [pscustomobject]$r }
            if ($build -ge 26100) { $r.Tier = 'Full' }
            elseif ($build -ge 20348 -and $build -lt 22000) { $r.Tier = 'Classic'; $r.ClassicOnly = $true }
            elseif ($build -lt 20348) { $r.Message = "Windows Server before 2022 is NOT supported ($($r.Name)). Supported: $supportedWin."; return [pscustomobject]$r }
            else { $r.Message = "This Windows Server build is not supported ($($r.Name)): only Windows Server 2022 (RTM, build 20348) and Windows Server 2025 (build 26100 or newer). Supported: $supportedWin."; return [pscustomobject]$r }
        }
        else {
            if ($build -lt 22000) { $r.Message = "Windows 10 and earlier are NOT supported ($($r.Name)). Supported: $supportedWin."; return [pscustomobject]$r }
            if ($build -lt 26100) { $r.Message = "Windows 11 before 24H2 is NOT supported ($($r.Name)): you need Windows 11 24H2 (build 26100) or newer. Supported: $supportedWin."; return [pscustomobject]$r }
            if ($edId -and $edId -notmatch '^(Core|CoreN|CoreSingleLanguage|Professional|ProfessionalN|ProfessionalWorkstation|ProfessionalWorkstationN|ProfessionalEducation|ProfessionalEducationN|Education|EducationN|Enterprise|EnterpriseN)$') {
                $r.Message = "This Windows edition is not supported ($($r.Name)). Supported editions: Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise (24H2 or newer)."; return [pscustomobject]$r
            }
            $r.Tier = 'Full'
        }
        return [pscustomobject]$r
    }

    # Linux (pwsh on a distribution / WSL)
    $uname = ''
    try { $uname = (& uname -s 2>$null) } catch { }
    if ($uname -eq 'Linux') {
        $r.Kind = 'Linux'
        $relFile = if ($env:PKI_OS_RELEASE_FILE) { $env:PKI_OS_RELEASE_FILE } else { '/etc/os-release' }
        $id = ''; $ver = ''; $pretty = ''
        if (Test-Path -LiteralPath $relFile) {
            foreach ($l in (Get-Content -LiteralPath $relFile)) {
                if ($l -match '^ID="?([^"]*)"?$') { $id = $Matches[1] }
                elseif ($l -match '^VERSION_ID="?([^"]*)"?$') { $ver = $Matches[1] }
                elseif ($l -match '^PRETTY_NAME="?([^"]*)"?$') { $pretty = $Matches[1] }
            }
        }
        $major = 0; [void][int]::TryParse(($ver -split '\.')[0], [ref]$major)
        $ok = $false
        if ($id -eq 'ubuntu') { $ok = ($major -ge 24) }
        elseif ($id -in 'centos', 'rhel', 'rocky', 'ol') { $ok = ($major -ge 10) }
        elseif ($id -in 'sles', 'sles_sap', 'sled', 'opensuse-leap') { $ok = ($major -ge 15) }
        elseif ($id -eq 'opensuse-tumbleweed') { $ok = $true }
        $r.Name = "$(if ($pretty) { $pretty } else { 'Linux' }) (ID=$id VERSION_ID=$ver)"
        if ($ok) { $r.Tier = 'Full' } else { $r.Message = "This Linux is not supported ($($r.Name)). Supported: Ubuntu 24 or newer, CentOS Stream 10+, RHEL 10+, Rocky Linux 10+, Oracle Linux 10+, SUSE Linux Enterprise 15+, openSUSE 15+ (Leap, Tumbleweed)." }
        return [pscustomobject]$r
    }
    $r.Kind = 'Other'; $r.Name = $uname
    $r.Message = "This operating system is not supported ($(if ($uname) { $uname } else { 'unknown' })). Supported: $supportedWin; Linux: Ubuntu 24+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE 15+."
    return [pscustomobject]$r
}

function Assert-PkiPlatform {
    # Stops the script (error + exit code 5) when this system is not supported. Sets $script:PkiPlatform / $global:PkiPlatform.
    param([switch]$Quiet)
    $p = Get-PkiPlatformInfo
    $global:PkiPlatform = $p
    $script:PkiPlatform = $p
    if ($p.Tier -eq 'Refused') {
        [Console]::Error.WriteLine("[ERROR] $($p.Message) Nothing was done.")
        exit 5
    }
    if (-not $Quiet) {
        $cs = @(Get-PSCallStack | Where-Object { $_.ScriptName } | Select-Object -Last 1)
        $nm = if ($cs.Count -gt 0) { Split-Path -Leaf $cs[0].ScriptName } else { 'PKI script' }
        Write-Host "[INFO] $nm version $script:PkiToolVersion" -ForegroundColor DarkGray
    }
    if ($p.ClassicOnly -and -not $Quiet) {
        Write-Host "[WARN] $($p.Name): Windows Server 2022 builds the CLASSIC track only (no Quantum / ML-DSA CAs or leaves); FIPS and non-FIPS, DV / OV / EV are available." -ForegroundColor Yellow
    }
}
