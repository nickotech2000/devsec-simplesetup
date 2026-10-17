# ============================================================
# PKI Script - Remove-PkiCa.ps1  (STANDALONE: needs no other script)
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 5.1
<#
.SYNOPSIS
    Removes the CA certificates of PKIs that Install-PkiCa.ps1 installed on this Windows machine (one company, several, or all). Run with -Help.
.EXAMPLE
    .\Remove-PkiCa.ps1 -List
.EXAMPLE
    .\Remove-PkiCa.ps1 -Pki raksaka
.EXAMPLE
    .\Remove-PkiCa.ps1 -All
#>
param(
    [string[]]$Pki,
    [switch]$All,
    [string[]]$Org,
    [switch]$List,
    [ValidateSet('Auto', 'Machine', 'User')][string]$Scope = 'Auto',
    [switch]$Check,
    [switch]$Yes,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:KitVersion = '6.4.3'

function Say { param([string]$Level, [string]$Text)
    $c = 'Cyan'; if ($Level -eq 'OK') { $c = 'Green' } elseif ($Level -eq 'WARN') { $c = 'Yellow' } elseif ($Level -eq 'ERROR') { $c = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Text) -ForegroundColor $c
}

if ($Help) {
@'
============================================================
 Remove-PkiCa.ps1  -  take PKIs away again that Install-PkiCa.ps1 installed (Windows)
 Version 6.4.3
 Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email:
                               nicko@nextmantra.com
============================================================
WHAT IT DOES
  Install-PkiCa.ps1 writes a list of every certificate it installed (Local Machine:
  %ProgramData%\PkiTrustKit\installed.tsv,
  Current User: %LOCALAPPDATA%\PkiTrustKit\installed.tsv). This script reads that list and removes
  the certificates of the PKI(s) you name from the Trusted Root and Intermediate stores. Only
  certificates that are in the list (same SHA-1 thumbprint) are removed.
  It needs no package, no password and no other file. It is the "RemoveTrust / RemoveAllTrust" of
  the destination computer.

HOW TO RUN
    .\Remove-PkiCa.ps1 -List                 what the kit installed (company, PKI release, store, `
          name)
    .\Remove-PkiCa.ps1 -Pki raksaka          remove ONE company (every release of it); -Pki `
          agantra,raksaka for several
    .\Remove-PkiCa.ps1 -Pki raksaka -Check   only show what would be removed
    .\Remove-PkiCa.ps1 -All                  remove EVERYTHING the kit installed (all companies)
    .\Remove-PkiCa.ps1 -Org "Raksaka"        no list (or an older kit): remove the certificates `
          whose organization (O=) contains this text
  For the whole machine run it in an ADMINISTRATOR window (Scope Machine); in a normal window it
  works on YOUR certificates (Scope User).

OPTIONS
  -Pki <name,...>   the company short name(s) as shown by -List
  -All              every PKI in the list
  -Org <text,...>   by organization text instead of the list (only with -Pki / -All left out)
  -List             show the list and stop
  -Scope Auto|Machine|User   Auto = Machine in an administrator window, else User
  -Check            show what would be removed, change nothing
  -Yes              do not ask "Remove N certificate(s)?"
  -Help             this text
EXIT CODES   0 done   1 error   2 administrator window needed   5 this Windows is not supported

SUPPORTED WINDOWS: Windows 11 24H2+ (Home, Pro, Pro for Workstations, Education, Pro Education,
Enterprise), Windows Server 2025 and 2022.
  Refused (exit 5, nothing changed): Windows 10 and earlier, Windows 11 before 24H2, Windows Server
  before 2022 and the Chinese, Government, IoT,
  SE and Embedded editions.
============================================================
'@ | Write-Host
    return
}

$exitCode = 0
try {
    Write-Host '============================================================'
    Write-Host ' Remove-PkiCa.ps1 - remove PKIs installed by Install-PkiCa.ps1'
    Write-Host ' Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com'
    Write-Host '============================================================'
    Say 'INFO' "Remove-PkiCa.ps1 version $script:KitVersion"
    $Pki = @(@($Pki) | ForEach-Object { "$_" -split '[,;]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() })
    $Org = @(@($Org) | ForEach-Object { "$_" -split '[,;]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim() })

    # ---- this machine (same rules as Install-PkiCa.ps1)
    $isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $osBuild = 0; $osProduct = ''; $osEd = ''; $osKind = ''
    if ($isWin) {
        try {
            $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $osBuild = [int]$cv.CurrentBuildNumber; $osProduct = [string]$cv.ProductName; $osKind = [string]$cv.InstallationType; $osEd = [string]$cv.EditionID
        } catch { $osBuild = [Environment]::OSVersion.Version.Build }
    }
    if ($env:PKI_FAKE_OS) { $fp = $env:PKI_FAKE_OS.Split(':'); $osKind = $fp[0]; $osBuild = [int]$fp[1]; $osProduct = 'test (PKI_FAKE_OS)'; $osEd = $(if ($fp.Count -gt 2) { $fp[2] } elseif ($osKind -like 'Server*') { 'ServerStandard' } else { 'Professional' }) }
    if ($isWin -or $env:PKI_FAKE_OS) {
        $isServer = ($osKind -like 'Server*')
        $osName = if ($osProduct) { "$osProduct (build $osBuild)" } else { "Windows build $osBuild" }
        if ($osEd) { $osName = "$osName, edition $osEd" }
        $osText = "$osEd $osProduct"
        $osBad = if ($osText -match '(?i)china|chinese|CountrySpecific') { 'a Chinese edition' } elseif ($osText -match '(?i)government|EnterpriseG\b|EnterpriseGN|\bGov\b') { 'a Government edition' } elseif ($osText -match '(?i)IoT') { 'an IoT / IoT Enterprise edition' } elseif ($osText -match '(?i)\bSE\b|Embedded') { 'an SE / Embedded edition' } else { '' }
        $bad = ''
        if ($osBad) { $bad = "$osBad. Specialised Windows editions are NOT supported" }
        elseif ($isServer) {
            if ($osEd -and $osEd -notmatch '^Server(Standard|Datacenter|Solution|Essentials)(Core|Eval|ACor)?$') { $bad = 'this Windows Server edition is NOT supported (Essentials, Standard, Datacenter only)' }
            elseif ($osBuild -lt 20348) { $bad = 'a Windows Server before 2022 is NOT supported' }
            elseif ($osBuild -ge 22000 -and $osBuild -lt 26100) { $bad = 'this Windows Server build is NOT supported (only Windows Server 2022 and 2025)' }
        }
        else {
            if ($osBuild -lt 22000) { $bad = 'Windows 10 and earlier are NOT supported' }
            elseif ($osBuild -lt 26100) { $bad = 'Windows 11 before 24H2 is NOT supported (needs 24H2 = build 26100 or newer)' }
            elseif ($osEd -and $osEd -notmatch '^(Core|CoreN|CoreSingleLanguage|Professional|ProfessionalN|ProfessionalWorkstation|ProfessionalWorkstationN|ProfessionalEducation|ProfessionalEducationN|Education|EducationN|Enterprise|EnterpriseN)$') { $bad = 'this Windows edition is NOT supported' }
        }
        if ($bad) { Say 'ERROR' "This computer is ${osName}: $bad. Nothing was changed."; exit 5 }
    }
    else { Say 'WARN' 'This is not Windows: test mode (the .NET store of this user; the list is read from PKI_KIT_STATE_DIR when it is set).' }

    $admin = $false
    if ($isWin) { $admin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    $machine = $false
    if ($Scope -eq 'Machine') { $machine = $true } elseif ($Scope -eq 'Auto') { $machine = $admin }
    if ($machine -and -not $admin -and -not $List) { Say 'ERROR' 'Scope Machine needs an administrator window: right click PowerShell -> Run as administrator, then run this script again.'; exit 2 }
    $loc = if ($machine) { 'LocalMachine' } else { 'CurrentUser' }
    $stateDir = $env:PKI_KIT_STATE_DIR
    if (-not $stateDir) { if ($machine) { $stateDir = Join-Path $(if ($env:ProgramData) { $env:ProgramData } else { '/var/lib' }) 'PkiTrustKit' } else { $stateDir = Join-Path $(if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME '.local/share' }) 'PkiTrustKit' } }
    $reg = Join-Path $stateDir 'installed.tsv'
    Say 'INFO' ("Scope: {0}.  List: {1}" -f $loc, $reg)

    # ---- the list
    $rows = @()
    if (Test-Path -LiteralPath $reg) {
        foreach ($l in (Get-Content -LiteralPath $reg -Encoding UTF8)) {
            if (-not $l -or $l.StartsWith('#')) { continue }
            $c = $l.Split("`t")
            if ($c.Count -lt 6) { continue }
            $rows += New-Object psobject -Property @{ Pki = $c[0]; Release = $c[1]; Store = $c[2]; Thumb = $c[3].ToUpperInvariant(); Name = $c[4]; Org = $c[5]; Line = $l }
        }
    }
    if ($List -or (-not $All -and $Pki.Count -eq 0 -and $Org.Count -eq 0)) {
        if ($rows.Count -eq 0) { Say 'INFO' 'The list is empty: this kit installed nothing here (or it was removed). Use -Org <organization> to remove by name.' }
        else {
            Say 'INFO' ("{0} certificate(s) of {1} PKI(s) were installed by the kit:" -f $rows.Count, @($rows | ForEach-Object { $_.Pki } | Sort-Object -Unique).Count)
            foreach ($g in ($rows | Group-Object Pki | Sort-Object Name)) {
                Say 'INFO' ("  {0}: {1} certificate(s), PKI {2}" -f $g.Name, $g.Count, ((@($g.Group | ForEach-Object { $_.Release } | Where-Object { $_ } | Sort-Object -Unique)) -join ', '))
                foreach ($r in ($g.Group | Sort-Object Store, Name)) { Say 'INFO' ("      {0,-4} {1}" -f $r.Store, $r.Name) }
            }
        }
        if (-not $List) { Say 'INFO' 'Say what to remove:  -Pki <name>   or   -All   (or -Org <text>).  -Check only shows.' }
        exit 0
    }

    # ---- what to remove
    $pick = @()
    if ($All) { $pick = @($rows) }
    elseif ($Pki.Count -gt 0) {
        $known = @($rows | ForEach-Object { $_.Pki.ToLowerInvariant() } | Sort-Object -Unique)
        foreach ($n in $Pki) { if ($known -notcontains $n) { Say 'ERROR' ("'{0}' is not in the list. Known: {1}" -f $n, $(if ($known.Count) { $known -join ', ' } else { '(empty)' })); exit 1 } }
        $pick = @($rows | Where-Object { $Pki -contains $_.Pki.ToLowerInvariant() })
    }
    # by organization (stores are read; only certificates whose O= contains the text)
    $byOrg = @()
    if ($Org.Count -gt 0) {
        foreach ($sn in 'Root', 'CA') {
            $st = New-Object Security.Cryptography.X509Certificates.X509Store($sn, $loc)
            $st.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            try {
                foreach ($c in $st.Certificates) {
                    $o = ''; if ($c.Subject -match '(?:^|,\s*)O=(?<o>"[^"]*"|[^,]+)') { $o = $Matches['o'].Trim('"').Trim() }
                    foreach ($t in $Org) { if ($o -and $o.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $byOrg += New-Object psobject -Property @{ Pki = '(org)'; Release = ''; Store = $sn; Thumb = $c.Thumbprint.ToUpperInvariant(); Name = $c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false); Org = $o; Line = '' }; break } }
                }
            } finally { $st.Close() }
        }
    }
    $todo = @($pick) + @($byOrg)
    if ($todo.Count -eq 0) { Say 'INFO' 'Nothing to remove.'; exit 0 }
    Say 'INFO' ("{0} certificate(s) to remove from the {1} stores:" -f $todo.Count, $loc)
    foreach ($r in ($todo | Sort-Object Pki, Store, Name)) { Say 'INFO' ("  {0,-10} {1,-4} {2}" -f $r.Pki, $r.Store, $r.Name) }
    if ($Check) { Say 'OK' 'Check finished: nothing was changed.'; exit 0 }
    if (-not $Yes) {
        $a = Read-Host -Prompt ('Remove {0} certificate(s)? (y/N)' -f $todo.Count)
        if ($a -notmatch '^(?i)y(es)?$') { Say 'INFO' 'Cancelled, nothing was changed.'; exit 0 }
    }

    $gone = 0; $absent = 0; $failed = 0; $removedThumbs = @{}
    foreach ($sn in 'Root', 'CA') {
        $mine = @($todo | Where-Object { $_.Store -eq $sn })
        if ($mine.Count -eq 0) { continue }
        $st = New-Object Security.Cryptography.X509Certificates.X509Store($sn, $loc)
        $st.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            foreach ($r in $mine) {
                $hit = @($st.Certificates | Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $r.Thumb })
                if ($hit.Count -eq 0) { $absent++; $removedThumbs[$r.Thumb] = $true; continue }
                try { foreach ($h in $hit) { $st.Remove($h) }; $gone++; $removedThumbs[$r.Thumb] = $true; Say 'OK' ("  removed: {0} ({1})" -f $r.Name, $sn) }
                catch { $failed++; Say 'ERROR' ("  could not remove {0}: {1}" -f $r.Name, $_.Exception.Message) }
            }
        } finally { $st.Close() }
    }
    # read back
    $left = 0
    foreach ($sn in 'Root', 'CA') {
        $st = New-Object Security.Cryptography.X509Certificates.X509Store($sn, $loc); $st.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        try { $have = @{}; foreach ($c in $st.Certificates) { $have[$c.Thumbprint.ToUpperInvariant()] = $true }; foreach ($r in @($todo | Where-Object { $_.Store -eq $sn })) { if ($have.ContainsKey($r.Thumb)) { $left++; Say 'ERROR' ("still in the store: " + $r.Name) } } } finally { $st.Close() }
    }
    # update the list
    if (Test-Path -LiteralPath $reg) {
        $keep = @($rows | Where-Object { -not $removedThumbs.ContainsKey($_.Thumb) } | ForEach-Object { $_.Line })
        if ($keep.Count -eq 0) { Remove-Item -LiteralPath $reg -Force; try { if (@(Get-ChildItem -LiteralPath $stateDir -Force).Count -eq 0) { Remove-Item -LiteralPath $stateDir -Force } } catch { } }
        else { [IO.File]::WriteAllLines($reg, [string[]](@('# pki' + "`t" + 'release' + "`t" + 'store' + "`t" + 'thumbprint' + "`t" + 'name' + "`t" + 'organization' + "`t" + 'scope' + "`t" + 'installedUtc') + $keep)) }
    }
    if ($left -gt 0 -or $failed -gt 0) { Say 'ERROR' ("{0} certificate(s) could not be removed. Run this in an administrator window (Scope Machine) or remove them in certlm.msc / certmgr.msc." -f ($left + $failed)); $exitCode = 1 }
    else { Say 'OK' ("Removed {0} certificate(s) ({1} were already gone). Restart your browser / Office / tools." -f $gone, $absent) }
}
catch { Say 'ERROR' $_.Exception.Message; $exitCode = 1 }
exit $exitCode
