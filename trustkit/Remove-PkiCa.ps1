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
$script:KitVersion = '5.3.6'

function Say { param([string]$Level, [string]$Text)
    $c = 'Cyan'; if ($Level -eq 'OK') { $c = 'Green' } elseif ($Level -eq 'WARN') { $c = 'Yellow' } elseif ($Level -eq 'ERROR') { $c = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Text) -ForegroundColor $c
}

if ($Help) {
@'
============================================================
 Remove-PkiCa.ps1  -  take PKIs away again that Install-PkiCa.ps1 installed (Windows)
 Version 5.3.6
 Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
============================================================
WHAT IT DOES
  Install-PkiCa.ps1 writes a list of every certificate it installed (Local Machine: %ProgramData%\PkiTrustKit\installed.tsv,
  Current User: %LOCALAPPDATA%\PkiTrustKit\installed.tsv). This script reads that list and removes the certificates of the PKI(s) you name
  from the Trusted Root and Intermediate stores. Only certificates that are in the list (same SHA-1 thumbprint) are removed.
  It needs no package, no password and no other file. It is the "RemoveTrust / RemoveAllTrust" of the destination computer.

HOW TO RUN
    .\Remove-PkiCa.ps1 -List                 what the kit installed (company, PKI release, store, name)
    .\Remove-PkiCa.ps1 -Pki raksaka          remove ONE company (every release of it); -Pki agantra,raksaka for several
    .\Remove-PkiCa.ps1 -Pki raksaka -Check   only show what would be removed
    .\Remove-PkiCa.ps1 -All                  remove EVERYTHING the kit installed (all companies)
    .\Remove-PkiCa.ps1 -Org "Raksaka"        no list (or an older kit): remove the certificates whose organization (O=) contains this text
  For the whole machine run it in an ADMINISTRATOR window (Scope Machine); in a normal window it works on YOUR certificates (Scope User).

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

SUPPORTED WINDOWS: Windows 11 24H2+ (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise), Windows Server 2025 and 2022.
  Refused (exit 5, nothing changed): Windows 10 and earlier, Windows 11 before 24H2, Windows Server before 2022 and the Chinese, Government, IoT,
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

# SIG # Begin signature block
# MIJENgYJKoZIhvcNAQcCoIJEJzCCRCMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCApBQ7J2fXkJP6x
# yfP253wtKvek5zZIdKCxDSBHy5Vgi6CCPI4wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzCCCDgwggYgoAMCAQICEC/wnA/zwDdlYzgmYE7STJMwDQYJKoZIhvcNAQEL
# BQAwggEKMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYDVQQFExFFRUFSSVJFRy4x
# NzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoM
# E0FnYW50cmEgSW5vdmF0aWYgT1UxGDAWBgNVBAsMD0ludGVybWVkaWF0ZS1DQTEl
# MCMGA1UEAwwcQWdhbnRyYSBFViBSU0EtNDA5NiBHMSBDQSBSNDEbMBkGA1UEKQwS
# Tmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFu
# dHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQwMTkwHhcNMjYxMDE0MDczOTA1
# WhcNMjcxMTE1MDczOTA1WjBtMQswCQYDVQQGEwJFRTEQMA4GA1UECAwHVGFsbGlu
# bjEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdhbnRyYSBJbm92YXRpZiBP
# VTEcMBoGA1UEAwwTQWdhbnRyYSBJbm92YXRpZiBPVTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAKFbev2e6J9ybFSt0oH0hZdH2ahZh+jF6xMfvK46lEMw
# lE4Nut5Ac3FUmJoRpVwu4oCEUZkUFrHmcnJ22Ps5TRcNwlZhCCqEL9UbmGkrytUf
# Oan/LFExlGlZ0R/unwi4de/8XvVSMugRoi0PyI/CVl4hEMKBNB9qMRSQySSON2SH
# glcnVjACK7Fp7fu9I+x5uW3h55a36mMSXKiB1Xe8s9VuLX7Q8Jdsdhk0DcPatCBy
# MARQTHr04H7bqf3vU4aPewJ1/LcKlBpHWVpbla35R3V9pA5CrGkeAH4/V4fendI5
# f8V5zQml8u+UeEVQ4h+HM1lQk9HnZ+L8VNrw5yxGEW7arDVJOIhxXrzDUMJ7lKb+
# 6yNi5ou7NJ2FSzxG0AaOawvulVUEqGK+oblFbzl6AJQj6tFKkPYjbKNz9aRJHSUV
# G+OiOSCiTAPX8qaB0kqNgN9NYqRbnlfCwkq7BJ85m7p9AlnIDeDseCnwMMthPmja
# uqpg/cSN5wQStX0tTsXxJp1JROUz0dLuXjsPj7XI2iG9HjZEB5Cr/s28IfWeSQ0N
# P4SbEGimz7mFZlhUgY91vCWQWQdan391bNyYju+BxNPQ4UYh2DEseXzLAmWlsZi7
# b9qyuevaBBDCB5ixWri6LJgAvrWv4BwhoEeKLAKOeMrafeWO5hdzqPTUkl+Uxq4D
# AgMBAAGjggIzMIICLzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNV
# HSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU7UNGc/tauoRRQYNJYD7VrsCxaIMw
# HwYDVR0jBBgwFoAUfQqouJFjhFteE2U8Qs3fLP8iGj4wge8GA1UdIASB5zCB5DBH
# BgVngQwBATA+MDwGCCsGAQUFBwIBFjBodHRwczovL25leHRtYW50cmEuY29tL3Nl
# Y3VyaXR5L2NlcnRzL2V2LWNwcy5wZGYwSwYJKwYBBAGEjBgBMD4wPAYIKwYBBQUH
# AgEWMGh0dHBzOi8vbmV4dG1hbnRyYS5jb20vc2VjdXJpdHkvY2VydHMvZXYtY3Bz
# LnBkZjBMBgorBgEEAYSMGAEBMD4wPAYIKwYBBQUHAgEWMGh0dHBzOi8vbmV4dG1h
# bnRyYS5jb20vc2VjdXJpdHkvY2VydHMvZXYtY3BzLnBkZjBHBgNVHR8EQDA+MDyg
# OqA4hjZodHRwOi8vY3JsLm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1xMS1l
# di1nMS1yNC5jcmwwfwYIKwYBBQUHAQEEczBxMCsGCCsGAQUFBzABhh9odHRwOi8v
# b2NzcC5uZXh0bWFudHJhLmludGVybmFsMEIGCCsGAQUFBzAChjZodHRwOi8vY3J0
# Lm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1xMS1ldi1nMS1yNC5jcnQwDQYJ
# KoZIhvcNAQELBQADggIBAH2cMoiRHY4uw0dyP9ekla5Hy9fNnh7zdBqS72NatuJ+
# bxiicgKxcFCqRbVsnphgXHRXV+Lr8bhoNG46Ijq6HGVyuemy+6E8jg+CkT4qI0zI
# aScgExBFaVxRo6JmnT/vz2e1hY8fWm61jf0bBV3L6vr3xsfrCF64T7uKw4D5B1ju
# E0Tejsy4zSKObDA4PFASi7cK/5PksNj8A7ajnaOeIJVhqpFOoMQiaRwJ2ulSaSkC
# 5rJsSG29JyXZXXaVwB1rA0nuq8cpLJh77+xXXSJw7nVrlwf6wfflGORNYS3Hgujw
# cgKYCa+dWX6EE+7NS+qAbt40n6kPHqeExT6Z5XYwnE5gPyCHq87A4emQRrxlzaJq
# LX2P63LQMFdMrvjssKOfAEdgx5tbFKcYQDbmTMfCd079D2BHnEuA9nruiA96ItXM
# CEs9TSssy3IOkbzmm0LZlmhEMI4/LwFeHl1MaXfr4w+fw8eU0HQUqCrsS103pLXB
# 7FUsZmWbVVIY6bja6l1e88SG7hu5B84/FOGSakBbviM2bSQldoRxBxVVrVsAdXJu
# lKg7G9b6jRDf9a5cLepaVD+Bg9p5Ods+67SSS1xDcsfGZdof81/1PihnZSh/uOeN
# NI85/ORGq3QPd8IOtfL2FIEiIol1hQa6DkC4eK6BzVMFFdwWDKMQrojsz75JnqoE
# MIII0jCCBrqgAwIBAgIQIC8gOot0KY+b0mJbLp35GjANBgkqhkiG9w0BAQwFADCC
# AQ0xEzARBgsrBgEEAYI3PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVHLjE3MzQ0
# MTMxMQswCQYDVQQGEwJFRTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdh
# bnRyYSBJbm92YXRpZiBPVTEXMBUGA1UECwwOUXVhZHJhbnQtUm9vdHMxKTAnBgNV
# BAMMIEFnYW50cmEgQ2xhc3NpYyBRMSBSb290IENBIEcxIFI0MRswGQYDVQQpDBJO
# aWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0BCQEWFG5pY2tvQG5leHRtYW50
# cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAxOTAgFw0yNjEwMTMxMDUyNTFa
# GA8yMjc2MTAxMzEwNTI1MVowggEKMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYD
# VQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1Rh
# bGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYgT1UxGDAWBgNVBAsMD0lu
# dGVybWVkaWF0ZS1DQTElMCMGA1UEAwwcQWdhbnRyYSBFViBSU0EtNDA5NiBHMSBD
# QSBSNDEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcNAQkB
# FhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQwMTkw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCl4u+x6WZUz26tMXEYzA4P
# 6fpSh7UhL8+JefHcpXT3A92BZQErechPq8AGINFux6DGbjex9XGoOd1P7In7uRqI
# y9OuHPt+QQHCEACSki4BcVjtAAcn3vDQZRDVFoB8JZEXJK1apBn8xajf44oqvMMK
# nQ0sUdGMAmyEEj0RkLe/cGdsd6B+7pzhGCMXS/B28++vZ1ypLWGknSpA3dUZh36P
# 1hzqzfG67MWOZ0XYF21MbNkr7zKe4ESmp9qO1lyZMrUvLLXPfPhtqlRJVEuG9dCb
# VkvPvNjvsK0IuWvntTk93xUa9ZvWy2r39TN6FVwmR/Aazddmr+V7r8fZH4yZJ1pj
# X2iAG7TglMu6Lv6FrVQAGeXTnqz2Io1/BL4JpESSv5or43C4ox2SSdFbh+VkU2vX
# /PE0LbV7eJn/7y2VG7szmI9yt+ynlkhnuY6GjFYB2vTqjUkvxKTTms1v/PbCwuSu
# wsGAjG27Gq0hJIQcl6wVp3lWZGvCT0lwZkHK5uD+1mAoP4i26rZYpyRK7JuXE+ZE
# 2Wk/DFacYWEmksKbRgY+nRis958f5y7S7t1qg63PjMLnAfs/epZ0KIqvlhdMl0a1
# nCwGVt469geMBHCjVQ02PqAV30l+uzhBvex/YWwbkUpfS4JCyi5ApyTpmQoRDim6
# LadwqCD/jmySFWUGZX8JtQIDAQABo4ICKTCCAiUwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFH0KqLiRY4RbXhNlPELN3yz/Iho+
# MB8GA1UdIwQYMBaAFChduOZZ2PzKwCx0DZ2gnnfSdBmqMIHvBgNVHSAEgecwgeQw
# RwYFZ4EMAQEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9z
# ZWN1cml0eS9jZXJ0cy9ldi1jcHMucGRmMEsGCSsGAQQBhIwYATA+MDwGCCsGAQUF
# BwIBFjBodHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzL2V2LWNw
# cy5wZGYwTAYKKwYBBAGEjBgBATA+MDwGCCsGAQUFBwIBFjBodHRwczovL25leHRt
# YW50cmEuY29tL3NlY3VyaXR5L2NlcnRzL2V2LWNwcy5wZGYwSQYDVR0fBEIwQDA+
# oDygOoY4aHR0cDovL2NybC5uZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEtcTEt
# cm9vdC1nMS1yNC5jcmwwgYEGCCsGAQUFBwEBBHUwczArBggrBgEFBQcwAYYfaHR0
# cDovL29jc3AubmV4dG1hbnRyYS5pbnRlcm5hbDBEBggrBgEFBQcwAoY4aHR0cDov
# L2NydC5uZXh0bWFudHJhLmludGVybmFsL2FnYW50cmEtcTEtcm9vdC1nMS1yNC5j
# cnQwDQYJKoZIhvcNAQEMBQADggIBAJP1SFc2V5gsVrmW7OjmxaRY84C1uGGiYQOO
# yZZFp1fV0Fc7LdJPVt0CN3/aWFvcIudhkW9Ks3XB8UMgfx0yIxoCeBmY8DgZ0IPx
# OJWSVKJeMYomZ8wnAJlKwWh3xqYQyRXiUPuTREMbIYKWPap7NLWjqOSY04OKeG0P
# gsTwJL0R2s6UsBC/Rtsd0nEC8WGAcwHECNBn8mGzSKXGqm/jh//PGMf8m1O8xPcG
# 6XkUUxUfp4GzjQODqUTvHnhSgqWr1oBLbGi4B/9lcyAsGo8qmBT5ME4GF1eZGiDn
# M3GyRQZsMLgZcw+JvjDjIrBSWGjPpjN/VqKnNJw9wc/FnuVrt41cxKgMJXA4UhvR
# bsAhPgEPa1Do7mZRZHCI+GDt4UNQd3AF0nPQzO+k1fkudLxnRdJsKcVUnQPBqdmK
# axEdSw7e8SsgB1BGiOuTk0umzp0QsBVGG3ju5SbJbV+zfDcr2a4LSe35zSY+0nqJ
# g/SNjgjCfUT9/Lvquzl4WyNwh5brS90iH1yAuh8g9owGCV10BfWKA8rZ1xhqaVyf
# vbzoVmMQlNCDsWo58T6W41guIYRCrTG3SvRmA8GJVdI1/ghqp3jHJrWOvSIVyNnq
# n6m2b1S2tD+nlX+/ZzGayfXqXD850DriO/POfYV7wokK/h/p1IFrFdErYEl31DkI
# KUl/E8yQMIIMGDCCCACgAwIBAgIQeiwJ3fIGYU9JY1Q0EQG5zTANBgkqhkiG9w0B
# AQ0FADCCAQcxEzARBgsrBgEEAYI3PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVH
# LjE3MzQ0MTMxMQswCQYDVQQGEwJFRTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UE
# CgwTQWdhbnRyYSBJbm92YXRpZiBPVTEUMBIGA1UECwwLVHJhY2stUm9vdHMxJjAk
# BgNVBAMMHUFnYW50cmEgQ2xhc3NpYyBSb290IENBIEcxIFI0MRswGQYDVQQpDBJO
# aWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0BCQEWFG5pY2tvQG5leHRtYW50
# cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAxOTAgFw0yNjEwMTMxMDUyNDla
# GA8yNDI2MTAxMzEwNTI0OVowggENMRMwEQYLKwYBBAGCNzwCAQMTAkVFMRowGAYD
# VQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1Rh
# bGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0aWYgT1UxFzAVBgNVBAsMDlF1
# YWRyYW50LVJvb3RzMSkwJwYDVQQDDCBBZ2FudHJhIENsYXNzaWMgUTEgUm9vdCBD
# QSBHMSBSNDEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1hMSMwIQYJKoZIhvcN
# AQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwOKCszNzIpNTMxOTQw
# MTkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCsKWvO2g37z5Ot77n0
# 08rLq1CO28p9gubOzRJVNTfc91xNYwEKuHedRT1zeKSzwY5+fUhxUR5Zzvroxf+k
# BFX9xO2pvNK2iXvV6Wer3yh6N+zIo9C486HNcU05f71o6d2qPVVhmmJbvrngqrYF
# tbig/S98Htt3LeoQU1DmJuwlst7ZKaj3XT0NxKVngUvGKA9AM/iULfGcsv2pML2M
# icK/K1TBK0zSAvbgZggebWx5ft3EZlsMfF9MKeYifbk0b8rZDD/dmcUczNm1F82n
# 8Jg9J2E7LFRi/HGd1515nrj+FO2UL5mbCeVfBzzPegE5VhyNCessKKd7kt6Mk/qZ
# inL3THincHs64Qxr+8KOeH/v+qdpSq1tDgy2JOfCwtr/7eWNfav7orYtFI2PlH8N
# Szk0VJW2Drndnf0wZItaRFdZaJUffPWr+6eB8EhBwUkzIrPCnTSTIKUD8IpajJzy
# 0iyVpVsS4b0KiAXlKJ3hDyQN9gwVS1CSndAIK7Pe/jyL6aA93wpb/0b1RzZrBdmp
# q+ZNon9PuTIBwGDcRYQKSvh34XOMU5h7Xbzb5MrlwZ6Is/+VZT0N/dMPffEOx+PM
# vJRUA2r945C5JZ2qL1QC7RLiFibLsPZqA6mMXwxieLOxE8NNJOjW4ExHqGzAAMzM
# GwyRhpEUmX/5/wHOQLEGCwMD8QIDAQABo4IDcjCCA24wEgYDVR0TAQH/BAgwBgEB
# /wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFChduOZZ2PzKwCx0DZ2gnnfS
# dBmqMB8GA1UdIwQYMBaAFND4vlby6dM1xkldSNF4LXDh4+3VMIICLQYDVR0gBIIC
# JDCCAiAwRwYFZ4EMAQEwPjA8BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJh
# LmNvbS9zZWN1cml0eS9jZXJ0cy9ldi1jcHMucGRmMD0GBmeBDAECAjAzMDEGCCsG
# AQUFBwIBFiVodHRwczovL25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzMD0G
# BmeBDAECATAzMDEGCCsGAQUFBwIBFiVodHRwczovL25leHRtYW50cmEuY29tL3Nl
# Y3VyaXR5L2NlcnRzMEAGCSsGAQQBhIwYATAzMDEGCCsGAQUFBwIBFiVodHRwczov
# L25leHRtYW50cmEuY29tL3NlY3VyaXR5L2NlcnRzMEwGCisGAQQBhIwYAQEwPjA8
# BggrBgEFBQcCARYwaHR0cHM6Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0
# cy9ldi1jcHMucGRmMEEGCisGAQQBhIwYAQIwMzAxBggrBgEFBQcCARYlaHR0cHM6
# Ly9uZXh0bWFudHJhLmNvbS9zZWN1cml0eS9jZXJ0czBBBgorBgEEAYSMGAEDMDMw
# MQYIKwYBBQUHAgEWJWh0dHBzOi8vbmV4dG1hbnRyYS5jb20vc2VjdXJpdHkvY2Vy
# dHMwQQYKKwYBBAGEjBgBBTAzMDEGCCsGAQUFBwIBFiVodHRwczovL25leHRtYW50
# cmEuY29tL3NlY3VyaXR5L2NlcnRzME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly9j
# cmwubmV4dG1hbnRyYS5pbnRlcm5hbC9hZ2FudHJhLWNsYXNzaWMtcm9vdC1nMS1y
# NC5jcmwwgYYGCCsGAQUFBwEBBHoweDArBggrBgEFBQcwAYYfaHR0cDovL29jc3Au
# bmV4dG1hbnRyYS5pbnRlcm5hbDBJBggrBgEFBQcwAoY9aHR0cDovL2NydC5uZXh0
# bWFudHJhLmludGVybmFsL2FnYW50cmEtY2xhc3NpYy1yb290LWcxLXI0LmNydDAN
# BgkqhkiG9w0BAQ0FAAOCBAEAT4ELi1pdD2mGhC8NO6S/1ViPT+t5g7OZj+/j4bxS
# mLDd5v6lUXulMxb1Ie3Wd3HO4BdDslWP3f2MA4BEtmfDYZmUspF2hiyynCZlDC3A
# PJz71xIybLl7m3T41SmsMHTVgtqrACuUmez91cjFec5eOiFr84mHqwz9YALVmJ1o
# fvpahYeNs9ZUh3XsRUuyvPrasTdFALOczNhe3HG4fr4ExkIiDGBFs772Vn5/UOTK
# 8sMC4uj1cZUcw4Ibs69szUqitsyaztv4vIKOutLyWOdgZwuNUsUWfy5+HwvilfUM
# 3lBB7IwmVxF2q2v2Nq2+4z8F0CFcVi+7Z3yNywVTP1xfJTawPTVxUpdYelCu/8Ov
# lffJOFYDfO2/MbglrYyxcPkw2x24zkHSSUYW247zryjbY2rYQsdNeChRkCl0JN7A
# z90dSAvfkZVnRipu13swu9/FMaZwJ8aI31Vc81zfPpq0lLXkIKtMppU5U8F4GaVa
# YMd9t72aJpb6Ol2z+idCt8Hpd/D5dm+LjfLUK/OjeY31lew7rNzRsvSh2XmELdsK
# FkdGyc/mq0bxEAJOT6UP3URh0yex/iuoamgEeHY3ec1WoDMdYjIlMKL7Fzy+sTLf
# jhkOHU3774MaEtKbkr+dFzAroOVBhoQCnv4kmbs+gZMr4ods1lxIbZ0BEoyN+NXQ
# N7kjgtAFdUBVKwfGMmfyt8LIS4CcRW5atRQO74Z3PrQuz0IhhYydQI3FAtqCbaN2
# sHq1EKI82xEnI8+HcK808wN1pVB/UifsdeA7JKaZ8tEBW4d9Kd9W8UiuK1FPonfp
# +tuaQRT4lFfFOjpJADxQBLZNBlB4DeTkrkHfBTFdE+yJQWF8IDJ/zSR2ZLT8orEj
# ONHDKDkEMOKgfTWBcydZJ0cMyZJg6o+gN5TeMPJB6TTONtDW6nFAv8l4IMXuNU5L
# r6OfCL6b33yXgvSver53MWtEpn4UyHAlKJvExR44jqVfzvoUSDLX4kH72ywJRHIq
# qp/SgSkOK3tD2kp5DIwHDcyp3AyYPFyGaJ8dEIgN6zCHHDvlwT+vjXuayH/bVk0m
# LLc9gNVdEUL3d66Si6tdwARoE8WQ7mHj0TJUhEolniTkwjIEppmABlM0sodn9s+T
# RauFsfY1AEE1ANt5LKnYXOjHLbGB+gtpjQqKHiXVKh2wVzl0nIyammnj8waaGVqj
# LozIEbKsacULJbsYg9oo5GHfECYw63ICVIHF6tFPsx+xxMOQ6dSy9YUXUUNzhQRM
# wXeIv+QrXUD5HdR0auoPyT4SSw0+LQdy1Da+nVqYjWDpiRaNfDYEwn7dsMICjSos
# X+XTG2gNIqw1Po2K1xvNrLbaEWcgDuoPlCBUOSqVw029RDCCDCIwgggKoAMCAQIC
# EAJihrjI0/Vk+DEfNdd/pkQwDQYJKoZIhvcNAQENBQAwgf4xEzARBgsrBgEEAYI3
# PAIBAxMCRUUxGjAYBgNVBAUTEUVFQVJJUkVHLjE3MzQ0MTMxMQswCQYDVQQGEwJF
# RTEQMA4GA1UEBwwHVGFsbGlubjEcMBoGA1UECgwTQWdhbnRyYSBJbm92YXRpZiBP
# VTETMBEGA1UECwwKUm9vdC1DZXJ0czEeMBwGA1UEAwwVQWdhbnRyYSBSb290IENB
# IEcxIFI0MRswGQYDVQQpDBJOaWNrbyBTYXRyaWEgVXRhbWExIzAhBgkqhkiG9w0B
# CQEWFG5pY2tvQG5leHRtYW50cmEuY29tMRcwFQYDVQQUDA4oKzM3Mik1MzE5NDAx
# OTAgFw0yNjEwMTMxMDUyNDhaGA8yNTI2MTAxMzEwNTI0OFowggEHMRMwEQYLKwYB
# BAGCNzwCAQMTAkVFMRowGAYDVQQFExFFRUFSSVJFRy4xNzM0NDEzMTELMAkGA1UE
# BhMCRUUxEDAOBgNVBAcMB1RhbGxpbm4xHDAaBgNVBAoME0FnYW50cmEgSW5vdmF0
# aWYgT1UxFDASBgNVBAsMC1RyYWNrLVJvb3RzMSYwJAYDVQQDDB1BZ2FudHJhIENs
# YXNzaWMgUm9vdCBDQSBHMSBSNDEbMBkGA1UEKQwSTmlja28gU2F0cmlhIFV0YW1h
# MSMwIQYJKoZIhvcNAQkBFhRuaWNrb0BuZXh0bWFudHJhLmNvbTEXMBUGA1UEFAwO
# KCszNzIpNTMxOTQwMTkwggQiMA0GCSqGSIb3DQEBAQUAA4IEDwAwggQKAoIEAQCy
# Drs2SqSfTbVrHWN2Zfk75iIxPQ/qOxAD/Xorcgygpmq8mpLDOY1Otwbi5v7mOQ/D
# 8qNeMp4vsqz2TCFJcQAA6OupMDeNVAlUSagEecwRwfpgrsRg4gVU9QpepX2TpibM
# bmMFWmQsVHI2A/Jhu8YtdFAA+gXy0pw5zOWPNpS4M0AnLqqmUgLqbOYX4IHkTBr/
# K95Sd09oMgOBYIeJjuW+Eg/ythvEseIzitwWGuKibRLEp9LrBmE2QAEByE2SNxor
# ZEi0q0Wa913VmGEpBPbc6qLNzYRndKeZmAOJwGptmtdaPlNllQowf3gAac4TtkGk
# nKwkphFofsEKYTlgMZV49UZzr8PJnDtFYk44zjuwdy3i1MfYWnmVbWrwACLlU70Z
# SBbkEFPQ9O9ptg9OOSLu5UtxIz8hpG/Ng03b33irY1nq+8YrBTTOg/MazV2AH8VO
# d+F/bHAKSCWeZ+PGOeZ+27XFAAlhJdAuNKqfqc8InGQvOyal7CtagWuFHZ9WAJ/O
# 2ca8wSnqQ3WbyvOD6LZnKZfkrd2EjnCP8O3A2FvCvPwDChUR3TiMK+0zJ0qn0FrK
# kxy2SbzI44EjICESdzEgnc6PKTIGuZummQWBKlBSTuhrWXeOA6AhhSdUCkqgmMxQ
# gE6hbCRF2bBWT+S7gW9DmFHuP1UE8RZ8Bpe87YWXk5rwAmgMsYIkK61dQCa4NLPL
# 6Mdg8JkjV4mlW51aRObYVi0FppkTZeYHGjicFxKqCAHMGvqYn8HRHrUIg7vS13uI
# pnuVYXI2Kp+F0cnJTDO2nc1gBj+y0Sb4sBiBVYXidnfj/pFQYpZBDfX8WpTOk9tN
# hanLnj+SMlkhiAXP8sxgGh2Qp24rlJLXocC8Kvq0kwRdI0o08KuchAsRY20fPvoN
# OUmAZ37KIojyRrDJZb+hg8iOU7MYLScnopdnZBmtWQZ34uELDC/y6Ls/XbIg/mNK
# vBwa4eZiYPELEl5vVR7XxA7s9k0WNzux8qCdLSiiqJDg4gvz9/qVSD5MMrYvgT96
# 2v9plk8/bLoP0maHM6WnyAgmiDIQF3Yr+cW/sqxOsty6nyeSvl/Vjzb9d99azw1y
# 0cwIWakyfqVufAG2Vmu3RNOkt43UTwlGNNxpT1ySbrwXx9WguNH6PddCG33OCVnl
# kbQkGq3xn1wzs/okWU3wwl88haATQSTozQDOUb1Ex4Q9Hj9RJr49rKPmXTJcxDbf
# kXcHWYBS2yVZuMldsqI1Uz8UQ8wXCu0TbGjgUAypJn4sC7wHsIRYOcCl3RWO9d8t
# LsS8a7dl+DSpIVNgHIfMLspelB7VtcklPD2fS3T1oWDQDiAMPCZ7y+urlLrrEVVB
# KkPlvV34RRtJS6ui76rVAgMBAAGjggGMMIIBiDASBgNVHRMBAf8ECDAGAQH/AgEC
# MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU0Pi+VvLp0zXGSV1I0XgtcOHj7dUw
# HwYDVR0jBBgwFoAUbJ7gqnlXpySXpKpJQSdq4xxxID8wWgYDVR0gBFMwUTAGBgRV
# HSAAMEcGBWeBDAEBMD4wPAYIKwYBBQUHAgEWMGh0dHBzOi8vbmV4dG1hbnRyYS5j
# b20vc2VjdXJpdHkvY2VydHMvZXYtY3BzLnBkZjBGBgNVHR8EPzA9MDugOaA3hjVo
# dHRwOi8vY3JsLm5leHRtYW50cmEuaW50ZXJuYWwvYWdhbnRyYS1yb290LWcxLXI0
# LmNybDB+BggrBgEFBQcBAQRyMHAwKwYIKwYBBQUHMAGGH2h0dHA6Ly9vY3NwLm5l
# eHRtYW50cmEuaW50ZXJuYWwwQQYIKwYBBQUHMAKGNWh0dHA6Ly9jcnQubmV4dG1h
# bnRyYS5pbnRlcm5hbC9hZ2FudHJhLXJvb3QtZzEtcjQuY3J0MA0GCSqGSIb3DQEB
# DQUAA4IEAQCMwFeVD4MJdfiH+XWe6pZeY82sBaj0otXM+ZPT8ayKKV9E9oPbW8JE
# m3TkdmIPAckQf7xcxLbKwfq3UHeH/e+ijl6vYOzD3nK1YygvL0YZrOZQoH13HW2t
# LQqi0KxfusBbniMX5LHRpJaHv8sLc/vhV01dLU0xijT9neInYEItaOrYG85msi67
# /LLYMY5Ld5/U/GbIx+kaUC1m0K+OXXWh089vAYSYoFyhKqGZaQhP42nn+X0jb02K
# dwDV4Hu/dloXbrSSG2owHnebtQbV19jmQmj8S4WQ5LGfq4DnU/j0FqxRe7KlJ1Gy
# /dkBUp0YI9TXnvcFcjLNHuRFE9ErE70/2R6TbzHVlqBJJjHzbpSwGY2Q9SvhG/4D
# eMDMu1xUd58Nn2Id2eGq56zDccH+RQwuDhFdQZvBzryhIsv8yqP7+kaD95BG1gpJ
# fxykc+IPQuPvNCxs+K2/rMO1ZcM9WYk7MyNYB+QLaT7QcFXW1i2ySq9NODvY2yuE
# qm4FLN/5Kz2BPtfHHPco0yRT2V2FHAS53r1WYqxICP3+qFJeuD60XjebDFt+J4V6
# /QN7L01rysLAbPEjbTR90fA9QVZ8Bo5BvPBdb5dPdawLl/Uw2EQQqAm3YVsCKmNe
# /dTuX0/zqrrlzqNN1YVHk0ZbWRrFmC/cWk2cHU02XrXB+Oo11FrCst6H98r5WaXI
# ahIeXdmL1X/cEh9F25Ltada7BVLSk0mZmRjX13WwUmwRQwT5p1uO2cMP7hO/ZBTp
# OOAsq6fPM6uIUhYQ1R4lYQ/L/6iXlFn97zsjRRGR5KVcekVqzcrp8McouLuYLTPa
# XtxQS9T8WnJictY7Nbaa+UcwdOaTsYnyJnsbigW1aAioR9H7+POpN2cdgvGqF8T5
# Fd6c9GW4e3AXDJUfuh1yprV2Nf5mBucBPRWtsj+DHoE1Ll7Y9iqhbuilRsjedt3a
# PVOwc3mdlU+UuC/QdJAA1wsTBBYzc6rhdid2AvJ9nA7PvBBv/x6gCDX1TuuYiNqU
# vPc2IXOLqoNa4mmq+Abq4QbmTJDcpOkzdrS54Z8VFxp6x5e59eD3ocC6Z7pu3s4B
# Nc02+TNCSbCUlT26cdCYGykDzyRp/ElJggSNjuYqr9T03+gOTjnDBheU9kTKoXXV
# V8+CZsOx40OuOQyCU+m8NlxI4QHNpbsekuIdVFKRoOTIb+zGJYWhIXs2RtkVg+bh
# FxMiveoY5IhWpL+fvXFdet0rPdJM0rOiKwYOuyCME52fCarfKb6JqN1l6Ittw9UY
# zPVI1UatO1Ar4Sz/xFo7LFFa3j30qz7iy2tsWqODD5qoKYy4Nbkxa5YmQ0oSaV94
# 4VDVMUObQJ4OgHTo7jip9UEaZ+eLQAtJMYIG/jCCBvoCAQEwggEgMIIBCjETMBEG
# CysGAQQBgjc8AgEDEwJFRTEaMBgGA1UEBRMRRUVBUklSRUcuMTczNDQxMzExCzAJ
# BgNVBAYTAkVFMRAwDgYDVQQHDAdUYWxsaW5uMRwwGgYDVQQKDBNBZ2FudHJhIElu
# b3ZhdGlmIE9VMRgwFgYDVQQLDA9JbnRlcm1lZGlhdGUtQ0ExJTAjBgNVBAMMHEFn
# YW50cmEgRVYgUlNBLTQwOTYgRzEgQ0EgUjQxGzAZBgNVBCkMEk5pY2tvIFNhdHJp
# YSBVdGFtYTEjMCEGCSqGSIb3DQEJARYUbmlja29AbmV4dG1hbnRyYS5jb20xFzAV
# BgNVBBQMDigrMzcyKTUzMTk0MDE5AhAv8JwP88A3ZWM4JmBO0kyTMA0GCWCGSAFl
# AwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIDg/OJ0Kt4UtaajW6AshWVYeLCg6G5BaouBjSNyiWMuyMA0G
# CSqGSIb3DQEBAQUABIICABXyZrsqc4pK8zAQX45qp+pnJWrQBQXoX8fTo03aDQnn
# Q5YF8OXNNIJnnPEnIpdoUlHXUP00s2JUeEwoS2LY6vxvdUcrPd5yCFKOlKEeF2wC
# aocRqXzhezqivW5QCtuattnQcBVn8lfmizwpbnlwjZshx3EUur8u8myXnZoRkpE+
# RGdCo7KIuNmCvRwv1/o3LRbzaCN+hVmzzKuvTF7mw0vLixYL60SjP7yuvrcQgy1l
# NrM14JeoHN63J95kN3wxsqk9CsXTwnweJRQzHdZrxE4Ro0jSIWW4tnrY9uvDIQlU
# wrT+25bSsD3UIPmSJkAGb+5Ycmp9ov3DywPS5dNxwpV5C6B/4rCMB+ExfzN4/a/k
# 0uYXh/a3ibRVWSbriuL3Bsj9u5zs4SbmG4G0MqGTFH5EphWBzi5Em7HLgfwRvXnm
# /V+5d368KDRpshII0op/quMZHuhQogUg1QIx9Tnfd0iRAjG4EiCw7PPcuOuxElpw
# XVCA6wh+hTwTsTmGSLkwvdzkQ6YSI2rG0cT/66ZN8HWTqyI/tQqQbbYEIxZNqoTp
# QPNLYw+uhAh33celbU5hBZw6KQcVfppKkj9VJLrpXYC4GVQdZ4TsLMr6mI4ns3cP
# MFvbKEDNgc5Ja2a68tD5+b9nNvg2hQUoweW6Yi+5Rc3KdGNfJhA2accYLgEZrSCM
# oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/c
# M09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxNDA3NTMyN1owLwYJKoZIhvcN
# AQkEMSIEIHyi63SplZjuE4EorzNUmx7lt3Y8opQZ10z7Xt0CiJthMA0GCSqGSIb3
# DQEBAQUABIICAHxgvirSyoPwhyqHUShAr6Qw3tqjkT4f73X8rPJsy6HSt/UNMies
# 19xBkcZm0N6gUrWXAJhm8h0M4HbEh1zwNscCQUCi6Ph+yhJtVWAoDq1XD4Vmgf6V
# 20fBdnwRRK/0v7L3UttHPNf/Pc+qZqcHtcNKWPYu8pHIoqjQv04rvXaElygPch3b
# UhnSbUGpWemxQfF8Cax/4PWWQrm5sxmLrmcYOYbkcp8Syn8tChJ3loWZkkstwnpV
# lNDRUGPZ8ByuAhsOBET/4AU7UFgPUwn/TZxFSakbIFw+4gf4EEMQ3bVeBLeL84v0
# mrccRAqQhWNGhZbm3TM70jJXGjUXQARvZCCdhzaFxR10L1fdcLr5T53hbQrAMOX6
# x9p7xSgQXORSJ8aCMGsQBfDTh/prjqk7YshvRc9DKL4s0bnH9H0YsqzYuM816n4d
# XjnVeRdnXsTF8Eu21wGRcfJqMobTov63k1sLl+MeDGQQXkS04LU+O7EUCWPwb97c
# 6klRikUFYtAcafOX2kLkJn5Zdm82ZrFV5PwFO3A1DPvU7RKaLWhTs5ifm5ve0xFW
# IHcldby9GrTTOyqyCP9ecOk5QwqYSbR6JJ4J6szMKzo5BVcX/LdDVslBioIfDLVG
# 8DulVspsc27LUXqHcVcd6nvfIhLKi0eTX0Rk+H7FqmpTbyiNWyKqmX3f
# SIG # End signature block
