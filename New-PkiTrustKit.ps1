# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 7.0
<#
.SYNOPSIS
    Makes the "trust kit" zips: the CA certificates of the PKI (roots + intermediates, NO keys) with ONE small standalone installer per
    platform, for people who only need to TRUST the PKI (junior developers, QA, customer testers): Windows, Ubuntu, Red Hat family, SUSE family.
    Full help: .\New-PkiTrustKit.ps1 -Help      Manual: docs\PkiTrustKit-MANUAL.txt
.EXAMPLE
    .\New-PkiTrustKit.ps1 -All
.EXAMPLE
    .\New-PkiTrustKit.ps1 -Target Windows,Ubuntu -Release 2
.EXAMPLE
    .\New-PkiTrustKit.ps1 -All -Pki agantra,raksaka          # ONE kit with the PKIs of two companies in ONE .certpacked
.EXAMPLE
    .\New-PkiTrustKit.ps1 -All -AllProfiles                  # every company, every release, in ONE .certpacked
.EXAMPLE
    .\New-PkiTrustKit.ps1 -All -AllReleases        # every system, and EVERY PKI of the project (all releases R1..Rn and all NoCR-R1..NoCR-Rn)
#>
param(
    # which company's PKI - ONE name, or SEVERAL for one kit: -Pki agantra,raksaka (default: agantra; names = the *_pki.cnf files next to the scripts; list: .\pki_setup.ps1 -ListPki)
    [Alias('Pki')][ArgumentCompleter({ param($c, $p, $w) $s = (Get-Command $c -ErrorAction SilentlyContinue).Source; $d = if ($s) { Split-Path -Parent $s } else { $PWD.Path }; Get-ChildItem -LiteralPath $d -Filter '*_pki.cnf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '_pki\.cnf$', '' } | Where-Object { $_ -like "$w*" } })][string[]]$PkiProfile,
    [ValidateSet('Windows', 'Ubuntu', 'Redhat', 'SUSE')][string[]]$Target,
    [switch]$All,
    [Alias('AllPki')][switch]$AllReleases,
    [ValidateRange(1, 99)][int]$Release,
    [switch]$NoCaRevocationInfo,
    [string]$PkiRoot,
    [string]$PkiName,
    [switch]$AllProfiles,
    [string]$OutDirectory,
    [string]$PackagePassword,
    [switch]$SelfExtract,
    [switch]$Force,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$script:Version = '5.3.5'

if ($Help) {
@'
============================================================
 New-PkiTrustKit.ps1 - trust kits (CA certificates + a standalone installer) for Windows, Ubuntu, Red Hat family, SUSE family
 Version 5.3.5
 Author : Nicko Satria Utama     Company: Agantra Inovatif OU (NextMantra)     Email: nicko@nextmantra.com
============================================================
FOR WHOM
  People who only need to TRUST the PKI: junior developers, QA, customer testers. They do not sign or issue anything and need no key.
  They get ONE zip for their system, unzip it, run ONE script, give the password. That is all.

WHAT YOU GET (in a new folder with a unique name inside .\transport\)
  transport\pki-trust-<pki-name>-<unique>-<date>-<time>\
      windows-pki-<pki-name>-<unique>-<date>-<time>.zip     Install-PkiCa.ps1  Remove-PkiCa.ps1  New-PkiCsr.ps1  Prepare-Computer.ps1  +  <name>.certpacked  (AES-256)
      ubuntu-pki-<pki-name>-<unique>-<date>-<time>.zip      install-pki-ca.sh  remove-pki-ca.sh  new-pki-csr.sh  prepare-computer.sh  +  <name>.certpacked  (ZipCrypto, see below)
      (Certificate request tools: New-PkiCsr.ps1 / new-pki-csr.sh make a key and a certificate request step by step; Prepare-Computer.ps1 / prepare-computer.sh install (PowerShell 7 on Windows,) OpenSSL and Python and put them on the PATH. Manual: docs\NewPkiCsr-MANUAL.txt)
      redhat-pki-...zip     suse-pki-...zip                 the same for the Red Hat family and the SUSE family
      PASSWORD.txt                                          the password of the .certpacked (send it by ANOTHER way than the zips)
      README.txt                                            what to tell the people
  <pki-name> = <PkiName>-r<release> (or <PkiName>-nocr-r<release>, <PkiName>-all with -AllReleases; several companies: agantra-raksaka, more than three: multipki, -AllProfiles: allpki-all);
  <unique> = 6 random characters, the same for the whole run.

SEVERAL PKIs IN ONE KIT  (5.1.0)
  A kit holds ONE .certpacked, and that .certpacked can hold as many PKIs as you choose - the PKIs of several companies, several releases of each:
      -Pki agantra,raksaka       the latest release of each company          -Pki agantra,raksaka -AllReleases   every release of those companies
      -AllProfiles               every company that has a PKI, every release (implies -AllReleases)
  The installer opens the .certpacked and installs EVERY PKI in it in one run (and writes down what it installed). certpack.tsv names the company and
  the PKI folder of each certificate. A company in -Pki that has no PKI built yet stops the run (exit 4): build it first with pki_setup.ps1 -Pki <name>.

TAKING A PKI AWAY AGAIN ON THE DESTINATION  (5.1.0)
  Every zip also holds a remove script: Remove-PkiCa.ps1 (Windows) / remove-pki-ca.sh (Linux). It reads the list the installer wrote and works like
  RemoveTrust / RemoveAllTrust of the PKI machine, without any package or password:
      Remove-PkiCa.ps1 -List | -Pki raksaka | -Pki agantra,raksaka | -All | -Org "Raksaka" [-Check] [-Scope Machine|User] [-Yes]
      remove-pki-ca.sh --list | --pki raksaka | --all | --org raksaka [--check] [--keep-files] [--yes]

THE INSTALLERS (standalone: they need none of the other scripts of this project)
  Windows (Install-PkiCa.ps1): Windows PowerShell 5.1 or PowerShell 7, Windows 10 / 11. In an ADMINISTRATOR window it installs into the
     Local Machine stores, in a normal window into the Current User stores. Every root (top, track, quadrant) -> Trusted Root Certification
     Authorities, every intermediate -> Intermediate Certification Authorities. An older version of the same PKI (same organization) is
     removed and replaced. When it is done the extracted files, the script and the .certpacked are deleted: only the zip stays.
     -Firefox: Firefox is told to use the Windows certificates. -Check: only show.
  Both installers write a list of what they installed (Windows: %ProgramData%\PkiTrustKit\installed.tsv or %LOCALAPPDATA%\PkiTrustKit; Linux: /var/lib/pki-trust-kit/installed.tsv).
  Linux (install-pki-ca.sh): the roots go to the system store of the distribution (ca-certificates): Ubuntu / Debian
     /usr/local/share/ca-certificates + update-ca-certificates; RHEL family /etc/pki/ca-trust/source/anchors + update-ca-trust;
     SUSE /etc/pki/trust/anchors + update-ca-certificates. The package is opened into the folder pki/ next to the script; the zip and pki/ stay.
     --firefox: Firefox profiles of the user. --check: only show.

PARAMETERS
  -Target <list>      Windows, Ubuntu, Redhat, SUSE (any of them, comma separated)       -All   all four
  -Release <n>        the release of the PKI to pack (default: the latest)               -NoCaRevocationInfo   the NoCR family
  -Pki <a,b,...>     the company/companies: one name, or several for one kit (5.1.0). Default agantra.
  -AllProfiles        the PKIs of ALL companies, every release (5.1.0)
  -AllReleases        every release (R1, R2 ...) AND every NoCR release (NoCR-R1, NoCR-R2 ...) of the chosen company/companies found in .\pki\
   (alias -AllPki)    (an old flat PKI in pki\ itself too). All of them go into ONE .certpacked; the installer installs them all in one run.
                      The kit is named <PkiName>-all. Not combined with -Release, -NoCaRevocationInfo, -PkiRoot.
  -PkiRoot <folder>   one PKI folder made by pki_setup.ps1 (default: the latest release in .\pki\)
  -PkiName <text>     the name in the file names (default agantra); letters, digits and - only
  -OutDirectory <dir> where the run folder is made (default .\transport)
  -PackagePassword    the password (default: a strong one is generated and written to PASSWORD.txt)
  -SelfExtract        ALSO make a self-extracting file of every zip (optional): Windows  windows-pki-...-selfextract.cmd  (double click: unpacks into the folder of the file),
                      Linux  ubuntu-pki-...-selfextract.sh  (bash file.sh: unpacks into the CURRENT folder, or --dir F). They only EXTRACT: the PKI is still installed by the
                      script that comes out (Install-PkiCa.ps1 / install-pki-ca.sh): the installer itself is never self-extracting.
  -Force              overwrite an existing run folder (the names are unique: normally not needed)
  -Help               this text

ABOUT THE PASSWORD
  The package holds only PUBLIC certificates. The password is a gate against a wrong or changed package, not a secret-keeper: Linux packages use
  ZipCrypto (opened by python3 / unzip / 7z that every distribution has; AES-256 would need 7-Zip), Windows packages use AES-256.
  There is no private key in any file of the kit.

SUPPORTED SYSTEMS (checked by the installers; anything else is REFUSED with an error, nothing is changed, exit 5)
  Windows : Windows 11 24H2 or newer (build 26100 and later: 25H2, 26H2 ...) and Windows Server 2025 = everything is installed.
            Windows Server 2022 = only the CLASSIC root and intermediate CAs are installed (the post-quantum ones are skipped).
            Refused: Windows 10 and earlier, Windows 11 before 24H2, Windows Server before 2022.
  Linux   : Ubuntu 24.04 / 26.04 or newer; CentOS Stream 10+, RHEL 10+, Rocky Linux 10+, Oracle Linux 10+; SUSE Linux Enterprise 15+ (15, 16 ...);
            openSUSE 15+ (Leap 15, 16 ..., Tumbleweed). Every other distribution or older version is refused.

EXIT CODES   0 ok   1 error   4 PKI folder not found   (the installers: 5 = this system is not supported)
============================================================

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
. (Join-Path $PSScriptRoot 'scripts/00b_Profiles.ps1')

function Write-Msg { param([string]$Text, [string]$Level = 'INFO') $c = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Cyan' } }; Write-Host "[$Level] $Text" -ForegroundColor $c }

Write-Host '============================================================'
Write-Host 'Author : Nicko Satria Utama'
Write-Host 'Company: Agantra Inovatif OÜ (NextMantra)'
Write-Host 'Email  : nicko@nextmantra.com'
Write-Host '============================================================'

# ---------------------------------------------------------------- what to build
# defaults from pki_tools.cnf [ trustkit ] (only when the command line did not say)
if (-not $All -and -not $Target) { $cfgT = Get-PkiToolSetting -Section 'trustkit' -Key 'Targets' -Default ''; if ($cfgT) { $Target = @($cfgT -split '[,;\s]+' | Where-Object { $_ }) } }
if (-not $SelfExtract -and ((Get-PkiToolSetting -Section 'trustkit' -Key 'SelfExtract' -Default 'false') -match '^(?i)(true|yes|1|on)$')) { $SelfExtract = [System.Management.Automation.SwitchParameter]::new($true) }
if ($All) { $Target = @('Windows', 'Ubuntu', 'Redhat', 'SUSE') }
if (-not $Target -or @($Target).Count -eq 0) { Write-Msg 'Say for which systems: -Target Windows,Ubuntu,Redhat,SUSE  or  -All   (see -Help)' 'ERROR'; exit 1 }
$Target = @($Target | Select-Object -Unique)
# which company's PKI: -Pki <name>  or  -Pki name1,name2 (several companies in ONE kit)  (default: DefaultPki of pki_tools.cnf = agantra); -AllProfiles = the PKIs of ALL companies
$rel01c = Join-Path $root 'scripts/01c_Releases.ps1'
$profNames = @(@($PkiProfile) | ForEach-Object { "$_" -split '[,;\s]+' } | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)    # pwsh -File passes a comma list as ONE string
if ($profNames.Count -eq 0) { $profNames = @('') }
$profiles = [System.Collections.Generic.List[object]]::new()
try { foreach ($n in $profNames) { [void]$profiles.Add((Resolve-PkiProfile -ScriptRoot $root -Name $n)) } } catch { Write-Msg $_.Exception.Message 'ERROR'; exit 1 }
$profName = $profiles[0].Name
$multiPki = ($AllProfiles -or $profiles.Count -gt 1)
if ($AllProfiles) { $AllReleases = [System.Management.Automation.SwitchParameter]::new($true) }     # every PKI of every company = every release of every one
if (-not $PkiName) { $PkiName = if ($AllProfiles) { 'allpki' } elseif ($profiles.Count -gt 3) { 'multipki' } else { ($profiles | ForEach-Object { $_.Name }) -join '-' } }
if ($PkiName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]*$') { Write-Msg '-PkiName: letters, digits and - only.' 'ERROR'; exit 1 }
$PkiName = $PkiName.ToLowerInvariant()

# ---------------------------------------------------------------- which PKI(s)
# $pkis = the PKI folders that go into the kit (ALL of them end up in ONE .certpacked): one (the latest, or -Release / -NoCaRevocationInfo / -PkiRoot),
# or the latest of each -Pki a,b,c, or ALL releases (-AllReleases) of the chosen PKI(s), or everything of every company (-AllProfiles)
$pkis = [System.Collections.Generic.List[object]]::new()
if (-not (Get-Command Write-PkiLog -ErrorAction SilentlyContinue)) { function Write-PkiLog { param([string]$Message, [string]$Level = 'INFO') Write-Msg $Message $Level } }
if (-not (Test-Path -LiteralPath $rel01c)) { Write-Msg "scripts\01c_Releases.ps1 not found: $rel01c" 'ERROR'; exit 1 }
. $rel01c
function Add-KitPki { param([string]$Path)
    $fi = Get-PkiFolderInfo -Path $Path
    $legacy = ($null -eq $fi -or [int]$fi.Release -le 0 -or (Split-Path -Leaf $Path) -notmatch '^pki-')
    $prof = if ($null -ne $fi) { [string]$fi.Profile } else { $profName }
    $folder = Split-Path -Leaf ($Path.TrimEnd('\', '/'))
    if ($folder -eq 'pki' -or $folder -match '^(R|NoCR-R)\d+$') { $folder = "$(Get-PkiFolderToken -Profile $prof)-$($folder.ToLowerInvariant())" ; $folder = "pki-$folder" }     # old layouts: a unique, readable folder name
    $rel = if ($null -ne $fi) { [int]$fi.Release } else { 0 }
    $nocr = ($null -ne $fi -and [bool]$fi.NoCr)
    $label = if ($rel -le 0) { "$prof old layout (pki\)" } else { "$prof $(if ($nocr) { 'NoCR ' })R$rel" }
    [void]$pkis.Add([pscustomobject]@{ Path = $Path; Folder = $folder; Profile = $prof; Release = $rel; NoCr = $nocr; Label = $label })
}
if ($multiPki -and ($PkiRoot -or $Release -or $NoCaRevocationInfo)) { Write-Msg 'Several PKIs in one kit (-Pki a,b or -AllProfiles): do not combine it with -PkiRoot, -Release or -NoCaRevocationInfo (the latest release of each PKI is taken; -AllReleases takes every release).' 'ERROR'; exit 1 }
if ($AllReleases) {
    if ($PkiRoot -or $Release -or $NoCaRevocationInfo) { Write-Msg '-AllReleases takes every release of the chosen PKI(s): do not combine it with -PkiRoot, -Release or -NoCaRevocationInfo.' 'ERROR'; exit 1 }
    $want = if ($AllProfiles) { @('') } else { @($profiles | ForEach-Object { $_.Name }) }
    foreach ($w in $want) {
        foreach ($i in @(Get-PkiInstalledPkis -ScriptRoot $root -Profile $w)) {
            if (-not (Test-Path -LiteralPath (Join-Path $i.Path 'publish') -PathType Container)) { continue }
            Add-KitPki -Path $i.Path
        }
    }
    if ($pkis.Count -eq 0) { Write-Msg "No PKI found in $(Join-Path $root 'pki') (no publish\ inside any release). Build one: .\pki_setup.ps1" 'ERROR'; exit 4 }
    Write-Msg ("ALL releases of {0}: {1}" -f $(if ($AllProfiles) { 'every company' } else { ($profiles | ForEach-Object { $_.Name }) -join ', ' }), (($pkis | ForEach-Object { $_.Label }) -join ', ')) 'INFO'
    $kitName = "$PkiName-all"
}
elseif ($multiPki) {
    foreach ($pr in $profiles) {
        $choice = Resolve-PkiRootChoice -ScriptRoot $root -NoCr $false -NoCrExplicit $false -Release 0 -Mode Use -Profile $pr.Name
        if (-not $choice.Exists -or -not (Test-Path -LiteralPath (Join-Path $choice.Path 'publish') -PathType Container)) { Write-Msg "No PKI is built for '$($pr.Name)' yet. Build it: .\pki_setup.ps1 -Pki $($pr.Name) -InstallTrust   (or leave it out of -Pki)" 'ERROR'; exit 4 }
        Add-KitPki -Path $choice.Path
    }
    Write-Msg ("The latest release of each PKI: {0}" -f (($pkis | ForEach-Object { $_.Label }) -join ', ')) 'INFO'
    $kitName = $PkiName
}
else {
    $pkiDir = $PkiRoot; $rel = 0; $nocr = [bool]$NoCaRevocationInfo
    if (-not $pkiDir) {
        $choice = Resolve-PkiRootChoice -ScriptRoot $root -NoCr $nocr -NoCrExplicit $nocr -Release $(if ($Release) { $Release } else { 0 }) -Mode Use -Profile $profName
        $pkiDir = $choice.Path; $rel = [int]$choice.Release; $nocr = [bool]$choice.NoCr
        if ($choice.Exists) { Write-Msg "PKI: release R$rel$(if ($nocr) { ' (NoCR)' })  $pkiDir" 'INFO' }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $pkiDir 'publish') -PathType Container)) { Write-Msg "PKI folder not found (no publish\ inside): $pkiDir   (-PkiRoot <folder>, or build one: .\pki_setup.ps1)" 'ERROR'; exit 4 }
    Add-KitPki -Path $pkiDir
    $one = $pkis[0]
    $kitName = if ($one.Release -gt 0) { "$PkiName-$(if ($one.NoCr) { 'nocr-' })r$($one.Release)" } else { $PkiName }   # NOT $pkiName (the parameter $PkiName): PowerShell variables are case-insensitive
}

# ---------------------------------------------------------------- run folder, names, password
$unique = [guid]::NewGuid().ToString('N').Substring(0, 6)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$base = if ($OutDirectory) { $OutDirectory } else { Get-PkiTransportFolder -Root $root }
$runDir = [System.IO.Path]::GetFullPath((Join-Path $base "pki-trust-$kitName-$unique-$stamp"))
if ((Test-Path -LiteralPath $runDir) -and -not $Force) { Write-Msg "Exists: $runDir (use -Force)" 'ERROR'; exit 1 }
[void][System.IO.Directory]::CreateDirectory($runDir)

function New-KitPassword {
    $a = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $b = 'abcdefghijkmnopqrstuvwxyz'; $d = '23456789'
    $all = $a + $b + $d
    $groups = for ($g = 0; $g -lt 5; $g++) { -join (1..4 | ForEach-Object { $all[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($all.Length)] }) }
    $pw = $groups -join '-'
    # at least one upper, lower, digit
    if ($pw -cnotmatch '[A-Z]' -or $pw -cnotmatch '[a-z]' -or $pw -notmatch '[0-9]') { return New-KitPassword }
    return $pw
}
$generated = $false
$pw = $PackagePassword
if ([string]::IsNullOrEmpty($pw)) { $pw = New-KitPassword; $generated = $true }
elseif ($pw.Length -lt 12) { Write-Msg 'The password you gave is short: fine for a lab, but without -PackagePassword a strong one is generated.' 'WARN' }

# ---------------------------------------------------------------- ONE .certpacked with ALL the selected PKIs (CA certificates only, no key)
# Built here from the PKI folders (their pki-manifest.json): flat names ca/roots/<folder>-<slug>.crt, so the installers of older kits can read it too.
# certpack.tsv has two extra columns at the end: pki (the company short name) and release (the PKI folder).
$PkiModuleSet = 'Transport'
. (Join-Path $root 'scripts/PkiModules.ps1')
Initialize-PkiMinimalContext -PkiRoot (Join-Path $root 'pki')
$work = Join-Path ([System.IO.Path]::GetTempPath()) "trustkit-$([guid]::NewGuid().ToString('N'))"
[void][System.IO.Directory]::CreateDirectory($work)
function Get-KitCaFile { param($Pki, $Ca)
    $cands = [System.Collections.Generic.List[string]]::new()
    $cert = [string]$Ca['certificate']
    if ($cert) {
        $norm = $cert -replace '\\', '/'
        $m = [regex]::Match($norm, '/' + [regex]::Escape((Split-Path -Leaf ($Pki.Path.TrimEnd('\', '/')))) + '/(?<rest>.+)$')
        if ($m.Success) { [void]$cands.Add((Join-Path $Pki.Path ($m.Groups['rest'].Value -replace '/', [System.IO.Path]::DirectorySeparatorChar))) }
        [void]$cands.Add($cert)
    }
    if ($Ca['slug']) { [void]$cands.Add((Join-Path (Join-Path $Pki.Path 'publish') "$($Ca['slug']).crt")) }
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c } }
    throw "The certificate of '$($Ca['commonName'])' was not found in $($Pki.Path)."
}
function New-KitPacked { param([string]$Enc)
    $gen = Join-Path $work "gen-$Enc"; [void][System.IO.Directory]::CreateDirectory($gen)
    $rows = [System.Collections.Generic.List[object]]::new(); $caList = [System.Collections.Generic.List[object]]::new(); $pkiList = [System.Collections.Generic.List[object]]::new()
    $seenEntry = @{}
    foreach ($pk in $pkis) {
        $mp = Join-Path $pk.Path 'pki-manifest.json'
        if (-not (Test-Path -LiteralPath $mp)) { throw "pki-manifest.json is missing in $($pk.Path): rebuild or repair this PKI first." }
        $man = Get-Content -LiteralPath $mp -Raw | ConvertFrom-Json -AsHashtable
        $n = 0
        foreach ($ca in @($man['certificateAuthorities'])) {
            $kind = [string]$ca['kind']; $isRoot = $kind -in 'root', 'track', 'quadrant'
            $ext = ($ca.ContainsKey('externallySigned') -and [bool]$ca['externallySigned'])
            $src = Get-KitCaFile -Pki $pk -Ca $ca
            $slug = if ($ca['slug']) { [string]$ca['slug'] } else { [string]$ca['id'] }
            $entry = "ca/$(if ($isRoot) { 'roots' } else { 'intermediates' })/$($pk.Folder)-$slug.crt"
            if ($seenEntry.ContainsKey($entry)) { continue }; $seenEntry[$entry] = $true
            $store = if ($ext) { 'CA' } elseif ($isRoot) { 'Root' } else { 'CA' }
            [void]$rows.Add([ordered]@{ Role = $(if ($isRoot) { 'root' } else { 'intermediate' }); Entry = $entry; Source = $src; Sha1 = [string]$ca['sha1']; Store = $store; Ext = $(if ($ext) { '1' } else { '0' }); Kind = $kind; Name = [string]$ca['commonName']; Pki = $pk.Profile; Release = $pk.Folder })
            [void]$caList.Add([ordered]@{ id = [string]$ca['id']; kind = $kind; commonName = [string]$ca['commonName']; sha1 = [string]$ca['sha1']; sha256 = [string]$ca['sha256']; externallySigned = $ext; store = $store; file = $entry; pki = $pk.Profile; release = $pk.Folder })
            $n++
        }
        if ($n -eq 0) { throw "No CA certificate listed in $mp." }
        [void]$pkiList.Add([ordered]@{ pki = $pk.Profile; release = $pk.Folder; label = $pk.Label; caCertificates = $n })
    }
    $files = foreach ($r in $rows) { $fi = [System.IO.FileInfo]::new($r.Source); [ordered]@{ path = $r.Entry; sha256 = (Get-PkiFileSha256 -Path $r.Source); size = $fi.Length; role = $r.Role } }
    $files = @($files)
    $manifest = [ordered]@{
        format = 'agantra-certpacked'; formatVersion = 1; generator = "New-PkiTrustKit.ps1 $script:Version"; createdUtc = [DateTime]::UtcNow.ToString('o')
        comment = "Trust kit $kitName ($unique): CA certificates of $($pkis.Count) PKI(s), no private key"
        archive = [ordered]@{ format = 'zip'; encryption = $(if ($Enc -eq 'Aes256') { 'AES-256 (WinZip AE-2)' } else { 'ZipCrypto' }) }
        scope = [ordered]@{ caCertificates = $true; leafcerts = $false; caPrivateKeys = $false; issuingKeysOnly = $false; multiPki = ($pkis.Count -gt 1) }
        pkis = @($pkiList); certificateAuthorities = @($caList); files = $files
    }
    $jsonF = Join-Path $gen 'certpack.json'; Write-Utf8NoBom -Path $jsonF -Content ($manifest | ConvertTo-Json -Depth 8)
    $tsv = [System.Text.StringBuilder]::new()
    [void]$tsv.Append("# role`tpath`tsha256`tsize`tsha1`tstore`texternallySigned`tkind`tname`tpki`trelease`n")
    foreach ($r in $rows) {
        $f = $files | Where-Object { $_.path -eq $r.Entry } | Select-Object -First 1
        [void]$tsv.Append("$($r.Role)`t$($r.Entry)`t$($f.sha256)`t$($f.size)`t$($r.Sha1)`t$($r.Store)`t$($r.Ext)`t$($r.Kind)`t$($r.Name)`t$($r.Pki)`t$($r.Release)`n")
    }
    $tsvF = Join-Path $gen 'certpack.tsv'; Write-Utf8NoBom -Path $tsvF -Content $tsv.ToString()
    $sums = [System.Text.StringBuilder]::new(); foreach ($f in $files) { [void]$sums.Append("$($f.sha256)  $($f.path)`n") }
    $sumF = Join-Path $gen 'SHA256SUMS'; Write-Utf8NoBom -Path $sumF -Content $sums.ToString()
    $readF = Join-Path $gen 'README.txt'
    Write-Utf8NoBom -Path $readF -Content ("CERTPACKED - trust kit $kitName ($unique)`nAuthor : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com`n" +
        "CA certificates only (no private key) of: $(($pkis | ForEach-Object { $_.Label }) -join ', ')`nOpen it with Install-PkiCa.ps1 / install-pki-ca.sh (or rename to .zip and use 7-Zip).`n")
    $final = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($x in @(@($jsonF, 'certpack.json'), @($tsvF, 'certpack.tsv'), @($sumF, 'SHA256SUMS'), @($readF, 'README.txt'))) { [void]$final.Add(@{ Source = $x[0]; Entry = $x[1] }) }
    foreach ($r in $rows) { [void]$final.Add(@{ Source = $r.Source; Entry = $r.Entry }) }
    $f = Join-Path $work "pki-$PkiName-$unique-$Enc.certpacked"
    New-PkiAesZipArchive -Path $f -Files $final -Password $pw -Encryption $Enc
    [void](Expand-PkiAesZipArchive -Path $f -Password $pw)       # decrypts and authenticates every entry
    return [pscustomobject]@{ File = $f; Name = "pki-$PkiName-$unique.certpacked"; Label = "$($pkis.Count) PKI(s)"; Cas = $caList.Count }
}
$needAes = $Target -contains 'Windows'
$needZc = @($Target | Where-Object { $_ -ne 'Windows' }).Count -gt 0
$packAes = @(); $packZc = @()
try {
    if ($needAes) { Write-Msg "Packing the CA certificates of $($pkis.Count) PKI(s) into ONE .certpacked (AES-256, for Windows) ..."; foreach ($p in $pkis) { Write-Msg "  $($p.Label)" 'INFO' }; $packAes += New-KitPacked 'Aes256' }
    if ($needZc) { Write-Msg "Packing the CA certificates of $($pkis.Count) PKI(s) into ONE .certpacked (ZipCrypto, for Linux: opened by python3 / unzip / 7z) ..."; $packZc += New-KitPacked 'ZipCrypto' }

    # ------------------------------------------------------------ the installers (the templates of trustkit\)
    $tk = Join-Path $root 'trustkit'
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    function Get-Template { param([string]$Name)
        $p = Join-Path $tk $Name
        if (-not (Test-Path -LiteralPath $p)) { throw "Template missing: $p" }
        return [System.IO.File]::ReadAllText($p)
    }
    $ps1Text = (Get-Template 'Install-PkiCa.ps1') -replace "`r`n", "`n"
    $ps1Bytes = $utf8.GetBytes(($ps1Text -replace "`n", "`r`n"))
    $shTemplate = (Get-Template 'install-pki-ca.sh') -replace "`r`n", "`n"
    $prefix = "pki-$PkiName"
    $rmPs1Bytes = $utf8.GetBytes((((Get-Template 'Remove-PkiCa.ps1') -replace "`r`n", "`n") -replace "`n", "`r`n"))
    $rmShText = (Get-Template 'remove-pki-ca.sh') -replace "`r`n", "`n"
    # 5.2.2: the destination tools - CSR maker and OpenSSL installer (ps1 for the Windows zip, sh for the Linux zips)
    $csrPs1Bytes = $utf8.GetBytes((((Get-Template 'New-PkiCsr.ps1') -replace "`r`n", "`n") -replace "`n", "`r`n"))
    $osslPs1Bytes = $utf8.GetBytes((((Get-Template 'Prepare-Computer.ps1') -replace "`r`n", "`n") -replace "`n", "`r`n"))
    $csrShBytes = $utf8.GetBytes(((Get-Template 'new-pki-csr.sh') -replace "`r`n", "`n"))
    $osslShBytes = $utf8.GetBytes(((Get-Template 'prepare-computer.sh') -replace "`r`n", "`n"))

    function New-KitZip { param([string]$Path, [object[]]$Items)
        $fs = [System.IO.File]::Create($Path)
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false, $utf8)
        foreach ($it in $Items) {
            $e = $zip.CreateEntry($it.Name, $(if ($it.Store) { [System.IO.Compression.CompressionLevel]::NoCompression } else { [System.IO.Compression.CompressionLevel]::Optimal }))
            $e.LastWriteTime = [DateTimeOffset]::Now
            $attr = [uint32](0x8000 -bor $it.Mode) -shl 16
            $e.ExternalAttributes = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$attr), 0)
            $es = $e.Open(); $es.Write($it.Bytes, 0, $it.Bytes.Length); $es.Dispose()
        }
        $zip.Dispose(); $fs.Dispose()
        # "version made by" = Unix (3), so unzip honours the mode bits (the .sh stays executable)
        $zb = [System.IO.File]::ReadAllBytes($Path)
        $eocd = -1; for ($i = $zb.Length - 22; $i -ge 0; $i--) { if ($zb[$i] -eq 0x50 -and $zb[$i + 1] -eq 0x4B -and $zb[$i + 2] -eq 5 -and $zb[$i + 3] -eq 6) { $eocd = $i; break } }
        $cnt = [BitConverter]::ToUInt16($zb, $eocd + 10); $p = [int][BitConverter]::ToUInt32($zb, $eocd + 16)
        for ($k = 0; $k -lt $cnt; $k++) { $zb[$p + 5] = 3; $p += 46 + [BitConverter]::ToUInt16($zb, $p + 28) + [BitConverter]::ToUInt16($zb, $p + 30) + [BitConverter]::ToUInt16($zb, $p + 32) }
        [System.IO.File]::WriteAllBytes($Path, $zb)
    }

    $made = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $Target) {
        $key = $t.ToLowerInvariant()
        $zipName = "$key-pki-$kitName-$unique-$stamp.zip"
        $zipPath = Join-Path $runDir $zipName
        if ($t -eq 'Windows') {
            $items = @([pscustomobject]@{ Name = 'Install-PkiCa.ps1'; Bytes = $ps1Bytes; Mode = 0x1A4; Store = $false }, [pscustomobject]@{ Name = 'Remove-PkiCa.ps1'; Bytes = $rmPs1Bytes; Mode = 0x1A4; Store = $false }, [pscustomobject]@{ Name = 'New-PkiCsr.ps1'; Bytes = $csrPs1Bytes; Mode = 0x1A4; Store = $false }, [pscustomobject]@{ Name = 'Prepare-Computer.ps1'; Bytes = $osslPs1Bytes; Mode = 0x1A4; Store = $false }) + @(
                @($packAes | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Bytes = [System.IO.File]::ReadAllBytes($_.File); Mode = 0x1A4; Store = $true } }))
        }
        else {
            $sh = $shTemplate.Replace('__PKI_PREFIX__', $prefix).Replace('__PKI_TARGET__', $key)
            $items = @([pscustomobject]@{ Name = 'install-pki-ca.sh'; Bytes = $utf8.GetBytes($sh); Mode = 0x1ED; Store = $false }, [pscustomobject]@{ Name = 'remove-pki-ca.sh'; Bytes = $utf8.GetBytes($rmShText); Mode = 0x1ED; Store = $false }, [pscustomobject]@{ Name = 'new-pki-csr.sh'; Bytes = $csrShBytes; Mode = 0x1ED; Store = $false }, [pscustomobject]@{ Name = 'prepare-computer.sh'; Bytes = $osslShBytes; Mode = 0x1ED; Store = $false }) + @(
                @($packZc | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Bytes = [System.IO.File]::ReadAllBytes($_.File); Mode = 0x1A4; Store = $true } }))
        }
        New-KitZip -Path $zipPath -Items $items
        [void]$made.Add([pscustomobject]@{ Target = $t; Path = $zipPath; Name = $zipName; Bytes = (Get-Item -LiteralPath $zipPath).Length })
        Write-Msg ("{0,-8} {1}  ({2:N0} KB)" -f $t, $zipName, ((Get-Item -LiteralPath $zipPath).Length / 1KB)) 'OK'
    }

    # ------------------------------------------------------------ optional self-extracting files (extract only; the installer stays a .ps1 / .sh)
    $selfMade = [System.Collections.Generic.List[string]]::new()
    if ($SelfExtract) {
        foreach ($m in $made) {
            $zipBytes = [System.IO.File]::ReadAllBytes($m.Path)
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($m.Name)
            if ($m.Target -eq 'Windows') {
                $cmdName = "$baseName-selfextract.cmd"
                $tpl = (Get-Template 'selfextract.cmd.template') -replace "`r`n", "`n"
                $tpl = $tpl.Replace('__ZIPNAME__', $m.Name)
                $b64 = [Convert]::ToBase64String($zipBytes)
                $sb = [System.Text.StringBuilder]::new($tpl.Replace("`n", "`r`n")); [void]$sb.Append("`r`n")
                for ($o = 0; $o -lt $b64.Length; $o += 76) { [void]$sb.Append('::').Append($b64.Substring($o, [Math]::Min(76, $b64.Length - $o))).Append("`r`n") }
                [System.IO.File]::WriteAllBytes((Join-Path $runDir $cmdName), [System.Text.Encoding]::ASCII.GetBytes($sb.ToString()))
                [void]$selfMade.Add($cmdName)
            }
            else {
                $shName = "$baseName-selfextract.sh"
                $tpl = (Get-Template 'selfextract.sh.template') -replace "`r`n", "`n"
                $tpl = $tpl.Replace('__ZIPNAME__', $m.Name).Replace('__SHNAME__', $shName)
                $tpl = $tpl.Replace('__ARCHIVE_FOLLOWS__' + "`n", '').Replace('__ARCHIVE_FOLLOWS__', '')
                $tpl = $tpl.Replace('__SKIP__', '0000000000')
                $skip = $utf8.GetByteCount($tpl)
                $tpl = $tpl.Replace('SKIP=0000000000', ('SKIP=' + $skip.ToString('0000000000')))
                $head = $utf8.GetBytes($tpl)
                $blob = [byte[]]::new($head.Length + $zipBytes.Length)
                [Array]::Copy($head, 0, $blob, 0, $head.Length); [Array]::Copy($zipBytes, 0, $blob, $head.Length, $zipBytes.Length)
                $shPath = Join-Path $runDir $shName
                [System.IO.File]::WriteAllBytes($shPath, $blob)
                if (-not $IsWindows) { & chmod 755 $shPath 2>$null }
                [void]$selfMade.Add($shName)
            }
        }
        foreach ($n in $selfMade) { Write-Msg ("{0}  (self-extracting: only extracts, the installer is the .ps1 / .sh inside)" -f $n) 'OK' }
    }

    # ------------------------------------------------------------ safety check: no private key anywhere in the zips
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($m in $made) {
        $z = [System.IO.Compression.ZipFile]::OpenRead($m.Path)
        try {
            foreach ($e in $z.Entries) {
                if ($e.FullName -match '\.(key|pfx|p12)$') { throw "A key file is in $($m.Name): $($e.FullName)" }
                if ($e.FullName -notmatch '\.certpacked$') {
                    $ms = [System.IO.MemoryStream]::new(); $s = $e.Open(); $s.CopyTo($ms); $s.Dispose()
                    if ([System.Text.Encoding]::Latin1.GetString($ms.ToArray()) -match '-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{40,}') { throw "A private key is in $($m.Name): $($e.FullName)" }
                }
            }
        } finally { $z.Dispose() }
    }

    # ------------------------------------------------------------ PASSWORD.txt, README.txt
    $pwFile = Join-Path $runDir 'PASSWORD.txt'
    $hdr = ('=' * 60) + "`nAuthor : Nicko Satria Utama`nCompany: Agantra Inovatif OU (NextMantra)`nEmail  : nicko@nextmantra.com`n" + ('=' * 60) + "`n`n"
    [System.IO.File]::WriteAllText($pwFile, $hdr + "Password of the .certpacked inside every zip of this folder (PKI $kitName, kit $unique).`nSend it to the people by ANOTHER way than the zips (chat, phone, a password manager). Delete this file when it is sent.`n`n$pw`n", $utf8)
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add("PKI trust kit $kitName ($unique), made $((Get-Date).ToString('yyyy-MM-dd HH:mm')) with New-PkiTrustKit.ps1 $script:Version")
    [void]$lines.Add('The zips hold the CA certificates (roots and intermediates, NO private key) and one small installer. Give each person the zip of THEIR system + the password (PASSWORD.txt).')
    if ($pkis.Count -gt 1) { [void]$lines.Add("This kit holds $($pkis.Count) PKIs in ONE .certpacked: $(($pkis | ForEach-Object { $_.Label }) -join ', '). The installer installs them all in one run.") }
    [void]$lines.Add('To take a PKI away again on that machine: Remove-PkiCa.ps1 (Windows) / remove-pki-ca.sh (Linux): -List shows what the kit installed, -Pki <name> removes one company, -All removes everything the kit installed.')
    [void]$lines.Add('Supported: Windows 11 24H2+ / Windows Server 2025 (all), Windows Server 2022 (classic CAs only); Ubuntu 24.04+, CentOS Stream 10+, RHEL 10+, Rocky 10+, Oracle Linux 10+, SLES 15+, openSUSE 15+. Other systems are refused with an error.')
    [void]$lines.Add('')
    foreach ($m in $made) {
        [void]$lines.Add("$($m.Name)")
        if ($m.Target -eq 'Windows') {
            [void]$lines.Add('   1. Copy the zip to the laptop and unzip it (right click -> Extract All).')
            [void]$lines.Add('   2. Open PowerShell in that folder (administrator window = whole machine; normal window = this user only) and run:')
            [void]$lines.Add('         powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-PkiCa.ps1')
            [void]$lines.Add('   3. Type the password. In a normal window Windows asks to confirm each root: click Yes. Add -Firefox to make Firefox trust it too.')
            [void]$lines.Add('   When it is done only the zip stays (the script and the extracted files are deleted).')
        }
        else {
            [void]$lines.Add('   1. Copy the zip to the machine and unzip it:   unzip <zip>     (or python3 -m zipfile -e <zip> .)')
            [void]$lines.Add('   2. In that folder run:   bash install-pki-ca.sh      (sudo is used by itself; add --firefox for Firefox)')
            [void]$lines.Add('   3. Type the password. The roots go to the system store; the zip and the folder pki/ stay.')
        }
        [void]$lines.Add('')
    }
    if ($selfMade.Count -gt 0) {
        [void]$lines.Add('Self-extracting files (optional, same content as the zips; they only EXTRACT, the install is still the script that comes out):')
        foreach ($n in $selfMade) { [void]$lines.Add("   $n") }
        [void]$lines.Add('   Windows: double click the .cmd (unpacks next to itself), then run Install-PkiCa.ps1.   Linux: bash <file>-selfextract.sh (unpacks into the current folder), then bash install-pki-ca.sh.')
        [void]$lines.Add('')
    }
    [void]$lines.Add('Check only (changes nothing):  Windows  .\Install-PkiCa.ps1 -Check     Linux  bash install-pki-ca.sh --check')
    [void]$lines.Add('Certificate request:  Windows  .\Prepare-Computer.ps1 (once: PowerShell 7 + OpenSSL + Python + PATH), then .\New-PkiCsr.ps1     Linux  bash prepare-computer.sh (once: PowerShell 7 + OpenSSL + Python + PATH), then bash new-pki-csr.sh   - send ONLY the .csr to the owner of the PKI.')
    [void]$lines.Add('Remove:  Windows  .\Remove-PkiCa.ps1 -List | -Pki <name> | -All     Linux  bash remove-pki-ca.sh --list | --pki <name> | --all   (add -Check / --check to only show)')
    [System.IO.File]::WriteAllText((Join-Path $runDir 'README.txt'), ($hdr + ($lines -join "`n") + "`n"), $utf8)
}
finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ''
Write-Msg "Folder   : $runDir" 'OK'
Write-Msg "Password : $(if ($generated) { "$pw   (generated; also in PASSWORD.txt: send it by another way than the zips)" } else { 'the one you gave (also in PASSWORD.txt)' })" 'OK'
Write-Msg 'Checked  : no private key and no key file in any zip; the installers are standalone.' 'OK'
Write-Msg 'Not tested on this machine: the Windows stores (see docs\PkiTrustKit-MANUAL.txt).' 'INFO'
exit 0
