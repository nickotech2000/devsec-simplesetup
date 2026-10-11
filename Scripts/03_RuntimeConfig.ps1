# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 03_RuntimeConfig.ps1
#
# Writes the OpenSSL configuration files the generators use:
#
#   pki\provider-default.cnf    provider section, non-FIPS
#   pki\provider-fips.cnf       provider section, FIPS (needs fipsmodule.cnf)
#   <ca dir>\<id>.cnf           one per CA: provider section, [ca] database
#                               section for the certificates this CA issues,
#                               [req] / [dn] for its own subject and the
#                               [ext] extensions of its own certificate
#
# Provider sections use native providers only:
#   default = default_sect   (non-FIPS)
#   fips    = fips_sect + base = base_sect   (FIPS)
# The ENGINE API and third-party providers (oqsprovider) are never used.
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-PkiConfValue {
    # Escape characters that OpenSSL config parsing treats specially.
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    $v = $Value -replace '\\', '\\'
    $v = $v -replace '\$', '\$'
    $v = $v -replace '#', '\#'
    $v = $v -replace '"', '\"'
    $v = $v -replace "'", "\'"
    return $v
}

function ConvertTo-PkiConfPath {
    param([Parameter(Mandatory)][string]$Path)
    return ($Path -replace '\\', '/')
}

function Find-PkiFipsModuleConfig {
    if (-not [string]::IsNullOrWhiteSpace($script:Pki.FipsModuleConfig)) {
        if (-not (Test-Path -LiteralPath $script:Pki.FipsModuleConfig -PathType Leaf)) {
            throw "-FipsModuleConfig file not found: $($script:Pki.FipsModuleConfig)"
        }
        return (Resolve-Path -LiteralPath $script:Pki.FipsModuleConfig).Path
    }
    $exeDir = Split-Path -Parent $script:Pki.OpenSslExe
    $candidates = @(
        (Join-Path $exeDir 'fipsmodule.cnf'),
        (Join-Path (Split-Path -Parent $exeDir) 'fipsmodule.cnf'),
        (Join-Path (Split-Path -Parent $exeDir) 'ssl\fipsmodule.cnf'),
        'C:\Program Files\Common Files\SSL\fipsmodule.cnf',
        'C:\Program Files\OpenSSL\ssl\fipsmodule.cnf',
        'C:\Program Files\OpenSSL-Win64\ssl\fipsmodule.cnf',
        '/etc/ssl/fipsmodule.cnf',
        '/usr/local/ssl/fipsmodule.cnf'
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    return $null
}

function Get-PkiProviderConfigHeader {
    param([bool]$Fips)
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add('# Native OpenSSL providers only. No ENGINE API, no oqsprovider.')
    [void]$lines.Add('openssl_conf = openssl_init')
    if ($Fips) {
        $fm = $script:Pki.FipsConfigResolved
        if ([string]::IsNullOrWhiteSpace($fm)) { throw 'FIPS module configuration was not resolved.' }
        [void]$lines.Add(".include $(ConvertTo-PkiConfPath $fm)")
    }
    [void]$lines.Add('')
    [void]$lines.Add('[ openssl_init ]')
    [void]$lines.Add('providers = provider_sect')
    [void]$lines.Add('')
    [void]$lines.Add('[ provider_sect ]')
    if ($Fips) {
        [void]$lines.Add('fips = fips_sect')
        [void]$lines.Add('base = base_sect')
        [void]$lines.Add('')
        [void]$lines.Add('[ base_sect ]')
        [void]$lines.Add('activate = 1')
    }
    else {
        [void]$lines.Add('default = default_sect')
        [void]$lines.Add('')
        [void]$lines.Add('[ default_sect ]')
        [void]$lines.Add('activate = 1')
    }
    [void]$lines.Add('')
    return $lines
}

function Initialize-PkiProviderConfigs {
    Ensure-PkiDirectory -Path $script:Pki.PkiRoot
    $needFips = @($script:Pki.Quadrants | Where-Object { $_ -in 2, 4 }).Count -gt 0

    $header = Get-PkiProviderConfigHeader -Fips $false
    Write-Utf8NoBom -Path (Get-PkiProviderConfigPath -Fips $false) -Content (($header -join "`n") + "`n")

    if ($needFips) {
        $resolved = Find-PkiFipsModuleConfig
        if ($null -eq $resolved) {
            throw @"
FIPS quadrants (2 and/or 4) were requested but fipsmodule.cnf was not found.
Create it once with:
    openssl fipsinstall -out fipsmodule.cnf -module <path to fips.dll>
and pass  -FipsModuleConfig <path to fipsmodule.cnf>
or generate only the non-FIPS quadrants with  -Quadrant 1,3
"@
        }
        $script:Pki.FipsConfigResolved = $resolved
        Write-PkiLog "FIPS module configuration: $resolved"
        $header = Get-PkiProviderConfigHeader -Fips $true
        Write-Utf8NoBom -Path (Get-PkiProviderConfigPath -Fips $true) -Content (($header -join "`n") + "`n")
        Test-PkiFipsProvider
    }
}

# ------------------------------------------------------------
# Paths of a CA
# ------------------------------------------------------------
function Get-PkiCaPaths {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $dir = Join-Path $script:Pki.PkiRoot $Ca.RelDir
    $id = $Ca.Id
    return [ordered]@{
        Dir = $dir
        Key = Join-Path $dir "$id.key"
        Crt = Join-Path $dir "$id.crt"
        Csr = Join-Path $dir "$id.csr"
        Pfx = Join-Path $dir "$id.pfx"
        Cnf = Join-Path $dir "$id.cnf"
        Chain = Join-Path $dir "$id-chain.crt"
        Issued = Join-Path $dir 'issued'
        Index = Join-Path $dir 'index.txt'
        Serial = Join-Path $dir 'serial'
        CrlNumber = Join-Path $dir 'crlnumber'
        CrlPem = Join-Path $dir "$id.crl.pem"
    }
}

function New-PkiRandomSerialHex {
    # 128-bit, positive (top bit clear), never zero.
    $b = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    $b[0] = $b[0] -band 0x7F
    if ($b[0] -eq 0) { $b[0] = 0x01 }
    return (($b | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Initialize-PkiCaDatabase {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $p = Get-PkiCaPaths -Ca $Ca
    Ensure-PkiDirectory -Path $p.Dir
    Ensure-PkiDirectory -Path $p.Issued
    Write-Utf8NoBom -Path $p.Index -Content ''
    Write-Utf8NoBom -Path "$($p.Index).attr" -Content "unique_subject = no`n"
    Write-Utf8NoBom -Path $p.Serial -Content ((New-PkiRandomSerialHex) + "`n")
    Write-Utf8NoBom -Path $p.CrlNumber -Content "01`n"
}

# ------------------------------------------------------------
# Common name of a CA (uses the key that was really created)
# ------------------------------------------------------------
# (CA names, algorithm labels and file-name stems: see 01b_CaNaming.ps1)

# ------------------------------------------------------------
# Certificate policies written into a CA certificate
# ------------------------------------------------------------
function Get-PkiCaPolicies {
    <#
    .SYNOPSIS
        Certificate policies of a CA certificate.
          Enterprise Root, Track Roots   All issuance policies (anyPolicy 2.5.29.32.0) + EV 2.23.140.1.1. Nothing else: neither
                                         the IANA PEN policies nor [ custom_policies ] (they start one level below).
          Quadrant Roots                 EV + OV + DV + the PEN policies (when a PEN is set) + [ custom_policies ]
          Intermediates                  their own level + the PEN policies of that level + [ custom_policies ]
        (Leaves: Get-PkiLeafPolicies, level + PEN of that level + custom + -Policy.)
    #>
    param([Parameter(Mandatory)][hashtable]$Ca)
    $list = [System.Collections.Generic.List[object]]::new()
    $cps = $script:Pki.CpsUrl
    if ($Ca.Kind -eq 'root' -or $Ca.Kind -eq 'track') {
        [void]$list.Add([ordered]@{ Label = 'AnyPolicy'; Oid = $script:PkiAnyPolicyOid; Cps = '' })
        [void]$list.Add([ordered]@{ Label = 'EV'; Oid = $script:PkiPolicyOid.EV; Cps = $cps })
        return $list
    }
    if ($Ca.Kind -eq 'intermediate') {
        [void]$list.Add([ordered]@{ Label = $Ca.Validation; Oid = $script:PkiPolicyOid[$Ca.Validation]; Cps = $cps })
        $extra = Get-PkiExtraPolicies -Level $Ca.Validation
    }
    else {
        # Quadrant Roots carry all three validation levels
        [void]$list.Add([ordered]@{ Label = 'EV'; Oid = $script:PkiPolicyOid.EV; Cps = $cps })
        [void]$list.Add([ordered]@{ Label = 'OV'; Oid = $script:PkiPolicyOid.OV; Cps = '' })
        [void]$list.Add([ordered]@{ Label = 'DV'; Oid = $script:PkiPolicyOid.DV; Cps = '' })
        $extra = Get-PkiExtraPolicies -Level 'All'
    }
    foreach ($cp in $extra) { [void]$list.Add($cp) }
    return $list
}

function Add-PkiPolicySections {
    # Appends [ <prefix>_N ] sections; returns the certificatePolicies value.
    param([System.Collections.Generic.List[string]]$Lines, $Policies, [string]$Prefix)
    $refs = [System.Collections.Generic.List[string]]::new()
    $i = 0
    foreach ($p in $Policies) {
        $i++
        $name = "${Prefix}_$i"
        [void]$refs.Add("@$name")
        [void]$Lines.Add("[ $name ]")
        [void]$Lines.Add("policyIdentifier = $($p.Oid)")
        if (-not [string]::IsNullOrWhiteSpace($p.Cps)) { [void]$Lines.Add("CPS.1 = $(ConvertTo-PkiConfValue $p.Cps)") }
        [void]$Lines.Add('')
    }
    return ($refs -join ',')
}

function Add-PkiLocationSections {
    # CRL distribution points and Authority Information Access for a given issuer slug.
    param([System.Collections.Generic.List[string]]$Lines, [string]$IssuerSlug, [string]$Prefix)
    $c = $script:Pki
    $hasCrl = $false; $hasAia = $false
    if ($c.CrlUrls.Count -gt 0) {
        $hasCrl = $true
        [void]$Lines.Add("[ ${Prefix}_crl ]")
        $n = 0
        foreach ($u in $c.CrlUrls) { $n++; [void]$Lines.Add("URI.$n = $(ConvertTo-PkiConfValue ($u -replace '\{ca\}', $IssuerSlug))") }
        [void]$Lines.Add('')
    }
    if (($c.OcspUrls.Count + $c.CaIssuerUrls.Count) -gt 0) {
        $hasAia = $true
        [void]$Lines.Add("[ ${Prefix}_aia ]")
        $n = 0
        foreach ($u in $c.OcspUrls) { $n++; [void]$Lines.Add("OCSP;URI.$n = $(ConvertTo-PkiConfValue ($u -replace '\{ca\}', $IssuerSlug))") }
        $n = 0
        foreach ($u in $c.CaIssuerUrls) { $n++; [void]$Lines.Add("caIssuers;URI.$n = $(ConvertTo-PkiConfValue ($u -replace '\{ca\}', $IssuerSlug))") }
        [void]$Lines.Add('')
    }
    return @{ Crl = $hasCrl; Aia = $hasAia }
}

# ------------------------------------------------------------
# Subject DN of a CA, in X.500 order
# ------------------------------------------------------------
function Get-PkiCaDnPairs {
    param([Parameter(Mandatory)][hashtable]$Ca)
    $s = $script:Pki.Subject
    $pairs = [System.Collections.Generic.List[object]]::new()
    $add = { param($k, $v) if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$pairs.Add(@($k, $v)) } }
    & $add 'jurisdictionCountryName' $s.JurisdictionCountry
    & $add 'serialNumber' $s.Serial
    & $add 'C' $s.Country
    & $add 'L' $s.Locality
    & $add 'O' $s.Organization
    & $add 'OU' $Ca.Ou
    & $add 'CN' (Get-PkiCaCommonName -Ca $Ca)
    & $add 'name' $s.ContactName
    & $add 'emailAddress' $s.ContactEmail
    & $add 'telephoneNumber' $s.ContactPhone
    return $pairs
}

# ------------------------------------------------------------
# Write <ca dir>\<id>.cnf
# ------------------------------------------------------------
function Write-PkiCaConfig {
    param([Parameter(Mandatory)][hashtable]$Ca)

    $p = Get-PkiCaPaths -Ca $Ca
    $dirConf = ConvertTo-PkiConfValue (ConvertTo-PkiConfPath $p.Dir)
    $issueMd = Get-PkiIssueMd -Kind $Ca.Kind -Family $Ca.Actual.Family
    $L = [System.Collections.Generic.List[string]]::new()

    foreach ($h in (Get-PkiProviderConfigHeader -Fips ([bool]$Ca.Fips))) { [void]$L.Add($h) }

    [void]$L.Add("# $($Ca.Id) - $(Get-PkiCaCommonName -Ca $Ca)")
    [void]$L.Add('')
    [void]$L.Add('[ ca ]')
    [void]$L.Add('default_ca = CA_default')
    [void]$L.Add('')
    [void]$L.Add('# --- database of the certificates THIS CA issues ---')
    [void]$L.Add('[ CA_default ]')
    [void]$L.Add("dir             = $dirConf")
    [void]$L.Add('database        = $dir/index.txt')
    [void]$L.Add('new_certs_dir   = $dir/issued')
    [void]$L.Add("certificate     = `$dir/$($Ca.Id).crt")
    [void]$L.Add("private_key     = `$dir/$($Ca.Id).key")
    [void]$L.Add('serial          = $dir/serial')
    [void]$L.Add('crlnumber       = $dir/crlnumber')
    [void]$L.Add("default_md      = $issueMd")
    [void]$L.Add('default_days    = 397')
    [void]$L.Add("default_crl_days = $([int]$script:Pki.CrlDays)")
    [void]$L.Add('policy          = policy_any')
    [void]$L.Add('unique_subject  = no')
    [void]$L.Add('copy_extensions = none')
    [void]$L.Add('preserve        = yes')
    [void]$L.Add('email_in_dn     = yes')
    [void]$L.Add('utf8            = yes')
    [void]$L.Add('string_mask     = utf8only')
    [void]$L.Add('name_opt        = ca_default')
    [void]$L.Add('cert_opt        = ca_default')
    [void]$L.Add('crl_extensions  = crl_ext')
    [void]$L.Add('')
    [void]$L.Add('[ policy_any ]')
    foreach ($f in 'countryName', 'stateOrProvinceName', 'localityName', 'organizationName', 'organizationalUnitName',
                   'emailAddress', 'name', 'telephoneNumber', 'businessCategory', 'serialNumber', 'streetAddress',
                   'postalCode', 'jurisdictionCountryName', 'jurisdictionStateOrProvinceName', 'jurisdictionLocalityName', 'organizationIdentifier') {
        [void]$L.Add("$f = optional")
    }
    [void]$L.Add('commonName = supplied')
    [void]$L.Add('')
    [void]$L.Add('[ crl_ext ]')
    [void]$L.Add('authorityKeyIdentifier = keyid:always')
    [void]$L.Add('')

    [void]$L.Add('# --- request for THIS CA''s own certificate ---')
    [void]$L.Add('[ req ]')
    [void]$L.Add('prompt = no')
    [void]$L.Add('utf8 = yes')
    [void]$L.Add('string_mask = utf8only')
    [void]$L.Add('distinguished_name = dn')
    [void]$L.Add('')
    [void]$L.Add('[ dn ]')
    foreach ($pair in (Get-PkiCaDnPairs -Ca $Ca)) {
        [void]$L.Add("$($pair[0]) = $(ConvertTo-PkiConfValue $pair[1])")
    }
    [void]$L.Add('')

    # --- extensions of THIS CA's certificate (issued by the parent) ---
    $parent = if ($null -ne $Ca.Parent) { Get-PkiCa -Id $Ca.Parent } else { $null }
    $policyRefs = Add-PkiPolicySections -Lines $L -Policies (Get-PkiCaPolicies -Ca $Ca) -Prefix 'cp'
    $loc = @{ Crl = $false; Aia = $false }
    if ($null -ne $parent) { $loc = Add-PkiLocationSections -Lines $L -IssuerSlug $parent.Slug -Prefix 'loc' }

    [void]$L.Add('[ ext ]')
    [void]$L.Add("basicConstraints = critical,CA:true,pathlen:$($Ca.PathLen)")
    [void]$L.Add('keyUsage = critical,keyCertSign,cRLSign')
    [void]$L.Add('subjectKeyIdentifier = hash')
    [void]$L.Add('authorityKeyIdentifier = keyid:always')
    [void]$L.Add("certificatePolicies = $policyRefs")
    if ($loc.Crl) { [void]$L.Add('crlDistributionPoints = @loc_crl') }
    if ($loc.Aia) { [void]$L.Add('authorityInfoAccess = @loc_aia') }
    [void]$L.Add('')

    Write-Utf8NoBom -Path $p.Cnf -Content (($L -join "`n") + "`n")
    return $p.Cnf
}
