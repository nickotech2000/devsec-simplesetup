# ============================================================
# 03_RuntimeConfig.ps1
#
# PKI Script - EV profile + OpenSSL runtime configuration
#
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
#
# Purpose:
#   - Read the EV leaf profile from ev_pki.cnf
#   - Apply optional command-line overrides (-Serial, -Locality ...)
#   - Generate pki/openssl.runtime.cnf  (CA + extensions)
#   - Generate pki/leaf-ev.req.cnf      (EV subject for leaf CSRs)
#
# Source of truth:
#   ev_pki.cnf supplies every EV default. A command-line value is
#   used ONLY when the parameter was explicitly passed.
#
# Sections read from ev_pki.cnf:
#   [ dn_leaf_ev ]   EV subject fields
#   [ v3_leaf ]      leaf extensions (must carry certificatePolicies)
#   [ ev_policy ]    policy section referenced by v3_leaf
#   [ leaf_san ]     SAN section referenced by v3_leaf
#   [ v3_root ], [ v3_intermediate ], [ new_oids ]   (optional)
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# CA/Browser Forum EV policy OID.
$script:EvPolicyOid = '2.23.140.1.1'

# Values allowed by the EV Guidelines for subject:businessCategory.
$script:EvBusinessCategories = @(
    'Private Organization'
    'Government Entity'
    'Business Entity'
    'Non-Commercial Entity'
)

# Subject key aliases -> canonical OpenSSL short name.
$script:EvDnAliases = @{
    'businesscategory'                = 'businessCategory'
    'jurisdictionc'                   = 'jurisdictionC'
    'jurisdictioncountryname'         = 'jurisdictionC'
    'jurisdictionst'                  = 'jurisdictionST'
    'jurisdictionstateorprovincename' = 'jurisdictionST'
    'jurisdictionl'                   = 'jurisdictionL'
    'jurisdictionlocalityname'        = 'jurisdictionL'
    'serialnumber'                    = 'serialNumber'
    'c'                               = 'C'
    'countryname'                     = 'C'
    'st'                              = 'ST'
    'stateorprovincename'             = 'ST'
    'l'                               = 'L'
    'localityname'                    = 'L'
    'street'                          = 'street'
    'streetaddress'                   = 'street'
    'postalcode'                      = 'postalCode'
    'o'                               = 'O'
    'organizationname'                = 'O'
    'ou'                              = 'OU'
    'organizationalunitname'          = 'OU'
    'cn'                              = 'CN'
    'commonname'                      = 'CN'
}

# Canonical key -> long name (as printed by `openssl x509 -nameopt multiline`).
$script:EvDnLongNames = @{
    'businessCategory' = 'businessCategory'
    'jurisdictionC'    = 'jurisdictionCountryName'
    'jurisdictionST'   = 'jurisdictionStateOrProvinceName'
    'jurisdictionL'    = 'jurisdictionLocalityName'
    'serialNumber'     = 'serialNumber'
    'C'                = 'countryName'
    'ST'               = 'stateOrProvinceName'
    'L'                = 'localityName'
    'street'           = 'streetAddress'
    'postalCode'       = 'postalCode'
    'O'                = 'organizationName'
    'OU'               = 'organizationalUnitName'
    'CN'               = 'commonName'
}

# ============================================================
# OpenSSL config value helpers
# ============================================================

function Remove-OpenSslConfComment {
    # Removes an unquoted, unescaped "# comment" tail, the same way
    # OpenSSL's config parser does.
    param([AllowEmptyString()][string]$Text)

    $sb = [System.Text.StringBuilder]::new()
    $quote = [char]0

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]

        if ($c -eq [char]'\' -and ($i + 1) -lt $Text.Length) {
            [void]$sb.Append($c)
            [void]$sb.Append($Text[$i + 1])
            $i++
            continue
        }

        if ($quote -ne [char]0) {
            if ($c -eq $quote) { $quote = [char]0 }
            [void]$sb.Append($c)
            continue
        }

        if ($c -eq [char]'"' -or $c -eq [char]"'") {
            $quote = $c
            [void]$sb.Append($c)
            continue
        }

        if ($c -eq [char]'#') { break }

        [void]$sb.Append($c)
    }

    return $sb.ToString().Trim()
}

function ConvertTo-OpenSslConfValue {
    # Escapes a plain string so it can be written on the right-hand
    # side of "key = value" in an OpenSSL config FILE.
    # (Not the same as -subj escaping.)
    param([Parameter(Mandatory)][string]$Value)

    if ($Value -match "[\r\n]") {
        throw 'Certificate subject values cannot contain line breaks.'
    }

    return $Value.Trim().
        Replace('\', '\\').
        Replace('$', '\$').
        Replace('#', '\#').
        Replace('"', '\"').
        Replace("'", "\'")
}

function ConvertFrom-OpenSslConfValue {
    # Inverse of ConvertTo-OpenSslConfValue (also removes quotes).
    param([AllowEmptyString()][string]$Raw)

    $sb = [System.Text.StringBuilder]::new()
    $quote = [char]0

    for ($i = 0; $i -lt $Raw.Length; $i++) {
        $c = $Raw[$i]

        if ($c -eq [char]'\' -and ($i + 1) -lt $Raw.Length) {
            [void]$sb.Append($Raw[$i + 1])
            $i++
            continue
        }

        if ($quote -ne [char]0) {
            if ($c -eq $quote) { $quote = [char]0 } else { [void]$sb.Append($c) }
            continue
        }

        if ($c -eq [char]'"' -or $c -eq [char]"'") {
            $quote = $c
            continue
        }

        [void]$sb.Append($c)
    }

    return $sb.ToString().Trim()
}

# ============================================================
# INI reader for ev_pki.cnf
# ============================================================

function Read-OpenSslIni {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $text = [System.IO.File]::ReadAllText(
        $Path,
        [System.Text.UTF8Encoding]::new($false, $false)
    )

    if ($text.Contains([string][char]0xFFFD)) {
        throw "$Path is not valid UTF-8. Save it as 'UTF-8' (no BOM) so characters such as the U-umlaut in the organization name survive."
    }

    $ini = [pscustomobject]@{
        Path     = $Path
        Order    = [System.Collections.Generic.List[string]]::new()
        Sections = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    $current = ''
    $ini.Sections[''] = [System.Collections.Generic.List[object]]::new()

    foreach ($line in ($text -split "`r?`n")) {

        $t = $line.Trim()

        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }

        if ($t -match '^\[\s*([^\]]+?)\s*\]') {
            $current = $Matches[1]
            if (-not $ini.Sections.ContainsKey($current)) {
                $ini.Sections[$current] = [System.Collections.Generic.List[object]]::new()
                [void]$ini.Order.Add($current)
            }
            continue
        }

        $idx = $t.IndexOf('=')
        if ($idx -lt 1) { continue }

        [void]$ini.Sections[$current].Add(
            [pscustomobject]@{
                Key = $t.Substring(0, $idx).Trim()
                Raw = (Remove-OpenSslConfComment -Text $t.Substring($idx + 1))
            }
        )
    }

    return $ini
}

function Find-OpenSslIniEntry {
    param(
        [Parameter(Mandatory)]$Ini,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key
    )

    if (-not $Ini.Sections.ContainsKey($Section)) { return $null }

    foreach ($entry in $Ini.Sections[$Section]) {
        if ($entry.Key -ieq $Key) { return $entry }
    }

    return $null
}

function Get-OpenSslIniSectionClosure {
    # Returns the named sections plus every section they reference
    # through "@section" values (leaf_san, ev_policy, ...).
    param(
        [Parameter(Mandatory)]$Ini,
        [Parameter(Mandatory)][string[]]$Names
    )

    $seen   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $result = [System.Collections.Generic.List[string]]::new()
    $queue  = [System.Collections.Generic.Queue[string]]::new()

    foreach ($n in $Names) {
        if ($Ini.Sections.ContainsKey($n)) { $queue.Enqueue($n) }
    }

    while ($queue.Count -gt 0) {
        $name = $queue.Dequeue()
        if (-not $seen.Add($name)) { continue }
        [void]$result.Add($name)

        foreach ($entry in $Ini.Sections[$name]) {
            foreach ($m in [regex]::Matches($entry.Raw, '@\s*([A-Za-z0-9_\.\-]+)')) {
                $ref = $m.Groups[1].Value
                if ($Ini.Sections.ContainsKey($ref)) { $queue.Enqueue($ref) }
            }
        }
    }

    return @($result)
}

# ============================================================
# EV subject helpers
# ============================================================

function Get-EvDnCanonicalKey {
    param([Parameter(Mandatory)][string]$Key)

    $k = ($Key.Trim() -replace '^\d+\.', '')
    $lookup = $k.ToLowerInvariant()

    if ($script:EvDnAliases.ContainsKey($lookup)) {
        return [string]$script:EvDnAliases[$lookup]
    }

    return $k
}

function Get-EvDnValue {
    # Decoded (plain text) value of a canonical subject key, or $null.
    param(
        [Parameter(Mandatory)]$Fields,
        [Parameter(Mandatory)][string]$Canonical
    )

    foreach ($f in $Fields) {
        if ($f.Canonical -ieq $Canonical) {
            return (ConvertFrom-OpenSslConfValue -Raw $f.Raw)
        }
    }

    return $null
}

function Get-EvOverride {
    param(
        [Parameter(Mandatory)][hashtable]$Overrides,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Overrides.ContainsKey($Name)) {
        $value = [string]$Overrides[$Name]
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
    }

    return $null
}

# ============================================================
# Load + validate the EV profile
# ============================================================

function Get-EvProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MasterConfig,
        [hashtable]$Overrides = @{}
    )

    if (-not (Test-Path -LiteralPath $MasterConfig -PathType Leaf)) {
        throw "EV master configuration not found: $MasterConfig. Every leaf certificate takes its EV subject, policy and SAN list from this file."
    }

    $ini = Read-OpenSslIni -Path $MasterConfig

    # --------------------------------------------------------
    # [v3_leaf] -> policy section and SAN section
    # --------------------------------------------------------

    if (-not $ini.Sections.ContainsKey('v3_leaf')) {
        throw "Section [ v3_leaf ] is missing in $MasterConfig."
    }

    if (-not $ini.Sections.ContainsKey('dn_leaf_ev')) {
        throw "Section [ dn_leaf_ev ] is missing in $MasterConfig."
    }

    $cpEntry = Find-OpenSslIniEntry -Ini $ini -Section 'v3_leaf' -Key 'certificatePolicies'
    if ($null -eq $cpEntry) {
        throw "[ v3_leaf ] in $MasterConfig has no certificatePolicies entry. Add: certificatePolicies = @ev_policy"
    }

    $cpMatch = [regex]::Match($cpEntry.Raw, '@\s*([A-Za-z0-9_\.\-]+)')
    if (-not $cpMatch.Success) {
        throw "certificatePolicies in [ v3_leaf ] must reference a policy section, for example: certificatePolicies = @ev_policy"
    }
    $policySection = $cpMatch.Groups[1].Value

    $sanEntry = Find-OpenSslIniEntry -Ini $ini -Section 'v3_leaf' -Key 'subjectAltName'
    if ($null -eq $sanEntry) {
        throw "[ v3_leaf ] in $MasterConfig has no subjectAltName entry. Add: subjectAltName = @leaf_san"
    }

    $sanMatch = [regex]::Match($sanEntry.Raw, '@\s*([A-Za-z0-9_\.\-]+)')
    if (-not $sanMatch.Success) {
        throw "subjectAltName in [ v3_leaf ] must reference a SAN section, for example: subjectAltName = @leaf_san"
    }
    $sanSection = $sanMatch.Groups[1].Value

    foreach ($required in @($policySection, $sanSection)) {
        if (-not $ini.Sections.ContainsKey($required)) {
            throw "Section [ $required ] is referenced by [ v3_leaf ] but is missing in $MasterConfig."
        }
    }

    # --------------------------------------------------------
    # EV policy OID
    # --------------------------------------------------------

    $polEntry = Find-OpenSslIniEntry -Ini $ini -Section $policySection -Key 'policyIdentifier'
    if ($null -eq $polEntry) {
        throw "[ $policySection ] in $MasterConfig has no policyIdentifier."
    }

    $policyOid = ConvertFrom-OpenSslConfValue -Raw $polEntry.Raw
    if ($policyOid -notmatch '^\d+(\.\d+)+$') {
        $alias = Find-OpenSslIniEntry -Ini $ini -Section 'new_oids' -Key $policyOid
        if ($null -ne $alias) {
            $policyOid = ConvertFrom-OpenSslConfValue -Raw $alias.Raw
        }
    }

    # --------------------------------------------------------
    # EV subject: ev_pki.cnf first, explicit parameters override
    # --------------------------------------------------------

    $fields = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $ini.Sections['dn_leaf_ev']) {
        [void]$fields.Add(
            [pscustomobject]@{
                Key       = $entry.Key
                Canonical = (Get-EvDnCanonicalKey -Key $entry.Key)
                Raw       = $entry.Raw
            }
        )
    }

    $cnfCommonName = Get-EvDnValue -Fields $fields -Canonical 'CN'

    $parameterToKey = [ordered]@{
        BusinessCategory     = 'businessCategory'
        JurisdictionCountry  = 'jurisdictionC'
        JurisdictionState    = 'jurisdictionST'
        JurisdictionLocality = 'jurisdictionL'
        Serial               = 'serialNumber'
        Country              = 'C'
        State                = 'ST'
        Locality             = 'L'
        Street               = 'street'
        PostalCode           = 'postalCode'
        Organization         = 'O'
        Domain               = 'CN'
    }

    $domainOverridden = $false

    foreach ($parameter in $parameterToKey.Keys) {

        $value = Get-EvOverride -Overrides $Overrides -Name $parameter
        if ($null -eq $value) { continue }

        $canonical = [string]$parameterToKey[$parameter]

        if ($canonical -in @('C', 'jurisdictionC')) {
            if ($value -notmatch '^[A-Za-z]{2}$') {
                throw "-$parameter must be a two-letter ISO country code: '$value'."
            }
            $value = $value.ToUpperInvariant()
        }

        if ($canonical -eq 'CN') {
            $value = $value.ToLowerInvariant()
            $domainOverridden = $true
        }

        $raw = ConvertTo-OpenSslConfValue -Value $value

        $existing = $null
        foreach ($f in $fields) {
            if ($f.Canonical -ieq $canonical) { $existing = $f; break }
        }

        if ($null -ne $existing) {
            $existing.Raw = $raw
        }
        else {
            [void]$fields.Add(
                [pscustomobject]@{ Key = $canonical; Canonical = $canonical; Raw = $raw }
            )
        }
    }

    # --------------------------------------------------------
    # Validate EV subject
    # --------------------------------------------------------

    $problems = [System.Collections.Generic.List[string]]::new()

    foreach ($required in @('businessCategory', 'jurisdictionC', 'serialNumber', 'C', 'O', 'CN')) {
        if ([string]::IsNullOrWhiteSpace((Get-EvDnValue -Fields $fields -Canonical $required))) {
            [void]$problems.Add("[ dn_leaf_ev ] is missing the required EV field '$required'.")
        }
    }

    if (
        [string]::IsNullOrWhiteSpace((Get-EvDnValue -Fields $fields -Canonical 'L')) -and
        [string]::IsNullOrWhiteSpace((Get-EvDnValue -Fields $fields -Canonical 'ST'))
    ) {
        [void]$problems.Add('EV requires a locality (L) or state/province (ST).')
    }

    $category = Get-EvDnValue -Fields $fields -Canonical 'businessCategory'
    if (-not [string]::IsNullOrWhiteSpace($category) -and $category -notin $script:EvBusinessCategories) {
        [void]$problems.Add("businessCategory '$category' is not valid. Use one of: $($script:EvBusinessCategories -join ', ').")
    }

    foreach ($key in @('C', 'jurisdictionC')) {
        $cc = Get-EvDnValue -Fields $fields -Canonical $key
        if (-not [string]::IsNullOrWhiteSpace($cc) -and $cc -notmatch '^[A-Za-z]{2}$') {
            [void]$problems.Add("$key must be a two-letter country code: '$cc'.")
        }
    }

    $serial = Get-EvDnValue -Fields $fields -Canonical 'serialNumber'
    if (-not [string]::IsNullOrWhiteSpace($serial) -and $serial -match '^0+$') {
        [void]$problems.Add("serialNumber '$serial' is still the placeholder. Set the real registration number in [ dn_leaf_ev ] or pass -Serial.")
    }

    if ($policyOid -ne $script:EvPolicyOid) {
        [void]$problems.Add("[ $policySection ] policyIdentifier is '$policyOid'. EV leaf certificates must use $($script:EvPolicyOid).")
    }

    $ekuEntry = Find-OpenSslIniEntry -Ini $ini -Section 'v3_leaf' -Key 'extendedKeyUsage'
    if ($null -eq $ekuEntry -or $ekuEntry.Raw -notmatch 'serverAuth') {
        [void]$problems.Add('[ v3_leaf ] extendedKeyUsage must include serverAuth for an EV TLS certificate.')
    }

    # --------------------------------------------------------
    # SAN list (a -Domain override replaces the old domain/www pair)
    # --------------------------------------------------------

    $domain = $null
    $cn = Get-EvDnValue -Fields $fields -Canonical 'CN'
    if (-not [string]::IsNullOrWhiteSpace($cn)) { $domain = $cn.ToLowerInvariant() }

    $sanItems = [System.Collections.Generic.List[object]]::new()
    $sanSeen  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Add-SanItem {
        param([string]$Type, [string]$Raw)
        $id = '{0}:{1}' -f $Type.ToLowerInvariant(), (ConvertFrom-OpenSslConfValue -Raw $Raw)
        if ($sanSeen.Add($id)) {
            [void]$sanItems.Add([pscustomobject]@{ Type = $Type; Raw = $Raw })
        }
    }

    if ($domainOverridden -and -not [string]::IsNullOrWhiteSpace($domain)) {
        Add-SanItem -Type 'DNS' -Raw (ConvertTo-OpenSslConfValue -Value $domain)
        Add-SanItem -Type 'DNS' -Raw (ConvertTo-OpenSslConfValue -Value "www.$domain")
    }

    foreach ($entry in $ini.Sections[$sanSection]) {

        $type  = ($entry.Key -replace '\.\d+$', '')
        $plain = ConvertFrom-OpenSslConfValue -Raw $entry.Raw

        if (
            $domainOverridden -and
            $type -ieq 'DNS' -and
            -not [string]::IsNullOrWhiteSpace($cnfCommonName) -and
            ($plain -ieq $cnfCommonName -or $plain -ieq "www.$cnfCommonName")
        ) {
            continue
        }

        Add-SanItem -Type $type -Raw $entry.Raw
    }

    $counters   = @{}
    $sanEntries = [System.Collections.Generic.List[object]]::new()

    foreach ($item in $sanItems) {
        $typeKey = $item.Type.ToLowerInvariant()
        if (-not $counters.ContainsKey($typeKey)) { $counters[$typeKey] = 0 }
        $counters[$typeKey] = [int]$counters[$typeKey] + 1

        [void]$sanEntries.Add(
            [pscustomobject]@{
                Key = ('{0}.{1}' -f $item.Type, $counters[$typeKey])
                Raw = $item.Raw
            }
        )
    }

    $dnsNames = @(
        $sanItems |
            Where-Object { $_.Type -ieq 'DNS' } |
            ForEach-Object { ConvertFrom-OpenSslConfValue -Raw $_.Raw }
    )

    if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -notin $dnsNames) {
        [void]$problems.Add("The common name '$domain' must also be listed as a DNS entry in [ $sanSection ].")
    }

    # --------------------------------------------------------
    # Policy section (optional -CpsUrl override)
    # --------------------------------------------------------

    $policyEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $ini.Sections[$policySection]) {
        [void]$policyEntries.Add([pscustomobject]@{ Key = $entry.Key; Raw = $entry.Raw })
    }

    $cpsUrl = Get-EvOverride -Overrides $Overrides -Name 'CpsUrl'
    if ($null -ne $cpsUrl) {
        $cpsRaw = ConvertTo-OpenSslConfValue -Value $cpsUrl
        $cpsEntry = $policyEntries | Where-Object { $_.Key -match '^CPS\.\d+$' } | Select-Object -First 1
        if ($null -ne $cpsEntry) { $cpsEntry.Raw = $cpsRaw }
        else { [void]$policyEntries.Add([pscustomobject]@{ Key = 'CPS.1'; Raw = $cpsRaw }) }
    }

    if ($problems.Count -gt 0) {
        throw ("EV profile validation failed ({0}):`n - {1}" -f $MasterConfig, ($problems -join "`n - "))
    }

    return [pscustomobject]@{
        MasterConfig  = $MasterConfig
        Ini           = $ini
        DnFields      = $fields
        Domain        = $domain
        Organization  = (Get-EvDnValue -Fields $fields -Canonical 'O')
        Country       = (Get-EvDnValue -Fields $fields -Canonical 'C').ToUpperInvariant()
        PolicyOid     = $policyOid
        PolicySection = $policySection
        PolicyEntries = $policyEntries
        SanSection    = $sanSection
        SanEntries    = $sanEntries
        DnsNames      = $dnsNames
    }
}

# ============================================================
# Directories / CA database
# ============================================================

function Initialize-PkiDirectories {
    Ensure-PkiDirectory -Path $script:Pki.PkiRoot
    Ensure-PkiDirectory -Path $script:Pki.RootDir
    Ensure-PkiDirectory -Path $script:Pki.IntermediateDir
    Ensure-PkiDirectory -Path $script:Pki.LeafDir
    Ensure-PkiDirectory -Path $script:Pki.IssuedDir
}

function Initialize-CaDatabase {
    Write-Utf8NoBom -Path $script:Pki.IndexFile -Content ''
    Write-Utf8NoBom -Path $script:Pki.IndexAttrFile -Content "unique_subject = no`r`n"
    Write-Utf8NoBom -Path $script:Pki.SerialFile -Content "1000`r`n"
    Write-Utf8NoBom -Path $script:Pki.RootSerialFile -Content "2000`r`n"
}

# ============================================================
# Runtime OpenSSL configuration
# ============================================================

function Add-OpenSslConfSection {
    param(
        [Parameter(Mandatory)][System.Text.StringBuilder]$Builder,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Entries
    )

    [void]$Builder.AppendLine("[ $Name ]")
    foreach ($e in $Entries) {
        [void]$Builder.AppendLine(('{0} = {1}' -f $e.Key, $e.Raw))
    }
    [void]$Builder.AppendLine('')
}

function New-ConfEntry {
    param([string]$Key, [string]$Raw)
    return [pscustomobject]@{ Key = $Key; Raw = $Raw }
}

function New-RuntimeOpenSSLConfig {

    $p  = $script:Pki
    $ev = $p.Ev

    if ($null -eq $ev) {
        throw 'The EV profile has not been loaded. Initialize-PkiConfiguration must run first.'
    }

    $ini = $ev.Ini

    $dir             = $p.PkiRoot.Replace('\', '/')
    $intermediateCrt = $p.IntermediateCrt.Replace('\', '/')
    $intermediateKey = $p.IntermediateKey.Replace('\', '/')

    # --------------------------------------------------------
    # Sections generated here (never copied from ev_pki.cnf)
    # --------------------------------------------------------

    $generated = @('ca', 'CA_default', 'policy_ev', 'req', 'dn')

    $seed = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @('v3_root', 'v3_intermediate', 'v3_leaf', 'new_oids')) {
        if ($ini.Sections.ContainsKey($name)) { [void]$seed.Add($name) }
    }

    $copyNames = @(
        Get-OpenSslIniSectionClosure -Ini $ini -Names @($seed) |
            Where-Object { $_ -notin $generated }
    )

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine('# Generated runtime configuration. Do not edit manually.')
    [void]$sb.AppendLine("# EV profile source: $($ev.MasterConfig.Replace('\', '/'))")

    if ($copyNames -contains 'new_oids') {
        [void]$sb.AppendLine('oid_section = new_oids')
    }

    [void]$sb.AppendLine('')

    # --------------------------------------------------------
    # CA behaviour
    # --------------------------------------------------------

    Add-OpenSslConfSection -Builder $sb -Name 'ca' -Entries @(
        (New-ConfEntry 'default_ca' 'CA_default')
    )

    Add-OpenSslConfSection -Builder $sb -Name 'CA_default' -Entries @(
        (New-ConfEntry 'dir'             $dir)
        (New-ConfEntry 'database'        '$dir/index.txt')
        (New-ConfEntry 'new_certs_dir'   '$dir/issued')
        (New-ConfEntry 'certificate'     $intermediateCrt)
        (New-ConfEntry 'private_key'     $intermediateKey)
        (New-ConfEntry 'serial'          '$dir/serial')
        (New-ConfEntry 'default_md'      'sha256')
        (New-ConfEntry 'default_days'    ([string]$p.LeafDays))
        (New-ConfEntry 'policy'          'policy_ev')
        (New-ConfEntry 'unique_subject'  'no')
        (New-ConfEntry 'copy_extensions' 'none')
        (New-ConfEntry 'email_in_dn'     'no')
        (New-ConfEntry 'string_mask'     'utf8only')
        (New-ConfEntry 'utf8'            'yes')
    )

    # --------------------------------------------------------
    # Subject policy: every EV field is accepted.
    # --------------------------------------------------------

    $policyEntriesList = [System.Collections.Generic.List[object]]::new()
    $policyKnown = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($pair in @(
        @('countryName', 'optional'), @('stateOrProvinceName', 'optional'),
        @('localityName', 'optional'), @('organizationName', 'optional'),
        @('organizationalUnitName', 'optional'), @('commonName', 'supplied'),
        @('emailAddress', 'optional'), @('businessCategory', 'optional'),
        @('serialNumber', 'optional'), @('streetAddress', 'optional'),
        @('postalCode', 'optional'), @('jurisdictionCountryName', 'optional'),
        @('jurisdictionStateOrProvinceName', 'optional'),
        @('jurisdictionLocalityName', 'optional')
    )) {
        [void]$policyKnown.Add($pair[0])
        [void]$policyEntriesList.Add((New-ConfEntry $pair[0] $pair[1]))
    }

    foreach ($f in $ev.DnFields) {
        $long = $script:EvDnLongNames[$f.Canonical]
        if ($null -ne $long -and $policyKnown.Contains($long)) { continue }
        if ($policyKnown.Add($f.Key)) {
            [void]$policyEntriesList.Add((New-ConfEntry $f.Key 'optional'))
        }
    }

    Add-OpenSslConfSection -Builder $sb -Name 'policy_ev' -Entries $policyEntriesList

    # --------------------------------------------------------
    # CSR defaults for Root / Intermediate (-subj supplies values)
    # --------------------------------------------------------

    Add-OpenSslConfSection -Builder $sb -Name 'req' -Entries @(
        (New-ConfEntry 'prompt'             'no')
        (New-ConfEntry 'utf8'               'yes')
        (New-ConfEntry 'string_mask'        'utf8only')
        (New-ConfEntry 'default_md'         'sha256')
        (New-ConfEntry 'distinguished_name' 'dn')
    )

    Add-OpenSslConfSection -Builder $sb -Name 'dn' -Entries @(
        (New-ConfEntry 'C'  (ConvertTo-OpenSslConfValue -Value $p.Country))
        (New-ConfEntry 'O'  (ConvertTo-OpenSslConfValue -Value $p.Organization))
        (New-ConfEntry 'CN' (ConvertTo-OpenSslConfValue -Value $p.Domain))
    )

    # --------------------------------------------------------
    # Extension sections (from ev_pki.cnf, with built-in fallback)
    # --------------------------------------------------------

    if ($copyNames -notcontains 'v3_root') {
        Add-OpenSslConfSection -Builder $sb -Name 'v3_root' -Entries @(
            (New-ConfEntry 'basicConstraints'       'critical,CA:true,pathlen:1')
            (New-ConfEntry 'keyUsage'               'critical,keyCertSign,cRLSign')
            (New-ConfEntry 'subjectKeyIdentifier'   'hash')
            (New-ConfEntry 'authorityKeyIdentifier' 'keyid:always')
        )
    }

    if ($copyNames -notcontains 'v3_intermediate') {
        Add-OpenSslConfSection -Builder $sb -Name 'v3_intermediate' -Entries @(
            (New-ConfEntry 'basicConstraints'       'critical,CA:true,pathlen:0')
            (New-ConfEntry 'keyUsage'               'critical,keyCertSign,cRLSign')
            (New-ConfEntry 'subjectKeyIdentifier'   'hash')
            (New-ConfEntry 'authorityKeyIdentifier' 'keyid,issuer')
            (New-ConfEntry 'certificatePolicies'    '@ev_policy_ca')
        )

        if ($copyNames -notcontains 'ev_policy_ca') {
            Add-OpenSslConfSection -Builder $sb -Name 'ev_policy_ca' -Entries @(
                (New-ConfEntry 'policyIdentifier' '2.5.29.32.0')
            )
        }
    }

    foreach ($name in $copyNames) {

        if ($name -ieq 'new_oids' -or $name -ieq $ev.SanSection -or $name -ieq $ev.PolicySection) {
            continue
        }

        Add-OpenSslConfSection -Builder $sb -Name $name -Entries $ini.Sections[$name]
    }

    if ($copyNames -contains 'new_oids') {
        Add-OpenSslConfSection -Builder $sb -Name 'new_oids' -Entries $ini.Sections['new_oids']
    }

    Add-OpenSslConfSection -Builder $sb -Name $ev.PolicySection -Entries $ev.PolicyEntries
    Add-OpenSslConfSection -Builder $sb -Name $ev.SanSection    -Entries $ev.SanEntries

    Write-Utf8NoBom -Path $p.RuntimeConfig -Content $sb.ToString()

    # --------------------------------------------------------
    # Leaf CSR configuration: the complete EV subject.
    #
    # A config file (not -subj) is used so Unicode characters
    # such as the U-umlaut survive the Windows process boundary.
    # --------------------------------------------------------

    $req = [System.Text.StringBuilder]::new()

    [void]$req.AppendLine('# Generated EV leaf request configuration. Do not edit manually.')
    [void]$req.AppendLine('')

    Add-OpenSslConfSection -Builder $req -Name 'req' -Entries @(
        (New-ConfEntry 'prompt'             'no')
        (New-ConfEntry 'utf8'               'yes')
        (New-ConfEntry 'string_mask'        'utf8only')
        (New-ConfEntry 'default_md'         'sha256')
        (New-ConfEntry 'distinguished_name' 'dn_leaf_ev')
    )

    Add-OpenSslConfSection -Builder $req -Name 'dn_leaf_ev' -Entries $ev.DnFields

    Write-Utf8NoBom -Path $p.LeafReqConfig -Content $req.ToString()

    Write-PkiVerbose "Runtime OpenSSL config: $($p.RuntimeConfig)"
    Write-PkiVerbose "EV leaf request config: $($p.LeafReqConfig)"
}