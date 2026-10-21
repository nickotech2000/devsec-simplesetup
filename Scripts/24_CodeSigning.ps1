# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 24_CodeSigning.ps1  -  the CODE SIGNING profiles of GenerateCodeSigningCertificate.ps1 (7.5.2)
#
#   Platforms  Windows   Authenticode: exe dll sys msi msix appx cab cat ocx ps1 psm1 vbs js, Office VBA, NuGet, ClickOnce
#              Java      jarsigner: jar war ear aab
#              Android   apksigner: apk (v1 + v2 + v3 + v4 schemes) and aab (jarsigner)
#              Apple     rcodesign / codesign: Mach-O, .app, .dylib, .framework, .dmg (Application) and .pkg (Installer)
#   Level      OV or EV (default EV). EV adds businessCategory, jurisdiction and serialNumber to the subject.
#   Issuer     the intermediate of the level (default), the Quadrant Root, any CA of the catalog (-IssuerId), or a CA that
#              is on this computer: PEM files (-IssuerCert / -IssuerKey), a PFX (-IssuerPfx) or the Windows store (-IssuerThumbprint).
#   Key / hash RSA 4096 (default; 6144, 7680, 8192) or ECDSA P-384 / P-521; SHA-256 (default), SHA-384, SHA-512, SHA3-256/384/512.
#   Output     leafcerts\codesign\<company>\<platform>\  (one folder per platform; a run never overwrites: a new folder is made)
#
# Provides : Get-PkiCodeSignSettings, Get-PkiCodeSignPlatforms, Resolve-PkiCodeSignPlatformList, Get-PkiCodeSignSubject,
#            Resolve-PkiCodeSignIssuer, Get-PkiCodeSignPolicyOids, New-PkiCodeSignSpec, New-PkiCodeSignExternalCertificate,
#            Write-PkiCodeSignNotes, Add-PkiCodeSignIndex, Get-PkiCodeSignIndex, Show-PkiCodeSignIssuers
# Requires : 00-04, 06, 13, 14 (New-PkiLeafSpec, New-PkiLeafCertificate, Test-PkiLeafResult, Write-PkiLeafFormats)
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# CA/Browser Forum Code Signing Baseline Requirements: the policy OIDs of an OV and an EV code signing certificate.
# Sign-Code.ps1 / .sh read them to tell OV from EV.
$script:PkiCodeSignCabfOid = @{ OV = '2.23.140.1.4.1'; EV = '2.23.140.1.3' }

# EKUs beyond codeSigning (1.3.6.1.5.5.7.3.3)
$script:PkiCodeSignEku = [ordered]@{
    LifetimeSigning = '1.3.6.1.4.1.311.10.3.13'      # Windows: the signature ends with the certificate (no timestamp extension of life)
    KernelMode      = '1.3.6.1.4.1.311.61.1.1'       # Windows kernel mode code signing (drivers in test mode / own policy)
    ApplePackage    = '1.2.840.113635.100.4.13'      # Apple: packageSign (the Installer certificate of a .pkg)
}

# The platforms. Token = folder and file name part. Files = what the certificate signs (shown in the notes).
$script:PkiCodeSignPlatforms = [ordered]@{
    Windows = @{ Token = 'windows'; Label = 'Windows (Authenticode)'; Tool = 'signtool (Windows), osslsigncode (Linux), Sign-Code.ps1 / .sh'
                 Files = 'exe dll sys ocx scr cpl efi drv winmd msi msp msix appx msixbundle appxbundle cab cat ps1 psm1 psd1 ps1xml vbs js wsf, Office VBA (docm xlsm ...), NuGet (nupkg), ClickOnce / VSTO manifests' }
    Java    = @{ Token = 'java'; Label = 'Java (jarsigner)'; Tool = 'jarsigner, Maven jarsigner plugin, Gradle signing, Sign-Code.ps1 / .sh'
                 Files = 'jar war ear, Java applets / Web Start, aab (Android App Bundle upload key)' }
    Android = @{ Token = 'android'; Label = 'Android (apksigner)'; Tool = 'apksigner (build-tools), Android Gradle Plugin signingConfigs, Sign-Code.ps1 / .sh'
                 Files = 'apk (signature schemes v1, v2, v3, v4), aab (upload key, jarsigner)' }
    Apple   = @{ Token = 'apple'; Label = 'Apple macOS / iOS (Application)'; Tool = 'rcodesign (Windows, Linux), codesign (macOS), Sign-Code.ps1 / .sh'
                 Files = 'Mach-O executables, .app bundles, .dylib, .framework, .bundle, .dmg' }
    AppleInstaller = @{ Token = 'apple-installer'; Label = 'Apple macOS Installer (.pkg)'; Tool = 'rcodesign (Windows, Linux), productsign (macOS), Sign-Code.ps1 / .sh'
                 Files = 'flat installer packages .pkg / .mpkg' }
}

function Get-PkiCodeSignSettings {
    # agantra_pki.cnf [ codesign ]; every value can be replaced on the command line
    $c = $script:Pki
    $g = { param($k, $d) Get-PkiIniValue -Ini $c.Ini -Section 'codesign' -Key $k -Default $d }
    $b = { param($k, $d) ([string](& $g $k $d)).Trim().ToLowerInvariant() -in 'true', 'yes', '1', 'on' }
    return [ordered]@{
        Level        = [string](& $g 'Level' 'EV')
        Platform     = @(([string](& $g 'Platform' 'Windows')) -split '[,; ]+' | Where-Object { $_ })
        KeyType      = [string](& $g 'KeyType' 'RSA')
        KeyBits      = [int](& $g 'KeyBits' '4096')
        Curve        = [string](& $g 'Curve' 'P-384')
        Hash         = [string](& $g 'Hash' 'sha256')
        DaysOV       = [int](& $g 'DaysOV' '1095')
        DaysAndroid  = [int](& $g 'DaysAndroid' '9125')
        Company      = [string](& $g 'Company' '')
        CabfPolicy   = (& $b 'CabfPolicy' 'true')
        Folder       = [string](& $g 'Folder' 'codesign')
    }
}

function Get-PkiCodeSignPlatforms { return $script:PkiCodeSignPlatforms }

function Resolve-PkiCodeSignPlatformList {
    # -Platform Windows,Java,Android,Apple,All  and -AppleType Application|Installer|Both  ->  the profile names, in order
    param([string[]]$Platform, [ValidateSet('Application', 'Installer', 'Both')][string]$AppleType = 'Application')
    $out = [System.Collections.Generic.List[string]]::new()
    $want = @($Platform | ForEach-Object { $_ -split '[,; ]+' } | Where-Object { $_ })
    if ($want -contains 'All') { $want = @('Windows', 'Java', 'Android', 'Apple') }
    foreach ($p in $want) {
        switch -Regex ($p) {
            '^(?i)(windows|win|authenticode|exe|dll|ps1|msi|powershell)$' { if (-not $out.Contains('Windows')) { [void]$out.Add('Windows') } }
            '^(?i)(java|jar)$'                                            { if (-not $out.Contains('Java')) { [void]$out.Add('Java') } }
            '^(?i)(android|apk|aab)$'                                     { if (-not $out.Contains('Android')) { [void]$out.Add('Android') } }
            '^(?i)(apple|macos|mac|ios|osx)$' {
                if ($AppleType -in 'Application', 'Both' -and -not $out.Contains('Apple')) { [void]$out.Add('Apple') }
                if ($AppleType -in 'Installer', 'Both' -and -not $out.Contains('AppleInstaller')) { [void]$out.Add('AppleInstaller') }
            }
            '^(?i)(appleinstaller|pkg)$' { if (-not $out.Contains('AppleInstaller')) { [void]$out.Add('AppleInstaller') } }
            default { throw "Unknown platform '$p'. Use Windows, Java, Android, Apple or All (several: -Platform Windows,Java)." }
        }
    }
    if ($out.Count -eq 0) { throw 'No platform: give -Platform Windows, Java, Android, Apple or All.' }
    return @($out)
}

function Get-PkiCodeSignSubject {
    <#
    .SYNOPSIS
        The subject of a code signing certificate.  OV: C, ST, L, O, CN (CN = O = the company).
        EV (CA/B Forum EV Code Signing): businessCategory, jurisdictionC / ST / L, serialNumber (the registration number) first, then C, ST, L, O, CN.
        Values: the command line (-Company, -Country, -State, -Locality, -Serial, -BusinessCategory, -Jurisdiction*), else [ subject_ev ] /
        [ subject_ov ] of the configuration, else EE / Tallinn.
    #>
    param([string]$Company = '', [Parameter(Mandatory)][ValidateSet('OV', 'EV')][string]$Level, [string]$OrganizationalUnit = '')
    $pairs = [System.Collections.Generic.List[object]]::new()
    $add = { param($k, $v) if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$pairs.Add(@($k, (ConvertTo-PkiAscii ([string]$v).Trim()))) } }
    if ($Level -eq 'EV') {
        & $add 'businessCategory' (Get-PkiLeafSubjectValue 'BusinessCategory' 'businessCategory' 'Private Organization' 'EV')
        & $add 'jurisdictionCountryName' (Get-PkiLeafSubjectValue 'JurisdictionCountry' 'jurisdictionCountryName' (Get-PkiLeafSubjectValue 'Country' 'C' 'EE' 'EV') 'EV')
        & $add 'jurisdictionStateOrProvinceName' (Get-PkiLeafSubjectValue 'JurisdictionState' 'jurisdictionStateOrProvinceName' '' 'EV')
        & $add 'jurisdictionLocalityName' (Get-PkiLeafSubjectValue 'JurisdictionLocality' 'jurisdictionLocalityName' '' 'EV')
        $sn = Get-PkiLeafSubjectValue 'Serial' 'serialNumber' '' 'EV'
        if ([string]::IsNullOrWhiteSpace($sn)) { throw 'An EV code signing certificate needs the registration number of the company (-Serial <number>, or serialNumber in [ subject_ev ]).' }
        & $add 'serialNumber' $sn
    }
    foreach ($p in (Get-PkiCodeSigningDn -Company $Company -Level $Level)) {
        if ($p[0] -eq 'CN' -and -not [string]::IsNullOrWhiteSpace($OrganizationalUnit)) { & $add 'OU' $OrganizationalUnit }
        [void]$pairs.Add($p)
    }
    return ,$pairs
}

function Get-PkiCodeSignPolicyOids {
    # extra policies of a code signing certificate: the CA/B Forum code signing OID of the level (unless -NoCabfPolicy)
    param([Parameter(Mandatory)][ValidateSet('OV', 'EV')][string]$Level, [bool]$Cabf = $true)
    if (-not $Cabf) { return @() }
    return @($script:PkiCodeSignCabfOid[$Level])
}

function Show-PkiCodeSignIssuers {
    # -ListIssuers: the CAs of this PKI that can sign (key present), and on Windows the CA certificates with a private key in the stores
    $c = $script:Pki
    Write-Host ''
    Write-Host 'CAS OF THIS PKI   (-IssuerId <id>, or -Issuer Intermediate | QuadrantRoot)' -ForegroundColor Cyan
    Write-Host ('  {0,-14} {1,-12} {2,-6} {3,-11} {4}' -f 'ID', 'KIND', 'KEY', 'EXPIRES', 'COMMON NAME')
    foreach ($ca in $c.Catalog) {
        if ($ca.Kind -in 'root', 'track') { continue }
        if ($ca.Quadrant -notin 1, 2) { continue }
        if ($c.Quadrants -notcontains $ca.Quadrant) { continue }
        $p = Get-PkiCaPaths -Ca $ca
        if (-not (Test-Path -LiteralPath $p.Crt)) { continue }
        $b = $c.Built[$ca.Id]
        $na = if ($null -ne $b) { [string]$b['notAfter'] } else { '' }
        $cn = if ($null -ne $b) { [string]$b['commonName'] } else { '' }
        Write-Host ('  {0,-14} {1,-12} {2,-6} {3,-11} {4}' -f $ca.Id, $ca.Kind, $(if (Test-Path -LiteralPath $p.Key) { 'yes' } else { 'NO' }), $na, $cn)
    }
    Write-Host '  The Enterprise Root and the Track Roots never sign a leaf (offline anchors).' -ForegroundColor DarkGray
    if ($IsWindows) {
        Write-Host ''
        Write-Host 'CA CERTIFICATES WITH A PRIVATE KEY IN THE WINDOWS STORES   (-IssuerThumbprint <sha1> -IssuerStore ...)' -ForegroundColor Cyan
        $found = 0
        foreach ($loc in 'CurrentUser', 'LocalMachine') {
            foreach ($name in 'My', 'CA', 'Root') {
                try {
                    $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, $loc); $st.Open('ReadOnly')
                    foreach ($x in $st.Certificates) {
                        if (-not $x.HasPrivateKey) { continue }
                        $bc = $x.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | Select-Object -First 1
                        if (-not $bc -or -not $bc.CertificateAuthority) { continue }
                        $found++
                        Write-Host ('  {0}\{1,-5} {2}  until {3}  {4}' -f $loc, $name, $x.Thumbprint, $x.NotAfter.ToString('yyyy-MM-dd'), $x.Subject)
                    }
                    $st.Close()
                } catch { }
            }
        }
        if ($found -eq 0) { Write-Host '  none (a CA key in the store must be exportable to be used here).' -ForegroundColor DarkGray }
    }
    Write-Host ''
    Write-Host 'A CA ON THIS COMPUTER AS FILES:   -IssuerCert ca.crt -IssuerKey ca.key [-IssuerChain chain.pem]   or   -IssuerPfx ca.pfx' -ForegroundColor Cyan
    Write-Host '  The key password comes from the variable named by -IssuerPasswordEnv (default PKI_ISSUER_PASSWORD).' -ForegroundColor DarkGray
}

function Resolve-PkiCodeSignIssuer {
    <#
    .SYNOPSIS
        Which CA signs.  Catalog = a CA of this PKI (Spec.Ca is replaced).  External = files / PFX / Windows store: a hashtable with Crt, Key,
        Chain (CA certificates above the issuer), Family and a temporary folder that the caller removes.
    #>
    param([string]$Issuer = 'Intermediate', [string]$IssuerId, [string]$IssuerCert, [string]$IssuerKey, [string]$IssuerChain, [string]$IssuerPfx,
          [string]$IssuerThumbprint, [string]$IssuerStore = 'CurrentUser\My', [string]$IssuerPasswordEnv = 'PKI_ISSUER_PASSWORD',
          [Parameter(Mandatory)][ValidateSet('OV', 'EV')][string]$Level, [Parameter(Mandatory)][int]$Quadrant)
    $c = $script:Pki
    if ($IssuerCert -or $IssuerPfx -or $IssuerThumbprint) {
        $n = @($IssuerCert, $IssuerPfx, $IssuerThumbprint | Where-Object { $_ }).Count
        if ($n -gt 1) { throw 'Give ONE external issuer: -IssuerCert/-IssuerKey, -IssuerPfx or -IssuerThumbprint.' }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('codesign-issuer-' + [Guid]::NewGuid().ToString('N'))
        [void][System.IO.Directory]::CreateDirectory($tmp)
        $crt = Join-Path $tmp 'issuer.crt'; $key = Join-Path $tmp 'issuer.key'; $chain = Join-Path $tmp 'issuer-chain.crt'
        $pw = [Environment]::GetEnvironmentVariable($IssuerPasswordEnv)
        $X = [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
        $label = ''
        if ($IssuerCert) {
            if (-not $IssuerKey) { throw '-IssuerCert needs -IssuerKey (the private key of that CA).' }
            foreach ($f in $IssuerCert, $IssuerKey) { if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "Issuer file not found: $f" } }
            [void](Invoke-OpenSSL -Arguments @('x509', '-in', (Resolve-Path -LiteralPath $IssuerCert).Path, '-out', $crt))
            $kArgs = @('pkey', '-in', (Resolve-Path -LiteralPath $IssuerKey).Path, '-out', $key)
            if ($pw) { $env:PKI_CODESIGN_ISSUER_PW = $pw; $kArgs += @('-passin', 'env:PKI_CODESIGN_ISSUER_PW') } else { $kArgs += @('-passin', 'pass:') }
            try { [void](Invoke-OpenSSL -Arguments $kArgs) } finally { Remove-Item Env:PKI_CODESIGN_ISSUER_PW -ErrorAction SilentlyContinue }
            if ($IssuerChain) { Copy-Item -LiteralPath $IssuerChain -Destination $chain -Force } else { Write-Utf8NoBom -Path $chain -Content '' }
            $label = "files $IssuerCert"
        }
        else {
            $pfxPath = $null; $pfxPw = $pw
            if ($IssuerPfx) {
                if (-not (Test-Path -LiteralPath $IssuerPfx -PathType Leaf)) { throw "Issuer PFX not found: $IssuerPfx" }
                $pfxPath = (Resolve-Path -LiteralPath $IssuerPfx).Path; $label = "PFX $IssuerPfx"
            }
            else {
                if (-not $IsWindows) { throw '-IssuerThumbprint reads the Windows certificate store: Windows only. On Linux use -IssuerCert/-IssuerKey or -IssuerPfx.' }
                $parts = $IssuerStore -split '\\'
                if ($parts.Count -ne 2 -or $parts[0] -notin 'CurrentUser', 'LocalMachine') { throw "-IssuerStore must be CurrentUser\<name> or LocalMachine\<name> (got '$IssuerStore')." }
                $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($parts[1], $parts[0]); $st.Open('ReadOnly')
                $hit = $st.Certificates | Where-Object { $_.Thumbprint -eq ($IssuerThumbprint -replace '\s', '').ToUpperInvariant() } | Select-Object -First 1; $st.Close()
                if (-not $hit) { throw "No certificate with thumbprint $IssuerThumbprint in $IssuerStore." }
                if (-not $hit.HasPrivateKey) { throw "The certificate $IssuerThumbprint in $IssuerStore has no private key on this computer." }
                $pfxPw = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
                try { $bytes = $hit.Export('Pfx', $pfxPw) } catch { throw "The private key of $IssuerThumbprint cannot be exported (it was imported as not exportable, or it lives on a smart card / HSM). Export it as a PFX by hand, or use the files." }
                $pfxPath = Join-Path $tmp 'store.pfx'; [System.IO.File]::WriteAllBytes($pfxPath, $bytes)
                $label = "Windows store $IssuerStore $IssuerThumbprint"
            }
            $env:PKI_CODESIGN_ISSUER_PW = [string]$pfxPw
            try {
                $base = @('pkcs12', '-in', $pfxPath, '-passin', 'env:PKI_CODESIGN_ISSUER_PW')
                $r1 = Invoke-OpenSSL -AllowFailure -Arguments ($base + @('-nokeys', '-clcerts', '-out', $crt))
                if ($r1.ExitCode -ne 0) { $base += '-legacy'; $r1 = Invoke-OpenSSL -AllowFailure -Arguments ($base + @('-nokeys', '-clcerts', '-out', $crt)) }
                if ($r1.ExitCode -ne 0) { throw "The issuer PFX cannot be opened (password in the variable ${IssuerPasswordEnv}?)." }
                [void](Invoke-OpenSSL -Arguments ($base + @('-nocerts', '-noenc', '-out', (Join-Path $tmp 'k.pem'))))
                [void](Invoke-OpenSSL -Arguments @('pkey', '-in', (Join-Path $tmp 'k.pem'), '-out', $key))
                Remove-Item -LiteralPath (Join-Path $tmp 'k.pem') -Force
                $r3 = Invoke-OpenSSL -AllowFailure -Arguments ($base + @('-nokeys', '-cacerts', '-out', $chain))
                if ($r3.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $chain)) { Write-Utf8NoBom -Path $chain -Content '' }
            }
            finally { Remove-Item Env:PKI_CODESIGN_ISSUER_PW -ErrorAction SilentlyContinue }
            if ($IssuerChain) { Copy-Item -LiteralPath $IssuerChain -Destination $chain -Force }
        }
        # strip the bag attributes: only the PEM blocks stay
        foreach ($f in $crt, $chain) {
            $t = [System.IO.File]::ReadAllText($f)
            $blocks = @([regex]::Matches($t, '-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----') | ForEach-Object { ($_.Value -replace "`r", '').Trim() })
            Write-Utf8NoBom -Path $f -Content $(if ($blocks.Count) { ($blocks -join "`n") + "`n" } else { '' })
        }
        $text = Get-PkiCertText -Path $crt
        if ($text -notmatch 'CA:TRUE') { throw "The issuer ($label) is not a CA certificate (basicConstraints CA:TRUE is missing): a leaf cannot sign another certificate." }
        if ($text -match 'X509v3 Key Usage:[^\r\n]*\r?\n\s*([^\r\n]+)' -and $Matches[1] -notmatch 'Certificate Sign') { throw "The issuer ($label) has no keyCertSign key usage." }
        if ((Get-PkiPublicKeyPem -Path $crt -Kind cert -Fips $false) -ne (Get-PkiPublicKeyPem -Path $key -Kind key -Fips $false)) { throw "The private key does not belong to the issuer certificate ($label)." }
        $fam = if ($text -match 'Public Key Algorithm:\s*id-ecPublicKey') { 'ecdsa' } elseif ($text -match 'Public Key Algorithm:\s*rsa') { 'rsa' } else { throw "The issuer key type is not RSA or ECDSA ($label): it cannot sign a code signing certificate." }
        $na = ''
        try { $x = $X::new($crt); $na = $x.NotAfter.ToUniversalTime(); $room = [int][Math]::Floor(($na - [DateTime]::UtcNow).TotalDays) - 1 } catch { $room = $null }
        $subj = ''; if ($text -match '(?m)^\s*Subject:\s*(.+)$') { $subj = $Matches[1].Trim() }
        Write-PkiLog "Issuer: EXTERNAL CA from $label  [$subj]" 'INFO'
        return [ordered]@{ Mode = 'External'; Crt = $crt; Key = $key; Chain = $chain; Family = $fam; Room = $room; Subject = $subj; Label = $label; Temp = $tmp; Ca = $null }
    }
    $id = if ($IssuerId) { $IssuerId.ToLowerInvariant() } elseif ($Issuer -eq 'QuadrantRoot') { "q$Quadrant-root" } else { "q$Quadrant-$($Level.ToLowerInvariant())" }
    $ca = Get-PkiCa -Id $id
    if ($ca.Kind -in 'root', 'track') { throw "The $($ca.Kind) CA '$id' is an offline anchor and never signs a leaf. Use the Quadrant Root (q$Quadrant-root) or an intermediate." }
    if ($ca.Quadrant -in 3, 4) { throw "The CA '$id' is a Quantum (ML-DSA) CA: code signing tools do not accept ML-DSA. Use a Classic CA (Quadrant 1 or 2)." }
    if ($null -eq $ca.Actual) { throw "The CA '$id' is not part of this PKI (built quadrants: $(($c.Quadrants | ForEach-Object { "Q$_" }) -join ', '))." }
    if (-not (Test-Path -LiteralPath (Get-PkiCaPaths -Ca $ca).Key)) { throw "The private key of the CA '$id' is not on this computer ($((Get-PkiCaPaths -Ca $ca).Key)). Choose another issuer (-ListIssuers)." }
    if ($ca.Kind -eq 'intermediate' -and $ca.Id -notmatch "-$($Level.ToLowerInvariant())$") { Write-PkiLog "The issuer $id is not the $Level intermediate: the level policy of the certificate and of its issuer differ." 'WARN' }
    if ($ca.Kind -eq 'quadrant') { Write-PkiLog "Issuer: the Quadrant Root $id signs directly (chain leaf -> Quadrant Root -> Track Root -> Enterprise Root). Usual practice is an intermediate." 'WARN' }
    return [ordered]@{ Mode = 'Catalog'; Ca = $ca; Room = (Get-PkiIssuerRemainingDays -IssuerId $ca.Id); Label = $id; Temp = $null }
}

function New-PkiCodeSignSpec {
    <#
    .SYNOPSIS
        Everything of ONE code signing certificate, decided before a file is written: the leaf spec of 14_LeafGenerator with the platform EKUs,
        the code signing subject, the CA/B Forum policy, the days and the names.
    #>
    param([Parameter(Mandatory)][string]$Platform, [Parameter(Mandatory)][hashtable]$Base, [Parameter(Mandatory)]$Issuer, [string[]]$CombinedPlatforms = @())
    $prof = $script:PkiCodeSignPlatforms[$Platform]
    $eku = [System.Collections.Generic.List[string]]::new()
    $plats = if ($CombinedPlatforms.Count -gt 0) { $CombinedPlatforms } else { @($Platform) }
    if (@($plats | Where-Object { $_ -ne 'AppleInstaller' }).Count -gt 0) { [void]$eku.Add('CodeSigning') }
    if ($plats -contains 'AppleInstaller') { [void]$eku.Add($script:PkiCodeSignEku.ApplePackage) }
    if ($plats -contains 'Windows') {
        if ($Base.LifetimeSigning) { [void]$eku.Add($script:PkiCodeSignEku.LifetimeSigning) }
        if ($Base.KernelMode) { [void]$eku.Add($script:PkiCodeSignEku.KernelMode) }
    }
    $policy = @(@($Base.Policy | Where-Object { $_ }) + @(Get-PkiCodeSignPolicyOids -Level $Base.Level -Cabf $Base.Cabf))
    $o = @{
        Level = $Base.Level; Quadrant = $Base.Quadrant; Eku = @($eku); KeyType = $Base.KeyType; KeyBits = $Base.KeyBits; Curve = $Base.Curve
        Hash = $Base.Hash; Policy = $policy; Format = $Base.Format; NoCrl = $Base.NoCrl; NoOcsp = $Base.NoOcsp
        PersonDn = $Base.Dn; NameOverride = $Base.Name
    }
    # days: Android signing keys live long (the key of an app never changes); others: the level default or -Days
    $days = [int]$Base.Days
    if ($days -le 0) {
        if ($plats -contains 'Android' -and $Base.Level -eq 'OV') { $days = [int]$Base.DaysAndroid }
        elseif ($Base.Level -eq 'OV') { $days = [int]$Base.DaysOV }
        else { $days = 397 }
    }
    $o.Days = $days
    if ($Issuer.Mode -eq 'External') { $spec = New-PkiCodeSignExternalSpec -Options $o -Issuer $Issuer }
    elseif ($Issuer.Ca.Kind -ne 'intermediate') {
        # New-PkiLeafSpec limits by the intermediate of the level; the real issuer decides
        $spec = New-PkiLeafSpec -Options $o
        $spec.Ca = $Issuer.Ca
        $room = $Issuer.Room
        if ($null -ne $room -and $spec.Days -gt $room) { [void]$spec.Notes.Add("validity limited by the issuer: $($spec.Days) -> $room days"); $spec.Days = $room }
        $spec.Md = (Resolve-PkiLeafHash -Ca $Issuer.Ca -Hash $Base.Hash).Md
    }
    else { $spec = New-PkiLeafSpec -Options $o }
    # a code signing certificate carries the CA/B Forum CODE SIGNING policy, not the TLS level policy (2.23.140.1.1 / 2.23.140.1.2.x)
    if ($Base.Cabf) { $spec.Policies = @($spec.Policies | Where-Object { $_.Oid -notin '2.23.140.1.1', '2.23.140.1.2.1', '2.23.140.1.2.2' }) }
    if ($plats -contains 'Android' -and $spec.Days -lt 9125) { [void]$spec.Notes.Add("Android: the app signing key is valid $($spec.Days) days. Google Play wants an upload / signing certificate valid after 22 October 2033; a key cannot be replaced without key rotation (APK signature scheme v3). Use -OV and a long -Days for a real app.") }
    if ($Base.Hash -match '^sha3') { [void]$spec.Notes.Add("$($Base.Hash.ToUpperInvariant()) signature: Windows before 11 24H2, Java before 17 and Android do not verify SHA-3 certificate signatures. Use sha256 / sha384 / sha512 for wide support.") }
    $tag = $spec.Tag
    $tok = if ($CombinedPlatforms.Count -gt 0) { 'multi' } else { $prof.Token }
    $spec.Stem = (ConvertTo-PkiSafeName ("{0}-codesign-{1}-{2}-{3}" -f $Base.Name, $tok, $Base.Level.ToLowerInvariant(), $tag))
    $spec.FriendlyName = "Code Signing $($prof.Label) for $($Base.Company) Sign by : $(if ($Issuer.Mode -eq 'External') { $Issuer.Subject } else { Get-PkiCaCommonName -Ca $spec.Ca })"
    $spec.CodeSign = [ordered]@{ Platform = $Platform; Platforms = @($plats); Token = $tok; Label = $(if ($CombinedPlatforms.Count -gt 0) { 'Multi-platform: ' + ($plats -join ', ') } else { $prof.Label }); Issuer = $Issuer.Label; IssuerMode = $Issuer.Mode }
    $spec.CodeSign.Company = $Base.Company
    return $spec
}

function New-PkiCodeSignExternalSpec {
    # The spec for an issuer that is NOT in the catalog: the same rules as New-PkiLeafSpec (key, hash, EKU, policies, days, formats)
    param([Parameter(Mandatory)][hashtable]$Options, [Parameter(Mandatory)]$Issuer)
    $level = [string]$Options.Level
    $eku = @($Options.Eku)
    $notes = [System.Collections.Generic.List[string]]::new()
    $key = Resolve-PkiLeafKey -Quadrant 1 -KeyType ([string]$Options.KeyType) -KeyBits ([int]$Options.KeyBits) -Curve ([string]$Options.Curve) -Eku $eku
    foreach ($n in $key.Notes) { [void]$notes.Add($n) }
    $h = [string]$Options.Hash
    if ($h) {
        $h = $h.Trim().ToLowerInvariant()
        if ($h -in $script:PkiRejectedHashes) { throw "Hash '$h' is rejected: a leaf signature needs SHA-256 or stronger." }
        if ($h -notin $script:PkiLeafHashes) { throw "Hash must be one of $($script:PkiLeafHashes -join ', ') (got '$h')." }
    }
    else { $h = if ($Issuer.Family -eq 'ecdsa') { 'sha384' } else { 'sha256' } }
    $ekuInfo = Get-PkiLeafEkuInfo -Eku $eku -Family $key.Family
    $policies = Get-PkiLeafPolicies -Level $level -PolicyText @($Options.Policy)
    $days = [int]$Options.Days
    if ($level -eq 'EV' -and $days -gt 397) { throw "An EV certificate may not be valid longer than 397 days (asked $days)." }
    if ($null -ne $Issuer.Room -and $days -gt $Issuer.Room) { [void]$notes.Add("validity limited by the issuer: $days -> $($Issuer.Room) days"); $days = $Issuer.Room }
    if ($days -lt 1) { throw 'The external issuer has expired or ends within a day.' }
    $fm = @($Options.Format) | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique
    if ($fm -contains 'ALL') { $fm = @('PEM', 'DER', 'CER', 'CERT', 'P7B', 'RFC7468', 'PFX') }
    return @{
        Level = $level; Quadrant = 1; Track = 'Classic'; Fips = $false; Ca = $null
        Family = $key.Family; Bits = $key.Bits; Curve = $key.Curve; PqcAlg = $null; KeyAlgorithm = $key.Algorithm; Tag = "ext-$($key.Tag)"
        Md = $h; Eku = $eku; EkuOpenSsl = $ekuInfo.Ekus; KeyUsage = $ekuInfo.KeyUsage; KeyUsageFixed = $false; ExtraExt = @($ekuInfo.Extra); ExtraConfig = @()
        San = [ordered]@{ Dns = @(); Ip = @(); Email = @(); Given = $false }; DnPairs = $Options.PersonDn; Policies = $policies; Days = $days
        Primary = [string]$Options.NameOverride; FriendlyName = ''; Folder = ''; PurposeFolder = ''; SetMode = $false; Stem = ''; OutputFolder = ''; UniqueSuffix = '_{Date}-{Time}'
        Formats = @($fm); Notes = $notes; Tokens = @{}; NoCrl = $true; NoOcsp = $true; DevSan = $false; EvSanOverride = $false; TimestampPolicyOid = ''; OutDir = $null; Extras = $true
    }
}

function New-PkiCodeSignExternalCertificate {
    <#
    .SYNOPSIS
        Issues the leaf with a CA that is NOT in the catalog (files, PFX, Windows store): openssl x509 -req with a random 128-bit serial.
        The same files as New-PkiLeafCertificate: .key .pub .pub.der .crt -chain.crt -fullchain.crt .cnf .pfx + the formats + hash files.
    #>
    param([Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)]$Issuer)
    $c = $script:Pki
    $dir = $Spec.OutDir; $stem = $Spec.Stem
    $key = Join-Path $dir "$stem.key"; $csr = Join-Path $dir "$stem.csr"; $crt = Join-Path $dir "$stem.crt"; $cnf = Join-Path $dir "$stem.cnf"
    $full = Join-Path $dir "$stem-fullchain.crt"; $chainF = Join-Path $dir "$stem-chain.crt"; $pfx = Join-Path $dir "$stem.pfx"
    Write-PkiLog "Leaf $stem  ($($Spec.Level), external issuer $($Issuer.Label))"
    foreach ($n in $Spec.Notes) { Write-PkiLog "  note       : $n" 'WARN' }
    $actual = New-PkiPrivateKey -KeyPath $key -Family $Spec.Family -Bits $Spec.Bits -Curve $Spec.Curve -Fips $false -Label $stem -PqcAlgorithm $null -FallbackBits $c.FallbackRsaBits
    [void](ConvertTo-PkiLfFile -Path $key)
    $pubPem = Join-Path $dir "$stem.pub"; $pubDer = Join-Path $dir "$stem.pub.der"
    Write-Utf8NoBom -Path $pubPem -Content (((Invoke-OpenSSL -Arguments @('pkey', '-in', $key, '-pubout')).StdOut -replace "`r", '').TrimEnd() + "`n")
    [void](Invoke-OpenSSL -Arguments @('pkey', '-in', $key, '-pubout', '-outform', 'DER', '-out', $pubDer))
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($x in '[ req ]', 'prompt = no', 'utf8 = yes', 'string_mask = utf8only', 'distinguished_name = dn', '', '[ dn ]') { [void]$L.Add($x) }
    foreach ($pair in $Spec.DnPairs) { [void]$L.Add("$($pair[0]) = $(ConvertTo-PkiConfValue $pair[1])") }
    [void]$L.Add('')
    $policyRefs = Add-PkiPolicySections -Lines $L -Policies $Spec.Policies -Prefix 'lp'
    foreach ($x in '[ ext ]', 'basicConstraints = critical,CA:false', "keyUsage = $($Spec.KeyUsage)", "extendedKeyUsage = $($Spec.EkuOpenSsl)", 'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid,issuer', "certificatePolicies = $policyRefs") { [void]$L.Add($x) }
    Write-Utf8NoBom -Path $cnf -Content (($L -join "`n") + "`n")
    [void](Invoke-OpenSSL -Arguments @('req', '-new', '-key', $key, '-config', $cnf, '-out', $csr) -ConfigPath $cnf)
    $serial = '0x' + (New-PkiRandomSerialHex)
    [void](Invoke-OpenSSL -Arguments @('x509', '-req', '-in', $csr, '-CA', $Issuer.Crt, '-CAkey', $Issuer.Key, '-set_serial', $serial, '-days', [string]$Spec.Days, "-$($Spec.Md)", '-extfile', $cnf, '-extensions', 'ext', '-out', $crt) -ConfigPath $cnf)
    Remove-Item -LiteralPath $csr -Force -ErrorAction SilentlyContinue
    [void](ConvertTo-PkiLfFile -Path $crt)
    $chainText = (([System.IO.File]::ReadAllText($Issuer.Crt)) -replace "`r", '').TrimEnd() + "`n"
    $up = (([System.IO.File]::ReadAllText($Issuer.Chain)) -replace "`r", '').Trim()
    if ($up) { $chainText += $up + "`n" }
    Write-Utf8NoBom -Path $chainF -Content $chainText
    Write-Utf8NoBom -Path $full -Content (((([System.IO.File]::ReadAllText($crt)) -replace "`r", '').TrimEnd() + "`n") + $chainText)
    $pfxOk = $false
    if ($Spec.Formats -contains 'PFX') {
        try { [void](New-PkiPfxFile -KeyPath $key -CertPath $crt -PfxPath $pfx -ChainPath $chainF -Name $Spec.FriendlyName -Legacy:$c.LegacyPfx); $pfxOk = $true }
        catch { Write-PkiLog "PFX for $stem was not created: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
    }
    $fp = Get-PkiCertificateFingerprint -Path $crt
    $notAfter = ''
    try { $notAfter = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($crt)).NotAfter.ToUniversalTime().ToString('yyyy-MM-dd') } catch { }
    $R = @{
        Stem = $stem; Dir = $dir; Crt = $crt; Key = $key; Full = $full; Chain = $chainF; Cnf = $cnf; Pfx = $(if ($pfxOk) { $pfx } else { $null }); PfxFips = $null
        Sha1 = $fp.Sha1; Sha256 = $fp.Sha256; Actual = $actual; Md = $Spec.Md; Days = $Spec.Days; NotAfter = $notAfter; Files = @(); PubPem = $pubPem; PubDer = $pubDer
    }
    [void](Write-PkiLeafFormats -Spec $Spec -R $R)
    $hashAlgs = if (Test-Path variable:script:PkiHashFileAlgs) { @($script:PkiHashFileAlgs) } else { @('sha256', 'sha512') }
    [void](Write-PkiHashFiles -Directory $dir -Stem $stem -Algorithm $hashAlgs)
    # check: key matches, chain verifies against the issuer (and what is above it)
    if ((Get-PkiPublicKeyPem -Path $crt -Kind cert -Fips $false) -ne (Get-PkiPublicKeyPem -Path $key -Kind key -Fips $false)) { throw "The private key does not match the certificate [$stem]." }
    $anchor = Join-Path $dir "$stem.anchor.tmp.pem"
    Write-Utf8NoBom -Path $anchor -Content $chainText
    try {
        $v = Invoke-OpenSSL -AllowFailure -Arguments @('verify', '-partial_chain', '-purpose', 'codesign', '-CAfile', $anchor, $crt)
        if ($v.ExitCode -ne 0) { $v = Invoke-OpenSSL -AllowFailure -Arguments @('verify', '-partial_chain', '-CAfile', $anchor, $crt) }
        if ($v.ExitCode -ne 0) { throw "The certificate does not verify against the external issuer [$stem]: $(($v.StdErr + $v.StdOut) -replace '\s+', ' ')" }
    }
    finally { Remove-Item -LiteralPath $anchor -Force -ErrorAction SilentlyContinue }
    $R.Files = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -notlike '*.tmp.*' } | ForEach-Object { $_.Name } | Sort-Object)
    Write-PkiLog "  thumbprint : $($fp.Sha1)" 'OK'
    return $R
}

function Write-PkiCodeSignNotes {
    # CODESIGN-NOTES.txt next to the certificate: how to sign on this platform, in a pipeline, and what the receiver must trust
    param([Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R, [string]$Password = 'Abc12345!')
    $cs = $Spec.CodeSign
    $subject = (@($Spec.DnPairs) | ForEach-Object { '{0}={1}' -f $_[0], $_[1] }) -join ', '
    $pfxName = "$($R.Stem).pfx"
    $L = [System.Collections.Generic.List[string]]::new()
    [void]$L.Add("Code signing certificate - $($cs.Label)")
    [void]$L.Add("Subject   : $subject")
    [void]$L.Add("Issuer    : $($cs.Issuer)   Level: $($Spec.Level)   Valid until: $($R.NotAfter)   SHA-1: $($R.Sha1)")
    [void]$L.Add("Key       : $($R.Actual.Algorithm)   Signature hash: $($Spec.Md)   EKU: $($Spec.EkuOpenSsl)")
    [void]$L.Add("PFX       : $pfxName   (password: the one given with -Password; default Abc12345! = lab password, CHANGE IT)")
    [void]$L.Add('')
    [void]$L.Add('SIGN WITH THE PROJECT SCRIPT (any platform; timestamp DigiCert by default)')
    [void]$L.Add("  Windows : `$env:SIGN_PFX_PASSWORD = '<password>';  .\Sign-Code.ps1 -Pfx .\$pfxName -File <file> -Verbose")
    [void]$L.Add("  Linux   : export SIGN_PFX_PASSWORD='<password>';  ./Sign-Code.sh --pfx ./$pfxName --file <file> --verbose")
    [void]$L.Add('  Generated certificates are found by the signing script too:  Sign-Code.ps1 -UseGenerated -Folder <build output>')
    [void]$L.Add('')
    foreach ($p in $cs.Platforms) {
        switch ($p) {
            'Windows' {
                [void]$L.Add('WINDOWS (Authenticode)')
                [void]$L.Add('  signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f ' + $pfxName + ' /p <password> app.exe')
                [void]$L.Add('  PowerShell: Set-AuthenticodeSignature -FilePath x.ps1 -Certificate <cert> -TimestampServer http://timestamp.digicert.com -HashAlgorithm SHA256')
                [void]$L.Add('  Linux     : osslsigncode sign -pkcs12 ' + $pfxName + ' -pass <password> -h sha256 -ts http://timestamp.digicert.com -in app.exe -out app-signed.exe')
                [void]$L.Add('  MSIX / APPX: the Publisher of AppxManifest.xml must be EXACTLY the subject, in the RFC 4514 order of the certificate.')
                [void]$L.Add('  Trust: the Root CA of this PKI in Trusted Root, and (for no SmartScreen / UAC warning on your machines) this')
                [void]$L.Add('         certificate in Trusted Publishers:  Import-Certificate -FilePath ' + "$($R.Stem).cer" + ' -CertStoreLocation Cert:\LocalMachine\TrustedPublisher')
                [void]$L.Add('')
            }
            'Java' {
                [void]$L.Add('JAVA (jarsigner)')
                [void]$L.Add('  The PFX is a PKCS#12 key store (Java 9+ default). Alias = the friendly name: keytool -list -keystore ' + $pfxName + ' -storetype PKCS12')
                [void]$L.Add('  jarsigner -keystore ' + $pfxName + ' -storetype PKCS12 -digestalg SHA-256 -tsa http://timestamp.digicert.com app.jar "<alias>"')
                [void]$L.Add('  Maven: maven-jarsigner-plugin (keystore, storetype PKCS12, tsa);  Gradle: the signing / jar tasks with ant.signjar.')
                [void]$L.Add('  Trust: the receivers import the Root CA into their cacerts (keytool -importcert -cacerts) to see a trusted signer.')
                [void]$L.Add('')
            }
            'Android' {
                [void]$L.Add('ANDROID (apksigner)')
                [void]$L.Add('  apksigner sign --ks ' + $pfxName + ' --ks-type PKCS12 --ks-pass env:SIGN_PFX_PASSWORD --v4-signing-enabled true app.apk')
                [void]$L.Add('  Gradle: signingConfigs { release { storeFile file("' + $pfxName + '"); storeType "pkcs12"; keyAlias "<alias>"; storePassword / keyPassword from the environment } }')
                [void]$L.Add('  An APK signature has NO timestamp. The certificate is the identity of the app for ever: keep the key safe and backed up.')
                [void]$L.Add('  Google Play: this key can be the UPLOAD key (Play App Signing keeps the real one).')
                [void]$L.Add('')
            }
            'Apple' {
                [void]$L.Add('APPLE macOS / iOS (Application)')
                [void]$L.Add('  Windows / Linux: rcodesign sign --p12-file ' + $pfxName + ' --p12-password-file pw.txt --timestamp-url http://timestamp.apple.com/ts01 MyApp.app')
                [void]$L.Add('  macOS: security import ' + $pfxName + ' -k login.keychain-db;  codesign --sign "<CN>" --timestamp --options runtime MyApp.app')
                [void]$L.Add('  Gatekeeper and notarization accept ONLY Apple Developer ID certificates. A private PKI certificate is for internal / MDM')
                [void]$L.Add('  managed Macs that trust the Root CA (configuration profile), development and testing.')
                [void]$L.Add('')
            }
            'AppleInstaller' {
                [void]$L.Add('APPLE INSTALLER (.pkg)')
                [void]$L.Add('  rcodesign sign --p12-file ' + $pfxName + ' --p12-password-file pw.txt installer.pkg      macOS: productsign --sign "<CN>" in.pkg out.pkg')
                [void]$L.Add('  The certificate carries the Apple packageSign purpose (1.2.840.113635.100.4.13).')
                [void]$L.Add('')
            }
        }
    }
    [void]$L.Add('CI / CD: store the PFX as base64 in a pipeline secret and the password in a second secret, then')
    [void]$L.Add('  Sign-Code.ps1 -Ci -PfxBase64Env SIGN_PFX_B64 -Folder <output>      (Sign-Code.ps1 -Template all writes examples)')
    [void]$L.Add('This is a certificate of a private PKI. Only computers that trust its Root CA trust the signature.')
    Write-Utf8NoBom -Path (Join-Path $R.Dir 'CODESIGN-NOTES.txt') -Content (($L -join "`n") + "`n")
}

function Get-PkiCodeSignIndexPath { param([string]$Root) return (Join-Path $Root 'codesign-index.json') }

function Add-PkiCodeSignIndex {
    # leafcerts\codesign\codesign-index.json: every generated code signing certificate (Sign-Code -UseGenerated reads it). No passwords.
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$R, [string]$Folder)
    $path = Get-PkiCodeSignIndexPath -Root $Root
    $list = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $path) { try { foreach ($e in @((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).certificates)) { [void]$list.Add($e) } } catch { } }
    $entry = [ordered]@{
        name = $R.Stem; company = $Spec.CodeSign.Company; platform = $Spec.CodeSign.Platform; platforms = @($Spec.CodeSign.Platforms); level = $Spec.Level
        folder = $Folder; pfx = $(if ($R.Pfx) { [System.IO.Path]::GetRelativePath($Root, $R.Pfx) -replace '\\', '/' } else { '' })
        crt = ([System.IO.Path]::GetRelativePath($Root, $R.Crt) -replace '\\', '/'); key = ([System.IO.Path]::GetRelativePath($Root, $R.Key) -replace '\\', '/')
        chain = ([System.IO.Path]::GetRelativePath($Root, $R.Chain) -replace '\\', '/')
        sha1 = $R.Sha1; sha256 = $R.Sha256; keyAlgorithm = $R.Actual.Algorithm; hash = $Spec.Md; notAfter = $R.NotAfter; issuer = $Spec.CodeSign.Issuer
        createdUtc = [DateTime]::UtcNow.ToString('o')
    }
    [void]$list.Add($entry)
    Write-Utf8NoBom -Path $path -Content (([ordered]@{ generator = "GenerateCodeSigningCertificate.ps1 $($script:PkiGeneratorVersion)"; certificates = @($list) } | ConvertTo-Json -Depth 6) + "`n")
    # the same rows as codesign-index.tsv (one per platform), the format GenerateCodeSigningCertificate.sh writes and Sign-Code.sh reads
    $tsv = Join-Path (Split-Path -Parent $path) 'codesign-index.tsv'
    $rows = [System.Text.StringBuilder]::new()
    if (-not (Test-Path -LiteralPath $tsv)) { [void]$rows.Append("# platform`tlevel`tnotAfter`tsha1`tpfx`tcrt`tkey`n") }
    $na = "$($entry.notAfter)"; try { $na = ([datetime]$entry.notAfter).ToString('yyyy-MM-dd') } catch { }
    foreach ($pl in @($entry.platforms)) { $tk = if ($script:PkiCodeSignPlatforms.Contains("$pl")) { $script:PkiCodeSignPlatforms["$pl"].Token } else { "$pl".ToLowerInvariant() }; [void]$rows.Append("$tk`t$($entry.level)`t$na`t$($entry.sha1)`t$($entry.pfx)`t$($entry.crt)`t$($entry.key)`n") }
    [System.IO.File]::AppendAllText($tsv, $rows.ToString(), [System.Text.UTF8Encoding]::new($false))
    return $entry
}

function Get-PkiCodeSignIndex {
    param([Parameter(Mandatory)][string]$Root)
    $path = Get-PkiCodeSignIndexPath -Root $Root
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    return @((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).certificates)
}
