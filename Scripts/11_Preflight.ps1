# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 11_Preflight.ps1
#
#   .\pki_setup.ps1 -Check    Preflight: is this machine ready to generate the PKI?
#                             Tests PowerShell, OS, OpenSSL 4.x, the providers, the FIPS
#                             module (when quadrant 2 or 4 is selected), blocked scripts,
#                             rights, the output folder - and runs a real mini CA with
#                             the exact OpenSSL options the generator uses. Nothing is
#                             written to the PKI folder.
#
#   .\pki_setup.ps1 -Verify   Re-validates an EXISTING PKI folder against pki-manifest.json
#                             (keys, digests, pathlen, policies, chains, PFX) and, on
#                             Windows, shows what is installed in the certificate stores.
#                             It changes nothing.
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiChecks = [System.Collections.Generic.List[object]]::new()

function Add-PkiCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status,
        [string]$Detail = ''
    )
    [void]$script:PkiChecks.Add([ordered]@{ Name = $Name; Status = $Status; Detail = $Detail })
    $color = switch ($Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Gray' } }
    Write-Host ('[{0}] {1,-34} {2}' -f $Status, $Name, $Detail) -ForegroundColor $color
}

function Write-PkiCheckSummary {
    param([string]$ReadyText = 'READY: this machine can generate the PKI.', [string]$NotReadyText = 'NOT READY: fix the FAIL lines above and run -Check again.')
    $fail = @($script:PkiChecks | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn = @($script:PkiChecks | Where-Object { $_.Status -eq 'WARN' }).Count
    Write-Host ''
    if ($fail -eq 0) { Write-Host "$ReadyText  ($warn warning(s))" -ForegroundColor Green }
    else { Write-Host "$NotReadyText  ($fail failure(s), $warn warning(s))" -ForegroundColor Red }
    return ($fail -eq 0)
}

# ------------------------------------------------------------
# A real mini CA with the options the generator uses
# ------------------------------------------------------------
function Invoke-PkiSelfTest {
    param([Parameter(Mandatory)][string]$Dir)

    Ensure-PkiDirectory -Path $Dir
    $d = ConvertTo-PkiConfPath $Dir
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips $false)) { [void]$L.Add($h) }
    foreach ($line in @(
        '[ ca ]', 'default_ca = CA_default', '',
        '[ CA_default ]',
        "dir = $d", 'database = $dir/index.txt', 'new_certs_dir = $dir', 'certificate = $dir/ca.crt',
        'private_key = $dir/ca.key', 'serial = $dir/serial', 'crlnumber = $dir/crlnumber',
        'default_md = sha512', 'default_days = 1', 'default_crl_days = 1', 'policy = pol',
        'unique_subject = no', 'copy_extensions = none', 'preserve = yes', 'utf8 = yes', 'string_mask = utf8only', '',
        '[ pol ]', 'commonName = supplied', '',
        '[ req ]', 'prompt = no', 'utf8 = yes', 'string_mask = utf8only', 'distinguished_name = dn', '',
        '[ dn ]', 'CN = Preflight Root CA', '',
        '[ ext_ca ]', 'basicConstraints = critical,CA:true,pathlen:0', 'keyUsage = critical,keyCertSign,cRLSign',
        'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid:always',
        "certificatePolicies = $($script:PkiPolicyOid.EV)", '',
        '[ ext_leaf ]', 'basicConstraints = critical,CA:false', 'keyUsage = critical,digitalSignature',
        'extendedKeyUsage = serverAuth,clientAuth', 'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid,issuer',
        'subjectAltName = DNS:preflight.local', "certificatePolicies = $($script:PkiPolicyOid.EV)", ''
    )) { [void]$L.Add($line) }
    $cnf = Join-Path $Dir 'st.cnf'
    Write-Utf8NoBom -Path $cnf -Content (($L -join "`n") + "`n")
    Write-Utf8NoBom -Path (Join-Path $Dir 'index.txt') -Content ''
    Write-Utf8NoBom -Path (Join-Path $Dir 'index.txt.attr') -Content "unique_subject = no`n"
    Write-Utf8NoBom -Path (Join-Path $Dir 'serial') -Content ((New-PkiRandomSerialHex) + "`n")
    Write-Utf8NoBom -Path (Join-Path $Dir 'crlnumber') -Content "01`n"

    $prov = Get-PkiProviderArgs -Fips $false
    $p = { param($n) Join-Path $Dir $n }
    $steps = [ordered]@{
        'RSA 2048 key (genpkey)'            = @('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', (& $p 'ca.key'))
        'ECDSA P-521 key (root curve)'      = @('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-521', '-pkeyopt', 'ec_param_enc:named_curve', '-out', (& $p 'p521.key'))
        'Self-signed root, SHA-512'         = @('req', '-x509', '-new', '-key', (& $p 'ca.key'), '-config', $cnf, '-extensions', 'ext_ca', '-days', '2', '-set_serial', '0x1234567890ABCDEF', '-sha512', '-out', (& $p 'ca.crt'))
        'ECDSA P-256 key (leaf)'            = @('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-pkeyopt', 'ec_param_enc:named_curve', '-out', (& $p 'leaf.key'))
        'CSR (req -new)'                    = @('req', '-new', '-key', (& $p 'leaf.key'), '-config', $cnf, '-subj', '/CN=preflight.local', '-sha256', '-out', (& $p 'leaf.csr'))
        'CA issues a certificate (ca)'      = @('ca', '-batch', '-notext', '-utf8', '-preserveDN', '-config', $cnf, '-in', (& $p 'leaf.csr'), '-out', (& $p 'leaf.crt'), '-extfile', $cnf, '-extensions', 'ext_leaf', '-days', '1', '-md', 'sha512')
        'Chain verifies (-x509_strict)'     = @('verify', '-x509_strict', '-purpose', 'sslserver', '-CAfile', (& $p 'ca.crt'))
        'PFX export'                        = @('pkcs12', '-export', '-inkey', (& $p 'leaf.key'), '-in', (& $p 'leaf.crt'), '-out', (& $p 'leaf.pfx'), '-passout', 'env:PKI_PFX_PASSWORD')
        'CRL (ca -gencrl)'                  = @('ca', '-gencrl', '-config', $cnf, '-out', (& $p 'ca.crl.pem'), '-md', 'sha512')
    }
    foreach ($name in $steps.Keys) {
        $args = @($steps[$name])
        if ($name -like 'Chain verifies*') { $args += $prov; $args += (& $p 'leaf.crt') }
        else { $args += $prov }
        try { [void](Invoke-OpenSSL -Arguments $args -ConfigPath $cnf) }
        catch { return [ordered]@{ Ok = $false; Step = $name; Error = ($_.Exception.Message -split "`n" | Select-Object -First 3) -join ' | ' } }
    }
    return [ordered]@{ Ok = $true; Step = ''; Error = '' }
}

# ------------------------------------------------------------
# ML-DSA self-test (only when quadrant 3 or 4 is selected)
# ------------------------------------------------------------
function Invoke-PkiPqcSelfTest {
    param([Parameter(Mandatory)][string]$Dir, [bool]$Fips = $false)
    Ensure-PkiDirectory -Path $Dir
    $L = [System.Collections.Generic.List[string]]::new()
    foreach ($h in (Get-PkiProviderConfigHeader -Fips $Fips)) { [void]$L.Add($h) }
    foreach ($line in @('[ req ]', 'prompt = no', 'utf8 = yes', 'distinguished_name = dn', '', '[ dn ]', 'CN = PQ Preflight', '', '[ ext ]', 'basicConstraints = critical,CA:false', 'keyUsage = critical,digitalSignature', '', '[ ext_ca ]', 'basicConstraints = critical,CA:true', 'keyUsage = critical,keyCertSign,cRLSign', 'subjectKeyIdentifier = hash', '')) { [void]$L.Add($line) }
    $cnf = Join-Path $Dir 'pq.cnf'
    Write-Utf8NoBom -Path $cnf -Content (($L -join "`n") + "`n")
    $prov = Get-PkiProviderArgs -Fips $Fips
    $p = { param($n) Join-Path $Dir $n }
    $rootAlg = $script:PkiRootPqc
    $leafAlg = $script:Pki.PqcLeafAlgorithm
    $steps = [ordered]@{
        "$rootAlg key (CA)"            = @('genpkey', '-algorithm', $rootAlg, '-out', (& $p 'pq-ca.key'))
        'ML-DSA self-signed root'      = @('req', '-x509', '-new', '-key', (& $p 'pq-ca.key'), '-config', $cnf, '-subj', '/CN=PQ Preflight Root', '-extensions', 'ext_ca', '-days', '2', '-set_serial', '0x1234567890ABCDEF', '-out', (& $p 'pq-ca.crt'))
        "$leafAlg key (leaf)"          = @('genpkey', '-algorithm', $leafAlg, '-out', (& $p 'pq-leaf.key'))
        'ML-DSA CSR'                   = @('req', '-new', '-key', (& $p 'pq-leaf.key'), '-config', $cnf, '-subj', '/CN=pq-preflight.local', '-out', (& $p 'pq-leaf.csr'))
        'ML-DSA signs a certificate'   = @('x509', '-req', '-in', (& $p 'pq-leaf.csr'), '-CA', (& $p 'pq-ca.crt'), '-CAkey', (& $p 'pq-ca.key'), '-set_serial', '0x1234', '-days', '1', '-extfile', $cnf, '-extensions', 'ext', '-out', (& $p 'pq-leaf.crt'))
        'ML-DSA chain verifies'        = @('verify', '-CAfile', (& $p 'pq-ca.crt'))
    }
    foreach ($name in $steps.Keys) {
        $a = @($steps[$name]) + $prov
        if ($name -like '*verifies') { $a += (& $p 'pq-leaf.crt') }
        try { [void](Invoke-OpenSSL -Arguments $a -ConfigPath $cnf) }
        catch { return [ordered]@{ Ok = $false; Step = $name; Error = ($_.Exception.Message -split "`n" | Select-Object -First 3) -join ' | ' } }
    }
    return [ordered]@{ Ok = $true; Step = ''; Error = '' }
}

# ------------------------------------------------------------
# -Check
# ------------------------------------------------------------
function Invoke-PkiPreflight {
    $c = $script:Pki
    $script:PkiChecks.Clear()
    Write-Host ''
    Write-Host 'PREFLIGHT  (nothing is written to the PKI folder)' -ForegroundColor Cyan

    # PowerShell
    $psv = $PSVersionTable.PSVersion
    if ($psv.Major -ge 7) { Add-PkiCheck 'PowerShell' 'PASS' "$psv ($($PSVersionTable.PSEdition))" }
    else { Add-PkiCheck 'PowerShell' 'FAIL' "${psv}: PowerShell 7 or newer is required" }

    # Operating system
    $os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    if ($IsWindows) {
        if ($c.ClassicOnly) { Add-PkiCheck 'Operating system' 'WARN' "${os} (build $($c.WindowsBuild)): Windows Server 2022: CLASSIC track only (quadrants 1, 2); no Quantum / ML-DSA" }
        else { Add-PkiCheck 'Operating system' 'PASS' "${os} (build $($c.WindowsBuild)): ML-DSA certificates can be stored; hybrid ML-KEM in Schannel" }
    }
    else { Add-PkiCheck 'Operating system' 'INFO' "${os}: generation works; certificate stores are Windows only (see the manual, section 7)" }

    # Configuration
    Add-PkiCheck 'Configuration file' 'PASS' $c.ConfigPath
    Add-PkiCheck 'Quadrants' 'INFO' ("$($c.Quadrants -join ', ')   (1 Classic Non-FIPS, 2 Classic FIPS, 3 Quantum Non-FIPS, 4 Quantum FIPS)")
    Add-PkiCheck 'Policy OIDs' 'PASS' "EV $($script:PkiPolicyOid.EV) | OV $($script:PkiPolicyOid.OV) | DV $($script:PkiPolicyOid.DV)"
    if ([string]::IsNullOrWhiteSpace($c.IanaPen)) { Add-PkiCheck 'IANA PEN' 'INFO' 'not set yet (fine): add IanaPen to agantra_pki.cnf or use -IanaPen later' }
    else { Add-PkiCheck 'IANA PEN' 'PASS' "$($c.IanaPen) -> company policy 1.3.6.1.4.1.$($c.IanaPen).$($c.PenArc) (+ .1 EV, .2 OV, .3 DV)" }
    Add-PkiCheck 'Leaf validity' 'INFO' "EV $($c.LeafDays) days | OV $($c.OvLeafYears) years | DV $($c.DvLeafYears) years"
    if ($c.CustomPolicies.Count -gt 0) { Add-PkiCheck 'Custom policies' 'INFO' (($c.CustomPolicies | ForEach-Object { "$($_.Label)=$($_.Oid)" }) -join ', ') }

    # Rights
    $needsAdmin = $c.InstallTrust -or $c.RemoveTrust -or $c.RemoveAllTrust -or $c.Clean
    $isAdmin = Test-IsAdministrator
    if ($IsWindows) {
        if ($needsAdmin -and -not $isAdmin) { Add-PkiCheck 'Administrator' 'FAIL' 'a trust option is requested but PowerShell is not elevated' }
        elseif ($isAdmin) { Add-PkiCheck 'Administrator' 'PASS' 'elevated (needed only for -InstallTrust, -RemoveTrust, -RemoveAllTrust, -Clean)' }
        else { Add-PkiCheck 'Administrator' 'INFO' 'not elevated: fine for generation; start an elevated PowerShell for -InstallTrust' }
    }

    # Blocked scripts
    if ($IsWindows) {
        $blocked = 0
        foreach ($f in (Get-ChildItem -LiteralPath $c.ScriptRoot -Recurse -File -ErrorAction SilentlyContinue)) {
            if ($null -ne (Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue)) { $blocked++ }
        }
        if ($blocked -gt 0) { Add-PkiCheck 'Blocked files' 'WARN' "$blocked file(s) carry the Internet mark: run .\pki_setup.ps1 -Unblock" }
        else { Add-PkiCheck 'Blocked files' 'PASS' 'no blocked files' }
    }

    # Output folder
    $root = $c.PkiRoot
    if (Test-Path -LiteralPath (Join-Path $root 'root' 'root.crt')) { Add-PkiCheck 'Output folder' 'WARN' "a PKI already exists in ${root}: generation needs -Clean (or use -Verify)" }
    else { Add-PkiCheck 'Output folder' 'PASS' "$root is free" }
    # Write access: the nearest EXISTING parent of the output folder must be writable
    $parent = Split-Path -Parent $root
    while (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) { $parent = Split-Path -Parent $parent }
    try {
        if ([string]::IsNullOrWhiteSpace($parent)) { throw 'no existing parent folder' }
        $probe = Join-Path $parent ".pki-write-test-$([guid]::NewGuid().ToString('N'))"
        Write-Utf8NoBom -Path $probe -Content 'x'; Remove-Item -LiteralPath $probe -Force
        Add-PkiCheck 'Write access' 'PASS' $parent
    }
    catch { Add-PkiCheck 'Write access' 'FAIL' "cannot write below ${parent}: $($_.Exception.Message.Split("`n")[0])" }

    # OpenSSL
    $openSslOk = $false
    try {
        Initialize-OpenSSL
        Add-PkiCheck 'OpenSSL 4.x' 'PASS' "$($c.OpenSslVersion)  [$($c.OpenSslExe)]"
        $openSslOk = $true
    }
    catch {
        $lines = @($_.Exception.Message -split "`r?`n")
        Add-PkiCheck 'OpenSSL 4.x' 'FAIL' $lines[0]
        foreach ($l in ($lines | Select-Object -Skip 1)) { Write-Host ('      ' + $l) -ForegroundColor Yellow }
    }

    if ($openSslOk) {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "agantra-pki-check-$([guid]::NewGuid().ToString('N'))"
        $realRoot = $c.PkiRoot
        try {
            Ensure-PkiDirectory -Path $tmp
            $c.PkiRoot = $tmp                    # keep every test file out of the real PKI folder
            Add-PkiCheck 'Default provider' 'PASS' 'native provider "default" loads (no ENGINE API, no oqsprovider)'

            $st = Invoke-PkiSelfTest -Dir (Join-Path $tmp 'selftest')
            if ($st.Ok) { Add-PkiCheck 'OpenSSL self-test' 'PASS' 'mini CA: RSA/ECDSA P-521 keys, SHA-512 root, ca, CRL, PFX, strict chain verify' }
            else { Add-PkiCheck 'OpenSSL self-test' 'FAIL' "step '$($st.Step)' failed: $($st.Error)" }

            $needFips = @($c.Quadrants | Where-Object { $_ -in 2, 4 }).Count -gt 0
            if ($needFips) {
                try {
                    Initialize-PkiProviderConfigs
                    Add-PkiCheck 'FIPS provider' 'PASS' "loads with $($c.FipsConfigResolved)"
                }
                catch { Add-PkiCheck 'FIPS provider' 'FAIL' (($_.Exception.Message -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ') }
            }
            else { Add-PkiCheck 'FIPS provider' 'INFO' 'not needed (quadrants 2 and 4 not selected)' }
            foreach ($mode in @(@{ Q = 3; Fips = $false; Name = 'ML-DSA (quadrant 3, Quantum non-FIPS)' }, @{ Q = 4; Fips = $true; Name = 'ML-DSA (quadrant 4, Quantum FIPS)' })) {
                if ($c.Quadrants -notcontains $mode.Q) { continue }
                if ($mode.Fips -and -not (Test-Path -LiteralPath (Get-PkiProviderConfigPath -Fips $true))) { Add-PkiCheck $mode.Name 'FAIL' 'the FIPS provider is not available, see above'; continue }
                $pq = Invoke-PkiPqcSelfTest -Dir (Join-Path $tmp "pqtest-q$($mode.Q)") -Fips $mode.Fips
                if ($pq.Ok) { Add-PkiCheck $mode.Name 'PASS' "$(Get-PkiPqcDisplayName $script:PkiRootPqc) CA + $(Get-PkiPqcDisplayName $c.PqcLeafAlgorithm) leaf: key, CSR, signature, chain verify" }
                elseif ($c.PqcFallback) { Add-PkiCheck $mode.Name 'WARN' "step '$($pq.Step)' failed: with -PqcFallback this quadrant would use RSA-$($c.FallbackRsaBits) (NOT quantum-safe). $($pq.Error)" }
                else { Add-PkiCheck $mode.Name 'FAIL' "step '$($pq.Step)' failed: this OpenSSL cannot do ML-DSA here. $($pq.Error)" }
            }
            if (@($c.Quadrants | Where-Object { $_ -in 3, 4 }).Count -eq 0) { Add-PkiCheck 'ML-DSA (Quantum quadrants)' 'INFO' 'not needed (quadrants 3 and 4 not selected)' }
        }
        finally {
            $c.PkiRoot = $realRoot
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $ready = Write-PkiCheckSummary
    if (-not $ready) { $global:LASTEXITCODE = 1 }
}

# ------------------------------------------------------------
# -Verify
# ------------------------------------------------------------
function Get-PkiStoreStatus {
    # Windows: is each certificate of the manifest in the right LocalMachine store?
    param([Parameter(Mandatory)][string]$Thumbprint, [Parameter(Mandatory)][string]$Store)
    try {
        $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($Store, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        try { return ($s.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Thumbprint, $false).Count -gt 0) }
        finally { $s.Close() }
    }
    catch { return $false }
}

# ------------------------------------------------------------
# Windows: does CryptoAPI accept the chain of a leaf? (needs the CA certificates installed)
# ------------------------------------------------------------
function Test-PkiWindowsChain {
    param([Parameter(Mandatory)]$Leaf)
    try {
        $der = [byte[]](ConvertFrom-PkiPemToDer -Path $Leaf['certificate'])
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)
    }
    catch { return @{ Status = 'WARN'; Detail = "this Windows cannot read the certificate: $($_.Exception.Message.Split("`n")[0])" } }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck   # CRL / OCSP URLs are yours to publish
    [void]$chain.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))      # serverAuth
    try { $ok = $chain.Build($cert) }
    catch { return @{ Status = 'WARN'; Detail = "chain build failed: $($_.Exception.Message.Split("`n")[0])" } }
    if ($ok) { return @{ Status = 'PASS'; Detail = "Windows builds and trusts the chain ($($chain.ChainElements.Count) certificates, $($Leaf['keyAlgorithm']))" } }
    $st = (@($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) | Select-Object -Unique) -join ', '
    return @{ Status = 'WARN'; Detail = "Windows does not accept the chain yet: $st. Install the CA certificates first (-InstallTrust); ML-DSA chains need Windows 11 24H2+ / Server 2025." }
}

function Invoke-PkiVerify {
    $c = $script:Pki
    $script:PkiChecks.Clear()
    Initialize-OpenSSL
    $m = Import-PkiExisting
    Write-Host ''
    Write-Host "VERIFY  $($c.PkiRoot)   (generator $($m['generator']))" -ForegroundColor Cyan

    try { Test-AllPkiArtifacts -NoManifest }
    catch {
        $why = (($_.Exception.Message -split "`n" | Select-Object -First 2) -join ' ')
        Add-PkiCheck 'PKI validation' 'FAIL' $why
        [void](Write-PkiCheckSummary -ReadyText 'PKI is valid.' -NotReadyText 'PKI is NOT valid.')
        $global:LASTEXITCODE = 1
        return
    }
    Add-PkiCheck 'PKI validation' 'PASS' "$($c.Built.Count) CA certificate(s) and $($c.Leaves.Count) leaf certificate(s) are valid"

    if ($IsWindows) {
        try {
            $rep = Get-PkiTrustStoreReport -Entries @($c.Built.Values)
            $ok = Write-PkiTrustStoreReport -Report $rep
            if ($rep.WrongStore.Count -gt 0) {
                Add-PkiCheck 'Windows certificate stores' 'FAIL' "$($rep.WrongStore.Count) CA certificate(s) in the wrong store (roots must be in Trusted Root, intermediates in Intermediate): run .\\pki_setup.ps1 -ReinstallTrust (elevated)"
            }
            elseif ($rep.Missing.Count -gt 0) {
                Add-PkiCheck 'Windows certificate stores' 'WARN' "$($rep.Missing.Count) CA certificate(s) not installed on this machine: run .\\pki_setup.ps1 -ReinstallTrust (elevated)"
            }
            else { Add-PkiCheck 'Windows certificate stores' 'PASS' "$($rep.RootExpected) roots in Trusted Root, $($rep.CaExpected) intermediates in Intermediate, none in the wrong store" }
            if ($rep.Stale.Count -gt 0) { Add-PkiCheck 'Older generations in the stores' 'WARN' "$($rep.Stale.Count) certificate(s) with this PKI's name are not part of the PKI in .\\pki (see above)" }
        }
        catch { Add-PkiCheck 'Windows certificate stores' 'WARN' "could not read the stores: $($_.Exception.Message.Split("`n")[0])" }
    }
    if ($IsWindows) {
        foreach ($l in $c.Leaves) {
            $r = Test-PkiWindowsChain -Leaf $l
            Add-PkiCheck "Windows chain: $($l['name'])" $r.Status $r.Detail
        }
    }
    [void](Write-PkiCheckSummary -ReadyText 'PKI is valid.' -NotReadyText 'PKI is NOT valid.')
}


# ------------------------------------------------------------
# Generation gate: before ANY key is made, prove that this OpenSSL can do what the selected quadrants need
# ------------------------------------------------------------
function Assert-PkiGenerationCapabilities {
    $c = $script:Pki
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "agantra-pki-cap-$([guid]::NewGuid().ToString('N'))"
    try {
        foreach ($mode in @(@{ Q = 3; Fips = $false; Name = 'Quadrant 3 (Quantum, non-FIPS)' }, @{ Q = 4; Fips = $true; Name = 'Quadrant 4 (Quantum, FIPS)' })) {
            if ($c.Quadrants -notcontains $mode.Q) { continue }
            $pq = Invoke-PkiPqcSelfTest -Dir (Join-Path $tmp "q$($mode.Q)") -Fips $mode.Fips
            if ($pq.Ok) { Write-PkiLog "$($mode.Name): ML-DSA works in this OpenSSL ($($c.OpenSslVersion.Split([char]40)[0].Trim()))" 'OK'; continue }
            if ($c.PqcFallback) {
                Write-PkiLog "$($mode.Name): ML-DSA does NOT work here (step '$($pq.Step)'). -PqcFallback is set: RSA-$($c.FallbackRsaBits) keys will be used (NOT quantum-safe)." 'WARN'
                continue
            }
            $advice = Get-PkiOpenSslAdvice -Found @($c.OpenSslVersion.Split([char]40)[0].Trim() + '   at ' + $c.OpenSslExe)
            throw ("$($mode.Name) needs ML-DSA, but this OpenSSL cannot create or use it (step '$($pq.Step)').`n$($pq.Error)`n`n" + $advice +
                   "`n`nOr build without the Quantum quadrants:  .\pki_setup.ps1 -ClassicPKI   (or -Quadrant 1,2)" +
                   "`nOr, knowingly, use RSA keys in their place (NOT quantum-safe):  -PqcFallback")
        }
    }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
