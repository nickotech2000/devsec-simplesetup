# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 07_TrustStore.ps1
#
# Windows LocalMachine certificate stores for the new hierarchy.
#
#   Enterprise Root, Track Roots, Quadrant Roots  -> LocalMachine\Root    (Trusted Root Certification Authorities)
#   DV / OV / EV intermediates                    -> LocalMachine\CA      (Intermediate Certification Authorities)
#   Default leaf PFX files (every quadrant)       -> LocalMachine\My
#
# Track and Quadrant Roots are issued by the Enterprise Root (they are not self-signed). Windows treats a
# certificate in the Trusted Root store as a trust anchor whether or not it is self-signed, so each of
# them is a root here, as requested. Exception: an Enterprise Root that a PUBLIC CA signed is an
# intermediate of that public chain and goes to LocalMachine\CA.
# A certificate found in the other store (an earlier version put Track / Quadrant Roots in CA) is moved.
#
# ML-DSA (Quantum quadrants): Windows 11 24H2 or newer (late-2025 updates) and Windows Server 2025
# store ML-DSA certificates and validate ML-DSA chains in CryptoAPI. Each certificate is installed
# with .NET first and, if that fails, with certutil.exe; the result is checked by thumbprint.
# Windows 10 / Server 2022 cannot hold them. Windows TLS (Schannel) cannot bind an ML-DSA server
# certificate for HTTPS yet: the store holds it, Kestrel / IIS on Windows cannot serve it.
#
#   Install-PkiTrust        install everything described above
#   Remove-CurrentTrust     remove only the certificates of THIS PKI (by thumbprint)
#   Remove-AllTrust         remove EVERY certificate whose subject or issuer
#                           contains 'Agantra Inovatif' or 'NextMantra'
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PkiWindows {
    if (-not $IsWindows) { throw 'Certificate store operations are only available on Windows.' }
}

function Open-PkiStore {
    # Returns $null when the store does not exist (nothing to remove there).
    param([Parameter(Mandatory)][ValidateSet('Root', 'CA', 'My')][string]$Name)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($Name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::IncludeArchived)
        return $store
    }
    catch {
        Write-PkiLog "  LocalMachine\$Name could not be opened ($($_.Exception.Message.Split("`n")[0])); skipped." 'INFO'
        return $null
    }
}

function Test-PkiCertificateIdentity {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $text = (Normalize-PkiIdentity "$($Certificate.Subject) | $($Certificate.Issuer)")
    foreach ($m in $script:PkiIdentityMarkers) {
        if ($text.Contains((Normalize-PkiIdentity $m))) { return $true }
    }
    return $false
}

function Get-PkiThumbprintStoreName {
    # Where a CA certificate belongs: every root-level CA -> Root, DV / OV / EV intermediates -> CA.
    param([string]$Kind)
    if ($Kind -in 'root', 'track', 'quadrant') { return 'Root' }
    return 'CA'
}

function Get-PkiTrustStoreOf {
    # Decided by the kind of CA, NOT by a "store" value an older manifest may carry.
    param([Parameter(Mandatory)]$Entry)
    $kind = $null; $ext = $false
    if ($Entry -is [System.Collections.IDictionary]) {
        if ($Entry.Contains('kind')) { $kind = $Entry['kind'] }
        if ($Entry.Contains('externallySigned')) { $ext = [bool]$Entry['externallySigned'] }
    }
    else {
        if ($null -ne $Entry.PSObject.Properties['kind']) { $kind = $Entry.kind }
        if ($null -ne $Entry.PSObject.Properties['externallySigned']) { $ext = [bool]$Entry.externallySigned }
    }
    if ($ext) { return 'CA' }
    return (Get-PkiThumbprintStoreName -Kind ([string]$kind))
}

function Invoke-PkiCertutil {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $out = & certutil.exe @Arguments 2>&1
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (($out | ForEach-Object { "$_" }) -join "`n") }
}

function Test-PkiCertificateInStore {
    # True when a certificate with this SHA-1 thumbprint is in LocalMachine\<Store>.
    param([Parameter(Mandatory)][string]$Thumbprint, [Parameter(Mandatory)][string]$Store)
    try {
        $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($Store, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        try { if ($s.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Thumbprint, $false).Count -gt 0) { return $true } }
        finally { $s.Close() }
    }
    catch { }
    # .NET could not read the store (or parse a certificate in it): ask CryptoAPI directly
    $r = Invoke-PkiCertutil -Arguments @('-store', $Store, $Thumbprint)
    return ($r.ExitCode -eq 0)      # certutil returns non-zero when the certificate is not in the store
}

function Remove-PkiCertificateFromStore {
    # Removes one certificate (by SHA-1 thumbprint) from LocalMachine\<Store>. True when it is gone afterwards.
    param([Parameter(Mandatory)][string]$Thumbprint, [Parameter(Mandatory)][string]$Store)
    try {
        $s = [System.Security.Cryptography.X509Certificates.X509Store]::new($Store, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        try {
            foreach ($c in @($s.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Thumbprint, $false))) { $s.Remove($c) }
        }
        finally { $s.Close() }
    }
    catch { }
    if (-not (Test-PkiCertificateInStore -Thumbprint $Thumbprint -Store $Store)) { return $true }
    $r = Invoke-PkiCertutil -Arguments @('-delstore', $Store, $Thumbprint)
    return (-not (Test-PkiCertificateInStore -Thumbprint $Thumbprint -Store $Store))
}

function Add-PkiCertificateToStore {
    # Returns @{ Status = present | installed | failed; Method; Message }
    param([string]$CertificatePath, [string]$StoreName, [string]$Label)
    $thumb = (Get-PkiCertificateFingerprint -Path $CertificatePath).Sha1
    if (Test-PkiCertificateInStore -Thumbprint $thumb -Store $StoreName) {
        Write-PkiLog "  already in $StoreName : $Label" 'INFO'
        return [ordered]@{ Status = 'present'; Method = ''; Message = '' }
    }
    $err = ''
    try {
        $der = [byte[]](ConvertFrom-PkiPemToDer -Path $CertificatePath)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { $store.Add($cert) } finally { $store.Close() }
        if (Test-PkiCertificateInStore -Thumbprint $thumb -Store $StoreName) {
            Write-PkiLog "  installed in $StoreName : $Label" 'OK'
            return [ordered]@{ Status = 'installed'; Method = '.NET'; Message = '' }
        }
        $err = '.NET reported success but the certificate is not in the store'
    }
    catch { $err = $_.Exception.Message.Split("`n")[0] }

    # Second route: CryptoAPI through certutil.exe (does not need .NET to parse the certificate)
    $r = Invoke-PkiCertutil -Arguments @('-f', '-addstore', $StoreName, $CertificatePath)
    if ($r.ExitCode -eq 0 -and (Test-PkiCertificateInStore -Thumbprint $thumb -Store $StoreName)) {
        Write-PkiLog "  installed in $StoreName : $Label   (certutil)" 'OK'
        return [ordered]@{ Status = 'installed'; Method = 'certutil'; Message = '' }
    }
    $msg = ".NET: $err | certutil: exit $($r.ExitCode) $(($r.Output -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1))"
    Write-PkiLog "  FAILED $StoreName : $Label - $msg" 'ERROR'
    return [ordered]@{ Status = 'failed'; Method = ''; Message = $msg }
}

function Get-PkiLeafFromPfx {
    # Loads a PFX and returns ONLY its leaf: the certificate that has the private key.
    # Why: Windows files every OTHER certificate of a PFX (here: intermediate, Quadrant Root, Track Root) in the
    # Intermediate store when the PFX is imported with Import-PfxCertificate / certutil. That put our roots
    # back under Intermediate Certification Authorities. Loading the PFX ourselves avoids it.
    param(
        [Parameter(Mandatory)][string]$PfxPath, [Parameter(Mandatory)][string]$Password, [string]$Thumbprint,
        $Flags = ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
    )
    $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]      # .NET 9 and newer
    if ($null -ne $loader) { $col = $loader::LoadPkcs12CollectionFromFile($PfxPath, $Password, $Flags) }
    else {
        $col = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $col.Import($PfxPath, $Password, $Flags)
    }
    $leaf = $null
    foreach ($c in $col) { if ($c.HasPrivateKey) { $leaf = $c; break } }
    if ($null -eq $leaf -and $Thumbprint) { foreach ($c in $col) { if ($c.Thumbprint -ieq $Thumbprint) { $leaf = $c; break } } }
    if ($null -eq $leaf) { throw 'The PFX contains no certificate with a private key.' }
    return $leaf
}

function Install-PkiLeafPfx {
    param([Parameter(Mandatory)]$Leaf)
    $thumb = $Leaf.sha1
    if (Test-PkiCertificateInStore -Thumbprint $thumb -Store 'My') {
        Write-PkiLog "  already in My : $($Leaf.name)" 'INFO'
        return [ordered]@{ Status = 'present'; Message = '' }
    }
    # route 1: only the leaf goes to My; the chain certificates of the PFX are NOT imported
    $err0 = ''
    try {
        $cert = Get-PkiLeafFromPfx -PfxPath $Leaf.pfx -Password $script:Pki.Password -Thumbprint $thumb
        $st = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { $st.Add($cert) } finally { $st.Close() }
        if (Test-PkiCertificateInStore -Thumbprint $thumb -Store 'My') {
            Write-PkiLog "  installed in My : $($Leaf.name)   (leaf only)" 'OK'
            return [ordered]@{ Status = 'installed'; Message = '' }
        }
        $err0 = 'the leaf is not in the store after Add'
    }
    catch { $err0 = $_.Exception.Message.Split("`n")[0] }
    Write-PkiLog "  leaf-only import of $($Leaf.name) failed ($err0); using the Windows PFX import" 'INFO'

    # route 2 / 3: the Windows PFX import. It also puts the chain certificates of the PFX in the Intermediate
    # store; Install-PkiTrust removes those copies afterwards.
    $err = ''
    try {
        $secure = ConvertTo-SecureString -String $script:Pki.Password -AsPlainText -Force
        Import-PfxCertificate -FilePath $Leaf.pfx -CertStoreLocation 'Cert:\LocalMachine\My' -Password $secure | Out-Null
        if (Test-PkiCertificateInStore -Thumbprint $thumb -Store 'My') {
            Write-PkiLog "  installed in My : $($Leaf.name)" 'OK'
            return [ordered]@{ Status = 'installed'; Message = '' }
        }
        $err = 'Import-PfxCertificate reported success but the certificate is not in the store'
    }
    catch { $err = $_.Exception.Message.Split("`n")[0] }
    # The PFX password is the lab password of this PKI.
    $r = Invoke-PkiCertutil -Arguments @('-f', '-p', $script:Pki.Password, '-importpfx', 'My', $Leaf.pfx)
    if ($r.ExitCode -eq 0 -and (Test-PkiCertificateInStore -Thumbprint $thumb -Store 'My')) {
        Write-PkiLog "  installed in My : $($Leaf.name)   (certutil)" 'OK'
        return [ordered]@{ Status = 'installed'; Message = '' }
    }
    $msg = "leaf-only: $err0 | Import-PfxCertificate: $err | certutil: exit $($r.ExitCode)"
    Write-PkiLog "  could not import $($Leaf.name) into My: $msg" 'WARN'
    return [ordered]@{ Status = 'failed'; Message = $msg }
}

# ------------------------------------------------------------
# Where do our certificates REALLY sit?  (read back after every install and in -Verify)
# ------------------------------------------------------------
function Get-PkiStorePlacement {
    <#
    .SYNOPSIS
        Pure classification (no store access). 
    .PARAMETER Current
        Our CA certificates: objects/hashtables with Id, Name, Sha1, Expected (Root | CA).
    .PARAMETER Stores
        Contents of the stores: @{ Root = @(@{Sha1; Subject}); CA = @(...) } (only certificates that carry
        this PKI's identity need to be listed).
    .OUTPUTS
        Ok, Missing, WrongStore (in the other store, or in BOTH), Stale (ours, but not in the current PKI).
    #>
    param([Parameter(Mandatory)]$Current, [Parameter(Mandatory)][hashtable]$Stores)
    $get = { param($o, $k) if ($o -is [System.Collections.IDictionary]) { $o[$k] } else { $o.$k } }
    $has = { param($store, $sha) @($Stores[$store] | Where-Object { (& $get $_ 'Sha1') -ieq $sha }).Count -gt 0 }
    $r = [ordered]@{
        Ok = [System.Collections.Generic.List[object]]::new(); Missing = [System.Collections.Generic.List[object]]::new()
        WrongStore = [System.Collections.Generic.List[object]]::new(); Stale = [System.Collections.Generic.List[object]]::new()
        Other = [System.Collections.Generic.List[object]]::new()      # CAs of ANOTHER release / variant of this PKI (pki\R2, pki\NoCR-R1 ...): normal, not stale
    }
    $curRel = 1; $curNoCr = $false
    if ($null -ne (Get-Variable -Name Pki -Scope Script -ErrorAction SilentlyContinue) -and $script:Pki.Contains('Release')) { $curRel = [int]$script:Pki.Release; $curNoCr = [bool]$script:Pki.NoCaRevocationInfo }
    $known = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in @($Current)) {
        $id = & $get $c 'Id'; $name = & $get $c 'Name'; $sha = & $get $c 'Sha1'; $exp = & $get $c 'Expected'
        [void]$known.Add($sha)
        $other = if ($exp -eq 'Root') { 'CA' } else { 'Root' }
        $inExp = & $has $exp $sha
        $inOther = & $has $other $sha
        if ($inExp -and -not $inOther) { [void]$r.Ok.Add([ordered]@{ Id = $id; Name = $name; Store = $exp }) }
        elseif ($inOther) {
            $where = if ($inExp) { "in BOTH stores (also in $other)" } else { "in $other instead of $exp" }
            [void]$r.WrongStore.Add([ordered]@{ Id = $id; Name = $name; Expected = $exp; Actual = $other; Detail = $where })
        }
        else { [void]$r.Missing.Add([ordered]@{ Id = $id; Name = $name; Expected = $exp }) }
    }
    foreach ($st in 'Root', 'CA') {
        foreach ($e in @($Stores[$st])) {
            $sha = & $get $e 'Sha1'
            if ($known.Contains($sha)) { continue }
            $subj = [string](& $get $e 'Subject')
            $item = [ordered]@{ Store = $st; Subject = $subj; Sha1 = $sha }
            $isOther = $false
            if ($subj -match '(?:^|, )CN=(?<cn>[^,]+)') {
                $cn = $Matches['cn']
                $item['CommonName'] = $cn
                if ($cn -match '^(?<base>.+?)(?<nocr> \(NoCR\))?(?: R(?<rel>\d+))?$') {
                    # Copy the groups first: the next -match overwrites $Matches.
                    $gBase = [string]$Matches['base']; $gRel = [string]$Matches['rel']; $gNoCr = [string]$Matches['nocr']
                    if ($gBase -match '(CA G\d+|G\d+ CA)$') {
                        $rel = if ($gRel) { [int]$gRel } else { 1 }
                        $isOther = ($rel -ne $curRel -or ($gNoCr -ne '') -ne $curNoCr)
                    }
                }
            }
            if ($isOther) { [void]$r.Other.Add($item) } else { [void]$r.Stale.Add($item) }
        }
    }
    return $r
}

function Read-PkiStoreContents {
    # LocalMachine Root and CA: the certificates that carry this PKI's identity. $null for a store that cannot be read.
    $out = @{ Root = $null; CA = $null }
    foreach ($name in 'Root', 'CA') {
        try {
            $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
            try {
                $out[$name] = @($st.Certificates | Where-Object { Test-PkiCertificateIdentity -Certificate $_ } |
                    ForEach-Object { [ordered]@{ Sha1 = $_.Thumbprint; Subject = $_.Subject } })
            }
            finally { $st.Close() }
        }
        catch { Write-PkiLog "  LocalMachine\$name could not be read: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
    }
    return $out
}

function Get-PkiTrustStoreReport {
    # Reads the real stores and classifies every CA certificate of $Entries.
    param([Parameter(Mandatory)]$Entries)
    Assert-PkiWindows
    $current = foreach ($e in @($Entries)) {
        $g = { param($k) if ($e -is [System.Collections.IDictionary]) { $e[$k] } else { $e.$k } }
        [ordered]@{ Id = (& $g 'id'); Name = (& $g 'commonName'); Sha1 = (& $g 'sha1'); Expected = (Get-PkiTrustStoreOf -Entry $e) }
    }
    $stores = Read-PkiStoreContents
    $readable = @{ Root = ($null -ne $stores.Root); CA = ($null -ne $stores.CA) }
    $stores = @{ Root = @($stores.Root); CA = @($stores.CA) }
    $rep = Get-PkiStorePlacement -Current @($current) -Stores $stores
    $rep['Readable'] = $readable
    $rep['Total'] = @($current).Count
    $rep['RootExpected'] = @($current | Where-Object { $_.Expected -eq 'Root' }).Count
    $rep['CaExpected'] = @($current | Where-Object { $_.Expected -eq 'CA' }).Count
    return $rep
}

function Write-PkiTrustStoreReport {
    # Prints the report; returns $true when every CA certificate is in the right store and in no other.
    param([Parameter(Mandatory)]$Report)
    $r = $Report
    $okRoot = @($r.Ok | Where-Object { $_.Store -eq 'Root' }).Count
    $okCa = @($r.Ok | Where-Object { $_.Store -eq 'CA' }).Count
    Write-PkiLog "Trusted Root Certification Authorities : $okRoot of $($r.RootExpected) roots in place (Enterprise Root, Track Roots, Quadrant Roots)" $(if ($okRoot -eq $r.RootExpected) { 'OK' } else { 'ERROR' })
    Write-PkiLog "Intermediate Certification Authorities : $okCa of $($r.CaExpected) intermediates in place (DV / OV / EV)" $(if ($okCa -eq $r.CaExpected) { 'OK' } else { 'ERROR' })
    foreach ($w in $r.WrongStore) { Write-PkiLog "  WRONG STORE : $($w.Name) is $($w.Detail)" 'ERROR' }
    foreach ($m in $r.Missing) { Write-PkiLog "  NOT INSTALLED: $($m.Name) (belongs in $($m.Expected))" 'ERROR' }
    if ($r.Stale.Count -gt 0) {
        Write-PkiLog "$($r.Stale.Count) certificate(s) with this PKI's name carry this PKI's identity (phone / e-mail) but are not a release of the current naming - leftovers of an earlier version (old 'Enterprise' / 'Inovatif' / 'PostQuantum' names) or certificates made by hand. They do no harm:" 'INFO'
        foreach ($t in $r.Stale) { Write-PkiLog "  LocalMachine\$($t.Store) : $(if ($t.CommonName) { $t.CommonName } else { $t.Subject })   [$($t.Sha1.Substring(0, 12))...]" 'INFO' }
        Write-PkiLog '  They are left alone. Remove them with  .\pki_remove.ps1 -All  (this also deletes the folder pki) or in certlm.msc.' 'INFO'
    }
    if ($r.Contains('Other') -and $r.Other.Count -gt 0) {
        Write-PkiLog "$($r.Other.Count) CA certificate(s) of OTHER releases / variants of this PKI are installed as well (normal). List and remove them: .\pki_remove.ps1 -List" 'INFO'
    }
    return ($r.WrongStore.Count -eq 0 -and $r.Missing.Count -eq 0)
}

function Install-PkiTrust {
    <#
    .SYNOPSIS
        Installs every CA certificate (Root / CA) and every default leaf PFX (My) in LocalMachine.
    .DESCRIPTION
        Each certificate is verified in the store by thumbprint afterwards. A CA certificate that
        cannot be installed stops the run with an error at the end (all the others are still
        installed). A leaf PFX that Windows cannot import is a warning: the files stay on disk.
    .PARAMETER Manifest
        Optional parsed pki-manifest.json. Defaults to the state of the current run.
    #>
    param($Manifest)
    Assert-PkiWindows
    Assert-Administrator

    $cas = if ($null -ne $Manifest) { @($Manifest.certificateAuthorities) } else { @($script:Pki.Built.Values) }
    $leaves = if ($null -ne $Manifest) { @($Manifest.leaves) } else { @($script:Pki.Leaves) }

    $failedCa = [System.Collections.Generic.List[string]]::new()
    $nNew = 0; $nPresent = 0; $nMoved = 0
    foreach ($ca in $cas) {
        $store = Get-PkiTrustStoreOf -Entry $ca
        $r = Add-PkiCertificateToStore -CertificatePath $ca.certificate -StoreName $store -Label $ca.commonName
        switch ($r.Status) { 'installed' { $nNew++ } 'present' { $nPresent++ } default { [void]$failedCa.Add("$($ca.commonName): $($r.Message)") } }
    }

    # Enterprise Root signed by a public CA: also install the public CA's intermediates (not the public
    # root, which is already trusted) so Windows can build the chain without downloading anything.
    if ($null -ne $script:Pki.ExternalRoot -and $script:Pki.ExternalRoot.Chain) {
        $k = 0
        foreach ($pem in (Get-PkiExternalChainIntermediates)) {
            $k++
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "pki-ext-$k-$([guid]::NewGuid().ToString('N')).pem"
            try {
                Write-Utf8NoBom -Path $tmp -Content $pem
                $r = Add-PkiCertificateToStore -CertificatePath $tmp -StoreName 'CA' -Label "public CA intermediate $k"
                if ($r.Status -eq 'failed') { Write-PkiLog "  public CA intermediate $k could not be installed (ignored): $($r.Message)" 'WARN' }
            }
            finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    $nLeaf = 0; $failedLeaf = [System.Collections.Generic.List[string]]::new()
    foreach ($leaf in $leaves) {
        if (-not $leaf.pfx) { continue }
        $r = Install-PkiLeafPfx -Leaf $leaf
        if ($r.Status -eq 'failed') { [void]$failedLeaf.Add("$($leaf.name): $($r.Message)") } else { $nLeaf++ }
    }

    # RECONCILE (after the leaf PFX import, which may have filed chain certificates in the Intermediate store):
    # no root may stay in Intermediate and no intermediate in Trusted Root. Copies in the other store are removed.
    foreach ($ca in $cas) {
        $store = Get-PkiTrustStoreOf -Entry $ca
        $other = if ($store -eq 'Root') { 'CA' } else { 'Root' }
        $thumb = if ($ca -is [System.Collections.IDictionary]) { [string]$ca['sha1'] } else { [string]$ca.sha1 }
        if (-not $thumb) { continue }
        if (Test-PkiCertificateInStore -Thumbprint $thumb -Store $store) {
            if (Test-PkiCertificateInStore -Thumbprint $thumb -Store $other) {
                if (Remove-PkiCertificateFromStore -Thumbprint $thumb -Store $other) { $nMoved++; Write-PkiLog "  removed the copy in $other (it belongs in $store) : $($ca.commonName)" 'OK' }
                else { Write-PkiLog "  could not remove the copy in $other : $($ca.commonName)" 'WARN' }
            }
        }
    }

    Write-PkiLog "Trust store: $($cas.Count - $failedCa.Count) of $($cas.Count) CA certificate(s) in place ($nNew installed now, $nPresent already there, $nMoved copies removed from the wrong store); $nLeaf leaf PFX file(s) in My." 'OK'
    if ($failedLeaf.Count -gt 0) {
        Write-PkiLog "$($failedLeaf.Count) leaf PFX file(s) could not be imported (the files stay in .\pki\leaf):" 'WARN'
        foreach ($f in $failedLeaf) { Write-PkiLog "  - $f" 'WARN' }
        Write-PkiLog '  ML-DSA private keys need a Windows build with post-quantum CNG support (Windows 11 24H2+ / Server 2025, updated).' 'WARN'
    }
    # Read the stores back: every root MUST be in Trusted Root, every intermediate in Intermediate, none in both.
    $placementOk = $true
    try {
        $rep = Get-PkiTrustStoreReport -Entries $cas
        $placementOk = Write-PkiTrustStoreReport -Report $rep
    }
    catch { Write-PkiLog "The stores could not be read back: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
    if (-not $placementOk -and $failedCa.Count -eq 0) {
        throw "Some CA certificates are not in the required store (see the ERROR lines above). Run  .\pki_setup.ps1 -ReinstallTrust  from an elevated PowerShell; if it still fails, send me this output."
    }
    if ($failedCa.Count -gt 0) {
        throw ("These CA certificates could not be installed in the LocalMachine stores:`n  - " + ($failedCa -join "`n  - ") +
               "`nML-DSA certificates need Windows 11 24H2 or newer / Windows Server 2025 with the 2025-2026 updates. " +
               "Windows 10 and Server 2022 cannot hold them: use the Classic quadrants (-Quadrant 1,2) there.")
    }
}

function Remove-PkiCertificatesWhere {
    # Removes the matching certificates. Anything already gone is simply ignored:
    # a missing store, a certificate that is not there, or one that cannot be
    # removed produces at most a note, and the process continues.
    param([scriptblock]$Predicate, [string[]]$Stores = @('Root', 'CA', 'My'))
    Assert-PkiWindows
    Assert-Administrator
    $removed = 0
    foreach ($name in $Stores) {
        $store = Open-PkiStore -Name $name
        if ($null -eq $store) { continue }
        try {
            $hits = @()
            try { $hits = @($store.Certificates | Where-Object { & $Predicate $_ }) }
            catch { Write-PkiLog "  could not read LocalMachine\$name ($($_.Exception.Message.Split("`n")[0])); skipped." 'WARN' }
            foreach ($cert in $hits) {
                try {
                    $store.Remove($cert)
                    $removed++
                    Write-PkiLog "  removed from $name : $(Get-PkiCertDisplayName -Certificate $cert)   [$($cert.Thumbprint.Substring(0, 12))...]" 'OK'
                }
                catch { Write-PkiLog "  already gone or not removable from $name, ignored: $($cert.Subject) ($($_.Exception.Message.Split("`n")[0]))" 'INFO' }
            }
        }
        finally { $store.Close() }
    }
    return $removed
}

function Get-PkiFolderThumbprints {
    # SHA-1 thumbprints of every PEM certificate file below the PKI folder.
    # Works for ANY layout (also the old single-root layout), so a leftover PKI
    # from an earlier version can still be removed from Windows.
    param([Parameter(Mandatory)][string]$Folder)
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { return $set }
    foreach ($f in (Get-ChildItem -LiteralPath $Folder -Recurse -File -Include '*.crt', '*.pem', '*.cer' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike 'external-chain*' -and $_.Name -notlike '*-chain.pem' })) {   # never the public CA's certificates
        try {
            $der = ConvertFrom-PkiPemToDer -Path $f.FullName
            [void]$set.Add([BitConverter]::ToString([System.Security.Cryptography.SHA1]::HashData($der)).Replace('-', ''))
        }
        catch { }   # not a PEM certificate (private key, CRL, chain with no cert ...)
    }
    return $set
}

function Get-PkiCaNameInfo {
    # Release and variant of a CA certificate of this PKI, read from its common name:
    #   "... Root CA G1"                       -> release 1, normal
    #   "... DV RSA-4096 G1 CA (NoCR) R2"      -> release 2, NoCR
    # $null when the certificate is not one of our CAs (a leaf, another company's CA).
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ([string]::IsNullOrWhiteSpace($cn)) { return $null }
    $prefix = 'Agantra'
    if ($null -ne (Get-Variable -Name Pki -Scope Script -ErrorAction SilentlyContinue) -and $script:Pki.Contains('Naming') -and $script:Pki.Naming) { $prefix = [string]$script:Pki.Naming.Prefix }
    if (-not $cn.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    if ($cn.StartsWith("$prefix Inovatif", [StringComparison]::OrdinalIgnoreCase)) { return $null }   # names of the generation before 4.9.5: never a current release
    if ($cn -notmatch '^(?<base>.+?)(?<nocr> \(NoCR\))?(?: R(?<rel>\d+))?$') { return $null }
    $gBase = [string]$Matches['base']; $gRel = [string]$Matches['rel']; $gNoCr = [string]$Matches['nocr']
    if ($gBase -notmatch '(CA G\d+|G\d+ CA)$') { return $null }
    $rel = if ($gRel) { [int]$gRel } else { 1 }
    return [pscustomobject]@{ Release = $rel; NoCr = ($gNoCr -ne ''); CommonName = $cn }
}

function Get-PkiCertDisplayName {
    # The common name (the subject of a leaf is long: phone, e-mail, jurisdiction ...).
    param([Parameter(Mandatory)]$Certificate)
    $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ([string]::IsNullOrWhiteSpace($cn)) { return [string]$Certificate.Subject }
    return $cn
}

function Get-PkiStoreReleases {
    # Releases / variants of this PKI that have CA certificates in LocalMachine Root or CA (read from the common names). Empty off Windows or when a store cannot be read.
    $out = [System.Collections.Generic.List[object]]::new()
    if (-not $IsWindows) { return @() }
    foreach ($name in 'Root', 'CA') {
        try {
            $st = [System.Security.Cryptography.X509Certificates.X509Store]::new($name, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
            try {
                foreach ($c in $st.Certificates) {
                    $i = Get-PkiCaNameInfo -Certificate $c
                    if ($null -ne $i) { $out.Add([pscustomobject]@{ Release = $i.Release; NoCr = $i.NoCr; Store = $name }) }
                }
            }
            finally { $st.Close() }
        }
        catch { }
    }
    return @($out)
}

function Remove-PkiTrustByRelease {
    # Removes the CA certificates of ONE release / variant from Root and CA (matched by common name), whether or not its folder still exists.
    # -Release 0 with -AllReleases = every release of the variant.
    param([int]$Release = 1, [bool]$NoCr = $false, [switch]$AllReleases)
    $n = Remove-PkiCertificatesWhere -Stores @('Root', 'CA') -Predicate {
        param($c)
        $i = Get-PkiCaNameInfo -Certificate $c
        return ($null -ne $i -and $i.NoCr -eq $NoCr -and ($AllReleases -or $i.Release -eq $Release))
    }
    return $n
}

function Remove-CurrentTrust {
    # Removes the certificates of the PKI in .\pki, matched by SHA-1 thumbprint.
    $thumbs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($b in $script:Pki.Built.Values) { [void]$thumbs.Add($b.sha1) }
    foreach ($l in $script:Pki.Leaves) { [void]$thumbs.Add($l.sha1) }

    # 1. manifest of this generator (older manifests have a different shape: tolerate it)
    $manifestPath = Join-Path $script:Pki.PkiRoot 'pki-manifest.json'
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $m = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            foreach ($section in 'certificateAuthorities', 'leaves') {
                $prop = $m.PSObject.Properties[$section]
                if ($null -eq $prop -or $null -eq $prop.Value) { continue }
                foreach ($entry in @($prop.Value)) {
                    $sha = $entry.PSObject.Properties['sha1']
                    if ($null -ne $sha -and $sha.Value) { [void]$thumbs.Add([string]$sha.Value) }
                }
            }
        }
        catch { Write-PkiLog "Manifest could not be read ($($_.Exception.Message.Split("`n")[0])); using the certificate files instead." 'WARN' }
    }

    # 2. every certificate file in the folder (any layout, any generator version)
    foreach ($t in (Get-PkiFolderThumbprints -Folder $script:Pki.PkiRoot)) { [void]$thumbs.Add($t) }

    if ($thumbs.Count -eq 0) {
        Write-PkiLog 'No certificates found in the PKI folder, so there is nothing to remove by thumbprint. Use -RemoveAllTrust to remove by identity.' 'WARN'
        return
    }
    Write-PkiLog "Looking for $($thumbs.Count) certificate thumbprint(s) in LocalMachine Root, CA and My ..."
    $n = Remove-PkiCertificatesWhere -Predicate { param($c) $thumbs.Contains($c.Thumbprint) }
    # and the CAs of the same release / variant by name (the folder may have lost files, or the CAs came from another copy of this PKI)
    $rel = [int]$script:Pki.Release; $noCr = [bool]$script:Pki.NoCaRevocationInfo
    $n += Remove-PkiTrustByRelease -Release $rel -NoCr $noCr
    if ($n -eq 0) { Write-PkiLog 'None of them is installed (already removed, or never installed). Use -RemoveAllTrust to remove by name instead.' 'INFO' }
    Write-PkiLog "Removed $n certificate(s) of the PKI $(if ($noCr) { 'NoCR ' })R$rel ($($script:Pki.PkiRoot))." 'OK'
}

function Remove-AllTrust {
    # Removes every certificate that carries this PKI's identity, from Root, CA and My.
    $n = Remove-PkiCertificatesWhere -Predicate { param($c) Test-PkiCertificateIdentity -Certificate $c }
    Write-PkiLog "Removed $n certificate(s) matching 'Agantra Inovatif' / 'NextMantra'." 'OK'
}
