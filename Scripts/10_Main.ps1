# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 10_Main.ps1  - orchestration
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-PkiPlan {
    $c = $script:Pki
    if ($c.ClassicPki) { Write-PkiLog 'Mode          : ClassicPKI - Enterprise Root, Classic Track Root, Q1 Root, DV / OV / EV intermediates (RSA only, no FIPS, no post-quantum)' }
    if ($null -ne $c.ExternalRoot) {
        Write-PkiLog "Enterprise Root: signed by $(if ($c.ExternalRoot.CaName) { $c.ExternalRoot.CaName } else { 'a public CA' }) until $($c.ExternalRoot.NotAfter); every CA below is shortened to fit inside that date" 'WARN'
    }
    if ($c.Windows10) {
        Write-PkiLog "This Windows (build $($c.WindowsBuild)) is older than Windows 11 / Server 2025: it cannot store or validate ML-DSA certificates and has no hybrid ML-KEM key exchange." 'WARN'
        if ($c.QuadrantWasChosen -and (($c.Quadrants -contains 3) -or ($c.Quadrants -contains 4))) {
            Write-PkiLog '  Quantum quadrants (3, 4) were requested: -InstallTrust will fail for their ML-DSA certificates on this Windows.' 'WARN'
        }
        else {
            Write-PkiLog '  Building the Classic quadrants only (1, 2). Add -Quadrant 1,2,3,4 to build the Quantum quadrants as well.' 'WARN'
        }
    }
    elseif ($null -ne $c.WindowsBuild) {
        Write-PkiLog "Windows 11 / Server 2025 (build $($c.WindowsBuild)): ML-DSA certificates can be stored and validated$(if ($c.WindowsBuild -lt 26100) { ' (needs 24H2 / build 26100 or newer: update Windows)' }); hybrid ML-KEM TLS in Schannel."
    }
    Write-PkiLog "Configuration : $($c.ConfigPath)"
    Write-PkiLog "Output        : $($c.PkiRoot)"
    Write-PkiLog "Quadrants     : $($c.Quadrants -join ', ')   (1 Classic Non-FIPS, 2 Classic FIPS, 3 Quantum Non-FIPS, 4 Quantum FIPS)"
    Write-PkiLog "Validity      : Enterprise Root $($c.RootYears) years | Track Root $($c.TrackYears) years | Quadrant Root $($c.QuadrantYears) years | Intermediate $($c.IntYears) years | Leaf $($c.LeafDays) days"
    Write-PkiLog "Root keys     : RSA-$($script:PkiRootRsaBits) / SHA-512 (Enterprise Root, Classic Track, Q1) | ECDSA $($script:PkiRootCurve) / SHA-512 (Q2) | $(Get-PkiPqcDisplayName $script:PkiRootPqc) (Quantum Track, Q3, Q4)"
    Write-PkiLog "Intermediates : RSA-$($c.IntermediateRsaBits) / SHA-256 (Q1) | ECDSA $($c.IntermediateCurve) / SHA-384 (Q2) | $(Get-PkiPqcDisplayName $c.PqcAlgorithm) (Q3, Q4)   Leaf: Q1 RSA | Q2 ECDSA P-256 | Q3, Q4 $(Get-PkiPqcDisplayName $c.PqcLeafAlgorithm)$(if ($c.PqcFallback) { '   [-PqcFallback: RSA ' + $c.FallbackRsaBits + ' if ML-DSA fails]' })"
    if ($c.RsaPss) { Write-PkiLog 'RSA-PSS      : enabled for RSA CA signatures' }
    Write-PkiLog "Leaf defaults : EV $($c.LeafDays) days | OV $($c.OvLeafYears) years | DV $($c.DvLeafYears) years   (this script issues EV leaves; OV / DV leaves use these defaults)"
    Write-PkiLog "Policy OIDs   : EV $($script:PkiPolicyOid.EV) | OV $($script:PkiPolicyOid.OV) | DV $($script:PkiPolicyOid.DV)"
    if ([string]::IsNullOrWhiteSpace($c.IanaPen)) { Write-PkiLog 'IANA PEN      : not set (add IanaPen to agantra_pki.cnf or use -IanaPen when you have it)' }
    else { Write-PkiLog "IANA PEN      : $($c.IanaPen)  -> company policy 1.3.6.1.4.1.$($c.IanaPen).$($c.PenArc), level policies .1 EV  .2 OV  .3 DV" }
    if ($c.CustomPolicies.Count -gt 0) { Write-PkiLog "Custom policy : $(($c.CustomPolicies | ForEach-Object { "$($_.Label)=$($_.Oid)" }) -join ', ')" }
}

function Write-PkiSummary {
    $c = $script:Pki
    Write-Host ''
    Write-Host 'CERTIFICATE AUTHORITIES' -ForegroundColor Cyan
    Write-Host ('{0,-13} {1,-9} {2,-12} {3,-8} {4,-12} {5}' -f 'ID', 'VALIDITY', 'KEY', 'DIGEST', 'EXPIRES', 'COMMON NAME') -ForegroundColor Cyan
    foreach ($b in $c.Built.Values) {
        $digest = if ($b.signatureDigest -eq 'default') { 'none' } else { $b.signatureDigest }
        $exp = if ($b.notAfter) { ([string]$b.notAfter).Substring(0, [Math]::Min(10, ([string]$b.notAfter).Length)) } else { '' }
        $mark = if ($b.pqcFallback) { '*' } else { '' }
        Write-Host ('{0,-13} {1,-9} {2,-12} {3,-8} {4,-12} {5}' -f $b.id, "$($b.validityYears) y", "$($b.keyAlgorithm)$mark", $digest, $exp, $b.commonName)
    }
    if ($c.Leaves.Count -gt 0) {
        Write-Host ''
        Write-Host 'LEAF CERTIFICATES' -ForegroundColor Cyan
        foreach ($l in $c.Leaves) { Write-Host ('{0,-34} {1,-6} {2,-12} {3} days   {4}' -f $l.name, "Q$($l.quadrant)", "$($l.keyAlgorithm)$(if ($l.pqcFallback) { '*' })", $l.days, $l.fullchain) }
    }
    Write-Host ''
    Write-PkiLog "CA certificates: $($c.Built.Count)   Leaf certificates: $($c.Leaves.Count)" 'OK'
    if ($c.PqcFallbacks.Count -gt 0) {
        Write-PkiLog "WARNING: $($c.PqcFallbacks.Count) ML-DSA key(s) (marked * above) were replaced by RSA because of -PqcFallback:" 'WARN'
        foreach ($f in $c.PqcFallbacks) { Write-PkiLog "  - $($f.Label)  ($($f.RequestedAlgorithm) -> $($f.UsedAlgorithm))" 'WARN' }
        Write-PkiLog '  These certificates are NOT quantum-safe. See pqcFallbacks in pki-manifest.json.' 'WARN'
    }
}

function Invoke-PkiGeneration {
    # Leaf certificates of an earlier PKI stay in <script folder>\leafcerts (never deleted here). Say so.
    try {
        $lr = Get-PkiLeafRoot
        $idx = Join-Path $lr 'leaf-index.json'
        if (Test-Path -LiteralPath $idx) {
            $cnt = @(Get-Content -LiteralPath $idx -Raw | ConvertFrom-Json -AsHashtable).Count
            Write-PkiLog "$cnt leaf certificate(s) of an earlier PKI are in $lr. A new PKI has new CA keys: they will NOT chain to it. Keep them for the old PKI or delete them." 'WARN'
        }
    }
    catch { }
    Invoke-PkiStep -Name 'Check output folder' -Action { Test-PkiOutputBeforeGeneration; Write-PkiFolderMarker -Folder $script:Pki.PkiRoot }
    Invoke-PkiStep -Name 'Initialize OpenSSL 4.x' -Action { Initialize-OpenSSL }
    Invoke-PkiStep -Name 'Write provider configuration' -Action { Initialize-PkiProviderConfigs }
    Invoke-PkiStep -Name 'Check that this OpenSSL can do what the quadrants need (ML-DSA, FIPS)' -Action { Assert-PkiGenerationCapabilities }
    if ($script:Pki.ImportEnterpriseRoot) {
        Invoke-PkiStep -Name 'Check and import the Enterprise Root signed by the public CA' -Action { Import-PkiEnterpriseRoot }
    }
    Write-PkiPlan
    Invoke-PkiStep -Name 'Generate CA hierarchy' -Action { New-PkiHierarchy }
    if (-not $script:Pki.SkipLeaf) {
        Invoke-PkiStep -Name 'Generate default EV leaf certificates' -Action { New-AllLeafCertificates }
    }
    Invoke-PkiStep -Name 'Publish CRL and CA issuer files' -Action { Publish-PkiCaFiles }
    Invoke-PkiStep -Name 'Validate keys, certificates, PFX and chains' -Action { Test-AllPkiArtifacts }
    if ($script:Pki.InstallTrust) {
        Invoke-PkiStep -Name 'Install PKI into LocalMachine certificate stores' -Action { Install-PkiTrust }
    }
}

function Invoke-PkiUnblock {
    # .\pki_setup.ps1 -Unblock : UNBLOCK + UNLOCK every script, the PKI folder and the leaf folder (children, recursive),
    # then report the processes that hold files open.
    if ($null -ne (Get-Variable -Name BootstrapUnlocked -Scope Script -ErrorAction SilentlyContinue)) {
        Write-PkiLog "Start-up bootstrap of this script: $($script:BootstrapUnlocked) read-only item(s) unlocked in $($script:Pki.ScriptRoot) (the Internet mark is removed on Windows)."
    }
    $paths = @($script:Pki.ScriptRoot, $script:Pki.PkiRoot, (Get-PkiLeafRoot)) | Select-Object -Unique
    [void](Invoke-PkiUnblockUnlock -Path $paths)
}

function Invoke-PkiMain {
    Assert-GenerationModeIsSafe

    if ($script:Pki.CheckOnly) {
        Invoke-PkiPreflight
        Stop-PkiTelemetry -Success $true
        return
    }
    if ($script:Pki.VerifyOnly) {
        Invoke-PkiVerify
        Stop-PkiTelemetry -Success $true
        return
    }
    if ($script:Pki.ShowNamesOnly) {
        Show-PkiCaNames
        Stop-PkiTelemetry -Success $true
        return
    }
    if ($script:Pki.CrossSignCsr) { Invoke-PkiCrossSignCsr; Stop-PkiTelemetry -Success $true; return }
    if ($script:Pki.ImportCrossCert) { Invoke-PkiImportCrossCert; Stop-PkiTelemetry -Success $true; return }
    if ($script:Pki.UnblockOnly) {
        Invoke-PkiUnblock
        Stop-PkiTelemetry -Success $true
        return
    }

    $needsAdmin = $script:Pki.ReinstallTrust -or $script:Pki.InstallTrust -or $script:Pki.RemoveTrust -or $script:Pki.RemoveAllTrust -or $script:Pki.Clean
    if ($needsAdmin) { Assert-Administrator }

    # Files of a PKI folder (and of other script folders) that came from a zip or a download.
    $n = Unblock-PkiTree -Path @($script:Pki.PkiRoot)
    if ($n -gt 0) { Write-PkiLog "Unblocked $n file(s) in $($script:Pki.PkiRoot)." 'INFO' }
    $n = Unlock-PkiTree -Path @($script:Pki.PkiRoot)
    if ($n -gt 0) { Write-PkiLog "Unlocked $n read-only item(s) in $($script:Pki.PkiRoot)." 'INFO' }

    if ($script:Pki.ReinstallTrust) {
        # Install the PKI that already exists in .\pki into the Windows stores again (no regeneration, no OpenSSL):
        # roots -> Trusted Root, intermediates -> Intermediate, certificates in the wrong store are moved.
        Invoke-PkiStep -Name 'Install the trust of the existing PKI' -Action {
            $m = Import-PkiExisting -SkipProviders
            Write-PkiLog "PKI in $($script:Pki.PkiRoot): $($script:Pki.Built.Count) CA certificate(s), $($script:Pki.Leaves.Count) leaf certificate(s)"
            Install-PkiTrust
        }
        Stop-PkiTelemetry -Success $true
        return
    }
    if ($script:Pki.RemoveTrust) {
        Invoke-PkiStep -Name 'Remove current PKI trust' -Action { Remove-CurrentTrust }
        Stop-PkiTelemetry -Success $true
        return
    }
    if ($script:Pki.RemoveAllTrust) {
        Invoke-PkiStep -Name 'Remove all matching PKI trust' -Action { Remove-AllTrust }
        # -RemoveAllTrust also deletes the PKI folder: all contents and the folder itself.
        Invoke-PkiStep -Name 'Delete the PKI folder and its contents' -Action { Remove-PkiOutput }
        Stop-PkiTelemetryQuietly
        return
    }
    if ($script:Pki.Clean) {
        # Certificates that are already gone from the stores are not an error.
        Invoke-PkiStep -Name 'Remove current PKI trust before clean' -Action {
            if ($IsWindows) {
                try { Remove-CurrentTrust }
                catch { Write-PkiLog "Trust removal skipped, continuing: $($_.Exception.Message.Split("`n")[0])" 'WARN' }
            }
        }
        Invoke-PkiStep -Name 'Remove current PKI output' -Action { Remove-PkiOutput }
    }

    if ($script:Pki.EnterpriseRootCsr) {
        Invoke-PkiStep -Name 'Create the Enterprise Root key and certificate request' -Action { Invoke-PkiEnterpriseRootCsr }
        Stop-PkiTelemetry -Success $true
        return
    }

    Invoke-PkiGeneration

    [void](Unblock-PkiTree -Path @($script:Pki.PkiRoot)); [void](Unlock-PkiTree -Path @($script:Pki.PkiRoot))
    Stop-PkiTelemetry -Success $true
    Write-PkiTelemetryFile
    Write-PkiSummary
    Write-PkiLog 'PKI generation completed successfully.' 'OK'
    Write-PkiLog "PKI directory: $($script:Pki.PkiRoot)"
    Write-PkiLog "Total elapsed: $($script:PkiTelemetry.elapsed)" 'OK'
}

function Stop-PkiTelemetryQuietly {
    # The PKI folder (which held telemetry.json) is gone after -RemoveAllTrust: do not recreate it.
    Stop-PkiTelemetry -Success $true
    Write-PkiLog "Total elapsed: $($script:PkiTelemetry.elapsed)" 'OK'
}
