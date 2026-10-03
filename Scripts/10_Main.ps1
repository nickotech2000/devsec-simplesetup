# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-PkiGeneration {
    Invoke-PkiStep -Name 'Validate generation inputs' -Action {
        Test-PkiOutputBeforeGeneration
        Initialize-PkiDirectories
        Initialize-CaDatabase
        New-RuntimeOpenSSLConfig
    }
    Invoke-PkiStep -Name 'Initialize OpenSSL' -Action { Initialize-OpenSSL }
    Invoke-PkiStep -Name 'Generate Root CA' -Action { New-RootCA }
    Invoke-PkiStep -Name 'Generate Intermediate CA' -Action { New-IntermediateCA }
    Invoke-PkiStep -Name 'Generate leaf certificates' -Action { New-AllLeafCertificates }
    Invoke-PkiStep -Name 'Validate keys, certificates, PFX and chains' -Action { Validate-AllPkiArtifacts }
    if ($script:Pki.InstallTrust) {
        Invoke-PkiStep -Name 'Install PKI trust into LocalMachine stores' -Action { Install-PkiTrust }
    }
}

function Invoke-PkiMain {
    Assert-GenerationModeIsSafe
    Assert-Administrator

    if ($script:Pki.RemoveTrust) {
        Invoke-PkiStep -Name 'Remove current PKI trust' -Action { Remove-CurrentTrust }
        Stop-PkiTelemetry -Success $true
        Write-PkiTelemetryFile
        Write-PkiLog "Total elapsed: $($script:PkiTelemetry.elapsed)" 'OK'
        return
    }

    if ($script:Pki.RemoveAllTrust) {
        Invoke-PkiStep -Name 'Remove all matching PKI trust' -Action { Remove-AllTrust }
        Stop-PkiTelemetry -Success $true
        Write-PkiTelemetryFile
        Write-PkiLog "Total elapsed: $($script:PkiTelemetry.elapsed)" 'OK'
        return
    }

    if ($script:Pki.Clean) {
        Invoke-PkiStep -Name 'Remove current PKI trust before clean' -Action { Remove-CurrentTrust }
        Invoke-PkiStep -Name 'Remove current PKI output' -Action { Remove-PkiOutput }
    }

    Invoke-PkiGeneration
    Stop-PkiTelemetry -Success $true
    Write-PkiTelemetryFile
    Write-PkiLog 'PKI generation completed successfully.' 'OK'
    Write-PkiLog "PKI directory: $($script:Pki.PkiRoot)"
    Write-PkiLog "Telemetry: $($script:PkiTelemetryPath)"
    Write-PkiLog "Total elapsed: $($script:PkiTelemetry.elapsed)" 'OK'
}
