# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Remove-PkiOutput {
    if (Test-Path -LiteralPath $script:Pki.PkiRoot -PathType Container) {
        Remove-Item -LiteralPath $script:Pki.PkiRoot -Recurse -Force
        Write-PkiLog "Removed PKI directory: $($script:Pki.PkiRoot)" 'OK'
    }
    else {
        Write-PkiLog 'PKI directory does not exist. Nothing to remove.' 'INFO'
    }
}

function Assert-GenerationModeIsSafe {
    $p = $script:Pki
    $modes = @([bool]$p.RemoveTrust,[bool]$p.RemoveAllTrust)
    if (@($modes | Where-Object { $_ }).Count -gt 1) { throw '-RemoveTrust and -RemoveAllTrust cannot be used together.' }
    if ($p.RemoveTrust -and ($p.InstallTrust -or $p.Clean)) { throw '-RemoveTrust cannot be combined with -InstallTrust or -Clean.' }
    if ($p.RemoveAllTrust -and ($p.InstallTrust -or $p.Clean)) { throw '-RemoveAllTrust cannot be combined with -InstallTrust or -Clean.' }
}
