# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 09_Administrator.ps1
#
# Changed in the 4.x redesign: Administrator is required ONLY for
# operations that touch the LocalMachine certificate stores
# (-InstallTrust, -RemoveTrust, -RemoveAllTrust, -Clean). Plain
# generation writes files under .\pki and needs no elevation.
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    if (-not $IsWindows) {
        # Non-Windows hosts have no LocalMachine certificate store.
        return $true
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw 'Administrator privileges are required because this operation reads/writes LocalMachine certificate stores. Start PowerShell as Administrator and run the script again.'
    }
}
