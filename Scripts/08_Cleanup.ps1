# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 08_Cleanup.ps1
# -Clean removes the PKI output folder, but only when the folder is
# really a PKI folder created by this generator.
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Marker written by the generator into every PKI folder it creates. It lets -Clean
# recognise the folder even after an earlier clean was interrupted half-way.
$script:PkiFolderMarker = '.agantra-pki'

function Write-PkiFolderMarker {
    param([Parameter(Mandatory)][string]$Folder)
    Ensure-PkiDirectory -Path $Folder
    Write-Utf8NoBom -Path (Join-Path $Folder $script:PkiFolderMarker) -Content "Created by pki_setup.ps1 $($script:PkiGeneratorVersion). Safe to remove with -Clean.`n"
}

function Test-PkiFolderIsSafeToDelete {
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $leaf = Split-Path -Leaf $full
    if ($leaf -ne 'pki') { return $false }
    $parent = Split-Path -Parent $full
    if ([string]::IsNullOrWhiteSpace($parent)) { return $false }          # drive root
    if ($full.Length -lt 8) { return $false }
    # telemetry.json is NOT accepted as a marker: a refused run writes it into any folder.
    return ((Test-Path -LiteralPath (Join-Path $full $script:PkiFolderMarker)) -or
            (Test-Path -LiteralPath (Join-Path $full 'pki-manifest.json')) -or
            (Test-Path -LiteralPath (Join-Path $full 'root' 'root.crt')))
}

function Remove-PkiOutput {
    $dir = [System.IO.Path]::GetFullPath($script:Pki.PkiRoot).TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $dir)) { Write-PkiLog "Nothing to clean: $dir does not exist."; return }
    if (-not (Test-PkiFolderIsSafeToDelete -Path $dir)) {
        throw "Refusing to delete '$dir': it is not a folder named 'pki' that contains a PKI created by this generator."
    }

    # Safe now: leave a marker first so an interrupted clean can be repeated.
    Write-PkiFolderMarker -Folder $dir

    # A shell whose current directory is inside the folder keeps it locked.
    $here = (Get-Location).Path
    if ($here.StartsWith($dir, [StringComparison]::OrdinalIgnoreCase)) {
        Set-Location -LiteralPath (Split-Path -Parent $dir)
        Write-PkiLog "Left $here so the folder can be deleted." 'INFO'
    }

    # Read-only / hidden attributes block deletion on Windows.
    foreach ($item in (Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue)) {
        try { $item.Attributes = [System.IO.FileAttributes]::Normal } catch { }
    }

    # Retry: antivirus, the search indexer and Explorer previews release handles within seconds.
    $attempts = 6
    for ($i = 1; $i -le $attempts; $i++) {
        try {
            if (Test-Path -LiteralPath $dir) { [System.IO.Directory]::Delete($dir, $true) }
            Write-PkiLog "Removed $dir" 'OK'
            return
        }
        catch {
            if ($i -lt $attempts) {
                Write-PkiLog "Folder is in use (attempt $i of $attempts): $($_.Exception.Message.Split("`n")[0]) Retrying ..." 'WARN'
                Start-Sleep -Seconds 2
            }
        }
    }

    # Still locked: delete everything that CAN be deleted and say what is left.
    $left = [System.Collections.Generic.List[string]]::new()
    foreach ($item in (Get-ChildItem -LiteralPath $dir -Recurse -Force -File -ErrorAction SilentlyContinue)) {
        if ($item.Name -eq $script:PkiFolderMarker) { continue }
        try { Remove-Item -LiteralPath $item.FullName -Force } catch { [void]$left.Add($item.FullName) }
    }
    foreach ($d in (Get-ChildItem -LiteralPath $dir -Recurse -Force -Directory -ErrorAction SilentlyContinue | Sort-Object { $_.FullName.Length } -Descending)) {
        try { Remove-Item -LiteralPath $d.FullName -Force -Recurse } catch { [void]$left.Add($d.FullName) }
    }
    $shown = ($left | Select-Object -First 8) -join "`n    "
    $holders = @(Get-PkiLockingProcesses -Folder $dir)
    $holderText = if ($holders.Count -gt 0) { "Processes holding files in it (Windows Restart Manager):`n    " + ($holders -join "`n    ") } else { 'Windows could not name the process holding it.' }
    throw @"
The PKI folder could not be removed because another process is using it:
    $dir
Still present:
    $(if ($shown) { $shown } else { '(folder itself is locked)' })

$holderText

Close it and run the same command again (the folder is still recognised as a PKI folder).
Other usual causes: File Explorer windows or the preview pane, an editor with files from .\pki open,
another shell whose current directory is inside .\pki, antivirus or backup software.
Run  .\pki_setup.ps1 -Unblock  to unblock the files and list the lock holders at any time.
"@
}

function Assert-GenerationModeIsSafe {
    $c = $script:Pki
    $trustModes = @($c.RemoveTrust, $c.RemoveAllTrust) | Where-Object { $_ }
    if (@($trustModes).Count -gt 1) { throw 'Use only one of -RemoveTrust and -RemoveAllTrust.' }
    if (($c.RemoveTrust -or $c.RemoveAllTrust) -and ($c.InstallTrust -or $c.Clean)) {
        throw '-RemoveTrust / -RemoveAllTrust cannot be combined with -InstallTrust or -Clean.'
    }
    $readOnlyModes = @($c.UnblockOnly, $c.CheckOnly, $c.VerifyOnly, $c.ShowNamesOnly) | Where-Object { $_ }
    if (@($readOnlyModes).Count -gt 1) { throw 'Use only one of -Unblock, -Check, -Verify and -ShowNames.' }
    if (@($readOnlyModes).Count -eq 1 -and ($c.RemoveTrust -or $c.RemoveAllTrust -or $c.Clean -or $c.InstallTrust)) {
        throw '-Unblock, -Check, -Verify and -ShowNames cannot be combined with -InstallTrust, -Clean, -RemoveTrust or -RemoveAllTrust.'
    }
    if ($c.ReinstallTrust -and ($c.Clean -or $c.InstallTrust -or $c.RemoveTrust -or $c.RemoveAllTrust -or $c.EnterpriseRootCsr -or $c.ImportEnterpriseRoot -or $c.CrossSignCsr -or $c.ImportCrossCert -or $c.UnblockOnly -or $c.CheckOnly -or $c.VerifyOnly -or $c.ShowNamesOnly)) {
        throw '-ReinstallTrust installs the PKI that already exists and cannot be combined with another action.'
    }
    # public-CA Enterprise Root
    if ($c.EnterpriseRootCsr -and $c.InstallTrust) { throw '-EnterpriseRootCsr only creates the request. Install the trust in the later -ImportEnterpriseRoot run.' }
    if ($c.ImportEnterpriseRoot -and $c.Clean) { throw '-Clean would delete the Enterprise Root key created by -EnterpriseRootCsr. Do not combine it with -ImportEnterpriseRoot.' }
    if (($c.CrossSignCsr -or $c.ImportCrossCert) -and ($c.Clean -or $c.InstallTrust -or $c.RemoveTrust -or $c.RemoveAllTrust)) {
        throw '-CrossSignCsr / -ImportCrossCert work on the existing PKI and cannot be combined with -Clean, -InstallTrust, -RemoveTrust or -RemoveAllTrust.'
    }
    if (@($readOnlyModes).Count -ge 1 -and ($c.EnterpriseRootCsr -or $c.ImportEnterpriseRoot -or $c.CrossSignCsr -or $c.ImportCrossCert)) {
        throw 'The public-CA options cannot be combined with -Unblock, -Check, -Verify or -ShowNames.'
    }
}
