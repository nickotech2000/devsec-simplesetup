# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Initialize script-scoped state so fatal errors are diagnosable even when
# configuration validation fails before the normal PKI state is created.
$script:Pki = $null
$script:PkiTelemetry = $null
$script:PkiTelemetryStopwatch = $null
$script:PkiTelemetryOutputDirectory = $null
$script:PkiTelemetryPath = $null

function Get-PkiNowUtc { [DateTime]::UtcNow }

function Start-PkiTelemetry {
    param([string]$OutputDirectory)
    $script:PkiTelemetry = [ordered]@{
        schemaVersion = 1
        startedAtUtc = (Get-PkiNowUtc).ToString('o')
        endedAtUtc = $null
        elapsedMilliseconds = $null
        elapsed = $null
        success = $null
        steps = [System.Collections.Generic.List[object]]::new()
    }
    $script:PkiTelemetryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $script:PkiTelemetryOutputDirectory = $OutputDirectory
}

function Stop-PkiTelemetry {
    param([bool]$Success)
    if ($null -eq $script:PkiTelemetryStopwatch) { return }
    $script:PkiTelemetryStopwatch.Stop()
    $script:PkiTelemetry.endedAtUtc = (Get-PkiNowUtc).ToString('o')
    $script:PkiTelemetry.elapsedMilliseconds = [math]::Round($script:PkiTelemetryStopwatch.Elapsed.TotalMilliseconds, 3)
    $script:PkiTelemetry.elapsed = $script:PkiTelemetryStopwatch.Elapsed.ToString()
    $script:PkiTelemetry.success = $Success
}

function Write-PkiTelemetryFile {
    try {
        if ($null -eq $script:PkiTelemetry) { return }
        $dir = $script:PkiTelemetryOutputDirectory
        if ([string]::IsNullOrWhiteSpace($dir)) { return }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $path = Join-Path $dir 'telemetry.json'
        $script:PkiTelemetry | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
        $script:PkiTelemetryPath = $path
    }
    catch {
        Write-Host "[WARN] Could not write telemetry file: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Write-PkiLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $prefix = "[$Level]"
    switch ($Level) {
        'OK'    { Write-Host "$prefix $Message" -ForegroundColor Green }
        'WARN'  { Write-Host "$prefix $Message" -ForegroundColor Yellow }
        'ERROR' { Write-Host "$prefix $Message" -ForegroundColor Red }
        'DEBUG' { if ($script:Pki.VerboseOutput) { Write-Host "$prefix $Message" -ForegroundColor DarkGray } }
        default { Write-Host "$prefix $Message" }
    }
}

function Write-PkiVerbose {
    param([Parameter(Mandatory)][string]$Message)
    if ($script:Pki.VerboseOutput) { Write-Verbose -Message $Message }
}

function Invoke-PkiStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    $start = Get-PkiNowUtc
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-PkiLog "START: $Name"
    try {
        & $Action
        $sw.Stop()
        $step = [ordered]@{
            name = $Name
            startedAtUtc = $start.ToString('o')
            endedAtUtc = (Get-PkiNowUtc).ToString('o')
            elapsedMilliseconds = [math]::Round($sw.Elapsed.TotalMilliseconds, 3)
            elapsed = $sw.Elapsed.ToString()
            success = $true
        }
        if ($null -ne $script:PkiTelemetry) { [void]$script:PkiTelemetry.steps.Add($step) }
        Write-PkiLog "DONE: $Name | Step: $($step.elapsed) | Total: $($script:PkiTelemetryStopwatch.Elapsed)" 'OK'
    }
    catch {
        $sw.Stop()
        $step = [ordered]@{
            name = $Name
            startedAtUtc = $start.ToString('o')
            endedAtUtc = (Get-PkiNowUtc).ToString('o')
            elapsedMilliseconds = [math]::Round($sw.Elapsed.TotalMilliseconds, 3)
            elapsed = $sw.Elapsed.ToString()
            success = $false
            error = $_.Exception.Message
        }
        if ($null -ne $script:PkiTelemetry) { [void]$script:PkiTelemetry.steps.Add($step) }
        Write-PkiLog "FAILED: $Name | Step: $($step.elapsed) | Error: $($_.Exception.Message)" 'ERROR'
        throw
    }
}

function Ensure-PkiDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function ConvertTo-PkiLfFile {
    # PEM text must end its lines with LF only. OpenSSL on Windows writes text files with CRLF, and OpenSSL 3.5+ servers
    # (nginx on Ubuntu 26.04) then refuse the private key ("PEM_read_bio_PrivateKey() failed ... No supported data to decode").
    # Rewrites the file with LF endings, no BOM; returns $true when it changed anything.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $start = 0; if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $start = 3 }
    $out = [System.IO.MemoryStream]::new()
    for ($i = $start; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -ne 13) { $out.WriteByte($bytes[$i]) } }
    $new = $out.ToArray()
    if ($new.Length -eq $bytes.Length) { return $false }
    [System.IO.File]::WriteAllBytes($Path, $new)
    return $true
}

function Assert-PkiFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required file does not exist: $Path" }
}

function Normalize-PkiIdentity {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return '' }
    return (($Value -replace '\\,', ',' -replace '\s+', ' ').Trim().ToLowerInvariant())
}

function Escape-OpenSslValue {
    param([Parameter(Mandatory)][string]$Value)
    return ($Value -replace '\\', '\\\\' -replace '([,+=<>#;"\r\n])', '\\$1')
}

function Set-PkiSecretEnvironment {
    param([Parameter(Mandatory)][string]$Password)
    $env:PKI_PFX_PASSWORD = $Password
}

function Clear-PkiSecretEnvironment {
    if (Test-Path Env:PKI_PFX_PASSWORD) {
        Remove-Item Env:PKI_PFX_PASSWORD -ErrorAction SilentlyContinue
    }
}

function Get-PkiErrorLocation {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $inv = $ErrorRecord.InvocationInfo
    $file = $null
    $line = $null
    $column = $null
    $source = $null

    if ($null -ne $inv) {
        $file = $inv.ScriptName
        if ([string]::IsNullOrWhiteSpace($file)) { $file = $inv.MyCommand.Path }
        $line = $inv.ScriptLineNumber
        $column = $inv.OffsetInLine
        $source = $inv.Line
    }

    $stack = [string]$ErrorRecord.ScriptStackTrace
    if (-not [string]::IsNullOrWhiteSpace($stack)) {
        $matches = [regex]::Matches($stack, '(?m)^\s*at .*?,\s*(?<file>.+?):\s*line\s+(?<line>\d+)\s*$')
        if ($matches.Count -gt 0) {
            $m = $matches[0]
            if ([string]::IsNullOrWhiteSpace($file)) { $file = $m.Groups['file'].Value.Trim() }
            if (-not $line -or $line -eq 0) { $line = [int]$m.Groups['line'].Value }
        }
    }

    [pscustomobject]@{
        File = $file
        Line = $line
        Column = $column
        Source = $source
    }
}

function Write-PkiFatalError {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $loc = Get-PkiErrorLocation -ErrorRecord $ErrorRecord
    Stop-PkiTelemetry -Success $false
    Write-PkiTelemetryFile

    Write-Host ''
    Write-PkiLog 'PKI GENERATION FAILED' 'ERROR'
    Write-PkiLog "Exception: $($ErrorRecord.Exception.GetType().FullName)" 'ERROR'
    Write-PkiLog "Details: $($ErrorRecord.Exception.Message)" 'ERROR'
    if ($loc.File)   { Write-PkiLog "Filename: $($loc.File)" 'ERROR' }
    if ($loc.Line)   { Write-PkiLog "Line: $($loc.Line)" 'ERROR' }
    if ($loc.Column) { Write-PkiLog "Column: $($loc.Column)" 'ERROR' }
    if ($loc.Source) { Write-PkiLog "Code: $($loc.Source.Trim())" 'ERROR' }
    if ($ErrorRecord.CategoryInfo) { Write-PkiLog "Category: $($ErrorRecord.CategoryInfo)" 'ERROR' }
    if ($ErrorRecord.FullyQualifiedErrorId) { Write-PkiLog "ErrorId: $($ErrorRecord.FullyQualifiedErrorId)" 'ERROR' }
    if ($ErrorRecord.InvocationInfo.PositionMessage) {
        Write-Host $ErrorRecord.InvocationInfo.PositionMessage -ForegroundColor DarkRed
    }
    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ScriptStackTrace)) {
        Write-PkiLog 'Script stack:' 'ERROR'
        Write-Host $ErrorRecord.ScriptStackTrace -ForegroundColor DarkRed
    }
    if ($null -ne $script:PkiTelemetry -and $script:PkiTelemetry.elapsed) {
        Write-PkiLog "Total elapsed: $($script:PkiTelemetry.elapsed)" 'ERROR'
    }
    if ($script:PkiTelemetryPath) {
        Write-PkiLog "Telemetry: $($script:PkiTelemetryPath)" 'ERROR'
    }
}


# ============================================================
# Unblock files (remove the Windows "downloaded from the Internet" mark)
# and find out which processes lock files (Windows Restart Manager).
# ============================================================
function Unblock-PkiTree {
    <#
    .SYNOPSIS
        Unblock-File on every file below the given folders (scripts, certificates, keys ...).
        Same effect as:  Get-ChildItem -Recurse -File | Unblock-File
    .OUTPUTS
        Number of files that were blocked and are now unblocked.
    #>
    param([Parameter(Mandatory)][string[]]$Path)
    if (-not $IsWindows) { return 0 }
    $count = 0
    foreach ($root in $Path) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            try {
                if ($null -ne (Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue)) {
                    Unblock-File -LiteralPath $f.FullName -ErrorAction Stop
                    $count++
                }
            }
            catch { }
        }
    }
    return $count
}

function Unlock-PkiTree {
    <#
    .SYNOPSIS
        UNLOCK: removes the Read-only attribute from the folders and files below the given folders, children and
        recursive (Windows refuses to overwrite or delete read-only items; so does a copy from a read-only medium).
    .OUTPUTS
        Number of items (folders and files) that were read-only and are not any more.
    #>
    param([Parameter(Mandatory)][string[]]$Path)
    $count = 0
    $ro = [System.IO.FileAttributes]::ReadOnly
    foreach ($root in $Path) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }
        $items = @(Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue)
        foreach ($i in $items) {
            try {
                if (($i.Attributes -band $ro) -ne 0) { $i.Attributes = $i.Attributes -bxor $ro; $count++ }
            }
            catch { }
        }
    }
    return $count
}

function Invoke-PkiUnblockUnlock {
    <#
    .SYNOPSIS
        The mechanism behind -Unblock of every main script: UNBLOCK (the Windows "downloaded from the Internet" mark),
        UNLOCK (Read-only attribute) on every folder given, children and recursive, then list the processes that hold
        files open (Windows Restart Manager; nothing is killed).
    #>
    param([Parameter(Mandatory)][string[]]$Path, [switch]$Quiet)
    $paths = @($Path | Where-Object { $_ } | Select-Object -Unique)
    $unblocked = Unblock-PkiTree -Path $paths
    $unlocked = Unlock-PkiTree -Path $paths
    $holders = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p -PathType Container) { foreach ($h in @(Get-PkiLockingProcesses -Folder $p)) { if (-not $holders.Contains($h)) { [void]$holders.Add($h) } } }
    }
    if (-not $Quiet) {
        foreach ($p in $paths) { Write-PkiLog "  $(if (Test-Path -LiteralPath $p) { 'processed' } else { 'not found ' }) : $p" 'INFO' }
        Write-PkiLog "Unblocked $unblocked file(s) (Internet mark), unlocked $unlocked item(s) (Read-only), in $($paths.Count) folder(s), children and recursive." 'OK'
        if ($holders.Count -gt 0) {
            Write-PkiLog 'These processes hold files open in those folders (close them before deleting or overwriting):' 'WARN'
            foreach ($h in $holders) { Write-PkiLog "  $h" 'WARN' }
        }
    }
    return [ordered]@{ Unblocked = $unblocked; Unlocked = $unlocked; Holders = @($holders) }
}

function Get-PkiLockingProcesses {
    <#
    .SYNOPSIS
        Lists the processes that have files below a folder open (Windows Restart Manager).
        Returns strings like  "explorer (PID 1234)". Never throws: returns @() when unknown.
    #>
    param([Parameter(Mandatory)][string]$Folder, [int]$MaxFiles = 400)
    if (-not $IsWindows) { return @() }
    try {
        if (-not ('PkiRestartManager' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class PkiRestartManager
{
    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint handle, int flags, StringBuilder key);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint handle);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint handle, uint nFiles, string[] files, uint nApps, RM_UNIQUE_PROCESS[] apps, uint nSvcs, string[] svcs);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] info, ref uint reasons);

    public static List<string> GetLockers(string[] files)
    {
        var result = new List<string>();
        uint handle;
        var key = new StringBuilder(33);
        if (RmStartSession(out handle, 0, key) != 0) return result;
        try
        {
            if (RmRegisterResources(handle, (uint)files.Length, files, 0, null, 0, null) != 0) return result;
            uint needed = 0, count = 0, reasons = 0;
            int rc = RmGetList(handle, out needed, ref count, null, ref reasons);
            if (rc == 234 && needed > 0)           // ERROR_MORE_DATA
            {
                var info = new RM_PROCESS_INFO[needed];
                count = needed;
                if (RmGetList(handle, out needed, ref count, info, ref reasons) == 0)
                {
                    for (int i = 0; i < count; i++)
                        result.Add(info[i].strAppName + " (PID " + info[i].Process.dwProcessId + ")");
                }
            }
        }
        finally { RmEndSession(handle); }
        return result;
    }
}
'@
        }
        $items = @(Get-ChildItem -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object -First $MaxFiles | ForEach-Object { $_.FullName })
        $items = @($Folder) + $items
        return @([PkiRestartManager]::GetLockers([string[]]$items) | Sort-Object -Unique)
    }
    catch { return @() }
}

# ============================================================
# Shared helpers (used by the generator and by later scripts such as
# GenerateLeafCertificate.ps1 and the transport script)
# ============================================================

# Certificates whose subject or issuer contains one of these words belong to this PKI
# (-RemoveAllTrust). Edit here if the company name changes.
$script:PkiIdentityMarkers = @('Agantra Inovatif', 'NextMantra')

function ConvertFrom-PkiPemToDer {
    # First certificate of a PEM file -> DER bytes
    param([Parameter(Mandatory)][string]$Path)
    $text = [System.IO.File]::ReadAllText($Path)
    $m = [regex]::Match($text, '-----BEGIN CERTIFICATE-----(?<b>[^-]+)-----END CERTIFICATE-----')
    if (-not $m.Success) { throw "No PEM certificate found in $Path" }
    $bytes = [byte[]][Convert]::FromBase64String(($m.Groups['b'].Value -replace '\s', ''))
    return ,$bytes      # the comma keeps PowerShell from unrolling the byte[] into object[] (X509Certificate2 would read it as a path)
}

function Get-PkiCertificateFingerprint {
    # SHA-1 (Windows thumbprint) and SHA-256 of the first certificate of a PEM file
    param([Parameter(Mandatory)][string]$Path)
    $der = ConvertFrom-PkiPemToDer -Path $Path
    return [ordered]@{
        Sha1   = [BitConverter]::ToString([System.Security.Cryptography.SHA1]::HashData($der)).Replace('-', '')
        Sha256 = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($der)).Replace('-', '')
    }
}

function Split-PkiPemBundle {
    # A PEM bundle -> list of single-certificate PEM strings, in file order
    param([Parameter(Mandatory)][string]$Path)
    $text = [System.IO.File]::ReadAllText($Path)
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($text, '-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----')) {
        [void]$list.Add(($m.Value -replace '\s*\r?\n\s*', "`n").Trim() + "`n")
    }
    return ,$list      # the comma keeps a one-element list from being unrolled to a string
}

function Initialize-PkiMinimalContext {
    <#
    .SYNOPSIS
        Creates the small $script:Pki state that the shared modules need, for scripts that do not run
        the generator (for example the transport script, which only installs / removes trust).
    #>
    param([string]$PkiRoot = (Join-Path (Get-Location).Path 'pki'), [string]$Password = 'Abc12345!', [switch]$VerboseOutput)
    $script:Pki = [ordered]@{
        PkiRoot = $PkiRoot; Password = $Password; VerboseOutput = [bool]$VerboseOutput
        Built = [ordered]@{}; Leaves = [System.Collections.Generic.List[object]]::new(); ExternalRoot = $null
    }
}

