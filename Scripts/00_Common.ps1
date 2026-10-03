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
