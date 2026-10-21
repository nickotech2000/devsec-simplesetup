# ============================================================
# PKI Tool (developer only, not part of the runtime)
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# Version: 7.5.2
# ============================================================
# Puts the shared -Version block (tools\version-block.ps1) into the given .ps1 files:
# adds [switch]$Version to the param() block and (re)places the marked block right after it.
# Safe to run again: the old block is cut out by its markers first.   Use: pwsh tools/Update-VersionBlock.ps1 file1.ps1 file2.ps1
param([Parameter(ValueFromRemainingArguments)][string[]]$Files)
$block = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'version-block.ps1') -Raw -Encoding UTF8).TrimEnd() 
foreach ($f in $Files) {
    $full = (Resolve-Path $f).Path; $bom = ([IO.File]::ReadAllBytes($full)[0..2] -join ',') -eq '239,187,191'
    $text = [IO.File]::ReadAllText($full, [Text.UTF8Encoding]::new($false))
    $nl = if ($text -match "`r`n") { "`r`n" } else { "`n" }
    $text = [regex]::Replace($text, '(?s)\r?\n?# >>> PKI-VERSION-INFO.*?# <<< PKI-VERSION-INFO\r?\n?', '')
    $errs = $null; $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errs)
    $pb = $ast.ParamBlock
    if (-not $pb -or $pb.Parameters.Count -eq 0) { Write-Host "NO PARAM BLOCK: $f"; continue }
    $has = $pb.Parameters.Name.VariablePath.UserPath -contains 'Version'
    $endParam = $pb.Parameters[-1].Extent.EndOffset
    $endBlock = $pb.Extent.EndOffset
    $ins = $nl + ($block -replace "`r?`n", $nl) + $nl
    $text = $text.Substring(0, $endBlock) + $ins + $text.Substring($endBlock)
    if (-not $has) { $text = $text.Substring(0, $endParam) + ",$nl    [switch]`$Version" + $text.Substring($endParam) }
    [IO.File]::WriteAllText($full, $text, [Text.UTF8Encoding]::new($bom))
    Write-Host "ok: $f"
}
