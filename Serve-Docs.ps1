# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# Version: 6.4.7
# ============================================================
#requires -Version 7.0
param([int]$Port = 1434, [string]$Folder, [switch]$Open, [switch]$Help)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
function Out-PagedHelp {
    # Shows help one screen at a time on a terminal (Space = next page, Enter = next line, q = quit).
    # When the output is redirected (a file, a pipe, a pipeline) it prints everything.
    param([Parameter(ValueFromPipeline = $true)][AllowEmptyString()][AllowNull()][string[]]$InputObject)
    begin { $all = [System.Collections.Generic.List[string]]::new() }
    process { foreach ($x in $InputObject) { foreach ($l in ([string]$x -split "\r?\n")) { [void]$all.Add($l) } } }
    end {
        $page = 0; $width = 120
        try { if (-not ([Console]::IsOutputRedirected -or [Console]::IsInputRedirected)) { $page = [Console]::WindowHeight - 2; $width = [Console]::WindowWidth } } catch { $page = 0 }
        if ($page -lt 8) { foreach ($l in $all) { Write-Host $l }; return }
        $rows = 0
        foreach ($l in $all) {
            Write-Host $l
            $rows += [Math]::Max(1, [Math]::Ceiling($l.Length / [Math]::Max(20, $width)))
            if ($rows -ge $page) {
                Write-Host ' -- more --  Space = next page   Enter = next line   q = quit ' -NoNewline -ForegroundColor Yellow
                $k = [Console]::ReadKey($true)
                Write-Host ("`r" + (' ' * 64) + "`r") -NoNewline
                if ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') { return }
                $rows = if ($k.Key -eq 'Enter') { $page - 1 } else { 0 }
            }
        }
    }
}
function Invoke-PagedHelp {
    param([scriptblock]$Block)
    & $Block 6>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.InformationRecord]) { [string]$_.MessageData } else { [string]$_ } } | Out-PagedHelp
}

if ($Help) {
    $t = @'
====================================================================================================
 Serve-Docs.ps1 - show the HTML documentation on a small local web server
 Version 6.4.7   Author: Nicko Satria Utama   Company: Agantra Inovatif OU   Email: nicko@nextmantra.com
====================================================================================================
 WHAT IT DOES
   Serves the folder html\ on http://localhost:<port>/ . Only this computer can connect.
   You do not need it: html\index.html also opens with a double click.

 OPTIONS
   -Port <n>      port number (default 1434)
   -Folder <dir>  the folder to show (default: html\ next to this script)
   -Open          open the browser
   -Help          this text
 Stop with Ctrl+C.
 EXIT CODES   0 ok   1 error
====================================================================================================
'@
    $t | Out-PagedHelp
    exit 0
}
if (-not $Folder) { $Folder = Join-Path $root 'html' }
$Folder = (Resolve-Path -LiteralPath $Folder).Path
$types = @{ '.html' = 'text/html; charset=utf-8'; '.txt' = 'text/plain; charset=utf-8'; '.woff2' = 'font/woff2'; '.css' = 'text/css'; '.js' = 'text/javascript' }
$l = [System.Net.HttpListener]::new(); $l.Prefixes.Add("http://localhost:$Port/")
try { $l.Start() } catch { Write-Host "[ERROR] Cannot listen on port ${Port}: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
Write-Host "[OK] http://localhost:$Port/index.html   (Ctrl+C stops)" -ForegroundColor Green
if ($Open) { Start-Process "http://localhost:$Port/index.html" }
try {
    while ($l.IsListening) {
        $c = $l.GetContext(); $rel = [Uri]::UnescapeDataString($c.Request.Url.AbsolutePath).TrimStart('/'); if (-not $rel) { $rel = 'index.html' }
        $f = [System.IO.Path]::GetFullPath((Join-Path $Folder $rel))
        if ($f.StartsWith($Folder, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $f -PathType Leaf)) {
            $b = [System.IO.File]::ReadAllBytes($f); $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
            $c.Response.ContentType = $(if ($types.ContainsKey($ext)) { $types[$ext] } else { 'application/octet-stream' })
            $c.Response.Headers.Add('X-Content-Type-Options', 'nosniff'); $c.Response.OutputStream.Write($b, 0, $b.Length)
        } else { $c.Response.StatusCode = 404 }
        $c.Response.Close()
    }
} finally { $l.Stop() }
