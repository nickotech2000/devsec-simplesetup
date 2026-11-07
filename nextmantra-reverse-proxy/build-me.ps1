<#------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------#>

# ==============================================================================
# NextMantra Private PKI Proxy Compiler Script (.NET 10 Target)
# Parallel Cross-Compilation for Windows, Linux, and macOS Outputs
# ==============================================================================

Clear-Host
Write-Host "-------------------------------------------------" -ForegroundColor Cyan
Write-Host "Author  : Nicko Satria Utama" -ForegroundColor Cyan
Write-Host "Company : Agantra Inovatif OU" -ForegroundColor Cyan
Write-Host "Email   : nicko@nextmantra.com" -ForegroundColor Cyan
Write-Host "-------------------------------------------------" -ForegroundColor Cyan

$ProjectDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($ProjectDir)) {
    $ProjectDir = "E:\ProjectCommons\DevSec-SimpleSetup\nextmantra-reverse-proxy"
}

Set-Location $ProjectDir

if (!(Test-Path "$ProjectDir\Program.cs")) {
    Write-Error "CRITICAL: Could not find your Program.cs file inside: $ProjectDir"
    return
}

# Define the targets for all three operating systems with explicit suffixes and extensions
$CompileTargets = @(
    @{ RID = "win-x64";   Ext = ".exe"; Suffix = "-win64" },
    @{ RID = "linux-x64"; Ext = "";     Suffix = "-linux64" },
    @{ RID = "osx-arm64"; Ext = "";     Suffix = "-mac" }
)

$BaseBinaryName = "agantra-inovatif-crl-ocsp-proxy"
$BuildErrors = 0

foreach ($Target in $CompileTargets) {
    $RuntimeID = $Target.RID
    $FinalName = "${BaseBinaryName}$($Target.Suffix)$($Target.Ext)"
    
    # Establish a clean, sandboxed temporary output folder for this target compilation
    $TempOutDir = "$ProjectDir\temp-build-$RuntimeID"
    if (!(Test-Path $TempOutDir)) { New-Item -ItemType Directory -Path $TempOutDir | Out-Null }

    Write-Host "`n========================================================" -ForegroundColor Yellow
    Write-Host "[>] STARTING OPTIMIZED COMPILATION FOR RUNTIME: $RuntimeID" -ForegroundColor Yellow
    Write-Host "Target Naming Output : $FinalName" -ForegroundColor DarkYellow
    Write-Host "========================================================" -ForegroundColor Yellow

    # Compile with Assembly Trimming and Size Optimization rules enabled
    dotnet publish "$ProjectDir\Program.cs" `
      -c Release `
      -r $RuntimeID `
      -o "$TempOutDir" `
      --self-contained true `
      -p:PublishAot=false `
      -p:PublishSingleFile=true `
      -p:IncludeNativeLibrariesForSelfExtract=true `
      -p:TargetFramework=net10.0 `
      -p:PublishReadyToRun=true `
      -p:DebugType=none `
      -p:DebugSymbols=false `
      -p:PublishTrimmed=true `
      -p:TrimMode=link `
      -p:MetadataUpdaterSupport=false `
      -p:UseSystemResourceKeys=true

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Isolating compiled binary inside temporary space..." -ForegroundColor Gray
        
        # Search the temporary directory for the generated file asset
        $GeneratedBinary = Get-ChildItem -Path $TempOutDir -File | Where-Object { $_.Extension -eq $Target.Ext -or $_.Extension -eq "" } | Select-Object -First 1

        if ($GeneratedBinary) {
            # Move the compiled binary to the root directory with the platform target name
            Move-Item -Path $GeneratedBinary.FullName -Destination "$ProjectDir\$FinalName" -Force
            
            # Calculate and display the new reduced size metrics
            $SizeInMB = [Math]::Round((Get-Item "$ProjectDir\$FinalName").Length / 1MB, 2)
            Write-Host "[+] Successfully packaged: $FinalName ($SizeInMB MB)" -ForegroundColor Green
        } else {
            Write-Error "Could not isolate the generated binary inside the temporary build space for $RuntimeID."
            $BuildErrors++
        }
    } else {
        Write-Error "Compilation tracking failed for Target Framework configuration: $RuntimeID"
        $BuildErrors++
    }

    # Clean up the temporary build directory completely
    Write-Host "Cleaning intermediate build artifacts for $RuntimeID..." -ForegroundColor Gray
    if (Test-Path $TempOutDir) { Remove-Item -Path $TempOutDir -Recurse -Force | Out-Null }
}

# Final workspace cleanup of rogue metadata leftovers
if (Test-Path "$ProjectDir\Program.pdb") { Remove-Item -Path "$ProjectDir\Program.pdb" -Force }

Write-Host "`n========================================================" -ForegroundColor Green
if ($BuildErrors -eq 0) {
    Write-Host "[+] OPTIMIZED THREE-PLATFORM PRODUCTION COMPILATION COMPLETE!" -ForegroundColor Green
    Write-Host "Output Workspace Directory: $ProjectDir" -ForegroundColor Green
    Write-Host "Active Compiled Deployment Artifacts:" -ForegroundColor Cyan
    Get-ChildItem -Path $ProjectDir | Where-Object { $_.Name -like "${BaseBinaryName}*" -or $_.Name -eq "appsettings.json" } | Select-Object Name, @{Name="Size (MB)";Expression={[Math]::Round($_.Length / 1MB, 2)}}
} else {
    Write-Host "[-] COMPILATION COMPLETED WITH ERRORS. Review active SDK configuration states." -ForegroundColor Red
}
Write-Host "========================================================" -ForegroundColor Green
