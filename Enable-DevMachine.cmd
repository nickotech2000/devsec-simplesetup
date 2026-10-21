@echo off
rem ============================================================
rem PKI Script (Command Prompt twin of Enable-DevMachine.ps1)
rem Author : Nicko Satria Utama
rem Company: Agantra Inovatif OU (NextMantra)
rem Email  : nicko@nextmantra.com
rem Version: 7.6.5
rem ============================================================
rem Makes this Windows computer a DEVELOPMENT machine: the PowerShell execution policy becomes Bypass for the
rem current user (and, when this window is "Run as administrator", for the whole computer), in every present and
rem future PowerShell session, and the files below this folder are unblocked.
rem This file needs no policy: it only calls the Set-ExecutionPolicy and Unblock-File commands. Plain text, read it.
rem   Enable-DevMachine.cmd            do it (asks Y/N)        Enable-DevMachine.cmd /yes      do it, no question
rem   Enable-DevMachine.cmd /status    show only               Enable-DevMachine.cmd /undo     back to the Windows default
rem   Enable-DevMachine.cmd /nounblock policy only             Enable-DevMachine.cmd /?        help
setlocal EnableExtensions
set "MODE=on" & set "ASK=1" & set "UNBLOCK=1"
:args
if "%~1"=="" goto :argsdone
if /i "%~1"=="/?" goto :help
if /i "%~1"=="-h" goto :help
if /i "%~1"=="--help" goto :help
if /i "%~1"=="/version" goto :version
if /i "%~1"=="--version" goto :version
if /i "%~1"=="/status" set "MODE=status"
if /i "%~1"=="/undo" set "MODE=undo"
if /i "%~1"=="/yes" set "ASK=0"
if /i "%~1"=="/nounblock" set "UNBLOCK=0"
shift
goto :args
:argsdone
if /i not "%OS%"=="Windows_NT" ( echo This file is for Windows. & exit /b 5 )
set "ADMIN=0"
net session >nul 2>&1 && set "ADMIN=1"
set "FOLDER=%~dp0."
echo Enable-DevMachine.cmd 7.6.5   (administrator: %ADMIN%)

rem every PowerShell: Windows PowerShell 64 bit, 32 bit, and pwsh 7 (found by where)
set "PSLIST="
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" ( set "PSLIST=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" ) else if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" set "PSLIST=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" set "PSLIST=%PSLIST%|%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
for /f "delims=" %%P in ('where pwsh.exe 2^>nul') do set "PSLIST=%PSLIST%|%%P"
for %%D in ("%ProgramFiles%\PowerShell\*") do if exist "%%~fD\pwsh.exe" set "PSLIST=%PSLIST%|%%~fD\pwsh.exe"
if not defined PSLIST ( echo No PowerShell found. & exit /b 1 )

if "%MODE%"=="status" goto :status
if "%MODE%"=="undo" ( set "POLICY=Undefined" ) else set "POLICY=Bypass"
if "%ASK%"=="1" (
  if "%MODE%"=="undo" ( echo This removes the Bypass setting. ) else (
    echo This switches the PowerShell script protection OFF ^(policy Bypass^) for every session, now and later.
    if "%ADMIN%"=="1" ( echo For the current user AND all users of this computer. ) else echo For the current user only ^(use "Run as administrator" for all users^).
    if "%UNBLOCK%"=="1" echo It also unblocks all files below %FOLDER%
    echo Use it on your own development computer only.
  )
  set "A="
  set /p "A=Continue? (Y/N) "
  if /i not "%A%"=="Y" if /i not "%A%"=="YES" ( echo Nothing changed. & exit /b 2 )
)
set "FAIL=0"
set "REST=%PSLIST%"
:setloop
for /f "tokens=1* delims=|" %%A in ("%REST%") do ( set "ENG=%%A" & set "REST=%%B" )
if defined ENG (
  call :setpolicy "%ENG%" CurrentUser
  if "%ADMIN%"=="1" call :setpolicy "%ENG%" LocalMachine
)
set "ENG="
if defined REST goto :setloop
if "%ADMIN%"=="0" echo [INFO] Not administrator: only the current user was changed.

if "%MODE%"=="on" if "%UNBLOCK%"=="1" (
  powershell -NoProfile -NonInteractive -Command "Get-ChildItem -LiteralPath '%FOLDER%' -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { try { Unblock-File -LiteralPath $_.FullName } catch { }; try { if ($_.IsReadOnly) { $_.IsReadOnly = $false } } catch { } }; 'Unblocked files below %FOLDER%'"
)
:status
echo.
echo Execution policy of every PowerShell:
set "REST=%PSLIST%"
:statloop
for /f "tokens=1* delims=|" %%A in ("%REST%") do ( set "ENG=%%A" & set "REST=%%B" )
if defined ENG (
  echo   "%ENG%"
  "%ENG%" -NoProfile -NonInteractive -Command "Get-ExecutionPolicy -List | ForEach-Object { '      {0,-16} {1}' -f $_.Scope, $_.ExecutionPolicy }; '      EFFECTIVE        ' + (Get-ExecutionPolicy)"
)
set "ENG="
if defined REST goto :statloop
echo.
if "%MODE%"=="status" exit /b 0
if "%FAIL%"=="0" ( echo Done. Open a NEW PowerShell window. ) else ( echo %FAIL% setting^(s^) could not be changed - often a Group Policy ^(MachinePolicy / UserPolicy above^). & exit /b 1 )
exit /b 0

:setpolicy
"%~1" -NoProfile -NonInteractive -Command "try { Set-ExecutionPolicy -ExecutionPolicy %POLICY% -Scope %~2 -Force -ErrorAction Stop; exit 0 } catch { Write-Host ('[WARN] ' + $_.Exception.Message); exit 1 }"
if errorlevel 1 ( set /a FAIL+=1 ) else echo [OK] %~1: %~2 = %POLICY%
exit /b 0

:version
echo ====================================================================================================
echo  Enable-DevMachine.cmd  -  version information
echo ====================================================================================================
echo  SCRIPT
echo  Name           : Enable-DevMachine.cmd
echo  Version        : 7.6.5   (build of 2026-10-21)
echo  Author         : Nicko Satria Utama
echo  Company        : Agantra Inovatif OU (NextMantra)
echo  Email          : nicko@nextmantra.com
echo ----------------------------------------------------------------------------------------------------
echo  The full report (OS, .NET, Node.js, Python, Java, shells, Schannel, OpenSSL):
echo      Enable-DevMachine.ps1 -Version
echo ====================================================================================================
exit /b 0

:help
echo ====================================================================================================
echo  Enable-DevMachine.cmd  -  make this Windows computer a development machine
echo  Version 7.6.5
echo  Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
echo ====================================================================================================
echo  Sets the PowerShell execution policy to Bypass in every present and future session ^(current user;
echo  all users when started with "Run as administrator"^) and unblocks the files below this folder, so
echo  unsigned .ps1 files run. Works in Windows PowerShell 5.1 ^(64 and 32 bit^) and PowerShell 7.
echo  It changes only the execution policy. Antivirus, Defender, SmartScreen and firewall stay as they are.
echo.
echo    Enable-DevMachine.cmd             do it ^(asks Y/N^)
echo    Enable-DevMachine.cmd /yes        do it without the question
echo    Enable-DevMachine.cmd /status     show the policy of every PowerShell, change nothing
echo    Enable-DevMachine.cmd /undo       remove the Bypass setting ^(back to the Windows default^)
echo    Enable-DevMachine.cmd /nounblock  set the policy only, leave the files alone
echo    Enable-DevMachine.cmd /version    version, author   ^(--version and /? also work^)
echo.
echo  Exit codes: 0 done   1 a setting failed ^(Group Policy?^)   2 you answered No   5 not Windows
echo  ONLY FOR YOUR OWN DEVELOPMENT COMPUTER. Bypass lets any script run, also a bad one.
echo  Twin: Enable-DevMachine.ps1 ^(same job, from PowerShell^).  Manual: docs\Enable-DevMachine-MANUAL.txt
echo ====================================================================================================
exit /b 0
