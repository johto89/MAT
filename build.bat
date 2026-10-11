@echo off
REM ============================================================
REM  M.A.T - MSSQL Attack Tool - Build Script
REM  Requires: Visual Studio 2019/2022 with .NET Framework 4.7.2
REM ============================================================

setlocal

REM Try to find MSBuild in common locations
set MSBUILD=
for %%M in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%M (
        set MSBUILD=%%M
        goto :found
    )
)

REM Try MSBuild from PATH
where msbuild >nul 2>&1
if %errorlevel%==0 (
    set MSBUILD=msbuild
    goto :found
)

echo [!] MSBuild not found. Install Visual Studio 2019/2022 with .NET desktop development workload.
echo [!] Or run this script from Developer Command Prompt.
exit /b 1

:found
echo [*] Using MSBuild: %MSBUILD%
echo [*] Restoring NuGet packages...

REM Restore NuGet packages
where nuget >nul 2>&1
if %errorlevel%==0 (
    nuget restore MAT.sln
) else (
    echo [!] NuGet CLI not found, skipping package restore.
    echo [!] Ensure packages are restored via Visual Studio or dotnet restore.
)

echo [*] Building MAT (Release, Any CPU)...
%MSBUILD% MAT.csproj /p:Configuration=Release /p:Platform="Any CPU" /t:Rebuild /verbosity:minimal

if %errorlevel%==0 (
    echo.
    echo [+] Build successful!
    echo [+] Output: bin\Release\MAT.exe
    echo.
    if exist "bin\Release\MAT.exe" (
        for %%A in ("bin\Release\MAT.exe") do echo [+] File size: %%~zA bytes
    )
) else (
    echo.
    echo [-] Build failed. Check errors above.
    exit /b 1
)

endlocal
