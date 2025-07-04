@echo off
REM Windows Privilege Escalation Scanner Launcher
REM This batch file launches the PowerShell privilege escalation script

echo ================================================================
echo     Windows Privilege Escalation Comprehensive Scanner
echo ================================================================
echo.

REM Check if PowerShell is available
powershell -Command "Get-Host" >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: PowerShell is not available or accessible
    echo Please ensure PowerShell is installed and accessible
    pause
    exit /b 1
)

REM Check execution policy
echo Checking PowerShell execution policy...
for /f "tokens=*" %%i in ('powershell -Command "Get-ExecutionPolicy"') do set POLICY=%%i
echo Current execution policy: %POLICY%

if "%POLICY%"=="Restricted" (
    echo.
    echo WARNING: PowerShell execution policy is Restricted
    echo The script may not run properly with this policy
    echo.
    echo Options:
    echo 1. Run as Administrator and temporarily bypass policy
    echo 2. Change execution policy permanently
    echo 3. Continue anyway (may fail)
    echo.
    set /p choice="Enter choice (1/2/3): "
    
    if "!choice!"=="1" (
        echo Running with execution policy bypass...
        powershell -ExecutionPolicy Bypass -File "windows_privesc_comprehensive.ps1"
        goto :end
    )
    
    if "!choice!"=="2" (
        echo Changing execution policy to RemoteSigned...
        powershell -Command "Set-ExecutionPolicy RemoteSigned -Force"
        if %errorlevel% neq 0 (
            echo Failed to change execution policy. Try running as Administrator.
            pause
            exit /b 1
        )
    )
)

REM Run the PowerShell script
echo.
echo Starting Windows Privilege Escalation Scan...
echo.

powershell -File "windows_privesc_comprehensive.ps1"

:end
echo.
echo Scan completed. Check the output directory for results.
pause
