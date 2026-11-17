@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  Bounty Hunter 2.6.0 - Automatic Setup and Tool Installer
echo =====================================================================
echo.

:: 1. Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11 or 3.12 from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Python detected:
python --version
echo.

:: 2. Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: 3. Install Python requirements
echo [*] Installing required Python packages from requirements.txt...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install Python dependencies.
    pause
    exit /b 1
)

:: 4. Install Bounty Hunter in editable mode
echo.
echo [*] Installing Bounty Hunter CLI (bb) in editable mode...
python -m pip install -e .
if errorlevel 1 (
    echo [ERROR] Failed to install Bounty Hunter package.
    pause
    exit /b 1
)

:: 5. Verify CLI works
echo.
echo [*] Verifying Bounty Hunter installation...
python -m bb.cli --help >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Could not invoke bb module directly.
) else (
    echo [+] Bounty Hunter CLI successfully verified!
)

:: 6. Check external binary security engines
echo.
echo [*] Checking availability of integrated security engines...
python -m bb.cli engines list

echo.
echo =====================================================================
echo  Optional External Tools Installation Guide:
echo =====================================================================
echo   To install additional binary engines:
echo.
echo   - Nuclei:     winget install ProjectDiscovery.Nuclei
echo                 or: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
echo.
echo   - DalFox:     go install github.com/hahwul/dalfox/v2@latest
echo.
echo   - Trivy:      winget install AquaSecurity.Trivy
echo.
echo   - TruffleHog: winget install TruffleSecurity.TruffleHog
echo.
echo   - Burp Suite: Download Community from https://portswigger.net/burp
echo.
echo =====================================================================
echo [+] Setup complete! You can now run: bb --help
echo =====================================================================
echo.
pause
