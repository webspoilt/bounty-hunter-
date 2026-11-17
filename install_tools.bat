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

:: 5. Install external binary security engines
echo.
echo [*] Installing and configuring external security engines (Nuclei, Trivy, TruffleHog, DalFox, Subfinder, Katana)...
python -m bb.cli engines install
if errorlevel 1 (
    echo [WARNING] Some external tools could not be automatically downloaded.
)

:: 6. Verify CLI & engine status
echo.
echo [*] Checking operational status of all integrated security engines...
python -m bb.cli engines list

echo.
echo =====================================================================
echo  [+] Setup complete! Bounty Hunter and all tools are ready.
echo  Run: bb --help
echo =====================================================================
echo.
pause
