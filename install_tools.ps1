<#
.SYNOPSIS
    Bounty Hunter 2.6.0 - Automated Tool and Dependency Installer for Windows PowerShell.
.DESCRIPTION
    Installs Python dependencies, registers the `bb` CLI, and automatically installs
    external security engines (Nuclei, Trivy, TruffleHog, DalFox, Subfinder, Katana).
#>

[CmdletBinding()]
param(
    [switch]$SkipBinaries = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Bounty Hunter 2.6.0 - Automatic Setup and Tool Installer" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
try {
    $pyVersion = python --version 2>&1
    Write-Host "[+] Python detected: $pyVersion" -ForegroundColor Green
} catch {
    Write-Error "[!] Python is not installed or not in PATH. Please install Python 3.11+."
    exit 1
}

# 2. Upgrade pip
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet

# 3. Install Python requirements
Write-Host "[*] Installing Python dependencies from requirements.txt..." -ForegroundColor Yellow
python -m pip install -r requirements.txt

# 4. Install editable bountybot
Write-Host "[*] Registering Bounty Hunter (bb) in editable mode..." -ForegroundColor Yellow
python -m pip install -e .

# 5. External binary installations
if (-not $SkipBinaries) {
    Write-Host ""
    Write-Host "[*] Installing and configuring external security engines..." -ForegroundColor Yellow
    python -m bb.cli engines install
}

# 6. Verify engines status
Write-Host ""
Write-Host "[*] Integrated Engines Operational Status:" -ForegroundColor Cyan
python -m bb.cli engines list

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host " [+] Installation complete and verified! You can now run: bb --help" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
