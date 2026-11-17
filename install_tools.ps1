<#
.SYNOPSIS
    Bounty Hunter 2.6.0 - Automated Tool and Dependency Installer for Windows PowerShell.
.DESCRIPTION
    Installs Python dependencies, registers the `bb` CLI, and checks or installs external security tools.
#>

[CmdletBinding()]
param(
    [switch]$InstallBinaries = $false
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

# 5. Optional binary installations via winget
if ($InstallBinaries) {
    Write-Host "[*] Checking winget for external security engines..." -ForegroundColor Yellow
    $tools = @(
        @{ Name = "Nuclei"; Id = "ProjectDiscovery.Nuclei" },
        @{ Name = "Trivy"; Id = "AquaSecurity.Trivy" },
        @{ Name = "TruffleHog"; Id = "TruffleSecurity.TruffleHog" }
    )

    foreach ($tool in $tools) {
        Write-Host "Checking $($tool.Name)..." -NoNewline
        if (Get-Command $tool.Name.ToLower() -ErrorAction SilentlyContinue) {
            Write-Host " [Installed]" -ForegroundColor Green
        } else {
            Write-Host " [Missing] - Attempting winget install..." -ForegroundColor Yellow
            try {
                winget install --id $tool.Id -e --silent --accept-source-agreements --accept-package-agreements
            } catch {
                Write-Warning "Could not automatically install $($tool.Name) via winget."
            }
        }
    }
}

# 6. Verify engines status
Write-Host ""
Write-Host "[*] Integrated Engines Status:" -ForegroundColor Cyan
python -m bb.cli engines list

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host " [+] Installation verified! You can now run: bb --help" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
