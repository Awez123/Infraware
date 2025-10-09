# InfraWare PowerShell Installation Script

param(
    [switch]$SkipCVE = $false
)

Write-Host "🚀 InfraWare Installation Script" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.0 or higher is required."
    exit 1
}

# Check if Python is available
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
} else {
    Write-Error "Python 3.8+ is required but not found. Please install Python first."
    Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check Python version
$pythonVersion = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$requiredVersion = [Version]"3.8"
$currentVersion = [Version]$pythonVersion

if ($currentVersion -lt $requiredVersion) {
    Write-Error "Python 3.8 or higher is required. Found: $pythonVersion"
    exit 1
}

Write-Host "✅ Python $pythonVersion detected" -ForegroundColor Green

# Check if pip is available
if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    Write-Error "pip is required but not found. Please install pip first."
    exit 1
}

# Install InfraWare
Write-Host "📦 Installing InfraWare..." -ForegroundColor Yellow
try {
    pip install infraware
    Write-Host "✅ InfraWare installed successfully!" -ForegroundColor Green
} catch {
    Write-Error "❌ Installation failed. Please try manual installation: pip install infraware"
    exit 1
}

# Verify installation
if (Get-Command infraware -ErrorAction SilentlyContinue) {
    Write-Host "🎉 InfraWare is ready to use!" -ForegroundColor Green
} else {
    Write-Error "❌ Installation verification failed."
    exit 1
}

# Create default directories
Write-Host "📁 Setting up default directories..." -ForegroundColor Yellow
$infrawareDir = "$env:USERPROFILE\.infraware"
New-Item -ItemType Directory -Force -Path "$infrawareDir\rules" | Out-Null
New-Item -ItemType Directory -Force -Path "$infrawareDir\ignores" | Out-Null
New-Item -ItemType Directory -Force -Path "$infrawareDir\cache" | Out-Null

# Download initial CVE database (optional)
if (-not $SkipCVE) {
    $downloadCVE = Read-Host "Download initial CVE database? (y/N)"
    if ($downloadCVE -eq "y" -or $downloadCVE -eq "Y") {
        Write-Host "📊 Downloading CVE database..." -ForegroundColor Yellow
        infraware cve download
    }
}

Write-Host ""
Write-Host "🎉 InfraWare setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📖 Quick start:" -ForegroundColor Cyan
Write-Host "   infraware welcome" -ForegroundColor White
Write-Host "   infraware scan <terraform-plan.json>" -ForegroundColor White
Write-Host "   infraware cost-analysis analyze <terraform-plan.json>" -ForegroundColor White
Write-Host ""
Write-Host "📚 Documentation: https://github.com/Awez123/Infraware" -ForegroundColor Cyan
Write-Host "🐛 Issues: https://github.com/Awez123/Infraware/issues" -ForegroundColor Cyan