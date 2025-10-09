# InfraWare Installation Script

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="darwin"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    arm64|aarch64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "Installing InfraWare for $OS-$ARCH..."

# Check if Python is available
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Python 3.8+ is required but not found. Please install Python first."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Python $REQUIRED_VERSION or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

# Check if pip is available
if ! command -v pip &> /dev/null && ! command -v pip3 &> /dev/null; then
    echo "pip is required but not found. Please install pip first."
    exit 1
fi

# Install InfraWare
echo "Installing InfraWare..."
if command -v pip3 &> /dev/null; then
    pip3 install infraware
else
    pip install infraware
fi

# Verify installation
if command -v infraware &> /dev/null; then
    echo "✅ InfraWare installed successfully!"
    echo "🚀 Run 'infraware welcome' to get started"
    echo "📚 Run 'infraware --help' for available commands"
else
    echo "❌ Installation failed. Please try manual installation:"
    echo "   pip install infraware"
    exit 1
fi

# Create default directories
echo "Setting up default directories..."
mkdir -p ~/.infraware/rules
mkdir -p ~/.infraware/ignores
mkdir -p ~/.infraware/cache

# Download initial CVE database (optional)
read -p "Download initial CVE database? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Downloading CVE database..."
    infraware cve download
fi

echo ""
echo "🎉 InfraWare setup complete!"
echo ""
echo "📖 Quick start:"
echo "   infraware welcome"
echo "   infraware scan <terraform-plan.json>"
echo "   infraware cost-analysis analyze <terraform-plan.json>"
echo ""
echo "📚 Documentation: https://github.com/Awez123/Infraware"