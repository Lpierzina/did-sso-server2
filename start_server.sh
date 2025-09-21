#!/bin/bash
# DID SSO Server Startup Script

echo "🔐 DID SSO Server - Starting up..."
echo "=================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo "❌ main.py not found. Please run this script from the project root directory."
    exit 1
fi

# Create storage directories if they don't exist
mkdir -p encrypted_storage
mkdir -p logs

# Set environment variables from config file if it exists
if [ -f ".env" ]; then
    echo "📁 Loading configuration from .env file..."
    set -a
    source .env
    set +a
else
    echo "⚠️  No .env file found. Using default configuration."
    echo "   Copy config.env to .env and modify for production use."
fi

# Set default values if not provided
export SECRET_KEY=${SECRET_KEY:-"change-this-secret-key-in-production"}
export MASTER_KEY=${MASTER_KEY:-"change-this-master-encryption-key-in-production"}
export HOST=${HOST:-"0.0.0.0"}
export PORT=${PORT:-"8000"}

# Check if dependencies are installed
echo "🔍 Checking dependencies..."
python3 -c "
import sys
required_modules = ['cryptography', 'pydantic', 'jwt']
missing = []

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing.append(module)

if missing:
    print(f'❌ Missing required modules: {missing}')
    print('   Install with: pip install -r requirements.txt')
    sys.exit(1)
else:
    print('✅ Core dependencies available')
"

if [ $? -ne 0 ]; then
    exit 1
fi

# Test core functionality
echo "🧪 Testing core systems..."
python3 -c "
from crypto_fs import EncryptedFileSystem
from permissions import PermissionManager
print('✅ All core modules load successfully')
"

if [ $? -ne 0 ]; then
    echo "❌ Core system test failed"
    exit 1
fi

echo ""
echo "🚀 Starting DID SSO Server..."
echo "   Host: $HOST"
echo "   Port: $PORT" 
echo "   Storage: encrypted_storage/"
echo "   Permissions: permissions.json"
echo ""
echo "🔗 Once started, access the API at: http://$HOST:$PORT"
echo "📚 API documentation available at: http://$HOST:$PORT/docs"
echo ""
echo "🛠️  Use the admin CLI: ./sso_admin.py --help"
echo "📖 Run demo: python3 demo.py"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=================================="

# Start the server
exec python3 main.py