#!/usr/bin/env bash
# compile.sh - Build my_proxy into a standalone binary using PyInstaller

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLIENT_DIR="$PROJECT_ROOT/my_proxy_client"

cd "$CLIENT_DIR"

echo "=== Building my_proxy standalone binary ==="

# Check if pyinstaller is available
if ! command -v pyinstaller &> /dev/null; then
    echo "PyInstaller not found. Installing..."
    pip install pyinstaller
fi

# Clean previous builds
rm -rf build dist *.spec

# Build the binary
# --onefile: single executable
# --name: output binary name
# --clean: clean cache before building
# --noconfirm: overwrite without asking
# --strip: strip debug symbols (smaller binary)
# --upx-dir: use UPX if available (smaller binary)
# --hidden-import: ensure all modules are included
# --add-data: include protocol if needed (but it's inline in my_proxy.py)

echo "Building with PyInstaller..."
pyinstaller \
    --onefile \
    --name my_proxy \
    --clean \
    --noconfirm \
    --strip \
    --hidden-import=asyncio \
    --hidden-import=json \
    --hidden-import=logging \
    --hidden-import=argparse \
    --hidden-import=dataclasses \
    --hidden-import=enum \
    --hidden-import=hashlib \
    --hidden-import=hmac \
    --hidden-import=secrets \
    --hidden-import=struct \
    --hidden-import=uuid \
    --hidden-import=collections \
    --hidden-import=pathlib \
    --hidden-import=signal \
    --hidden-import=typing \
    my_proxy.py

echo ""
echo "=== Build complete ==="
echo "Binary location: $CLIENT_DIR/dist/my_proxy"
echo ""
echo "Test the binary:"
echo "  $CLIENT_DIR/dist/my_proxy --help"
echo "  $CLIENT_DIR/dist/my_proxy authtoken YOUR_TOKEN"
echo "  $CLIENT_DIR/dist/my_proxy server proxy.example.com:9000"
echo "  $CLIENT_DIR/dist/my_proxy http 8080"