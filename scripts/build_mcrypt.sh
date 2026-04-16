#!/usr/bin/env bash
# Build libmcrypt 2.5.8 from source.
# Produces lib/mcrypt/ with headers and shared library.
#
# Usage: ./scripts/build_mcrypt.sh
#
# Requires: curl, tar, make, a C compiler (cc / gcc / clang)

set -euo pipefail

VERSION="2.5.8"
SHA256="e4eb6c074bbab168ac47b947c195ff8cef9d51a211cdd18ca9c9ef34d27a373e"
URL="https://sourceforge.net/projects/mcrypt/files/Libmcrypt/${VERSION}/libmcrypt-${VERSION}.tar.gz/download"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT}/.build/libmcrypt-${VERSION}"
INSTALL_DIR="${ROOT}/lib/mcrypt"

if [ -f "${INSTALL_DIR}/lib/libmcrypt.dylib" ] || [ -f "${INSTALL_DIR}/lib/libmcrypt.so" ]; then
    echo "[build_mcrypt] libmcrypt already built at ${INSTALL_DIR}"
    exit 0
fi

echo "[build_mcrypt] Downloading libmcrypt ${VERSION}..."
mkdir -p "${ROOT}/.build"
TARBALL="${ROOT}/.build/libmcrypt-${VERSION}.tar.gz"

if [ ! -f "${TARBALL}" ]; then
    curl -fSL -o "${TARBALL}" "${URL}"
fi

# Verify checksum
echo "[build_mcrypt] Verifying checksum..."
if command -v shasum &>/dev/null; then
    ACTUAL=$(shasum -a 256 "${TARBALL}" | awk '{print $1}')
elif command -v sha256sum &>/dev/null; then
    ACTUAL=$(sha256sum "${TARBALL}" | awk '{print $1}')
else
    echo "[build_mcrypt] WARNING: no sha256 tool found, skipping checksum"
    ACTUAL="${SHA256}"
fi

if [ "${ACTUAL}" != "${SHA256}" ]; then
    echo "[build_mcrypt] ERROR: checksum mismatch"
    echo "  expected: ${SHA256}"
    echo "  actual:   ${ACTUAL}"
    rm -f "${TARBALL}"
    exit 1
fi

echo "[build_mcrypt] Extracting..."
cd "${ROOT}/.build"
tar xzf "${TARBALL}"

echo "[build_mcrypt] Patching for modern systems..."
cd "${BUILD_DIR}"

# Replace ancient config.sub/config.guess that don't know about ARM64 macOS
curl -fSL -o config.sub 'https://git.savannah.gnu.org/cgit/config.git/plain/config.sub'
curl -fSL -o config.guess 'https://git.savannah.gnu.org/cgit/config.git/plain/config.guess'
chmod +x config.sub config.guess

echo "[build_mcrypt] Configuring..."

# Fix implicit-int and implicit-function-declaration errors on modern compilers
export CFLAGS="-O2 -Wno-implicit-function-declaration -Wno-incompatible-pointer-types -Wno-implicit-int"

./configure --prefix="${INSTALL_DIR}" --disable-static --enable-shared

echo "[build_mcrypt] Building..."
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

echo "[build_mcrypt] Installing..."
make install

echo "[build_mcrypt] Done. Library installed to ${INSTALL_DIR}"
echo "  Headers: ${INSTALL_DIR}/include/"
echo "  Library: ${INSTALL_DIR}/lib/"
ls -la "${INSTALL_DIR}/lib/"libmcrypt*
