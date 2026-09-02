#!/usr/bin/env bash
set -euo pipefail

# ---- Configuration ---------------------------------------------------------
NAME="bfguard"
VERSION="1.0.1"
ARCH="amd64"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
STAGE_DIR="${BUILD_DIR}/${NAME}_${VERSION}_${ARCH}"
OUTPUT_DEB="${BUILD_DIR}/${NAME}_${VERSION}_${ARCH}.deb"
PACKAGING_DIR="${ROOT_DIR}/packaging"
DEFAULTS_DIR="${ROOT_DIR}/defaults"

# ---- Clean previous build --------------------------------------------------
echo "==> Cleaning previous build"
rm -rf "${BUILD_DIR}"
mkdir -p "${STAGE_DIR}"

# ---- Stage default file tree (etc, usr, var) -------------------------------
echo "==> Staging default file tree"
if [ -d "${DEFAULTS_DIR}" ]; then
    cp -a "${DEFAULTS_DIR}/." "${STAGE_DIR}/"
fi

# ---- Build the binary (statically linked) ----------------------------------
echo "==> Building ${NAME} binary (static)"
mkdir -p "${STAGE_DIR}/usr/bin"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${STAGE_DIR}/usr/bin/${NAME}" .

# ---- Stage Debian control files --------------------------------------------
echo "==> Staging Debian control files"
cp -a "${PACKAGING_DIR}/DEBIAN" "${STAGE_DIR}/DEBIAN"

# ---- Fix permissions -------------------------------------------------------
chmod 755 "${STAGE_DIR}/DEBIAN/postinst" \
          "${STAGE_DIR}/DEBIAN/prerm" \
          "${STAGE_DIR}/DEBIAN/postrm" \
          "${STAGE_DIR}/usr/bin/${NAME}"

# ---- Build the .deb package ------------------------------------------------
echo "==> Building .deb package"
dpkg-deb --build --root-owner-group "${STAGE_DIR}" "${OUTPUT_DEB}"

echo "==> Done: ${OUTPUT_DEB}"
