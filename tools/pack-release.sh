#!/bin/bash
# =============================================================================
# Vigilant Sensor — Release Packager
# Usage: ./tools/pack-release.sh <VERSION>
# Example: ./tools/pack-release.sh 2.0.1
# Output: dist/sensor-pack-v2.0.1.tar.gz + dist/sensor-pack-v2.0.1.tar.gz.sha256
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <VERSION>"
    echo "Example: $0 2.0.1"
    exit 1
fi

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[ERROR] Version must be in format X.Y.Z (e.g., 2.0.1)"
    exit 1
fi

DIST_DIR="${REPO_ROOT}/dist"
PACKAGE_NAME="sensor-pack-v${VERSION}"
PACKAGE_FILE="${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
SHA256_FILE="${DIST_DIR}/${PACKAGE_NAME}.tar.gz.sha256"
STAGING_DIR="${DIST_DIR}/${PACKAGE_NAME}"

echo "========================================================"
echo "  Vigilant Sensor — Release Packager"
echo "  Version: v${VERSION}"
echo "========================================================"
echo ""

# Check source directories exist
if [[ ! -d "${REPO_ROOT}/sensor/scripts" ]]; then
    echo "[ERROR] sensor/scripts/ directory not found."
    exit 1
fi

# Create dist and staging dirs
mkdir -p "$DIST_DIR"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

echo "[1/5] Copying sensor scripts..."
cp -r "${REPO_ROOT}/sensor/scripts/." "${STAGING_DIR}/scripts/"
find "${STAGING_DIR}/scripts" -name "*.sh" -exec chmod +x {} \;
echo "[OK] scripts/ copied ($(find "${STAGING_DIR}/scripts" -name "*.sh" | wc -l | tr -d ' ') files)"

echo "[2/5] Copying configs..."
mkdir -p "${STAGING_DIR}/configs"
if [[ -d "${REPO_ROOT}/sensor/configs" ]] && [[ -n "$(ls -A "${REPO_ROOT}/sensor/configs" 2>/dev/null)" ]]; then
    cp -r "${REPO_ROOT}/sensor/configs/." "${STAGING_DIR}/configs/"
    echo "[OK] configs/ copied"
else
    echo "[INFO] configs/ is empty — skipping"
fi

echo "[3/4] Copying post-install.sh, custom-deploy.sh e updater..."
if [[ -f "${REPO_ROOT}/sensor/post-install.sh" ]]; then
    cp "${REPO_ROOT}/sensor/post-install.sh" "${STAGING_DIR}/post-install.sh"
    chmod +x "${STAGING_DIR}/post-install.sh"
    echo "[OK] post-install.sh included"
else
    echo "[WARN] sensor/post-install.sh not found — package will have no deployment logic"
fi
if [[ -f "${REPO_ROOT}/sensor/custom-deploy.sh" ]]; then
    cp "${REPO_ROOT}/sensor/custom-deploy.sh" "${STAGING_DIR}/custom-deploy.sh"
    chmod +x "${STAGING_DIR}/custom-deploy.sh"
    echo "[OK] custom-deploy.sh included"
fi
if [[ -f "${REPO_ROOT}/updater/rsyslog-sensor.conf" ]]; then
    cp "${REPO_ROOT}/updater/rsyslog-sensor.conf" "${STAGING_DIR}/rsyslog-sensor.conf"
    echo "[OK] rsyslog-sensor.conf included"
fi
# Inclui o proprio script do updater para habilitar auto-atualizacao
if [[ -f "${REPO_ROOT}/updater/vigilant-updater.sh" ]]; then
    mkdir -p "${STAGING_DIR}/updater"
    cp "${REPO_ROOT}/updater/vigilant-updater.sh" "${STAGING_DIR}/updater/vigilant-updater.sh"
    chmod +x "${STAGING_DIR}/updater/vigilant-updater.sh"
    echo "[OK] vigilant-updater.sh included (self-update)"
fi

echo "[4/4] Writing VERSION file..."
echo "$VERSION" > "${STAGING_DIR}/VERSION"
echo "[OK] VERSION = ${VERSION}"

echo "[5/5] Creating tar.gz..."
tar -czf "$PACKAGE_FILE" -C "$STAGING_DIR" .
rm -rf "$STAGING_DIR"

# Generate SHA256
sha256sum "$PACKAGE_FILE" | awk '{print $1}' > "$SHA256_FILE"
HASH=$(cat "$SHA256_FILE")

echo ""
echo "========================================================"
echo "  Package ready:"
echo "    ${PACKAGE_FILE}"
echo "    SHA256: ${HASH}"
echo ""
echo "  Next: run tools/sign-release.sh ${VERSION} ${PACKAGE_FILE}"
echo "========================================================"
