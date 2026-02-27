#!/bin/bash
# =============================================================================
# Vigilant Sensor — Release Signer & Publisher
# Usage: ./tools/sign-release.sh <VERSION> [PACKAGE_FILE]
# Example: ./tools/sign-release.sh 2.0.1
#          ./tools/sign-release.sh 2.0.1 dist/sensor-pack-v2.0.1.tar.gz
#
# Requirements:
#   - GPG key for updater@vigilant.com.br must be in your keyring
#   - GitHub CLI (gh) installed and authenticated
#   - GITHUB_REPO environment variable set, or edit GITHUB_REPO below
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# --- Configuration ---
# Set your GitHub repo here or export GITHUB_REPO before running
GITHUB_REPO="${GITHUB_REPO:-ORG/vigilant-sensor-updater}"
GPG_EMAIL="updater@vigilant.com.br"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <VERSION> [PACKAGE_FILE]"
    echo "Example: $0 2.0.1"
    exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[ERROR] Version must be in format X.Y.Z"
    exit 1
fi

PACKAGE_FILE="${2:-${REPO_ROOT}/dist/sensor-pack-v${VERSION}.tar.gz}"
SHA256_FILE="${PACKAGE_FILE%.tar.gz}.tar.gz.sha256"
SIG_FILE="${PACKAGE_FILE}.sig"

echo "========================================================"
echo "  Vigilant Sensor — Release Signer"
echo "  Version : v${VERSION}"
echo "  Package : ${PACKAGE_FILE}"
echo "  Repo    : ${GITHUB_REPO}"
echo "========================================================"
echo ""

# --- Verify package exists ---
if [[ ! -f "$PACKAGE_FILE" ]]; then
    echo "[ERROR] Package not found: ${PACKAGE_FILE}"
    echo "Run tools/pack-release.sh ${VERSION} first."
    exit 1
fi

# --- Check GPG key available ---
if ! gpg --list-secret-keys "$GPG_EMAIL" &>/dev/null; then
    echo "[ERROR] GPG private key not found for: ${GPG_EMAIL}"
    echo "Run tools/generate-gpg-key.sh first."
    exit 1
fi

# --- Check GitHub CLI ---
if ! command -v gh &>/dev/null; then
    echo "[ERROR] GitHub CLI (gh) not installed."
    echo "Install: https://cli.github.com"
    exit 1
fi

# --- Sign package ---
echo "[1/4] Signing package with GPG..."
gpg --batch --yes \
    --local-user "$GPG_EMAIL" \
    --detach-sign --armor \
    --output "$SIG_FILE" \
    "$PACKAGE_FILE"
echo "[OK] Signature: ${SIG_FILE}"

# --- Read SHA256 ---
if [[ ! -f "$SHA256_FILE" ]]; then
    sha256sum "$PACKAGE_FILE" | awk '{print $1}' > "$SHA256_FILE"
fi
HASH=$(cat "$SHA256_FILE")
echo "[OK] SHA256: ${HASH}"

# --- Update manifest.json ---
echo "[2/4] Updating manifest.json..."
MANIFEST_FILE="${REPO_ROOT}/manifest.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}"
PACKAGE_BASENAME="sensor-pack.tar.gz"

cat > "$MANIFEST_FILE" <<EOF
{
  "version": "${VERSION}",
  "released_at": "${TIMESTAMP}",
  "download_url": "${BASE_URL}/${PACKAGE_BASENAME}",
  "sha256": "${HASH}",
  "gpg_sig_url": "${BASE_URL}/${PACKAGE_BASENAME}.sig",
  "min_supported_version": "2.0.0",
  "rollback_safe": true,
  "changelog": "Release v${VERSION}"
}
EOF
echo "[OK] manifest.json updated."

# --- Commit manifest ---
echo "[3/4] Committing manifest.json..."
cd "$REPO_ROOT"
git add manifest.json
git commit -m "release: bump manifest to v${VERSION}" --no-verify 2>/dev/null || \
    echo "[INFO] No changes to commit in manifest.json"

# --- Create GitHub Release ---
echo "[4/4] Creating GitHub Release v${VERSION}..."

# Rename package to generic name for release (sensors always download "sensor-pack.tar.gz")
GENERIC_PACKAGE="${REPO_ROOT}/dist/sensor-pack.tar.gz"
GENERIC_SIG="${REPO_ROOT}/dist/sensor-pack.tar.gz.sig"
GENERIC_SHA="${REPO_ROOT}/dist/sensor-pack.tar.gz.sha256"

cp "$PACKAGE_FILE" "$GENERIC_PACKAGE"
cp "$SIG_FILE" "$GENERIC_SIG"
echo "$HASH" > "$GENERIC_SHA"

gh release create "v${VERSION}" \
    --repo "$GITHUB_REPO" \
    --title "v${VERSION}" \
    --notes "Release v${VERSION} — $(date -u +"%Y-%m-%d")" \
    "$GENERIC_PACKAGE" \
    "$GENERIC_SIG" \
    "$GENERIC_SHA"

echo ""
echo "========================================================"
echo "  Release v${VERSION} published successfully!"
echo ""
echo "  Assets:"
echo "    sensor-pack.tar.gz"
echo "    sensor-pack.tar.gz.sig"
echo "    sensor-pack.tar.gz.sha256"
echo ""
echo "  SHA256  : ${HASH}"
echo "  URL     : https://github.com/${GITHUB_REPO}/releases/tag/v${VERSION}"
echo "========================================================"
