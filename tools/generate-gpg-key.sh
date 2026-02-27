#!/bin/bash
# =============================================================================
# Vigilant Sensor — GPG Key Pair Generator (one-time setup)
# Run this ONCE locally to generate the signing key pair.
# The private key goes to GitHub Secrets. The public key goes into the repo.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
UPDATER_DIR="${REPO_ROOT}/updater"

KEY_NAME="Vigilant Sensor Updater"
KEY_EMAIL="updater@vigilant.com.br"
KEY_TYPE="RSA"
KEY_LENGTH="4096"
KEY_EXPIRE="2y"

PRIVATE_KEY_FILE="${SCRIPT_DIR}/vigilant-private.key.asc"
PUBLIC_KEY_FILE="${UPDATER_DIR}/vigilant.pub.gpg"

echo "========================================================"
echo "  Vigilant Sensor — GPG Key Pair Generator"
echo "========================================================"
echo ""
echo "  Name   : ${KEY_NAME}"
echo "  Email  : ${KEY_EMAIL}"
echo "  Type   : ${KEY_TYPE} ${KEY_LENGTH}"
echo "  Expiry : ${KEY_EXPIRE}"
echo ""

# Check for existing key to avoid duplicates
EXISTING=$(gpg --list-secret-keys "$KEY_EMAIL" 2>/dev/null | grep -c "sec" || true)
if [[ "$EXISTING" -gt 0 ]]; then
    echo "[WARN] A key for ${KEY_EMAIL} already exists in your keyring."
    read -rp "Overwrite? (y/N): " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo "Aborted."
        exit 0
    fi
    gpg --batch --yes --delete-secret-and-public-key \
        "$(gpg --list-keys --with-colons "$KEY_EMAIL" 2>/dev/null | awk -F: '/^pub/{print $5}' | head -1)" 2>/dev/null || true
fi

# --- Generate key non-interactively ---
echo "[1/4] Generating RSA ${KEY_LENGTH} key pair..."

gpg --batch --gen-key <<EOF
%no-protection
Key-Type: ${KEY_TYPE}
Key-Length: ${KEY_LENGTH}
Key-Usage: sign
Name-Real: ${KEY_NAME}
Name-Email: ${KEY_EMAIL}
Expire-Date: ${KEY_EXPIRE}
%commit
EOF

echo "[OK] Key generated."

# --- Get fingerprint ---
FINGERPRINT=$(gpg --list-keys --with-colons "$KEY_EMAIL" 2>/dev/null \
    | awk -F: '/^fpr/{print $10; exit}')

echo ""
echo "  Fingerprint: ${FINGERPRINT}"
echo ""

# --- Export public key ---
echo "[2/4] Exporting public key → ${PUBLIC_KEY_FILE}"
mkdir -p "$UPDATER_DIR"
gpg --armor --export "$KEY_EMAIL" > "$PUBLIC_KEY_FILE"
echo "[OK] Public key exported."

# --- Export private key (armored) ---
echo "[3/4] Exporting private key → ${PRIVATE_KEY_FILE}"
gpg --armor --export-secret-keys "$KEY_EMAIL" > "$PRIVATE_KEY_FILE"
chmod 600 "$PRIVATE_KEY_FILE"
echo "[OK] Private key exported (chmod 600)."

# --- Instructions ---
echo ""
echo "========================================================"
echo "  NEXT STEPS"
echo "========================================================"
echo ""
echo "  1. Add private key to GitHub Secrets:"
echo "     Secret name : GPG_PRIVATE_KEY"
echo "     Secret value: contents of tools/vigilant-private.key.asc"
echo ""
echo "  2. Add GPG passphrase to GitHub Secrets:"
echo "     Secret name : GPG_PASSPHRASE"
echo "     Secret value: (leave empty if you used %no-protection above)"
echo ""
echo "  3. The public key is already at:"
echo "     ${PUBLIC_KEY_FILE}"
echo "     → Commit it to the repository (it is safe to be public)"
echo ""
echo "  4. NEVER commit the private key (tools/*.asc is in .gitignore)"
echo ""
echo "  5. Store the private key file securely (password manager, etc.)"
echo ""
echo "  Fingerprint: ${FINGERPRINT}"
echo "========================================================"
