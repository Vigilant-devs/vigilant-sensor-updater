#!/bin/bash
# =============================================================================
# Vigilant Sensor — Post-Install Deployment Script
# Version: included in sensor-pack.tar.gz (versioned with each release)
#
# Called by vigilant-updater.sh after package extraction.
# Deploys scripts and configs from the versioned release directory
# to their final system locations on the sensor.
#
# Usage (called by updater, not manually):
#   ./post-install.sh <RELEASE_DIR> <DEPLOY_ROOT>
#
# Arguments:
#   RELEASE_DIR  — full path to extracted release (e.g. .../releases/v2.0.1)
#   DEPLOY_ROOT  — base deploy path (default: /vigilant)
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

RELEASE_DIR="${1:-}"
DEPLOY_ROOT="${2:-/vigilant}"

if [[ -z "$RELEASE_DIR" || ! -d "$RELEASE_DIR" ]]; then
    echo "[post-install][ERROR] RELEASE_DIR not specified or not found: '${RELEASE_DIR}'" >&2
    exit 1
fi

# Logging
log()  { echo "[post-install][INFO]  $*" >&2; }
warn() { echo "[post-install][WARN]  $*" >&2; }
err()  { echo "[post-install][ERROR] $*" >&2; }

log "============================================"
log "Release dir : ${RELEASE_DIR}"
log "Deploy root : ${DEPLOY_ROOT}"
log "============================================"

ERRORS=0

# =============================================================================
# SECTION 1: Scripts → /vigilant/scripts/
# =============================================================================
SCRIPTS_SRC="${RELEASE_DIR}/scripts"
SCRIPTS_DST="${DEPLOY_ROOT}/scripts"

if [[ -d "$SCRIPTS_SRC" ]] && [[ -n "$(ls -A "$SCRIPTS_SRC" 2>/dev/null)" ]]; then
    log "Deploying scripts: ${SCRIPTS_SRC} → ${SCRIPTS_DST}"
    mkdir -p "$SCRIPTS_DST"

    # Copy all files, preserving structure
    if cp -a "${SCRIPTS_SRC}/." "${SCRIPTS_DST}/"; then
        # Ensure all .sh files are executable
        find "$SCRIPTS_DST" -name "*.sh" -exec chmod +x {} \;
        COUNT=$(find "${SCRIPTS_SRC}" -type f | wc -l | tr -d ' ')
        log "Scripts deployed: ${COUNT} file(s)"
    else
        err "Failed to copy scripts to ${SCRIPTS_DST}"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "No scripts to deploy (scripts/ empty or missing)"
fi

# =============================================================================
# SECTION 2: Configs — dispatched per service
# Convention: configs/<service>/ → system path
#
# configs/snort/    → /etc/snort/
# configs/dionaea/  → /etc/dionaea/
# configs/cowrie/   → /etc/cowrie/
# configs/bettercap/→ /etc/bettercap/
# configs/exabgp/   → /etc/exabgp/
# =============================================================================

deploy_config() {
    local name="$1"     # service name (for logging)
    local src="$2"      # source directory
    local dst="$3"      # destination directory

    if [[ ! -d "$src" ]] || [[ -z "$(ls -A "$src" 2>/dev/null)" ]]; then
        log "No ${name} configs to deploy (${src} empty or missing)"
        return 0
    fi

    log "Deploying ${name} configs: ${src} → ${dst}"
    mkdir -p "$dst"

    if cp -a "${src}/." "${dst}/"; then
        COUNT=$(find "$src" -type f | wc -l | tr -d ' ')
        log "${name} configs deployed: ${COUNT} file(s)"
    else
        err "Failed to copy ${name} configs to ${dst}"
        ERRORS=$((ERRORS + 1))
    fi
}

CONFIGS_SRC="${RELEASE_DIR}/configs"

if [[ -d "$CONFIGS_SRC" ]]; then
    deploy_config "snort"     "${CONFIGS_SRC}/snort"     "/etc/snort"
    deploy_config "dionaea"   "${CONFIGS_SRC}/dionaea"   "/etc/dionaea"
    deploy_config "cowrie"    "${CONFIGS_SRC}/cowrie"    "/etc/cowrie"
    deploy_config "bettercap" "${CONFIGS_SRC}/bettercap" "/etc/bettercap"
    deploy_config "exabgp"    "${CONFIGS_SRC}/exabgp"    "/etc/exabgp"
else
    log "No configs/ directory in release — skipping config deployment"
fi

# =============================================================================
# SECTION 3: Custom hooks (optional)
# If the package includes a custom-deploy.sh, run it for any non-standard
# deployment logic specific to this release.
# =============================================================================

CUSTOM_HOOK="${RELEASE_DIR}/custom-deploy.sh"
if [[ -f "$CUSTOM_HOOK" ]]; then
    log "Running custom deploy hook: ${CUSTOM_HOOK}"
    chmod +x "$CUSTOM_HOOK"
    if bash "$CUSTOM_HOOK" "$RELEASE_DIR" "$DEPLOY_ROOT"; then
        log "Custom deploy hook completed successfully"
    else
        err "Custom deploy hook failed"
        ERRORS=$((ERRORS + 1))
    fi
fi

# =============================================================================
# RESULT
# =============================================================================

if [[ $ERRORS -gt 0 ]]; then
    err "Post-install completed with ${ERRORS} error(s)"
    exit 1
fi

log "Post-install completed successfully"
exit 0
