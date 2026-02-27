#!/bin/bash
# =============================================================================
# Vigilant Sensor — Remote Updater Daemon
# Version: 1.0.0
# Team: P&D — Vigilant Labs
# Deploy path on sensor: /vigilant/scripts/vigilantsensor/updater/
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_DIR="/vigilant/scripts/vigilantsensor"
UPDATER_DIR="${BASE_DIR}/updater"
RELEASES_DIR="${BASE_DIR}/releases"
LOGS_DIR="${BASE_DIR}/logs"
LOG_FILE="${LOGS_DIR}/vigilant-update.log"

VERSION_FILE="${UPDATER_DIR}/VERSION"
GPG_PUBKEY_FILE="${UPDATER_DIR}/vigilant.pub.gpg"
TOKEN_FILE="${UPDATER_DIR}/.gh-token"

# Manifest URL — raw GitHub (repo public) ou com token (repo private)
# Organização GitHub: Vigilant-devs
MANIFEST_URL="https://raw.githubusercontent.com/Vigilant-devs/vigilant-sensor-updater/main/manifest.json"

# Status reporting endpoint
STATUS_URL="http://177.190.148.68:80/api/sensor/update-status"

# Services to restart and health-check after update
SERVICES=("snort" "dionaea" "cowrie-ssh" "cowrie-telnet")

# Curl options
CURL_TIMEOUT=15
CURL_RETRIES=3

# Sensor identity
SENSOR_ID_FILE="/vigilant/scripts/sensor_id"

# =============================================================================
# HELPERS
# =============================================================================

# Sensor ID: read from file or fall back to hostname
get_sensor_id() {
    if [[ -f "$SENSOR_ID_FILE" ]]; then
        cat "$SENSOR_ID_FILE"
    else
        hostname
    fi
}

# Current installed version
get_local_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        tr -d '[:space:]' < "$VERSION_FILE"
    else
        echo "0.0.0"
    fi
}

# Write JSON event to local log file
update_log() {
    local event="$1"
    local version_from="${2:-}"
    local version_to="${3:-}"
    local details="${4:-}"
    local rollback="${5:-false}"

    mkdir -p "$LOGS_DIR"
    printf '{"timestamp":"%s","hostname":"%s","sensor_id":"%s","event":"%s","version_from":"%s","version_to":"%s","rollback":%s,"details":"%s"}\n' \
        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        "$(hostname)" \
        "$(get_sensor_id)" \
        "$event" \
        "$version_from" \
        "$version_to" \
        "$rollback" \
        "$details" >> "$LOG_FILE"
}

# HTTP POST status to central server; rsyslog fallback on failure
report_status() {
    local event="$1"
    local version_from="${2:-}"
    local version_to="${3:-}"
    local rollback="${4:-false}"
    local details="${5:-}"

    local payload
    payload=$(printf '{"sensor_id":"%s","hostname":"%s","event":"%s","version_from":"%s","version_to":"%s","timestamp":"%s","rollback":%s,"details":"%s"}' \
        "$(get_sensor_id)" \
        "$(hostname)" \
        "$event" \
        "$version_from" \
        "$version_to" \
        "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        "$rollback" \
        "$details")

    if curl -s --max-time 10 \
            -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "$STATUS_URL" > /dev/null 2>&1; then
        update_log "report_sent" "$version_from" "$version_to" "HTTP OK" "$rollback"
    else
        # Fallback: rsyslog via VPN
        logger -p local0.info -t "vigilant-updater" \
            "event=$event sensor=$(get_sensor_id) hostname=$(hostname) v_from=$version_from v_to=$version_to rollback=$rollback details=$details"
        update_log "report_fallback_rsyslog" "$version_from" "$version_to" "HTTP failed, sent via rsyslog" "$rollback"
    fi
}

# Remove temp download dir on exit
cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# =============================================================================
# PHASE 1: FETCH MANIFEST
# =============================================================================

fetch_manifest() {
    local url="$1"
    local output="$2"
    local auth_header=""

    # Use GitHub token if available (private repo phase)
    if [[ -f "$TOKEN_FILE" ]]; then
        local token
        token=$(cat "$TOKEN_FILE")
        auth_header="-H \"Authorization: token ${token}\""
    fi

    local attempt=1
    while [[ $attempt -le $CURL_RETRIES ]]; do
        update_log "fetch_attempt" "" "" "Attempt ${attempt} — ${url}"

        # Add cache-busting timestamp to bypass GitHub CDN cache
        local bust_url="${url}?t=$(date +%s)"

        if [[ -n "$auth_header" ]]; then
            if curl -sf --max-time "$CURL_TIMEOUT" \
                    -H "Authorization: token $(cat "$TOKEN_FILE")" \
                    "$bust_url" -o "$output" 2>/dev/null; then
                return 0
            fi
        else
            if curl -sf --max-time "$CURL_TIMEOUT" \
                    "$bust_url" -o "$output" 2>/dev/null; then
                return 0
            fi
        fi

        attempt=$((attempt + 1))
        sleep 5
    done

    return 1
}

# =============================================================================
# PHASE 2: COMPARE VERSIONS (semver: MAJOR.MINOR.PATCH)
# =============================================================================

version_gt() {
    # Returns 0 (true) if $1 > $2
    local v1="$1" v2="$2"
    if [[ "$v1" == "$v2" ]]; then return 1; fi

    local IFS=.
    read -ra A <<< "$v1"
    read -ra B <<< "$v2"

    for i in 0 1 2; do
        local a="${A[$i]:-0}" b="${B[$i]:-0}"
        if (( 10#$a > 10#$b )); then return 0; fi
        if (( 10#$a < 10#$b )); then return 1; fi
    done
    return 1
}

# =============================================================================
# PHASE 3: DOWNLOAD PACKAGE
# =============================================================================

download_package() {
    local url="$1"
    local output="$2"

    local attempt=1
    while [[ $attempt -le $CURL_RETRIES ]]; do
        update_log "download_attempt" "" "" "Attempt ${attempt} — $(basename "$url")"

        if [[ -f "$TOKEN_FILE" ]]; then
            local token
            token=$(cat "$TOKEN_FILE")

            # Private repo: resolve asset via GitHub API, then download with Accept header
            # URL format: https://github.com/OWNER/REPO/releases/download/TAG/FILE
            if [[ "$url" =~ github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/(.+) ]]; then
                local repo="${BASH_REMATCH[1]}"
                local tag="${BASH_REMATCH[2]}"
                local filename="${BASH_REMATCH[3]}"

                local asset_api_url
                asset_api_url=$(curl -sf --max-time 15 \
                    -H "Authorization: token ${token}" \
                    "https://api.github.com/repos/${repo}/releases/tags/${tag}" \
                    | jq -r ".assets[] | select(.name == \"${filename}\") | .url" 2>/dev/null)

                if [[ -n "$asset_api_url" ]]; then
                    if curl -Lf --max-time 120 \
                            -H "Authorization: token ${token}" \
                            -H "Accept: application/octet-stream" \
                            "$asset_api_url" -o "$output" 2>/dev/null; then
                        return 0
                    fi
                fi
            fi
        else
            # Public repo: direct download
            if curl -Lf --max-time 120 "$url" -o "$output" 2>/dev/null; then
                return 0
            fi
        fi

        attempt=$((attempt + 1))
        sleep 5
    done

    return 1
}

# =============================================================================
# PHASE 4: VERIFY INTEGRITY (SHA256 + GPG)
# =============================================================================

verify_integrity() {
    local package="$1"
    local sha256_file="$2"
    local sig_file="$3"
    local gpg_home="${TMP_DIR}/gnupg"

    # --- SHA256 ---
    update_log "verify_sha256" "" "" "Checking SHA256..."

    local expected_hash actual_hash
    expected_hash=$(awk '{print $1}' "$sha256_file")
    actual_hash=$(sha256sum "$package" | awk '{print $1}')

    if [[ "$expected_hash" != "$actual_hash" ]]; then
        update_log "verify_failed" "" "" "SHA256 mismatch: expected=${expected_hash} got=${actual_hash}"
        return 1
    fi
    update_log "verify_sha256_ok" "" "" "SHA256 match: ${actual_hash}"

    # --- GPG ---
    update_log "verify_gpg" "" "" "Checking GPG signature..."

    if [[ ! -f "$GPG_PUBKEY_FILE" ]]; then
        update_log "verify_failed" "" "" "Public GPG key not found: ${GPG_PUBKEY_FILE}"
        return 1
    fi

    mkdir -p "$gpg_home"
    chmod 700 "$gpg_home"

    # Import public key into isolated keyring
    if ! GNUPGHOME="$gpg_home" gpg --batch --import "$GPG_PUBKEY_FILE" 2>/dev/null; then
        update_log "verify_failed" "" "" "Failed to import GPG public key"
        return 1
    fi

    if ! GNUPGHOME="$gpg_home" gpg --batch --verify "$sig_file" "$package" 2>/dev/null; then
        update_log "verify_failed" "" "" "GPG signature verification FAILED — package rejected"
        return 1
    fi

    update_log "verify_gpg_ok" "" "" "GPG signature valid"
    return 0
}

# =============================================================================
# PHASE 5: ATOMIC INSTALL
# =============================================================================

atomic_install() {
    local package="$1"
    local new_version="$2"
    local prev_version="$3"

    local new_dir="${RELEASES_DIR}/${new_version}"
    local staging_link="${RELEASES_DIR}/new"
    local current_link="${RELEASES_DIR}/current"
    local previous_link="${RELEASES_DIR}/previous"

    # Create release directory
    mkdir -p "$new_dir"

    # Extract package
    update_log "extracting" "" "$new_version" "Extracting sensor-pack..."
    if ! tar -xzf "$package" -C "$new_dir" 2>/dev/null; then
        update_log "install_failed" "$prev_version" "$new_version" "Extraction failed"
        rm -rf "$new_dir"
        return 1
    fi
    update_log "extracted" "" "$new_version" "Extraction complete"

    # Make all .sh files executable
    find "$new_dir" -name "*.sh" -exec chmod +x {} \;

    # --- Atomic symlink swap ---
    # 1. Point staging link to new version
    ln -sfn "$new_dir" "$staging_link"

    # 2. Atomic rename of staging to current (mv -T is atomic on Linux)
    if ! mv -T "$staging_link" "$current_link" 2>/dev/null; then
        # Fallback for systems without mv -T (macOS, older Linux)
        ln -sfn "$new_dir" "$current_link"
    fi

    # 3. Update previous to old current
    if [[ -n "$prev_version" && "$prev_version" != "0.0.0" ]]; then
        local prev_dir="${RELEASES_DIR}/${prev_version}"
        if [[ -d "$prev_dir" ]]; then
            ln -sfn "$prev_dir" "$previous_link"
        fi
    fi

    # 4. Update VERSION file
    echo "$new_version" > "$VERSION_FILE"

    update_log "install_ok" "$prev_version" "$new_version" "Symlinks updated, VERSION written"
    return 0
}

# =============================================================================
# PHASE 5b: RESTART SERVICES
# =============================================================================

restart_services() {
    local version_from="$1"
    local version_to="$2"
    local failed_services=()

    for svc in "${SERVICES[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            update_log "restart_service" "$version_from" "$version_to" "Restarting: ${svc}"
            if ! systemctl restart "$svc" 2>/dev/null; then
                failed_services+=("$svc")
                update_log "restart_failed" "$version_from" "$version_to" "Failed to restart: ${svc}"
            fi
        fi
    done

    if [[ ${#failed_services[@]} -gt 0 ]]; then
        return 1
    fi
    return 0
}

# =============================================================================
# PHASE 6: HEALTH CHECK
# =============================================================================

check_services() {
    local version_from="$1"
    local version_to="$2"

    update_log "health_check_start" "$version_from" "$version_to" "Waiting 30s before health check..."
    sleep 30

    local failed_services=()
    for svc in "${SERVICES[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
                failed_services+=("$svc")
                update_log "health_check_fail" "$version_from" "$version_to" "Service not active: ${svc}"
            else
                update_log "health_check_ok" "$version_from" "$version_to" "Service OK: ${svc}"
            fi
        fi
    done

    if [[ ${#failed_services[@]} -gt 0 ]]; then
        return 1
    fi
    return 0
}

# =============================================================================
# PHASE 7: ROLLBACK
# =============================================================================

rollback() {
    local version_from="$1"
    local version_to="$2"
    local reason="$3"

    local current_link="${RELEASES_DIR}/current"
    local previous_link="${RELEASES_DIR}/previous"

    update_log "rollback_start" "$version_from" "$version_to" "Reason: ${reason}" "true"

    if [[ ! -L "$previous_link" ]]; then
        update_log "rollback_failed" "$version_from" "$version_to" "No previous version available for rollback" "true"
        report_status "rollback_failed" "$version_from" "$version_to" "true" "No previous version"
        logger -p local0.crit -t "vigilant-updater" \
            "CRITICAL: Rollback failed — no previous version. Sensor may be broken. sensor=$(get_sensor_id)"
        return 1
    fi

    # Revert symlink
    local prev_target
    prev_target=$(readlink "$previous_link")
    ln -sfn "$prev_target" "$current_link"

    # Restore version file
    local prev_ver
    prev_ver=$(basename "$prev_target")
    echo "$prev_ver" > "$VERSION_FILE"

    # Restart services on previous version
    restart_services "$version_to" "$prev_ver" || true

    update_log "rollback_complete" "$version_from" "$version_to" "Reverted to: ${prev_ver}" "true"
    report_status "rollback" "$version_to" "$prev_ver" "true" "Health check failed: ${reason}"
    return 0
}

# =============================================================================
# MAIN FLOW
# =============================================================================

main() {
    mkdir -p "$LOGS_DIR" "$RELEASES_DIR"

    local local_version
    local_version=$(get_local_version)

    update_log "check_start" "$local_version" "" "Current version: ${local_version}"

    # --- PHASE 1: Fetch manifest ---
    TMP_DIR=$(mktemp -d /tmp/vigilant-update-XXXXXX)
    local manifest_file="${TMP_DIR}/manifest.json"

    if ! fetch_manifest "$MANIFEST_URL" "$manifest_file"; then
        update_log "fetch_failed" "$local_version" "" "Could not download manifest — skipping cycle"
        report_status "fetch_failed" "$local_version" "" "false" "Manifest download failed after ${CURL_RETRIES} attempts"
        exit 0
    fi

    # --- Parse manifest with jq ---
    if ! command -v jq &>/dev/null; then
        update_log "error" "$local_version" "" "jq not installed — cannot parse manifest"
        exit 1
    fi

    local remote_version download_url sha256 gpg_sig_url min_version rollback_safe changelog
    remote_version=$(jq -r '.version'              "$manifest_file")
    download_url=$(jq -r '.download_url'           "$manifest_file")
    sha256=$(jq -r '.sha256'                       "$manifest_file")
    gpg_sig_url=$(jq -r '.gpg_sig_url'             "$manifest_file")
    min_version=$(jq -r '.min_supported_version'   "$manifest_file")
    rollback_safe=$(jq -r '.rollback_safe'         "$manifest_file")
    changelog=$(jq -r '.changelog'                 "$manifest_file")

    # --- PHASE 2: Compare versions ---
    if ! version_gt "$remote_version" "$local_version"; then
        update_log "no_update" "$local_version" "$remote_version" "Already at latest version"
        report_status "no_update" "$local_version" "$remote_version" "false" "Up to date"
        exit 0
    fi

    # Check minimum supported version
    if version_gt "$min_version" "$local_version"; then
        update_log "version_incompatible" "$local_version" "$remote_version" \
            "Local version ${local_version} below minimum ${min_version} — manual intervention required"
        report_status "version_incompatible" "$local_version" "$remote_version" "false" \
            "Below min supported version: ${min_version}"
        exit 1
    fi

    update_log "update_available" "$local_version" "$remote_version" "Changelog: ${changelog}"
    report_status "update_started" "$local_version" "$remote_version" "false" "Starting update"

    # --- PHASE 3: Download package ---
    local package_file="${TMP_DIR}/sensor-pack.tar.gz"
    local sha256_file="${TMP_DIR}/sensor-pack.tar.gz.sha256"
    local sig_file="${TMP_DIR}/sensor-pack.tar.gz.sig"

    if ! download_package "$download_url" "$package_file"; then
        update_log "download_failed" "$local_version" "$remote_version" "Package download failed"
        report_status "download_failed" "$local_version" "$remote_version" "false" "Package download failed"
        exit 0
    fi

    # Write expected SHA256 for verification
    echo "${sha256}  ${package_file}" > "$sha256_file"

    if ! download_package "$gpg_sig_url" "$sig_file"; then
        update_log "download_failed" "$local_version" "$remote_version" "Signature download failed"
        report_status "download_failed" "$local_version" "$remote_version" "false" "Signature download failed"
        exit 0
    fi

    # --- PHASE 4: Verify integrity ---
    if ! verify_integrity "$package_file" "$sha256_file" "$sig_file"; then
        update_log "verify_failed" "$local_version" "$remote_version" "Integrity check failed — ABORTING"
        report_status "verify_failed" "$local_version" "$remote_version" "false" \
            "SHA256 or GPG verification failed — package rejected"
        exit 1
    fi

    # --- PHASE 5: Atomic install ---
    if ! atomic_install "$package_file" "$remote_version" "$local_version"; then
        update_log "install_failed" "$local_version" "$remote_version" "Installation failed"
        report_status "install_failed" "$local_version" "$remote_version" "false" "Install error"
        exit 1
    fi

    # --- PHASE 5b: Restart services ---
    restart_services "$local_version" "$remote_version" || true

    # --- PHASE 6: Health check ---
    if ! check_services "$local_version" "$remote_version"; then
        # --- PHASE 7: Rollback ---
        rollback "$local_version" "$remote_version" "Health check failed after update to ${remote_version}"
        exit 1
    fi

    # --- SUCCESS ---
    update_log "update_success" "$local_version" "$remote_version" "Update completed successfully"
    report_status "update_success" "$local_version" "$remote_version" "false" \
        "Updated from ${local_version} to ${remote_version}"

    # Clean old releases (keep current + previous only)
    find "$RELEASES_DIR" -maxdepth 1 -type d -name 'v*' | sort -V | head -n -2 | while read -r old_dir; do
        rm -rf "$old_dir"
        update_log "cleanup_old_release" "$local_version" "$remote_version" "Removed: $(basename "$old_dir")"
    done

    exit 0
}

main "$@"
