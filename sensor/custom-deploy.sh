#!/bin/bash
# =============================================================================
# Vigilant Sensor — Custom Deploy Hook
# Executado pelo post-install.sh para logica de deploy nao padrao.
# =============================================================================

set -euo pipefail

RELEASE_DIR="${1:-}"

# Atualizar config do rsyslog se incluida no pacote
RSYSLOG_SRC="${RELEASE_DIR}/rsyslog-sensor.conf"
RSYSLOG_DST="/etc/rsyslog.d/50-vigilant-updater.conf"

if [[ -f "$RSYSLOG_SRC" ]]; then
    cp "$RSYSLOG_SRC" "$RSYSLOG_DST"
    systemctl restart rsyslog 2>/dev/null || true
    echo "[custom-deploy] rsyslog config atualizado: ${RSYSLOG_DST}"
fi

exit 0
