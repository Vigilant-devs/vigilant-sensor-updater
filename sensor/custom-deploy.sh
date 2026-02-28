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

# Instalar e executar hook pos-atualizacao
CHECK_SRC="${RELEASE_DIR}/scripts/check.sh"
CHECK_DST="/opt/check.sh"
if [[ -f "$CHECK_SRC" ]]; then
    cp "$CHECK_SRC" "$CHECK_DST"
    chmod +x "$CHECK_DST"
    echo "[custom-deploy] Hook instalado: ${CHECK_DST}"
    echo "[custom-deploy] Executando hook pos-atualizacao..."
    bash "$CHECK_DST" && echo "[custom-deploy] Hook concluido com sucesso." \
                      || echo "[custom-deploy] Hook retornou erro (ignorado)."
fi

exit 0
