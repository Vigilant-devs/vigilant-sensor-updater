#!/bin/bash
# =============================================================================
# Vigilant Sensor — Post-Update Check
# Executado automaticamente apos cada atualizacao bem-sucedida.
# Em producao: adicione aqui atualizacao de pacotes, sync de configs, etc.
# =============================================================================

echo "[check.sh] Executado em: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[check.sh] Hostname: $(hostname)"
echo "[check.sh] Versao do sensor-pack: $(cat /vigilant/scripts/vigilantsensor/updater/VERSION 2>/dev/null || echo 'desconhecida')"
