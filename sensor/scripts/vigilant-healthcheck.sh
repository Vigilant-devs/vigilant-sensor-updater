#!/bin/bash
# =============================================================================
# Vigilant Sensor — Health Check
# Verifica status dos principais servicos do sensor e imprime um resumo.
# Uso: bash /vigilant/scripts/vigilant-healthcheck.sh
# =============================================================================

SERVICES=(snortd dionaea cowrie exabgp bettercap)
PASS=0
FAIL=0

echo "=== Vigilant Sensor Health Check === $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  [OK]   $svc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $svc"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "Resultado: ${PASS} OK / ${FAIL} falhas"
echo ""
