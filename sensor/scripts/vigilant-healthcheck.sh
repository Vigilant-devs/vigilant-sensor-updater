#!/bin/bash
# =============================================================================
# Vigilant Sensor — Health Check
# Verifica status dos principais servicos do sensor e imprime um resumo.
# Uso: bash /vigilant/scripts/vigilant-healthcheck.sh
# =============================================================================

SERVICES=(snortd dionaea exabgp bettercap)
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

# Cowrie roda como processo do usuario cowrie (nao via systemd)
if pgrep -u cowrie -f "cowrie" &>/dev/null; then
    echo "  [OK]   cowrie (processo)"
    PASS=$((PASS + 1))
else
    echo "  [FAIL] cowrie (processo)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Resultado: ${PASS} OK / ${FAIL} falhas"
echo ""
