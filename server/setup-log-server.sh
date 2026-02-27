#!/bin/bash
# =============================================================================
# Vigilant Log Server — Setup Script
# OS: Rocky Linux 10 (instalação mínima, sem nada pré-configurado)
# Stack: rsyslog (receptor TCP 514) + Promtail + Loki + Grafana + nginx (HTTPS)
#
# Pré-requisito: Rocky Linux 10 com acesso root e internet.
# Uso: bash setup-log-server.sh
# =============================================================================

set -euo pipefail
export LANG=C.UTF-8

# =============================================================================
# CONFIGURAÇÃO — PREENCHA ANTES DE RODAR
# =============================================================================

# Hostname que este servidor terá
SERVER_HOSTNAME="vigilant-logs"

# Timezone do servidor
TIMEZONE="America/Sao_Paulo"

# Range de IPs dos sensores que podem enviar logs na porta 514.
# Coloque o range da rede onde os sensores estão.
# Deixe vazio ("") para aceitar de qualquer origem (menos seguro).
SENSOR_IP_RANGE=""

# Senha do admin do Grafana (painel web de logs)
GRAFANA_ADMIN_PASSWORD="CHANGE_ME"

# Versões dos componentes
LOKI_VERSION="3.3.2"
PROMTAIL_VERSION="3.3.2"

# =============================================================================
# NÃO ALTERE ABAIXO DESTA LINHA
# =============================================================================

LOG_DIR="/var/log/vigilant"
LOKI_DIR="/var/lib/loki"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
info() { echo -e "${YELLOW}[INFO]${NC}  $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step() { echo ""; echo -e "${GREEN}>>> $*${NC}"; echo ""; }

[[ $EUID -ne 0 ]] && err "Execute como root: sudo bash $0"

echo ""
echo "=================================================="
echo "   Vigilant Log Server — Iniciando instalacao"
echo "=================================================="
echo ""

# =============================================================================
# FASE 0: Preparação base do sistema operacional
# =============================================================================
step "FASE 0: Preparação base do SO"

# Hostname
hostnamectl set-hostname "$SERVER_HOSTNAME"
ok "Hostname: ${SERVER_HOSTNAME}"

# Timezone
timedatectl set-timezone "$TIMEZONE"
ok "Timezone: ${TIMEZONE}"

# NTP (chrony — vem pré-instalado no Rocky Linux mínimo)
systemctl enable --now chronyd 2>/dev/null || true
ok "NTP (chrony) ativo"

# Atualizar o sistema completamente
info "Atualizando sistema (pode demorar alguns minutos)..."
dnf upgrade -y --quiet
ok "Sistema atualizado"

# EPEL (repositório extra com pacotes adicionais)
dnf install -y epel-release --quiet
dnf install -y \
    rsyslog \
    nginx \
    curl \
    wget \
    tar \
    unzip \
    jq \
    logrotate \
    firewalld \
    openssl \
    --quiet
ok "Pacotes base instalados"

# Habilitar e iniciar firewalld (pode estar parado em instalação mínima)
systemctl enable --now firewalld
ok "firewalld iniciado"

# =============================================================================
# FASE 1: rsyslog — receptor de logs dos sensores (TCP 514)
# =============================================================================
step "FASE 1: rsyslog — receptor de logs"

mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

cp "${SCRIPT_DIR}/rsyslog-server.conf" /etc/rsyslog.d/40-vigilant-sensors.conf

# SELinux: permitir rsyslog ouvir na porta 514 TCP (padrão, mas garantir)
if command -v semanage &>/dev/null; then
    semanage port -a -t syslogd_port_t -p tcp 514 2>/dev/null || \
    semanage port -m -t syslogd_port_t -p tcp 514 2>/dev/null || true
fi

systemctl enable rsyslog
systemctl restart rsyslog
ok "rsyslog configurado — ouvindo TCP 514"

# =============================================================================
# FASE 2: Loki — armazenamento de logs
# =============================================================================
step "FASE 2: Loki v${LOKI_VERSION}"

LOKI_ARCH="amd64"
LOKI_URL="https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-${LOKI_ARCH}.zip"

mkdir -p /etc/loki "${LOKI_DIR}"/{chunks,index,index_cache,compactor}

info "Baixando Loki..."
curl -sL "$LOKI_URL" -o /tmp/loki.zip
unzip -oq /tmp/loki.zip loki-linux-${LOKI_ARCH} -d /tmp/loki-extract 2>/dev/null || \
    unzip -oq /tmp/loki.zip -d /tmp/loki-extract
find /tmp/loki-extract -name "loki-linux-${LOKI_ARCH}" -exec install -m 755 {} /usr/local/bin/loki \;
rm -rf /tmp/loki.zip /tmp/loki-extract
ok "Loki instalado em /usr/local/bin/loki"

cp "${SCRIPT_DIR}/loki-config.yaml" /etc/loki/loki-config.yaml

id loki &>/dev/null || useradd -r -s /sbin/nologin -d "$LOKI_DIR" loki
chown -R loki:loki "$LOKI_DIR" /etc/loki

# SELinux: permitir Loki executar e escrever
if command -v chcon &>/dev/null; then
    chcon -t bin_t /usr/local/bin/loki 2>/dev/null || true
fi

cat > /etc/systemd/system/loki.service << 'EOF'
[Unit]
Description=Loki Log Aggregation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=loki
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/loki-config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now loki
sleep 4

systemctl is-active --quiet loki && ok "Loki rodando em :3100" || \
    err "Loki falhou. Verifique: journalctl -u loki -n 30"

# =============================================================================
# FASE 3: Promtail — lê arquivo de log e envia ao Loki
# =============================================================================
step "FASE 3: Promtail v${PROMTAIL_VERSION}"

PROMTAIL_URL="https://github.com/grafana/loki/releases/download/v${PROMTAIL_VERSION}/promtail-linux-${LOKI_ARCH}.zip"

info "Baixando Promtail..."
curl -sL "$PROMTAIL_URL" -o /tmp/promtail.zip
unzip -oq /tmp/promtail.zip promtail-linux-${LOKI_ARCH} -d /tmp/promtail-extract 2>/dev/null || \
    unzip -oq /tmp/promtail.zip -d /tmp/promtail-extract
find /tmp/promtail-extract -name "promtail-linux-${LOKI_ARCH}" -exec install -m 755 {} /usr/local/bin/promtail \;
rm -rf /tmp/promtail.zip /tmp/promtail-extract
ok "Promtail instalado em /usr/local/bin/promtail"

mkdir -p /etc/promtail /var/lib/promtail
cp "${SCRIPT_DIR}/promtail-config.yaml" /etc/promtail/promtail-config.yaml

id promtail &>/dev/null || useradd -r -s /sbin/nologin -d /var/lib/promtail promtail
# Promtail precisa ler /var/log/vigilant
chown promtail:promtail /var/lib/promtail /etc/promtail
chmod 750 "$LOG_DIR"
chown root:promtail "$LOG_DIR"

if command -v chcon &>/dev/null; then
    chcon -t bin_t /usr/local/bin/promtail 2>/dev/null || true
fi

cat > /etc/systemd/system/promtail.service << 'EOF'
[Unit]
Description=Promtail Log Forwarder
After=network-online.target loki.service
Wants=loki.service

[Service]
Type=simple
User=promtail
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail-config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail
sleep 3

systemctl is-active --quiet promtail && ok "Promtail rodando — monitorando ${LOG_DIR}/sensor-updates.log" || \
    err "Promtail falhou. Verifique: journalctl -u promtail -n 30"

# =============================================================================
# FASE 4: Grafana
# =============================================================================
step "FASE 4: Grafana"

cat > /etc/yum.repos.d/grafana.repo << 'EOF'
[grafana]
name=Grafana OSS
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
exclude=*beta*
EOF

dnf install -y grafana --quiet
ok "Grafana instalado"

# Datasource Loki (auto-provisionado)
mkdir -p /etc/grafana/provisioning/{datasources,dashboards}
cp "${SCRIPT_DIR}/grafana-datasource.yaml" /etc/grafana/provisioning/datasources/vigilant-loki.yaml
cp "${SCRIPT_DIR}/grafana-dashboard.json"  /etc/grafana/provisioning/dashboards/

cat > /etc/grafana/provisioning/dashboards/vigilant.yaml << 'EOF'
apiVersion: 1
providers:
  - name: vigilant
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

# Desabilitar acesso anônimo e reforçar segurança
sed -i 's/^;admin_password\s*=.*/admin_password = '"${GRAFANA_ADMIN_PASSWORD}"'/' /etc/grafana/grafana.ini 2>/dev/null || true

cat >> /etc/grafana/grafana.ini << EOF

[auth.anonymous]
enabled = false

[security]
admin_password = ${GRAFANA_ADMIN_PASSWORD}
cookie_secure = true
cookie_samesite = strict
EOF

# SELinux: Grafana escrever seus dados
if command -v chcon &>/dev/null; then
    chcon -R -t var_t /var/lib/grafana 2>/dev/null || true
fi

systemctl enable --now grafana-server
sleep 5

systemctl is-active --quiet grafana-server && ok "Grafana rodando em :3000" || \
    err "Grafana falhou. Verifique: journalctl -u grafana-server -n 30"

# Definir senha admin via CLI (garante mesmo se grafana.ini não pegou)
grafana-cli admin reset-admin-password "$GRAFANA_ADMIN_PASSWORD" 2>/dev/null || true

# =============================================================================
# FASE 5: nginx — proxy reverso com HTTPS (certificado auto-assinado)
# =============================================================================
step "FASE 5: nginx + HTTPS"

mkdir -p /etc/nginx/ssl

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/vigilant.key \
    -out    /etc/nginx/ssl/vigilant.crt \
    -subj "/C=BR/ST=SP/O=Vigilant/CN=${SERVER_HOSTNAME}" \
    2>/dev/null
chmod 600 /etc/nginx/ssl/vigilant.key
ok "Certificado auto-assinado gerado (10 anos)"

# Remover config default do nginx
rm -f /etc/nginx/conf.d/default.conf

cat > /etc/nginx/conf.d/vigilant-logs.conf << 'EOF'
server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;

    ssl_certificate     /etc/nginx/ssl/vigilant.crt;
    ssl_certificate_key /etc/nginx/ssl/vigilant.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
EOF

# SELinux: nginx se conectar ao Grafana localmente
setsebool -P httpd_can_network_connect 1 2>/dev/null || true

# Testar config nginx antes de iniciar
nginx -t 2>/dev/null && ok "Configuração nginx válida" || err "Erro na configuração do nginx"

systemctl enable --now nginx
ok "nginx rodando — HTTPS na porta 443"

# =============================================================================
# FASE 6: Firewall
# =============================================================================
step "FASE 6: Firewall"

# HTTP e HTTPS para acesso ao Grafana (de qualquer IP)
firewall-cmd --permanent --add-service=https --quiet
firewall-cmd --permanent --add-service=http  --quiet
ok "Porta 443/80 aberta (Grafana)"

# Porta 514 TCP — para recebimento de logs dos sensores
if [[ -n "${SENSOR_IP_RANGE}" ]]; then
    # Restrito ao range de IPs configurado
    firewall-cmd --permanent --new-zone=vigilant-sensors 2>/dev/null || true
    firewall-cmd --permanent --zone=vigilant-sensors --add-source="${SENSOR_IP_RANGE}"
    firewall-cmd --permanent --zone=vigilant-sensors --add-port=514/tcp
    ok "Porta 514/tcp aberta para range: ${SENSOR_IP_RANGE}"
else
    # Aberta para qualquer origem (restringir depois com SENSOR_IP_RANGE)
    firewall-cmd --permanent --add-port=514/tcp
    info "Porta 514/tcp aberta para qualquer origem — defina SENSOR_IP_RANGE para restringir"
fi

firewall-cmd --reload
ok "Firewall aplicado"

# =============================================================================
# FASE 7: logrotate
# =============================================================================
step "FASE 7: logrotate"

cat > /etc/logrotate.d/vigilant-sensors << 'EOF'
/var/log/vigilant/sensor-updates.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root promtail
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service 2>/dev/null || true
    endscript
}
EOF
ok "logrotate configurado (90 dias)"

# =============================================================================
# RESUMO FINAL
# =============================================================================
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=================================================="
echo "   Vigilant Log Server — Instalacao concluida!"
echo "=================================================="
echo ""
echo "  Grafana:  https://${SERVER_IP}"
echo "  Login:    admin"
echo "  Senha:    ${GRAFANA_ADMIN_PASSWORD}"
echo ""
echo "  Logs:     ${LOG_DIR}/sensor-updates.log"
echo "  rsyslog:  TCP 514 — aguardando sensores"
echo ""
echo "  Proximos passos:"
echo "  1. Nos sensores, editar /etc/rsyslog.d/50-vigilant-updater.conf"
echo "     e substituir o IP pelo IP deste servidor: ${SERVER_IP}"
echo "  2. Nos sensores: systemctl restart rsyslog"
echo "  3. Testar: logger -p local0.info -t vigilant-updater 'event=test'"
echo "  4. Verificar chegada: tail -f ${LOG_DIR}/sensor-updates.log"
echo ""
echo "  Status dos servicos:"
for svc in rsyslog loki promtail grafana-server nginx; do
    STATUS=$(systemctl is-active "$svc" 2>/dev/null)
    if [[ "$STATUS" == "active" ]]; then
        echo "    [OK]  $svc"
    else
        echo "    [!!]  $svc — VERIFICAR"
    fi
done
echo ""
echo "=================================================="
