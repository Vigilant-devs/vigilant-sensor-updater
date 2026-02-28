#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 16/08/2022
#
#Este script atualiza as configurações do agente do vigilant.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)
ANALYTICMANAGER="$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"
sleep 10
sed -i "s/<address>.*<\/address>/<address>$ANALYTICMANAGER<\/address>/g" /var/ossec/etc/ossec.conf
sed -i "s/<address>.*<\/address>/<address>$ANALYTICMANAGER<\/address>/g" /opt/ossec/etc/ossec.conf
systemctl restart wazuh-agent
systemctl restart vigilant-agent
