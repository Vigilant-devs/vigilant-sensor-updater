#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 07/08/2023
#
#Este script atualiza as configurações do snort.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)

IPHOMENET="ipvar HOME_NET ""$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

sleep 10

sed -i "s/ipvar HOME_NET .*/$IPHOMENET/g" /etc/snort/snort.conf

systemctl restart snortd > /dev/null 2>&1 || systemctl restart snort > /dev/null 2>&1

