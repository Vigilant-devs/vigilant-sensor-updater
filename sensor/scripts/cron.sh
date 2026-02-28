#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 16/08/2022
#
#Este script atualiza as configurações do crontab referente ao usuário root.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)

IPHOMENET="ipvar HOME_NET ""$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
IPLAN="$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
IPVPN="$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3,4)"
ANALYTICMANAGER="$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"

sleep 10

echo '* * * * * root echo "c myvpn" > /var/run/xl2tpd/l2tp-control' > /etc/crontab
echo '* * * * * root /sbin/route add' $ANALYTICMANAGER 'gw' $IPVPN >> /etc/crontab
#echo '0 */8 * * * root /usr/sbin/reboot -f' >> /etc/crontab
echo '@reboot root sleep 200 && /usr/bin/systemctl restart snortd' >> /etc/crontab
echo '@reboot root sleep 250 && /usr/bin/systemctl restart dionaea' >> /etc/crontab
echo '@reboot cowrie sleep 300 && /home/cowrie/cowrie/bin/cowrie start' >> /etc/crontab
echo '*/5 * * * * root /vigilant/scripts/cron.sh' >> /etc/crontab
echo '0 */6 * * * root truncate -s 0 /var/log/remotelogs.log' >> /etc/crontab
echo '*/10 * * * * root /vigilant/scripts/update-exabgp-config.sh -s' >> /etc/crontab
