#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 18/07/2023
#Este script atualiza as configurações do Firewall baseando-se em variaveis.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)

IPLAN="$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
ANALYTICMANAGER="$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"

sleep 10
iptables -t nat -A PREROUTING -d $IPLAN -p TCP --dport 1514 -j DNAT --to-destination $ANALYTICMANAGER
iptables -t nat -A PREROUTING -d $IPLAN -p TCP --dport 1515 -j DNAT --to-destination $ANALYTICMANAGER
iptables -t nat -A PREROUTING -d $IPLAN -p TCP --dport 6514 -j DNAT --to-destination $ANALYTICMANAGER
iptables -t nat -A PREROUTING -d $IPLAN -p UDP --dport 1514 -j DNAT --to-destination $ANALYTICMANAGER
iptables -t nat -A PREROUTING -d $IPLAN -p UDP --dport 1515 -j DNAT --to-destination $ANALYTICMANAGER
iptables -t nat -A PREROUTING -d $IPLAN -p UDP --dport 6514 -j DNAT --to-destination $ANALYTICMANAGER
iptables -t nat -A POSTROUTING -o ppp0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o ppp1 -j MASQUERADE
iptables -t nat -A POSTROUTING -o ppp2 -j MASQUERADE
iptables -A FORWARD -s 0.0.0.0/0 -p tcp --dport 1514 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -p tcp --dport 1515 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -p tcp --dport 6514 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -p udp --dport 1514 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -p udp --dport 1515 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -p udp --dport 6514 -j ACCEPT
iptables -A FORWARD -s 10.128.0.0/16 -j ACCEPT
iptables -A FORWARD -j DROP
iptables -A INPUT -p tcp --dport 8081 -j DROP
iptables -A INPUT -p udp --dport 8081 -j DROP
