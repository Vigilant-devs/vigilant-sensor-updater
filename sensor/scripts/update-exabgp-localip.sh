#!/bin/bash

IPLAN="$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

sed -i 's/router-id .*;/router-id '$IPLAN';/g' /etc/exabgp/exabgp.conf 2>&1 > /dev/null
sed -i 's/local-address .*;/local-address '$IPLAN';/g' /etc/exabgp/exabgp.conf 2>&1 > /dev/null
systemctl restart exabgp.service

