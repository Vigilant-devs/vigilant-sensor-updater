#!/bin/bash

#######################################################
#      Script for installation of Vigilant Sensor     #
#                                                     #	
#           In case of problem, please contact        #
#                                                     #
#                 tel:+55(11)2227-9799                #
#              suporte@vigilant.com.br                #
#                                                     #
#               Last Review: fev 23 2026              #
#######################################################

###Approved operation in "Rocky Linux 8"

ignore_sigint() {
    echo -e "The script cannot be interrupted! Please continue the installation...\n"
}

# --- LOG ---
LOG="/var/log/vigilant.log"
mkdir -p "$(dirname "$LOG")"

color() {
  local c="$1"; shift
  case "$c" in
    red)    echo -e "\033[1;31m$*\033[0m" ;;
    green)  echo -e "\033[1;32m$*\033[0m" ;;
    yellow) echo -e "\033[1;33m$*\033[0m" ;;
    blue)   echo -e "\033[1;34m$*\033[0m" ;;
    *)      echo "$*" ;;
  esac
}

log() {
    local lvl="$1"; shift
    local msg
    msg="$(date +"%d-%m-%Y %H:%M:%S %z") $(hostname) vigilant-sensor [$lvl] $*"
    echo "$msg"
    echo "$msg" >> "$LOG"
}

# Validated input: Y/N — called via $(), I/O through /dev/tty
ask_yn() {
  local prompt="$1" resp confirm
  while true; do
    read -rp "$prompt (Y/N): " resp < /dev/tty
    resp="${resp^^}"
    if [[ "$resp" != "Y" && "$resp" != "N" ]]; then
      echo -e "\033[1;33m[WARN] Invalid input. Only Y or N allowed.\033[0m" >&2
      continue
    fi
    read -rp "You answered $resp. Continue? (Y/N): " confirm < /dev/tty
    confirm="${confirm^^}"
    if [[ "$confirm" == "Y" ]]; then
      echo "$resp"
      return 0
    fi
  done
}

# Validated input: alphanumeric+hyphen identifier — called via $()
ask_id() {
  local prompt="$1" resp confirm
  while true; do
    read -rp "$prompt: " resp < /dev/tty
    if [[ -z "$resp" ]]; then
      echo -e "\033[1;33m[WARN] Input cannot be empty.\033[0m" >&2
      continue
    fi
    if [[ ! "$resp" =~ ^[a-zA-Z0-9-]+$ ]]; then
      echo -e "\033[1;33m[WARN] Only alphanumeric characters and hyphens are allowed.\033[0m" >&2
      continue
    fi
    read -rp "You answered $resp. Continue? (Y/N): " confirm < /dev/tty
    confirm="${confirm^^}"
    if [[ "$confirm" == "Y" ]]; then
      echo "$resp"
      return 0
    fi
  done
}

# Validated input: password (any non-empty chars) — called via $()
ask_pass() {
  local prompt="$1" resp confirm
  while true; do
    read -rp "$prompt: " resp < /dev/tty
    if [[ -z "$resp" ]]; then
      echo -e "\033[1;33m[WARN] Input cannot be empty.\033[0m" >&2
      continue
    fi
    read -rp "You answered $resp. Continue? (Y/N): " confirm < /dev/tty
    confirm="${confirm^^}"
    if [[ "$confirm" == "Y" ]]; then
      echo "$resp"
      return 0
    fi
  done
}

# Global variables for two-phase execution
declare -g USER_NEW_HOSTNAME=""
declare -g VPN_USER=""
declare -g VPN_PASSWORD=""
declare -g VIGILANT_ID=""
declare -g VIGILANT_PASSWORD=""
declare -g ID_SHIELD=""
declare -g BACKUP_DNS="8.8.8.8"
declare -g PHASE_1_COMPLETE=0

download_start () {
    DISTRO_1="$1"
	URL="$2"
    OUTPUT="$3"
    RETRY="1"

	if [ $DISTRO_1 -eq 1 ]; then
		while [ $RETRY -lt 11 ]; do
			echo -e "\nPerforming $RETRY download attempt from $URL..."
			curl -L "$URL" -o "$OUTPUT"

			if [ $? -eq 0 ]; then
				echo -e "Download done successfully!\n\n"
				RETRY="11"
			else
				echo "\nDownload error. Retrying..."
				((RETRY++))
				if [ $RETRY -eq 6 ]; then
					echo "nameserver 8.8.8.8" > /etc/resolv.conf
				fi
				if [ $RETRY -eq 11 ]; then
					echo -e "\nDownload failed after 10 attempts. Applying backup DNS: $BACKUP_DNS"
					echo "nameserver $BACKUP_DNS" > /etc/resolv.conf
					echo -e "DNS set to: $BACKUP_DNS"
					RETRY="1"
				fi
			fi
		done

	elif [ $DISTRO_1 -eq 2 ]; then
			while [ $RETRY -lt 11 ]; do
			echo -e "\n\nPerforming $RETRY download attempt from $URL..."
			wget -q "$URL" -O "$OUTPUT"

			if [ $? -eq 0 ]; then
				echo -e "Download done successfully!\n\n"
				RETRY="11"
			else
				echo "\nDownload error. Retrying..."
				((RETRY++))
				if [ $RETRY -eq 6 ]; then
					echo "nameserver 8.8.8.8" > /etc/resolv.conf
				fi
				if [ $RETRY -eq 11 ]; then
					echo -e "\nDownload failed after 10 attempts. Applying backup DNS: $BACKUP_DNS"
					echo "nameserver $BACKUP_DNS" > /etc/resolv.conf
					echo -e "DNS set to: $BACKUP_DNS"
					RETRY="1"
				fi
			fi
		done
	fi
}

alter_hostname (){
	if [[ -n "$USER_NEW_HOSTNAME" && "$USER_NEW_HOSTNAME" != "$(hostname)" ]]; then
		hostnamectl set-hostname "$USER_NEW_HOSTNAME" 2>/dev/null || echo "$USER_NEW_HOSTNAME" > /etc/hostname
		log INFO "Hostname set to: $USER_NEW_HOSTNAME"
		echo -e "\nHostname set to: $USER_NEW_HOSTNAME\n"
	else
		log INFO "Hostname unchanged: $(hostname)"
		echo -e "\nHostname unchanged: $(hostname)\n"
	fi
}

disable_firewalld_and_selinux() {
	echo -e "\n\nDisabling SE Linux..."
	sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config	
	echo -e "OK!\n\nDisabling Firewalld..."
	systemctl disable firewalld 2> /dev/null
	systemctl stop firewalld 2> /dev/null
	echo -e "OK!\n\n"

}

install_prerequisites_rocky() {
    echo -e "\n\nStarting installation of prerequisites 1..."
	mkdir -p /vigilant/scripts/
	dnf config-manager --set-enabled devel
	dnf install -y epel-release
    dnf install -y openssh strongswan xl2tpd net-tools httpd vim openssl-devel libffi-devel bzip2-devel wget git gcc dionaea libdnet dialog ipcalc NetworkManager-initscripts-updown gcc-c++ libpcap libpcap-devel libusb libusb-devel libnetfilter_queue libnetfilter_queue-devel make automake rsyslog
    if [ $? -ne 0 ]; then
        echo -e "\n\nError: Failed to install prerequisites 1. Please check your internet connection."
        exit 1
    else
        echo -e "\n\nInstallation Prerequisites 1 Completed!"
    fi

    echo -e "\n\n Starting installation of prerequisites 2..."
	dnf groupinstall "Development Tools" -y
	if [ $? -ne 0 ]; then
        echo -e "\n\nError: Failed to install prerequisites 2. Please check your internet connection."
        exit 1
    else
        echo -e "\n\nInstallation Prerequisites 1 Completed!"
    fi

}

install_prerequisites_debian(){
	echo -e "\n\nStarting installation of prerequisites..."
	mkdir -p /vigilant/scripts/
	echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin' > /etc/environment
	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin
	apt-get update
	mv /etc/network/interfaces /etc/network/interfaces.old
	DEBIAN_FRONTEND=noninteractive apt-get -y install openssh-server git vim apache2 libdnet curl wget strongswan xl2tpd build-essential cmake check cython3 libcurl4-openssl-dev libev-dev libglib2.0-dev libloudmouth1-dev libnetfilter-queue-dev libnl-3-dev libpcap-dev libssl-dev libtool libudns-dev libusb-1.0-0-dev python3 python3-dev python3-bson python3-yaml python3-boto3 fonts-liberation snort git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv ipcalc dialog sudo network-manager rsyslog
	if [ $? -ne 0 ]; then
        echo -e "\n\nError: Failed to install prerequisites. Please check your internet connection."
        exit 1
    else
        echo -e "\n\nInstallation Prerequisites Completed!"
    fi
}

configure_ssh_and_httpd() {
	sed -i 's/#PermitRootLogin .*/PermitRootLogin yes/g' /etc/ssh/sshd_config > /dev/null 2>&1
	sed -i 's/PermitRootLogin .*/PermitRootLogin yes/g' /etc/ssh/sshd_config > /dev/null 2>&1
	sed -i 's/#PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config> /dev/null 2>&1
	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config > /dev/null 2>&1
	sed -i 's/#Port .*/Port 12222/g' /etc/ssh/sshd_config > /dev/null 2>&1
	sed -i 's/Port .*/Port 12222/g' /etc/ssh/sshd_config > /dev/null 2>&1
	sed -i 's/Listen 80/Listen 12280/g' /etc/httpd/conf/httpd.conf > /dev/null 2>&1
	sed -i 's/Listen 80/Listen 12280/g' /etc/apache2/ports.conf > /dev/null 2>&1
	systemctl enable sshd > /dev/null 2>&1
	systemctl enable httpd > /dev/null 2>&1
	systemctl enable apache2 > /dev/null 2>&1
}

configure_vpn(){
	echo -e "Configuring Vigilant VPN..."
	VPN_SERVER_IP=177.190.148.68
	VPN_IPSEC_PSK=VigilantVPNL2tpSec
	# VPN_USER and VPN_PASSWORD are set in Phase 1 (collect_user_inputs)

	cat > /etc/ipsec.conf <<EOF
# ipsec.conf - strongSwan IPsec configuration file

# basic configuration

#config setup
  # strictcrlpolicy=yes
  # uniqueids = no

# Add connections here.

# Sample VPN connections

conn %default
  ikelifetime=60m
  keylife=20m
  rekeymargin=3m
  keyingtries=1
  keyexchange=ikev1
  authby=secret
  ike=aes128-sha1-modp2048!
  esp=aes128-sha1-modp2048!

conn myvpn
  keyexchange=ikev1
  left=%defaultroute
  auto=add
  authby=secret
  type=transport
  leftprotoport=17/1701
  rightprotoport=17/1701
  right=$VPN_SERVER_IP
EOF

	cat > /etc/ipsec.secrets <<EOF
: PSK "$VPN_IPSEC_PSK"
EOF

chmod 600 /etc/ipsec.secrets

	cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[lac myvpn]
lns = $VPN_SERVER_IP
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes
EOF

	cat > /etc/ppp/options.l2tpd.client <<EOF
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-chap
noccp
noauth
mtu 1280
mru 1280
noipdefault
defaultroute
usepeerdns
connect-delay 5000
name $VPN_USER
password $VPN_PASSWORD
EOF

	chmod 600 /etc/ppp/options.l2tpd.client
	mkdir -p /var/run/xl2tpd
	touch /var/run/xl2tpd/l2tp-control
	systemctl enable xl2tpd.service
	systemctl start xl2tpd.service
	sleep 10
#	if systemctl is-active --quiet xl2tpd.service; then
#        echo -e "VPN Vigilant as started suceffully!\n"
#
#    else
#        echo -e "Error: Installation of VPN Vigilant failed. Please contact support."
#        exit 2
#    fi
	service xl2tpd restart
	echo '* * * * *	root	echo "c myvpn" > /var/run/xl2tpd/l2tp-control' >> /etc/crontab

}

install_vigilantagent (){
	if [ $1 -eq 1 ]; then
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/agent/linux/vigilant-agent-pack-v2.tar.gz /tmp/vigilant-agent-pack.tar.gz
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/agent/linux/scripts/vigilant-agent-install.sh /tmp/vigilant-agent-install.sh
		chmod +x /tmp/vigilant-agent-install.sh && /tmp/vigilant-agent-install.sh -m sensores -p $VIGILANT_ID -k $VIGILANT_PASSWORD -s $ID_SHIELD -i
	else
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/agent/linux/vigilant-agent-pack-v2.tar.gz /tmp/vigilant-agent-pack.tar.gz
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/agent/linux/scripts/vigilant-agent-install-1.0.sh /tmp/vigilant-agent-install.sh
		chmod +x /tmp/vigilant-agent-install.sh && /tmp/vigilant-agent-install.sh -m sensores -p $VIGILANT_ID -k $VIGILANT_PASSWORD -s $ID_SHIELD -i
	fi
	sed -i "s/<groups>.*<\/groups>/<groups>sensores<\/groups>/g" /var/ossec/etc/ossec.conf > /dev/null 2>&1
	sed -i "s/<groups>.*<\/groups>/<groups>sensores<\/groups>/g" /opt/ossec/etc/ossec.conf > /dev/null 2>&1
	rm -f /var/ossec/active-response/bin/AR-Universal > /dev/null 2>&1
	rm -rf /var/ossec/active-response/bin/lib/ > /dev/null 2>&1
	rm -f /opt/ossec/active-response/bin/AR-Universal > /dev/null 2>&1
	rm -rf /opt/ossec/active-response/bin/lib/ > /dev/null 2>&1
	if [ $1 -eq 1 ]; then
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/update/update-ARUniversal-Sensor.sh /tmp/update-ARUniversal-Sensor.sh
		chmod +x /tmp/update-ARUniversal-Sensor.sh && /tmp/update-ARUniversal-Sensor.sh
	else
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/update/update-ARUniversal-Sensor.sh /tmp/update-ARUniversal-Sensor.sh
		chmod +x /tmp/update-ARUniversal-Sensor.sh && /tmp/update-ARUniversal-Sensor.sh
	fi
	sed -i "s/<address>0.0.0.0<\/address>/<address>$VIGILANT_CORE<\/address>/g" /var/ossec/etc/ossec.conf > /dev/null 2>&1
	sed -i "s/<address>0.0.0.0<\/address>/<address>$VIGILANT_CORE<\/address>/g" /opt/ossec/etc/ossec.conf > /dev/null 2>&1
	rm -f /var/ossec/active-response/bin/route-null
	rm -f /opt/ossec/active-response/bin/route-null
}

configure_dionaea_on_rocky (){
	echo -e "\nConfiguring Vigilant-D...\n"
	systemctl enable dionaea
	systemctl start dionaea
	echo -e "\nVigilant-D configured!\n"
}

configure_dionaea_on_debian (){
	echo -e "\nConfiguring Vigilant-D...\n"
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/dionaea/libemu2_0.2.0+git20120122-1.2+b1_amd64.deb /root/libemu2_0.2.0+git20120122-1.2+b1_amd64.deb
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/dionaea/libemu-dev_0.2.0+git20120122-1.2+b1_amd64.deb /root/libemu-dev_0.2.0+git20120122-1.2+b1_amd64.deb
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/dionaea/dionaea.tar.gz /root/dionaea.tar.gz
	tar -zxf dionaea.tar.gz && cd /root/dionaea
	dpkg -i /root/libemu2_0.2.0+git20120122-1.2+b1_amd64.deb
	dpkg -i /root/libemu-dev_0.2.0+git20120122-1.2+b1_amd64.deb
	rm -f /root/dionaea.tar.gz
	mkdir build
	cd build
	cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea .. && make && make install

	/opt/dionaea/bin/dionaea -D
	cd /root && rm -rf *.deb dionaea/

	cat << EOF > /etc/systemd/system/dionaea.service
[Unit]
Description= HoneyPot Dionaea
After=network.target
[Install]
WantedBy=multi-user.target
[Service]
Type=simple
ExecStart=/opt/dionaea/bin/dionaea
WorkingDirectory=/opt/dionaea/bin
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=%n
EOF

	systemctl daemon-reload
	systemctl enable dionaea.service
	sed -i 's/^modules=.*/modules=curl,python,nfq,emu,pcap/g' /opt/dionaea/etc/dionaea/dionaea.cfg > /dev/null 2>&1
	echo -e "\nVigilant-D configured!\n"
}

configure_cowrie_on_rocky (){
	echo -e "\nConfiguring Vigilant-C...\n"
	cd /root
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/python/Python-3.9.13.tgz /root/Python-3.9.13.tgz
	tar -xvf Python-3.9.13.tgz
	cd Python-3.9*/
	./configure --enable-optimizations
	make altinstall
	cd /root
	/usr/local/bin/python3.9 -m pip install --upgrade pip
	pip3.9 install awscli --user
	useradd -m cowrie
	cd /home/cowrie
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/cowrie/cowrie.tar.gz /home/cowrie/cowrie.tar.gz
	tar -zxf cowrie.tar.gz
	rm -f cowrie.tar.gz

	cat > /home/cowrie/cowrie/requirements.txt <<EOF
appdirs==1.4.4
attrs
bcrypt==3.1.7
configparser==3.7.1
cryptography
packaging
pyasn1_modules==0.2.8
pyopenssl
pyparsing
python-dateutil==2.8.2
service_identity==21.1.0
tftpy==0.8.2
treq

EOF

	cat > /home/cowrie/cowrie/etc/cowrie.cfg <<EOF
[telnet]
enabled = true

[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0

[Telnet]
listen_endpoints = tcp:2223:interface=0.0.0.0
EOF

	chown -R cowrie. /home/cowrie/cowrie/

	cat > /tmp/cowrie.sh <<EOF
#!/bin/bash
cd /home/cowrie/cowrie
virtualenv --python=python3.9 cowrie-env
. cowrie-env/bin/activate
pip3.9 install --upgrade pip
pip3.9 install setuptools-rust
pip3.9 install pywinos
pip3.9 install paramiko
pip install --upgrade -r requirements.txt
bin/cowrie start
EOF

	chmod +x /tmp/cowrie.sh
	su -c "/bin/bash /tmp/cowrie.sh" -s /bin/bash cowrie
	cd /root
	rm -f /usr/bin/python3
    ln -s /usr/local/bin/python3.9 /usr/bin/python3
	echo -e "\nVigilant-C configured!\n"
}

configure_cowrie_on_debian (){
	echo -e "\nConfiguring Vigilant-C...\n"
	useradd -m -s /bin/bash cowrie
	cd /home/cowrie
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/cowrie/cowrie.tar.gz /home/cowrie/cowrie.tar.gz
	tar -zxf cowrie.tar.gz
	rm -f cowrie.tar.gz

	cat > /home/cowrie/cowrie/etc/cowrie.cfg <<EOF
[telnet]
enabled = true

[ssh]
listen_endpoints = tcp:2222:interface=0.0.0.0

[Telnet]
listen_endpoints = tcp:2223:interface=0.0.0.0
EOF

	chown -R cowrie. /home/cowrie/cowrie/

	cat > /tmp/cowrie.sh <<EOF
#!/bin/bash
cd /home/cowrie/cowrie
virtualenv --python=python3.9 cowrie-env
. cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install --upgrade -r requirements.txt
bin/cowrie start
EOF

	chmod +x /tmp/cowrie.sh
	su -c "/bin/bash /tmp/cowrie.sh" -s /bin/bash cowrie
	cd /root
	echo -e "\nVigilant-C configured!\n"
}

configure_snort_on_rocky (){
	echo -e "\nConfiguring Vigilant-C...\n"
	IPHOMENET="ipvar HOME_NET ""$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/snort/daq-2.0.6-1.centos7.x86_64.rpm /root/daq-2.0.6-1.centos7.x86_64.rpm
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/snort/snort-2.9.20-1.centos.x86_64.rpm /root/snort-2.9.20-1.centos.x86_64.rpm
	dnf install -y /root/daq-2.0.6-1.centos7.x86_64.rpm
	dnf install -y /root/snort-2.9.20-1.centos.x86_64.rpm
	ldconfig
	ln -s /usr/lib64/libdnet.so.1.0.1 /usr/lib64/libdnet.1
	mkdir -p /etc/snort/rules
	mkdir -p /var/log/snort
	mkdir -p /usr/local/lib/snort_dynamicrules
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/snort/snort.conf /root/snort.conf
	rm -f /etc/snort/snort.conf
	mv /root/snort.conf /etc/snort/snort.conf
	sed -i "s/ipvar HOME_NET .*/$IPHOMENET/g" /etc/snort/snort.conf
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/snort/rules.tar.gz /root/rules.tar.gz
	tar -zxf /root/rules.tar.gz -C /etc/snort/rules/
	rm -f /root/rules.tar.gz

	cat >>/usr/local/etc/rules/local.rules<<EOF
alert icmp any any -> \$HOME_NET any (msg:"Ping detected"; sid:1000001; classtype:icmp-event;)
alert icmp any any -> \$HOME_NET any (msg: “NMAP ping sweep Scan”; dsize:0;sid:10000004; rev: 1; )
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg: “NMAP TCP Scan”;sid:10000005; rev:2; )
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg:“Nmap XMAS Tree Scan”; flags:FPU; sid:1000006; rev:1; )
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg:“Nmap FIN Scan”; flags:F; sid:1000008; rev:1;)
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg:“Nmap NULL Scan”; flags:0; sid:1000009; rev:1; )


EOF

	sed -i "s/INTERFACE=eth0/INTERFACE=`ip a | grep -E "ens|eth|enp" |cut -d " " -f2 |cut -d ":" -f1 | grep -E "ens|eth|enp"`/g" /etc/sysconfig/snort
	chmod -R 5775 /etc/snort
	chmod -R 5775 /var/log/snort
	chmod -R 5775 /usr/local/lib/snort_dynamicrules
	chown -R snort:snort /etc/snort
	chown -R snort:snort /var/log/snort
	chown -R snort:snort /usr/local/lib/snort_dynamicrules
	systemctl enable snortd.service
	/usr/lib/systemd/systemd-sysv-install enable snortd
	echo -e "\nVigilant-S configured!\n"
}

configure_snort_on_debian (){
	echo -e "\nConfiguring Vigilant-S...\n"
	IPHOMENET="ipvar HOME_NET ""$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
	sed -i "s/ipvar HOME_NET .*/$IPHOMENET/g" /etc/snort/snort.conf
	sed -i 's/DEBIAN_SNORT_HOME_NET=.*/DEBIAN_SNORT_HOME_NET="10.0.0.0\/8,172.16.0.0\/12,192.168.0.0\/16"/g' /etc/snort/snort.debian.conf
	
	cat >>/etc/snort/rules/local.rules<<EOF
alert icmp any any -> \$HOME_NET any (msg:"Ping detected"; sid:1000001; classtype:icmp-event;)
alert icmp any any -> \$HOME_NET any (msg: “NMAP ping sweep Scan”; dsize:0;sid:10000004; rev: 1; )
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg: “NMAP TCP Scan”;sid:10000005; rev:2; )
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg:“Nmap XMAS Tree Scan”; flags:FPU; sid:1000006; rev:1; )
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg:“Nmap FIN Scan”; flags:F; sid:1000008; rev:1;)
alert tcp any any -> \$HOME_NET 21,22,23,80,443,445,1433 (msg:“Nmap NULL Scan”; flags:0; sid:1000009; rev:1; )
EOF

	sed -i "s/INTERFACE=.*/INTERFACE=`ip a | grep -E "ens|eth|enp" |cut -d " " -f2 |cut -d ":" -f1 | grep -E "ens|eth|enp"`/g" /etc/snort/snort.debian.conf
	chmod -R 5775 /etc/snort
	chmod -R 5775 /var/log/snort
	chmod -R 5775 /usr/local/lib/snort_dynamicrules
	chown -R snort:snort /etc/snort
	chown -R snort:snort /var/log/snort
	chown -R snort:snort /usr/local/lib/snort_dynamicrules
	systemctl enable snort.service 
	/usr/lib/systemd/systemd-sysv-install enable snort
	echo -e "\nVigilant-S configured!\n"
}

configure_network_manager_on_debian(){
	nmcli connection modify "Wired connection 1" connection.id $1 > /dev/null 2>&1
	nmcli connection modify "Conexão cabeada 1" connection.id $1 > /dev/null 2>&1
	nmcli con mod $1 ipv6.method disabled
	
	cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.ipv6.conf.$1.disable_ipv6 = 1
EOF

}

configure_network_manager_on_rocky(){

	cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.ipv6.conf.$1.disable_ipv6 = 1
EOF

}

configure_keepalive(){

	cat >> /vigilant/scripts/keepalive.sh << EOF
#!/bin/bash

while true
do
  IPHOMENET="ipvar HOME_NET ""\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
  IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
  IPVPN="\$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3,4)"
  ANALYTICMANAGER="\$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"

  /sbin/route add \$ANALYTICMANAGER gw \$IPVPN > /dev/null 2>&1
  sleep 1
  ping \$ANALYTICMANAGER -c 60 > /dev/null 2>&1
  sleep 9
done
EOF

chmod +x /vigilant/scripts/keepalive.sh

}

configure_bettercap (){
	echo -e "\nConfiguring Vigilant-B...\n"
	mkdir -p /usr/local/go
	if [ $1 -eq 1 ]; then
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/bettercap/go/go1.20.3.linux-amd64.tar.gz /tmp/go1.20.3.linux-amd64.tar.gz
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/bettercap/bettercap-2.32.0-rocky8-x64.tar.gz /usr/local/go/bettercap-2.32.0-rocky8-x64.tar.gz
	else
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/bettercap/go/go1.20.3.linux-amd64.tar.gz /tmp/go1.20.3.linux-amd64.tar.gz
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/bettercap/bettercap-2.32.0-debian11-x64.tar.gz /usr/local/go/bettercap-2.32.0-debian11-x64.tar.gz
	fi
    tar -zxf /tmp/go1.20.3.linux-*.tar.gz -C /opt/
    rm -f /tmp/go1.20.3.linux-*.tar.gz
    cp -f /etc/environment /etc/environment.bkp
    echo GOROOT=/opt/go > /etc/environment
    echo GOPATH=/usr/local/go >> /etc/environment
    echo PATH=$PATH:/usr/local/go/bin:/opt/go/bin >> /etc/environment
    sed -i 's/PATH=".*"/PATH="\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin:\/usr\/local\/go\/bin:\/opt\/go\/bin"/g' /etc/profile
    source /etc/environment
    cd /usr/local/go   
    tar -xzf bettercap-*.tar.gz
    rm -f bettercap-*.tar.gz
    cd /root

	cat > /usr/lib/systemd/system/bettercap.service <<EOF
[Unit]
Description=bettercap api.rest service.
Documentation=https://bettercap.org
Wants=network.target
After=network.target

[Service]
Type=simple
PermissionsStartOnly=true
ExecStart=/usr/local/go/bin/bettercap -no-colors -eval "set events.stream.output /var/log/bettercap.log; api.rest on"
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

	systemctl daemon-reload
	systemctl enable bettercap.service
	echo -e "\nVigilant-B configured!\n"
}

configure_rclocal (){
	cat > /etc/rc.local <<EOF
#!/bin/bash
# THIS FILE IS ADDED FOR COMPATIBILITY PURPOSES
#
# It is highly advisable to create own systemd services or udev rules
# to run scripts during boot instead of using this file.
#
# In contrast to previous versions due to parallel execution during boot
# this script will NOT be run after all other services.
#
# Please note that you must run 'chmod +x /etc/rc.d/rc.local' to ensure
# that this script will be executed during boot.
touch /var/lock/subsys/local
#Iniciando execucao personalizada
service procps restart
su - cowrie -c "/home/cowrie/cowrie/bin/cowrie start"
sleep 240
su -c "/bin/bash /vigilant/scripts/firewall.sh" -s /bin/bash root
su -c "/bin/bash /vigilant/scripts/cron.sh" -s /bin/bash root
#su -c "/bin/bash /vigilant/scripts/vigilantagent.sh" -s /bin/bash root
su -c "/bin/bash /vigilant/scripts/snort.sh" -s /bin/bash root
su -c "/bin/bash /vigilant/scripts/update-exabgp-localip.sh" -s /bin/bash root
su -c "/bin/bash /vigilant/scripts/keepalive.sh" -s /bin/bash root &
EOF

	chmod +x /etc/rc.d/rc.local > /dev/null 2>&1
	chmod +x /etc/rc.local > /dev/null 2>&1

}

configure_rsyslog (){
	cat > /etc/rsyslog.d/10-remote.conf <<EOF
module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")

\$template RemoteLogFormat,"%timegenerated% %fromhost-ip% %syslogtag%%msg%,fromhost=%fromhost-ip%\n"

*.* /var/log/remotelogs.log;RemoteLogFormat

EOF

	cat > /etc/rsyslog.conf <<EOF
# rsyslog configuration file

# For more information see /usr/share/doc/rsyslog-*/rsyslog_conf.html
# or latest version online at http://www.rsyslog.com/doc/rsyslog_conf.html
# If you experience problems, see http://www.rsyslog.com/doc/troubleshoot.html

#### MODULES ####

module(load="imuxsock"    # provides support for local system logging (e.g. via logger command)
       SysSock.Use="off") # Turn off message reception via local log socket;
                          # local messages are retrieved through imjournal now.
module(load="imjournal"             # provides access to the systemd journal
       StateFile="imjournal.state") # File to store the position in the journal
#module(load="imklog") # reads kernel messages (the same are read from journald)
#module(load="immark") # provides --MARK-- message capability

# Provides UDP syslog reception
# for parameters see http://www.rsyslog.com/doc/imudp.html
#module(load="imudp") # needs to be done just once
#input(type="imudp" port="514")


# Provides TCP syslog reception
# for parameters see http://www.rsyslog.com/doc/imtcp.html
#module(load="imtcp") # needs to be done just once
#input(type="imtcp" port="514")

# Direciona todos os logs recebidos de fontes remotas para /var/log/remotelogs
#*.* /var/log/remotelogs.log


#### GLOBAL DIRECTIVES ####

# Where to place auxiliary files
global(workDirectory="/var/lib/rsyslog")

# Use default timestamp format
module(load="builtin:omfile" Template="RSYSLOG_TraditionalFileFormat")

# Include all config files in /etc/rsyslog.d/
include(file="/etc/rsyslog.d/*.conf" mode="optional")

EOF

	echo -e "\nVigilant SYSLOG service configured!\n"

}

configure_exabgp (){
	download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/exabgp/exabgp-4.2.21.tar.gz /tmp/exabgp-4.2.21.tar.gz
	useradd -r -s /usr/sbin/nologin exabgp
    cd /tmp
    tar -zxf exabgp-4.2.21.tar.gz && cd /tmp/exabgp-4.2.21
    chmod +x setup.py
    ./setup.py install
    mkdir -p /etc/exabgp/ 2>&1 > /dev/null
    mkdir -p /usr/local/etc/exabgp/ 2>&1 > /dev/null
    exabgp --fi > /usr/local/etc/exabgp/exabgp.env
    sleep 2

    cat >/etc/exabgp/exabgp.conf<<EOF
neighbor 192.168.0.1 {
        local-as 65444;
        peer-as 65530;
        router-id 192.168.0.90;
        local-address 192.168.0.90;
        family {
            ipv4 unicast;
        }
}
EOF

    cat >/etc/systemd/system/exabgp.service<<EOF
[Unit]
Description=ExaBGP
Documentation=man:exabgp(1)
Documentation=man:exabgp.conf(5)
Documentation=https://github.com/Exa-Networks/exabgp/wiki
After=network.target
ConditionPathExists=/etc/exabgp/exabgp.conf

[Service]
User=exabgp
Group=exabgp
Environment=exabgp_daemon_daemonize=false
RuntimeDirectory=exabgp
RuntimeDirectoryMode=0750
ExecStartPre=-/usr/bin/mkfifo /run/exabgp/exabgp.in
ExecStartPre=-/usr/bin/mkfifo /run/exabgp/exabgp.out
ExecStart=/usr/local/bin/exabgp /etc/exabgp/exabgp.conf
ExecReload=/bin/kill -USR1 \$MAINPID
Restart=always
ExecStartPost=/vigilant/scripts/update-exabgp-config.sh -c
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

	cat > /vigilant/scripts/update-exabgp-config.sh <<EOG
#!/bin/bash

#Função para escrita de log
write_log () {
    local destination_log="/var/log/vigilant.log"
    local software="EXABGP"
    local tipo="\$1"
    local mensagem="\$2"
    local datahora=\$(date +'%d-%m-%Y %H:%M:%S')

    echo "\$datahora \$software \$tipo: \$mensagem" >> "\$destination_log"
}

enable_exabgp_service() {
    systemctl enable exabgp.service > /dev/null 2>&1
    systemctl start exabgp.service > /dev/null 2>&1
    if [ \$? -eq 0 ]; then
        write_log "INFO" "BGP service started successfully"
        return 0
    else
        write_log "ERROR" "Failed to start BGP service"
        return 1
    fi

}

restart_exabgp_service() {
    systemctl restart exabgp.service > /dev/null 2>&1
    if [ \$? -eq 0 ]; then
        write_log "INFO" "BGP service restarted successfully"
        return 0
    else
        write_log "ERROR" "Failed to restart BGP service"
        return 1
    fi

}

disable_exabgp_service() {
    systemctl disable exabgp.service > /dev/null 2>&1
    systemctl stop exabgp.service > /dev/null 2>&1
    if [ \$? -eq 0 ]; then
        write_log "INFO" "BGP service stopped successfully"
        return 0
    else
        write_log "ERROR" "Failed to stop BGP service"
        return 1
    fi

}

status_exabgp_service (){
    systemctl status exabgp.service > /dev/null 2>&1
    exa_stat=\$?
    if [ \$exa_stat -eq 0 ]; then
        exabgp_status="running"
        /usr/local/bin/exabgp-cli show neighbor summary > /dev/null 2>&1
        if [ \$? -eq 0 ]; then
            list_peers=\$(/usr/local/bin/exabgp-cli show neighbor summary)

            # Verifica se há peers estabelecidos
            if [[ \$(echo "\$list_peers" | grep -c "established") -gt 0 ]]; then
                # Extrai os IPs dos peers estabelecidos e os separa por vírgula
                IPs=\$(echo "\$list_peers" | awk '/established/{print \$1}' | tr '\n' ',' | sed 's/,\$//')
                write_log "STATUS" "The service status is \"\$exabgp_status\" and active connections are \"\$IPs\"."
                return 0

            else
                # Se não houver nenhum peer estabelecido, grava log apropriado
                write_log "STATUS" "The service status is \"\$exabgp_status\" and do not have peers connected."
                return 0

            fi
        
        else
            write_log "STATUS" "The service status is \"\$exabgp_status\" but there was an error when requesting peers connected."
            return 3

        fi
				
    elif [ \$exa_stat -eq 3 ]; then
        exabgp_status="stopped"
        write_log "STATUS" "The service status is \"\$exabgp_status\"."
        return 1

    else
        exabgp_status="unknown"
        write_log "STATUS" "The service status is \"\$exabgp_status\"."
        return 2

    fi

}

get_bpg_block() {
    systemctl status exabgp.service > /dev/null 2>&1
    exa_stat=\$?
    if [ \$exa_stat -eq 0 ]; then
        exabgp_status="running"
        /usr/local/bin/exabgp-cli show adj-rib out > /dev/null 2>&1
        /usr/local/bin/exabgp-cli show adj-rib out > /dev/null 2>&1

        declare -A peers

        # Simula a saída do comando exabgpcli
        data=\$(/usr/local/bin/exabgp-cli show adj-rib out)

        if [[ -z \$(echo "\$data" | grep -v '^\s*\$') ]]; then
            write_log "INFO" "No announce were identified"
            #echo "No announce were identified"
            exit 0
        fi

        # Processa cada linha
        while IFS= read -r line; do
            neighbor=\$(echo "\$line" | awk '{print \$2}')
            ip=\$(echo "\$line" | awk '{print \$5}' | cut -d/ -f1)
            
            # Se ainda não tiver esse IP na lista do peer, adiciona
            if [[ ! "\${peers[\$neighbor]}" =~ \$ip ]]; then
                peers["\$neighbor"]+="\$ip,"
            fi
        done <<< "\$data"

        # Monta a saída
        output=""
        for peer in "\${!peers[@]}"; do
            # Remove a vírgula final
            ip_list=\${peers[\$peer]%,}
            output+="Peer \$peer Blocklist \$ip_list - "
        done

        # Remove o " - " final e imprime
        write_log "INFO" "\${output::-3}"
        #echo "\${output::-3}"
    
    elif [ \$exa_stat -eq 3 ]; then
        exabgp_status="stopped"
        write_log "STATUS" "The service status is \"\$exabgp_status\"."
        return 1

    else
        exabgp_status="unknown"
        write_log "STATUS" "The service status is \"\$exabgp_status\"."
        return 2

    fi
 
}

check_exabgp_service() {
        write_log "WARNING" "BGP service has restarted"
        return 0

}

# Função para adicionar o bloco ao arquivo de configuração
add_conf() {
    cat >>/etc/exabgp/exabgp.conf<<EOF
neighbor \$1 {
        local-as \$2;
        peer-as \$3;
        router-id \$4;
        local-address \$4;
        family {
            ipv4 unicast;
        }
}

EOF
}

if [ "\$1" = "--announces" ] || [ "\$1" = "-a" ]; then
    get_bpg_block
    exit 0

elif [ "\$1" = "--enable" ] || [ "\$1" = "-e" ]; then
    enable_exabgp_service
    exit 0

elif [ "\$1" = "--restart" ] || [ "\$1" = "-r" ]; then
    restart_exabgp_service
    exit 0

elif [ "\$1" = "--disable" ] || [ "\$1" = "-d" ]; then
    disable_exabgp_service
    exit 0

elif [ "\$1" = "--status" ] || [ "\$1" = "-s" ]; then
    status_exabgp_service
    exit 0

elif [ "\$1" = "--check" ] || [ "\$1" = "-c" ]; then
    check_exabgp_service
    exit 0

elif [ "\$1" = "--block" ] || [ "\$1" = "-b" ]; then
        if [[ -z "\$2" || "\$2" == -* ]]; then
                write_log "ERROR" "Invalid number of arguments"
                exit 1
        fi

        for (( i=2; i<=\$#; i+=1 )); do
            IP=\$i

            IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

            echo "announce route \${!IP} next-hop \$IPLAN" > /run/exabgp/exabgp.in
            
        done
        exit 0

elif [ "\$1" = "--unblock" ] || [ "\$1" = "-u" ]; then
        if [[ -z "\$2" || "\$2" == -* ]]; then
                write_log "ERROR" "Invalid number of arguments"
                exit 1
        fi

        for (( i=2; i<=\$#; i+=1 )); do
            IP=\$i

            IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

            echo "withdraw route \${!IP} next-hop \$IPLAN" > /run/exabgp/exabgp.in

        done
        exit 0
    

else
    # Verifica se o número de argumentos é múltiplo de 3
    if (( \$# % 3 != 0 )); then
        write_log "ERROR" "Invalid number of arguments"
        exit 1
    fi

    # Apaga config atual do exabgp
    echo -n > /etc/exabgp/exabgp.conf

    # Itera sobre os argumentos passados
    for (( i=1; i<=\$#; i+=3 )); do
        IP=\$i
        LOCAL_AS=\$((i + 1))
        PEER_AS=\$((i + 2))

        IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
        add_conf "\${!IP}" "\${!LOCAL_AS}" "\${!PEER_AS}" "\$IPLAN"
    done

    systemctl enable exabgp.service > /dev/null 2>&1
    systemctl start exabgp.service > /dev/null 2>&1
    systemctl restart exabgp.service > /dev/null 2>&1
    if [ \$? -eq 0 ]; then
        write_log "INFO" "BGP configuration updated successfully"
        exit 0
				
    else
        write_log "ERROR" "BGP service was configured but the service failed to be restarted"
        exit 0

    fi

fi

EOG

	cat >/vigilant/scripts/update-exabgp-localip.sh<<EOF
#!/bin/bash

IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

sed -i 's/router-id .*;/router-id '\$IPLAN';/g' /etc/exabgp/exabgp.conf 2>&1 > /dev/null
sed -i 's/local-address .*;/local-address '\$IPLAN';/g' /etc/exabgp/exabgp.conf 2>&1 > /dev/null
systemctl restart exabgp.service

EOF

	sed -i 's/destination =.*/destination = '\''syslog'\''/g' /usr/local/etc/exabgp/exabgp.env
	chmod +x /vigilant/scripts/update-exabgp-config.sh
	chmod +x /vigilant/scripts/update-exabgp-localip.sh
    rm -rf /tmp/exabgp*
    systemctl daemon-reload
	systemctl enable exabgp.service
    cd /root
	echo -e "\nVigilant BGP service configured!\n"

}

configure_iptables_rules (){
	cat > /vigilant/scripts/firewall.sh <<EOF
#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 18/07/2023
#Este script atualiza as configurações do Firewall baseando-se em variaveis.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)

IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
ANALYTICMANAGER="\$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"

sleep 10
iptables -t nat -A PREROUTING -d \$IPLAN -p TCP --dport 1514 -j DNAT --to-destination \$ANALYTICMANAGER
iptables -t nat -A PREROUTING -d \$IPLAN -p TCP --dport 1515 -j DNAT --to-destination \$ANALYTICMANAGER
iptables -t nat -A PREROUTING -d \$IPLAN -p TCP --dport 6514 -j DNAT --to-destination \$ANALYTICMANAGER
iptables -t nat -A PREROUTING -d \$IPLAN -p UDP --dport 1514 -j DNAT --to-destination \$ANALYTICMANAGER
iptables -t nat -A PREROUTING -d \$IPLAN -p UDP --dport 1515 -j DNAT --to-destination \$ANALYTICMANAGER
iptables -t nat -A PREROUTING -d \$IPLAN -p UDP --dport 6514 -j DNAT --to-destination \$ANALYTICMANAGER
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
EOF

	chmod +x /vigilant/scripts/firewall.sh

}

configure_agent_ip (){
	cat > /vigilant/scripts/vigilantagent.sh <<EOF
#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 16/08/2022
#
#Este script atualiza as configurações do agente do vigilant.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)
ANALYTICMANAGER="\$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"
sleep 10
sed -i "s/<address>.*<\/address>/<address>\$ANALYTICMANAGER<\/address>/g" /var/ossec/etc/ossec.conf
sed -i "s/<address>.*<\/address>/<address>\$ANALYTICMANAGER<\/address>/g" /opt/ossec/etc/ossec.conf
systemctl restart wazuh-agent
systemctl restart vigilant-agent
EOF

	chmod +x /vigilant/scripts/vigilantagent.sh

}

configure_crontab (){
	cat > /vigilant/scripts/cron.sh <<EOF
#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 16/08/2022
#
#Este script atualiza as configurações do crontab referente ao usuário root.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)

IPHOMENET="ipvar HOME_NET ""\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
IPLAN="\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
IPVPN="\$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3,4)"
ANALYTICMANAGER="\$(/usr/sbin/ip add | grep "inet " | grep "peer " | cut -d " " -f 6 | cut -d "/" -f 1 | cut -d "." -f 1,2,3).2"

sleep 10

echo '* * * * * root echo "c myvpn" > /var/run/xl2tpd/l2tp-control' > /etc/crontab
echo '* * * * * root /sbin/route add' \$ANALYTICMANAGER 'gw' \$IPVPN >> /etc/crontab
#echo '0 */8 * * * root /usr/sbin/reboot -f' >> /etc/crontab
echo '@reboot root sleep 200 && /usr/bin/systemctl restart snortd' >> /etc/crontab
echo '@reboot root sleep 250 && /usr/bin/systemctl restart dionaea' >> /etc/crontab
echo '@reboot cowrie sleep 300 && /home/cowrie/cowrie/bin/cowrie start' >> /etc/crontab
echo '*/5 * * * * root /vigilant/scripts/cron.sh' >> /etc/crontab
echo '0 */6 * * * root truncate -s 0 /var/log/remotelogs.log' >> /etc/crontab
echo '*/10 * * * * root /vigilant/scripts/update-exabgp-config.sh -s' >> /etc/crontab
EOF

	chmod +x /vigilant/scripts/cron.sh

}

configure_dionaea_timer (){
	cat > /etc/systemd/system/dionaea.timer <<EOF
[Unit]
Description=Inicia Dionaea com atarso

[Timer]
OnBootSec=420s
Unit=dionaea.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable dionaea.timer
}

configure_snort_script (){
	cat > /vigilant/scripts/snort.sh <<EOF
#!/bin/bash
#Vigilant, Inc
#Data da ultima revisao: 07/08/2023
#
#Este script atualiza as configurações do snort.
#Sua execucao acontece durante a inicializacao do sistema (configurado em /etc/rc.local)

IPHOMENET="ipvar HOME_NET ""\$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

sleep 10

sed -i "s/ipvar HOME_NET .*/\$IPHOMENET/g" /etc/snort/snort.conf

systemctl restart snortd > /dev/null 2>&1 || systemctl restart snort > /dev/null 2>&1

EOF

	chmod +x /vigilant/scripts/snort.sh
}

install_interface_sensor (){
	if [ $1 -eq 1 ]; then
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/scripts/login-sensor-2.0.sh /usr/bin/login-sensor.sh
		useradd -m vigilant-interface
		useradd -m vigilant-ssh
		echo -e "vigilant@temp\nvigilant@temp" | passwd "vigilant-ssh"
		echo -e "vigilant-ssh    ALL=(ALL:ALL) ALL" >> /etc/sudoers
	else
		download_start $1 https://files.vigilant.com.br/other/public/ukfgbhjs3kdj7jsbh1jfvbtc9/sensor/scripts/login-sensor-2.0.sh /usr/bin/login-sensor.sh
		useradd -m -s /bin/bash vigilant-interface
		useradd -m -s /bin/bash vigilant-ssh
		echo -e "vigilant@temp\nvigilant@temp" | passwd "vigilant-ssh"
		echo -e "vigilant-ssh    ALL=(ALL:ALL) ALL" >> /etc/sudoers
	fi

	chmod +x /usr/bin/login-sensor.sh
	echo 'vigilant-interface ALL=(root) NOPASSWD: /usr/bin/login-sensor.sh' >> /etc/sudoers
	echo 'sudo login-sensor.sh' >> /home/vigilant-interface/.bashrc
	mkdir /etc/systemd/system/getty@tty1.service.d/
				
	cat > /etc/systemd/system/getty@tty1.service.d/override.conf <<EOF
[Service]
Type=simple
ExecStart=
ExecStart=-/sbin/agetty --autologin vigilant-interface --noclear %I \$TERM
EOF

	touch /vigilant/VERSION_SENSOR
	echo $2 > /vigilant/VERSION_SENSOR

}

collect_user_inputs() {
  echo ""
  echo "╔════════════════════════════════════════════════════════════════════════╗"
  echo "║                  PHASE 1: USER INPUT COLLECTION                        ║"
  echo "║           Please answer all questions before proceeding...             ║"
  echo "╚════════════════════════════════════════════════════════════════════════╝"
  echo ""

  # [INPUT 1] Hostname
  log INFO "[PHASE-1] Collecting hostname..."
  echo ""
  color blue "[INPUT-1/6] Hostname Configuration"
  local _current_host
  _current_host=$(hostname)
  echo "Current hostname: $_current_host"

  if [[ "$_current_host" =~ ^localhost(\.localdomain)?$ ]]; then
    color yellow "[WARN] Hostname is 'localhost' — must be changed before proceeding."
    echo "Suggested pattern: sensor-<your_choice>"
    echo "Examples: sensor-lab01, sensor-client1, sensor-core"
    while true; do
      USER_NEW_HOSTNAME=$(ask_id "Enter new hostname")
      if [[ "$USER_NEW_HOSTNAME" =~ ^localhost(\.localdomain)?$ ]]; then
        color red "[ERROR] Cannot use 'localhost' as hostname. Choose a different name."
        continue
      fi
      break
    done
    color green "[OK] Hostname validated: $USER_NEW_HOSTNAME"
  else
    local _change_host
    _change_host=$(ask_yn "Do you want to change the hostname?")
    if [[ "$_change_host" == "Y" ]]; then
      echo "Suggested pattern: sensor-<your_choice>"
      echo "Examples: sensor-lab01, sensor-client1, sensor-core"
      USER_NEW_HOSTNAME=$(ask_id "Enter new hostname")
      color green "[OK] Hostname validated: $USER_NEW_HOSTNAME"
    else
      USER_NEW_HOSTNAME="$_current_host"
      color yellow "[INFO] Hostname unchanged: $_current_host"
    fi
  fi
  log INFO "[PHASE-1] Hostname collected: $USER_NEW_HOSTNAME"

  # [INPUT 2] Vigilant ID
  echo ""
  color blue "[INPUT-2/6] Agent Registration — Vigilant ID"
  echo "Registration server: $VIGILANT_CORE"
  echo "Agent will be registered in group: sensores"
  VIGILANT_ID=$(ask_id "Enter Vigilant ID")
  color green "[OK] Vigilant ID: $VIGILANT_ID"
  log INFO "[PHASE-1] Vigilant ID collected: $VIGILANT_ID"

  # [INPUT 3] Registration Key
  echo ""
  color blue "[INPUT-3/6] Agent Registration — Key"
  VIGILANT_PASSWORD=$(ask_pass "Enter Key")
  color green "[OK] Key collected"
  log INFO "[PHASE-1] Key collected"

  # [INPUT 4] Shield ID
  echo ""
  color blue "[INPUT-4/6] Shield ID"
  ID_SHIELD=$(ask_id "Enter Shield ID")
  color green "[OK] Shield ID: $ID_SHIELD"
  log INFO "[PHASE-1] Shield ID collected: $ID_SHIELD"

  # [INPUT 5] VPN User ID
  echo ""
  color blue "[INPUT-5/6] VPN User ID"
  echo "This ID was provided by Vigilant (format: SENSOR-Client-UNIT)"
  VPN_USER=$(ask_id "Enter VPN User ID")
  color green "[OK] VPN User ID: $VPN_USER"
  log INFO "[PHASE-1] VPN User ID collected: $VPN_USER"

  # [INPUT 6] VPN Password
  echo ""
  color blue "[INPUT-6/6] VPN Password"
  VPN_PASSWORD=$(ask_pass "Enter VPN Password")
  color green "[OK] VPN Password collected"
  log INFO "[PHASE-1] VPN Password collected"

  # [OPTIONAL] Backup DNS
  echo ""
  color blue "[OPTIONAL] Backup DNS"
  echo "Used automatically if downloads fail after 10 attempts. Default: $BACKUP_DNS"
  local change_dns
  change_dns=$(ask_yn "Do you want to change the backup DNS?")
  if [[ "$change_dns" == "Y" ]]; then
    read -rp "Enter backup DNS address [default: 8.8.8.8]: " BACKUP_DNS < /dev/tty
    if [[ -z "$BACKUP_DNS" ]]; then
      BACKUP_DNS="8.8.8.8"
    fi
    color green "[OK] Backup DNS: $BACKUP_DNS"
  fi
  log INFO "[PHASE-1] Backup DNS: $BACKUP_DNS"

  # Summary
  echo ""
  echo "======================================================================"
  echo "                      SUMMARY OF INPUTS"
  echo "======================================================================"
  echo ""
  echo "  SENSOR CONFIGURATION"
  echo "  • Hostname:         $USER_NEW_HOSTNAME"
  echo "  • VPN User ID:      $VPN_USER"
  echo "  • VPN Password:     $VPN_PASSWORD"
  echo ""
  echo "  AGENT VIGILANT"
  echo "  • Group:            sensores"
  echo "  • Server:           $VIGILANT_CORE"
  echo "  • Vigilant ID:      $VIGILANT_ID"
  echo "  • Key:              $VIGILANT_PASSWORD"
  echo "  • Shield ID:        $ID_SHIELD"
  echo ""
  echo "  NETWORK"
  echo "  • Backup DNS:       $BACKUP_DNS"
  echo ""
  echo "======================================================================"
  echo ""

  local final_confirm
  while true; do
    read -rp "Proceed with Phase 2 (Automated Installation)? (Y/N): " final_confirm < /dev/tty
    final_confirm="${final_confirm^^}"
    if [[ "$final_confirm" != "Y" && "$final_confirm" != "N" ]]; then
      echo -e "\033[1;33m[WARN] Invalid input. Only Y or N allowed.\033[0m"
      continue
    fi
    if [[ "$final_confirm" == "N" ]]; then
      color red "[ABORT] Installation cancelled by user"
      log INFO "[PHASE-1] Installation aborted by user"
      exit 1
    fi
    break
  done

  PHASE_1_COMPLETE=1
  log INFO "[PHASE-1] All inputs collected. Proceeding to Phase 2..."
  color green "[OK] Phase 1 completed. Starting Phase 2 (automated)..."
  echo ""
  sleep 2
}

check_logrotate() {
    local CONF_FILE="${1:-/etc/logrotate.d/remotelogs}"
    local FILE_PATH="${2:-/var/log/remotelogs.log}"
    local LOG_PATH="${3:-/var/log/vigilant.log}"

    if ! command -v logrotate >/dev/null 2>&1; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') - Logrotate-healthcheck Action=Logrotate-not-found-in-the-system" >> "$LOG_PATH"
        return 1
    fi

    if [ ! -f "$CONF_FILE" ]; then
        cp /etc/cron.daily/logrotate /etc/cron.hourly/
        echo "GRAVOUUU" >> "$LOG_PATH"
        
        cat <<EOF > "$CONF_FILE"
$FILE_PATH {
    rotate 1
    size 1G
    compress
    delaycompress
    copytruncate
    missingok
    dateext
    dateformat -%Y%m%d%H%M%s
    su root root
    postrotate
        echo "\$(date '+%Y/%m/%d %H:%M:%S') - Logrotate-healthcheck Action=RemoteLog-Rotated-Successfully." >> "$LOG_PATH"
    endscript
}
EOF
        echo "$(date '+%Y/%m/%d %H:%M:%S') - Logrotate-healthcheck Action=RemoteLog-File-Created" >> "$LOG_PATH"
    fi

    if ! logrotate -v "$CONF_FILE"; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') - Logrotate-healthcheck Action=RemoteLog-File-Creation-Failed" >> "$LOG_PATH"
        return 1
    fi

    return 0
}

VIGILANT_CORE="registry.vigilant.com.br"

[[ $EUID -ne 0 ]] && { echo "Error: Please run the script with root privileges."; exit 2; }

clear
echo -e "         'dddddddddddddddddddddddxxxxxx"
echo -e "          odddddddddddddddddddddddxxxx,"
echo -e "           :ddd.                 :dxx. "
echo -e "looooooooooooodd.               oddd   "
echo -e " oooo        .odd,             oddl    "
echo -e "  ;ooo.        oddddddddddddddddddddddd    ######  ######## ##    ##  ######   #######  ########  "
echo -e "   .ooo.        cod'   ddd.       oddd    ##    ## ##       ###   ## ##    ## ##     ## ##     ## "
echo -e "     ooo;        ;od:.ddd        dddc     ##       ##       ####  ## ##       ##     ## ##     ## "
echo -e "      oooc        'ooddc       .ddd:       ######  ######   ## ## ##  ######  ##     ## ########  "
echo -e "       cooo       .ooo;       'ddd.             ## ##       ##  ####       ## ##     ## ##   ##   "
echo -e "        'ooo.    'ooo.       :ddd         ##    ## ##       ##   ### ##    ## ##     ## ##    ##  "
echo -e "         .ooo,  :ooo,       dddo           ######  ######## ##    ##  ######   #######  ##     ## "
echo -e "           loooooooooc     dddc        "
echo -e "            coooo: oool  .ood,         "
echo -e "             ,oo'   ;ooooooo.          "
echo -e "                     .ooooo            "
echo -e "                       oo:             "

echo ""
echo "===================================================================="
echo "Vigilant Sensor - TWO-PHASE INSTALLER"
echo "Start: $(date '+%d-%m-%Y %H:%M:%S %z')"
echo "===================================================================="
echo ""
echo "[PHASE 1] Collecting user inputs..."
echo "[PHASE 2] Automated installation (no user interaction)"
echo "===================================================================="
echo ""

cp /etc/resolv.conf /etc/resolv.conf.old > /dev/null 2>&1

# =====================================================================
# PHASE 1: USER INPUT (Interactive)
# =====================================================================
collect_user_inputs

# =====================================================================
# PHASE 2: AUTOMATED INSTALLATION (Non-interactive)
# =====================================================================
sleep 1
clear
echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║             PHASE 2: AUTOMATED INSTALLATION IN PROGRESS                ║"
echo "║                 *** NO USER INTERACTION REQUIRED ***                   ║"
echo "║                    Please wait for completion...                       ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
log INFO "[PHASE-2] Automated installation starting..."

trap ignore_sigint SIGINT

VERSION_SENSOR="1.1.2"

COLETA_INTERFACE=$(ip a |grep -E "ens|eth|enp" |cut -d " " -f2 |cut -d ":" -f1 | grep -E "ens|eth|enp")

###### Início da configuração em Rocky Linux #######
if cat /etc/*rele* |grep -m 1 'NAME="' |awk -F'=' '{ print $2 }' |grep -i -E 'Rocky' > /dev/null && cat /etc/*rele* |grep -m 1 'VERSION="8.' > /dev/null; then
	DISTRO="1"

	cd /root
	echo -e "Rocky Linux\n"
	alter_hostname
	install_prerequisites_rocky $DISTRO
	disable_firewalld_and_selinux
	configure_vpn
	configure_ssh_and_httpd
	install_vigilantagent $DISTRO
	configure_dionaea_on_rocky $DISTRO
	configure_dionaea_timer
	configure_cowrie_on_rocky $DISTRO
	configure_snort_on_rocky $DISTRO
	configure_bettercap $DISTRO
	configure_rsyslog
	configure_exabgp $DISTRO
	configure_network_manager_on_rocky $COLETA_INTERFACE
	configure_iptables_rules
	configure_agent_ip
	configure_crontab
	configure_snort_script
	configure_rclocal
	check_logrotate
	install_interface_sensor $DISTRO $VERSION_SENSOR

	nmcli con mod $COLETA_INTERFACE ipv6.method disabled

	log INFO "[END] Installation completed. Rebooting..."
	echo -e "\nInstallation completed! Restarting the system on..."
	sleep 1
	echo -e "3"
	sleep 1
	echo -e "2"
	sleep 1
	echo -e "1"
	sleep 1
	echo -e "Restarting..."
	reboot
	exit 0

######### Início da configuração em Debian ##########
# elif cat /etc/*rele* |grep -m 1 'NAME="' |awk -F'=' '{ print $2 }' |grep -i -E 'Debian' > /dev/null && cat /etc/*rele* |grep -m 1 'VERSION="11.' > /dev/null; then
# 	DISTRO="2"
#
# 	cd /root
# 	echo -e "Debian\n"
# 	alter_hostname
# 	install_prerequisites_debian $DISTRO
# 	configure_vpn
# 	configure_ssh_and_httpd
# 	install_vigilantagent $DISTRO
# 	configure_dionaea_on_debian $DISTRO
# 	configure_cowrie_on_debian $DISTRO
# 	configure_snort_on_debian $DISTRO
# 	configure_bettercap $DISTRO
# 	configure_rsyslog
# 	configure_exabgp $DISTRO
# 	configure_network_manager_on_debian $COLETA_INTERFACE
# 	configure_iptables_rules
# 	configure_agent_ip
# 	configure_crontab
# 	configure_snort_script
# 	configure_rclocal
# 	install_interface_sensor $DISTRO $VERSION_SENSOR
#
# 	nmcli con mod $COLETA_INTERFACE ipv6.method disabled
#
# 	echo -e "Installation completed! Restarting the system on..."
# 	sleep 1
# 	echo -e "3"
# 	sleep 1
# 	echo -e "2"
# 	sleep 1
# 	echo -e "1"
# 	sleep 1
# 	echo -e "Restarting..."
# 	reboot
# 	exit 0

else
	echo "Error: Operating system not supported, please contact our support."
	exit 3
fi
