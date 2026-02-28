#!/bin/bash

#Função para escrita de log
write_log () {
    local destination_log="/var/log/vigilant.log"
    local software="EXABGP"
    local tipo="$1"
    local mensagem="$2"
    local datahora=$(date +'%d-%m-%Y %H:%M:%S')

    echo "$datahora $software $tipo: $mensagem" >> "$destination_log"
}

enable_exabgp_service() {
    systemctl enable exabgp.service > /dev/null 2>&1
    systemctl start exabgp.service > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        write_log "INFO" "BGP service started successfully"
        return 0
    else
        write_log "ERROR" "Failed to start BGP service"
        return 1
    fi

}

restart_exabgp_service() {
    systemctl restart exabgp.service > /dev/null 2>&1
    if [ $? -eq 0 ]; then
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
    if [ $? -eq 0 ]; then
        write_log "INFO" "BGP service stopped successfully"
        return 0
    else
        write_log "ERROR" "Failed to stop BGP service"
        return 1
    fi

}

status_exabgp_service (){
    systemctl status exabgp.service > /dev/null 2>&1
    exa_stat=$?
    if [ $exa_stat -eq 0 ]; then
        exabgp_status="running"
        /usr/local/bin/exabgp-cli show neighbor summary > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            list_peers=$(/usr/local/bin/exabgp-cli show neighbor summary)

            # Verifica se há peers estabelecidos
            if [[ $(echo "$list_peers" | grep -c "established") -gt 0 ]]; then
                # Extrai os IPs dos peers estabelecidos e os separa por vírgula
                IPs=$(echo "$list_peers" | awk '/established/{print $1}' | tr '\n' ',' | sed 's/,$//')
                write_log "STATUS" "The service status is \"$exabgp_status\" and active connections are \"$IPs\"."
                return 0

            else
                # Se não houver nenhum peer estabelecido, grava log apropriado
                write_log "STATUS" "The service status is \"$exabgp_status\" and do not have peers connected."
                return 0

            fi
        
        else
            write_log "STATUS" "The service status is \"$exabgp_status\" but there was an error when requesting peers connected."
            return 3

        fi
				
    elif [ $exa_stat -eq 3 ]; then
        exabgp_status="stopped"
        write_log "STATUS" "The service status is \"$exabgp_status\"."
        return 1

    else
        exabgp_status="unknown"
        write_log "STATUS" "The service status is \"$exabgp_status\"."
        return 2

    fi

}

get_bpg_block() {
    systemctl status exabgp.service > /dev/null 2>&1
    exa_stat=$?
    if [ $exa_stat -eq 0 ]; then
        exabgp_status="running"
        /usr/local/bin/exabgp-cli show adj-rib out > /dev/null 2>&1
        /usr/local/bin/exabgp-cli show adj-rib out > /dev/null 2>&1

        declare -A peers

        # Simula a saída do comando exabgpcli
        data=$(/usr/local/bin/exabgp-cli show adj-rib out)

        if [[ -z $(echo "$data" | grep -v '^\s*$') ]]; then
            write_log "INFO" "No announce were identified"
            #echo "No announce were identified"
            exit 0
        fi

        # Processa cada linha
        while IFS= read -r line; do
            neighbor=$(echo "$line" | awk '{print $2}')
            ip=$(echo "$line" | awk '{print $5}' | cut -d/ -f1)
            
            # Se ainda não tiver esse IP na lista do peer, adiciona
            if [[ ! "${peers[$neighbor]}" =~ $ip ]]; then
                peers["$neighbor"]+="$ip,"
            fi
        done <<< "$data"

        # Monta a saída
        output=""
        for peer in "${!peers[@]}"; do
            # Remove a vírgula final
            ip_list=${peers[$peer]%,}
            output+="Peer $peer Blocklist $ip_list - "
        done

        # Remove o " - " final e imprime
        write_log "INFO" "${output::-3}"
        #echo "${output::-3}"
    
    elif [ $exa_stat -eq 3 ]; then
        exabgp_status="stopped"
        write_log "STATUS" "The service status is \"$exabgp_status\"."
        return 1

    else
        exabgp_status="unknown"
        write_log "STATUS" "The service status is \"$exabgp_status\"."
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
neighbor $1 {
        local-as $2;
        peer-as $3;
        router-id $4;
        local-address $4;
        family {
            ipv4 unicast;
        }
}

EOF
}

if [ "$1" = "--announces" ] || [ "$1" = "-a" ]; then
    get_bpg_block
    exit 0

elif [ "$1" = "--enable" ] || [ "$1" = "-e" ]; then
    enable_exabgp_service
    exit 0

elif [ "$1" = "--restart" ] || [ "$1" = "-r" ]; then
    restart_exabgp_service
    exit 0

elif [ "$1" = "--disable" ] || [ "$1" = "-d" ]; then
    disable_exabgp_service
    exit 0

elif [ "$1" = "--status" ] || [ "$1" = "-s" ]; then
    status_exabgp_service
    exit 0

elif [ "$1" = "--check" ] || [ "$1" = "-c" ]; then
    check_exabgp_service
    exit 0

elif [ "$1" = "--block" ] || [ "$1" = "-b" ]; then
        if [[ -z "$2" || "$2" == -* ]]; then
                write_log "ERROR" "Invalid number of arguments"
                exit 1
        fi

        for (( i=2; i<=$#; i+=1 )); do
            IP=$i

            IPLAN="$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

            echo "announce route ${!IP} next-hop $IPLAN" > /run/exabgp/exabgp.in
            
        done
        exit 0

elif [ "$1" = "--unblock" ] || [ "$1" = "-u" ]; then
        if [[ -z "$2" || "$2" == -* ]]; then
                write_log "ERROR" "Invalid number of arguments"
                exit 1
        fi

        for (( i=2; i<=$#; i+=1 )); do
            IP=$i

            IPLAN="$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"

            echo "withdraw route ${!IP} next-hop $IPLAN" > /run/exabgp/exabgp.in

        done
        exit 0
    

else
    # Verifica se o número de argumentos é múltiplo de 3
    if (( $# % 3 != 0 )); then
        write_log "ERROR" "Invalid number of arguments"
        exit 1
    fi

    # Apaga config atual do exabgp
    echo -n > /etc/exabgp/exabgp.conf

    # Itera sobre os argumentos passados
    for (( i=1; i<=$#; i+=3 )); do
        IP=$i
        LOCAL_AS=$((i + 1))
        PEER_AS=$((i + 2))

        IPLAN="$(/usr/sbin/ip add | grep "inet " | grep "brd " | cut -d " " -f 6 | cut -d "/" -f 1)"
        add_conf "${!IP}" "${!LOCAL_AS}" "${!PEER_AS}" "$IPLAN"
    done

    systemctl enable exabgp.service > /dev/null 2>&1
    systemctl start exabgp.service > /dev/null 2>&1
    systemctl restart exabgp.service > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        write_log "INFO" "BGP configuration updated successfully"
        exit 0
				
    else
        write_log "ERROR" "BGP service was configured but the service failed to be restarted"
        exit 0

    fi

fi

