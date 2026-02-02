#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\e[36m'
MAGENTA="\e[95m"
NC='\033[0m' # No Color

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   sleep 1
   exit 1
fi

# Configuration directories
CONFIG_DIR="/root/iranbaxtunnel"
RATHOLE_CORE_DIR="${CONFIG_DIR}/rathole-core"
mkdir -p "$CONFIG_DIR"

# Function to check and install dependencies
ensure_deps() {
    local deps=("curl" "jq" "unzip" "iptables" "ssh" "bc" "openssl")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Missing dependencies: ${missing_deps[*]}. Installing...${NC}"
        # Check if apt-get is available
        if command -v apt-get &> /dev/null; then
            # We only run apt update if absolutely necessary, but actually for installing new packages we usually should.
            # However, the user said "without apt update and only install requirements if needs".
            # I will try installing without update first.
            sudo apt-get install -y "${missing_deps[@]}" || {
                echo -e "${YELLOW}First attempt failed. Trying with apt-get update...${NC}"
                sudo apt-get update
                sudo apt-get install -y "${missing_deps[@]}"
            }
        else
            echo -e "${RED}Error: Package manager not found. Please install manually: ${missing_deps[*]}${NC}"
            exit 1
        fi
    fi
}

# Run dependency check
ensure_deps

# Function to display ASCII logo
display_logo() {
    echo -e "${CYAN}"
    cat << "EOF"
               __  .__           .__
____________ _/  |_|  |__   ____ |  |   ____
\_  __ \__  \\   __|  |  \ /  _ \|  | _/ __ \
 |  | \// __ \|  | |   Y  (  <_> |  |_\  ___/
 |__|  (____  |__| |___|  /\____/|____/\___  >
            \/          \/                 \/
EOF
    echo -e "${NC}${GREEN}"
    echo -e "${YELLOW}Unified IRANBAX Tunneling System${GREEN}"
    echo -e "Version: ${YELLOW}v2.0.0${GREEN}"
    echo -e "Features: Rathole, SIT/GRE, SSH Tunneling${NC}"
}

# Function to display main menu
display_menu() {
    clear
    display_logo
    echo ''
    echo -e "${CYAN}1. Tunneling Management (Rathole, SIT/GRE, SSH, Status)${NC}"
    echo -e "${YELLOW}2. Service & System Management (Optimizations, Restarts)${NC}"
    echo -e "${GREEN}3. Installation Proxy (SSH Reverse for Setup)${NC}"
    echo -e "${RED}4. Remove All Tunnels & Cleanup${NC}"
    echo -e "5. Update Script"
    echo -e "0. Exit"
    echo ''
    echo "-------------------------------"
}

manage_tunnels() {
    while true; do
        clear
        display_logo
        echo -e "${CYAN}--- Tunneling Management ---${NC}"
        echo -e "1. Rathole Tunnel"
        echo -e "2. SIT/GRE (Tunnel Wizard)"
        echo -e "3. SSH Traffic Tunnel"
        echo -e "4. Check All Tunnel Status"
        echo -e "5. Back"
        echo ''
        read -p "Choose an option: " t_choice
        case $t_choice in
            1) manage_rathole ;;
            2) manage_sit_gre ;;
            3) manage_ssh_tunnel ;;
            4) check_status ;;
            5) break ;;
            *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
        esac
    done
}

manage_services() {
    while true; do
        clear
        display_logo
        echo -e "${YELLOW}--- Service & System Management ---${NC}"
        echo -e "1. System Optimizations (BBR, Limits)"
        echo -e "2. Restart All Services"
        echo -e "3. Back"
        echo ''
        read -p "Choose an option: " s_choice
        case $s_choice in
            1) system_optimizations ;;
            2) restart_all ;;
            3) break ;;
            *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
        esac
    done
}

# --- Rathole Logic ---

# Global Variables for Rathole
RATHOLE_BIN="${RATHOLE_CORE_DIR}/rathole"
IRAN_RATHOLE_CONFIG="${CONFIG_DIR}/rathole_server.toml"
IRAN_RATHOLE_SERVICE="rathole-iran.service"

# Function to check if a given string is a valid IPv6 address
check_ipv6() {
    local ip=$1
    ipv6_pattern="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    ip="${ip#[}"
    ip="${ip%]}"
    if [[ $ip =~ $ipv6_pattern ]]; then return 0; else return 1; fi
}

download_rathole() {
    if [[ -f "$RATHOLE_BIN" ]]; then
        echo -e "${GREEN}Rathole already installed.${NC}"
        return 0
    fi
    mkdir -p "$RATHOLE_CORE_DIR"
    ARCH=$(uname -m)
    # Map ARCH to rathole naming
    case "$ARCH" in
        x86_64) R_ARCH="x86_64" ;;
        aarch64) R_ARCH="aarch64" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; return 1 ;;
    esac

    # Add github entry to /etc/hosts to help with DNS issues in Iran
    ENTRY="185.199.108.133 raw.githubusercontent.com"
    if ! grep -q "$ENTRY" /etc/hosts; then
        echo "$ENTRY" >> /etc/hosts
    fi

    echo -e "${CYAN}Fetching latest Rathole version...${NC}"
    DOWNLOAD_URL=$(curl -sSL https://api.github.com/repos/rathole-org/rathole/releases/latest | grep -oP "https://github.com/rathole-org/rathole/releases/download/[v\d.]+/rathole-$R_ARCH-unknown-linux-(gnu|musl)\.zip" | head -n 1)

    if [ -z "$DOWNLOAD_URL" ]; then
        echo -e "${RED}Failed to retrieve download URL. Try setting up the Installation Proxy (Option 5).${NC}"
        return 1
    fi

    DOWNLOAD_DIR=$(mktemp -d)
    curl -sSL -o "$DOWNLOAD_DIR/rathole.zip" "$DOWNLOAD_URL"
    unzip -q "$DOWNLOAD_DIR/rathole.zip" -d "$RATHOLE_CORE_DIR"
    chmod +x "$RATHOLE_BIN"
    rm -rf "$DOWNLOAD_DIR"
    echo -e "${GREEN}Rathole installed successfully.${NC}"
}

manage_rathole() {
    clear
    display_logo
    echo -e "${CYAN}--- Rathole Tunnel Management ---${NC}"
    echo -e "1. Install Rathole Binary"
    echo -e "2. Configure IRAN Server (Server Role)"
    echo -e "3. Configure KHAREJ Server (Client Role)"
    echo -e "4. Change Security Token"
    echo -e "5. Back"
    echo ''
    read -p "Choose an option: " r_choice

    case $r_choice in
        1) download_rathole; sleep 1 ;;
        2) rathole_iran_config ;;
        3) rathole_kharej_config ;;
        4) rathole_change_token ;;
        *) return ;;
    esac
}

rathole_iran_config() {
    check_install_proxy
    if [[ ! -f "$RATHOLE_BIN" ]]; then echo -e "${RED}Install Rathole first!${NC}"; sleep 1; return; fi
    clear
    echo -e "${YELLOW}Configuring IRAN server for Rathole...${NC}"
    read -p "Enter the tunnel port (the port Rathole listens on): " tunnel_port
    read -p "Enter number of services/ports to tunnel: " num_ports

    ports=()
    for ((i=1; i<=$num_ports; i++)); do
        read -p "Enter Service Port $i: " p
        ports+=("$p")
    done

    read -p "Use IPv6? (y/n): " use_ipv6
    local_ip="0.0.0.0"
    [[ "$use_ipv6" == "y" ]] && local_ip="[::]"

    cat << EOF > "$IRAN_RATHOLE_CONFIG"
[server]
bind_addr = "${local_ip}:${tunnel_port}"
default_token = "iranbax_tunnel"
heartbeat_interval = 20

[server.transport]
type = "tcp"
[server.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8
EOF

    for p in "${ports[@]}"; do
        cat << EOF >> "$IRAN_RATHOLE_CONFIG"
[server.services.${p}]
type = "tcp"
bind_addr = "${local_ip}:${p}"
EOF
    done

    # Service File
    cat << EOF > "/etc/systemd/system/${IRAN_RATHOLE_SERVICE}"
[Unit]
Description=Rathole Server (Iran)
After=network.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
ExecStart=${RATHOLE_BIN} ${IRAN_RATHOLE_CONFIG}
Restart=always
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$IRAN_RATHOLE_SERVICE"
    systemctl restart "$IRAN_RATHOLE_SERVICE"
    echo -e "${GREEN}Rathole IRAN server started!${NC}"
    sleep 2
}

rathole_kharej_config() {
    check_install_proxy
    if [[ ! -f "$RATHOLE_BIN" ]]; then echo -e "${RED}Install Rathole first!${NC}"; sleep 1; return; fi
    clear
    echo -e "${CYAN}Configuring KHAREJ server for Rathole...${NC}"
    read -p "How many IRAN servers to connect to? " server_num

    # Cleanup old services
    for svc in $(systemctl list-units --type=service --all | grep -oE 'rathole-kharej-s[0-9]+\.service'); do
        systemctl stop "$svc" >/dev/null 2>&1
        systemctl disable "$svc" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$svc"
    done

    for ((j=1; j<=$server_num; j++)); do
        echo -e "${YELLOW}Server $j:${NC}"
        read -p "  Enter IRAN Server IP: " iran_ip
        read -p "  Enter IRAN Tunnel Port: " tunnel_port
        read -p "  Enter number of services: " num_ports

        ports=()
        for ((i=1; i<=$num_ports; i++)); do
            read -p "    Enter Local Port $i: " p
            ports+=("$p")
        done

        local_ip="0.0.0.0"
        check_ipv6 "$iran_ip" && local_ip="[::]"

        config_file="${CONFIG_DIR}/rathole_client_s${j}.toml"
        cat << EOF > "$config_file"
[client]
remote_addr = "${iran_ip}:${tunnel_port}"
default_token = "iranbax_tunnel"
heartbeat_timeout = 40
retry_interval = 5

[client.transport]
type = "tcp"
[client.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8
EOF

        for p in "${ports[@]}"; do
            cat << EOF >> "$config_file"
[client.services.${p}]
type = "tcp"
local_addr = "${local_ip}:${p}"
EOF
        done

        service_name="rathole-kharej-s${j}.service"
        cat << EOF > "/etc/systemd/system/${service_name}"
[Unit]
Description=Rathole Client (Kharej) - Tunnel ${j}
After=network.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
ExecStart=${RATHOLE_BIN} ${config_file}
Restart=always
RestartSec=5s
LimitNOFILE=1048576
LimitNPROC=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF
    done

    systemctl daemon-reload
    for ((j=1; j<=$server_num; j++)); do
        systemctl enable "rathole-kharej-s${j}.service"
        systemctl restart "rathole-kharej-s${j}.service"
    done
    echo -e "${GREEN}Rathole KHAREJ tunnels started!${NC}"
    sleep 2
}

rathole_change_token() {
    read -p "Enter new Security Token: " new_token
    [[ -z "$new_token" ]] && return
    sed -i "s/default_token = \".*\"/default_token = \"$new_token\"/g" ${CONFIG_DIR}/rathole_*.toml
    echo -e "${YELLOW}Token updated in config files. Restarting services...${NC}"
    restart_all
}

# --- SIT/GRE Logic ---

# Constants for SIT/GRE
TUNNEL_6TO4="tun6to4"
TUNNEL_GRE="gre1"
TABLE_ID=4

detect_interface() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    [[ -z "$interface" ]] && interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
    echo "$interface"
}

manage_sit_gre() {
    clear
    display_logo
    local main_iface=$(detect_interface)
    echo -e "${BLUE}--- SIT/GRE Tunnel Management (Tunnel Wizard) ---${NC}"
    echo -e "Main Interface: ${YELLOW}$main_iface${NC}"
    echo ''
    echo -e "1. Setup IRAN Server (Relay)"
    echo -e "2. Setup KHAREJ Server (Endpoint)"
    echo -e "3. Remove SIT/GRE Tunnel"
    echo -e "4. Back"
    echo ''
    read -p "Choose an option: " s_choice

    case $s_choice in
        1) setup_sit_gre "iran" "$main_iface" ;;
        2) setup_sit_gre "kharej" "$main_iface" ;;
        3) remove_sit_gre ;;
        *) return ;;
    esac
}

setup_sit_gre() {
    check_install_proxy
    local role=$1
    local main_iface=$2

    read -p "Enter Remote Server Public IP: " remote_ip
    read -p "Enter IPv6 Prefix (default: fd01::): " prefix
    prefix=${prefix:-"fd01::"}

    # Modules
    modprobe sit
    modprobe ip6_gre

    # Cleanup old
    ip tunnel del "$TUNNEL_GRE" 2>/dev/null
    ip tunnel del "$TUNNEL_6TO4" 2>/dev/null

    if [[ "$role" == "iran" ]]; then
        local_v6="${prefix}2"
        remote_v6="${prefix}1"
        local_v4_tun="172.16.0.2/30"
        remote_v4_tun="172.16.0.1"
    else
        local_v6="${prefix}1"
        remote_v6="${prefix}2"
        local_v4_tun="172.16.0.1/30"
        remote_v4_tun="172.16.0.2"
    fi

    # SIT
    ip tunnel add "$TUNNEL_6TO4" mode sit ttl 254 remote "$remote_ip"
    ip link set dev "$TUNNEL_6TO4" up
    ip addr add "${local_v6}/64" dev "$TUNNEL_6TO4"
    ip link set dev "$TUNNEL_6TO4" mtu 1480

    # GRE
    ip tunnel add "$TUNNEL_GRE" mode ip6gre remote "$remote_v6" local "$local_v6"
    ip link set "$TUNNEL_GRE" up
    ip addr add "$local_v4_tun" dev "$TUNNEL_GRE"
    ip link set dev "$TUNNEL_GRE" mtu 1476

    # Routing & NAT
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Cleanup old iptables rules
    iptables -t nat -S | grep "tunnel_wizard" | sed 's/-A/-D/' | while read line; do iptables -t nat $line 2>/dev/null; done

    if [[ "$role" == "iran" ]]; then
        ip route add default via "$remote_v4_tun" table $TABLE_ID 2>/dev/null || ip route replace default via "$remote_v4_tun" table $TABLE_ID
        iptables -t nat -A PREROUTING -p tcp --dport 22 -m comment --comment "tunnel_wizard" -j ACCEPT
        iptables -t nat -A PREROUTING -p tcp --dport 1:65535 -m comment --comment "tunnel_wizard" -j DNAT --to-destination "$remote_v4_tun"
        iptables -t nat -A PREROUTING -p udp --dport 1:65535 -m comment --comment "tunnel_wizard" -j DNAT --to-destination "$remote_v4_tun"
        iptables -t nat -A POSTROUTING -m comment --comment "tunnel_wizard" -j MASQUERADE
    else
        ip route add default via "$remote_v4_tun" table $TABLE_ID 2>/dev/null || ip route replace default via "$remote_v4_tun" table $TABLE_ID
        ip rule del from 172.16.0.0/30 table $TABLE_ID 2>/dev/null
        ip rule add from 172.16.0.0/30 table $TABLE_ID
        iptables -t nat -A POSTROUTING -s 172.16.0.0/30 -m comment --comment "tunnel_wizard" -j MASQUERADE
    fi

    echo -e "${GREEN}SIT/GRE Tunnel Established!${NC}"
    sleep 2
}

remove_sit_gre() {
    echo -e "${YELLOW}Removing SIT/GRE Tunnels...${NC}"
    iptables -t nat -S | grep "tunnel_wizard" | sed 's/-A/-D/' | while read line; do iptables -t nat $line 2>/dev/null; done
    ip rule del from 172.16.0.0/30 table $TABLE_ID 2>/dev/null
    ip route flush table $TABLE_ID 2>/dev/null
    ip tunnel del "$TUNNEL_GRE" 2>/dev/null
    ip tunnel del "$TUNNEL_6TO4" 2>/dev/null
    echo -e "${GREEN}Done.${NC}"
    sleep 1
}
# --- SSH Traffic Tunnel Logic ---

manage_ssh_tunnel() {
    clear
    display_logo
    echo -e "${MAGENTA}--- SSH Traffic Tunnel Management ---${NC}"
    echo -e "1. Setup Local Port Forward (Iran -> Kharej)"
    echo -e "2. Setup Remote Port Forward (Kharej -> Iran)"
    echo -e "3. Remove SSH Tunnels"
    echo -e "4. Back"
    echo ''
    read -p "Choose an option: " s_choice

    case $s_choice in
        1) setup_ssh_traffic "local" ;;
        2) setup_ssh_traffic "remote" ;;
        3) remove_ssh_traffic ;;
        *) return ;;
    esac
}

setup_ssh_traffic() {
    check_install_proxy
    local type=$1
    read -p "Enter Target Server IP: " target_ip
    read -p "Enter SSH Username (default: root): " ssh_user
    ssh_user=${ssh_user:-root}
    read -p "Enter SSH Port (default: 22): " ssh_port
    ssh_port=${ssh_port:-22}
    read -p "Enter IRAN Port to listen on: " iran_port
    read -p "Enter KHAREJ Port to connect to: " kharej_port

    echo -e "${YELLOW}Establishing persistent SSH tunnel via Systemd...${NC}"
    echo -e "${CYAN}Note: It's highly recommended to setup SSH Keys for passwordless access.${NC}"

    local service_name="ssh-tunnel-${iran_port}.service"
    local ssh_cmd=""

    if [[ "$type" == "local" ]]; then
        # Local: Iran listens on iran_port and forwards to Kharej:kharej_port
        ssh_cmd="ssh -N -L 0.0.0.0:${iran_port}:localhost:${kharej_port} -p ${ssh_port} ${ssh_user}@${target_ip}"
    else
        # Remote: Iran listens on iran_port and traffic goes to Kharej:kharej_port (command run on Kharej)
        ssh_cmd="ssh -N -R ${iran_port}:localhost:${kharej_port} -p ${ssh_port} ${ssh_user}@${target_ip}"
    fi

    cat << EOF > "/etc/systemd/system/${service_name}"
[Unit]
Description=SSH Tunnel ${type} ${iran_port}->${kharej_port}
After=network.target

[Service]
Type=simple
ExecStart=${ssh_cmd}
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$service_name"
    systemctl restart "$service_name"

    echo -e "${GREEN}SSH Tunnel Service ${service_name} created and started!${NC}"
    sleep 2
}

remove_ssh_traffic() {
    echo -e "${YELLOW}Removing SSH Traffic Tunnels...${NC}"
    for svc in $(systemctl list-units --type=service --all | grep -oE 'ssh-tunnel-[0-9]+\.service'); do
        systemctl stop "$svc"
        systemctl disable "$svc"
        rm -f "/etc/systemd/system/$svc"
    done
    systemctl daemon-reload
    echo -e "${GREEN}Done.${NC}"
    sleep 1
}
# --- System Optimizations Logic ---

system_optimizations() {
    clear
    display_logo
    echo -e "${YELLOW}--- System & Network Optimizations ---${NC}"
    echo -e "This will apply BBR, increase file limits, and optimize TCP settings."
    echo ''
    echo -e "1. Apply All Optimizations (Ubuntu/Debian)"
    echo -e "2. Back"
    echo ''
    read -p "Choose an option: " opt_choice

    if [[ "$opt_choice" == "1" ]]; then
        echo -e "${CYAN}Applying optimizations...${NC}"

        # 1. Sysctl optimizations
        cat << EOF > /etc/sysctl.d/99-iranbaxtunnel.conf
fs.file-max = 67108864
net.core.default_qdisc = fq_codel
net.core.netdev_max_backlog = 32768
net.core.optmem_max = 262144
net.core.somaxconn = 65536
net.core.rmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_max = 33554432
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 16384 1048576 33554432
net.ipv4.tcp_wmem = 16384 1048576 33554432
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fin_timeout = 25
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 7
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_orphans = 819200
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_mem = 65536 1048576 33554432
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 32768
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.udp_mem = 65536 1048576 33554432
vm.min_free_kbytes = 65536
vm.swappiness = 10
vm.vfs_cache_pressure = 250
EOF
        sysctl --system

        # 2. Limits optimizations
        if ! grep -q "iranbaxtunnel" /etc/security/limits.conf; then
            cat << EOF >> /etc/security/limits.conf

# iranbaxtunnel limits
* soft nofile 1048576
* hard nofile 1048576
* soft nproc unlimited
* hard nproc unlimited
EOF
        fi

        echo -e "${GREEN}Optimizations applied! A reboot is recommended for all changes to take effect.${NC}"
        sleep 2
    fi
}
clear_proxy() {
    unset http_proxy
    unset https_proxy
    sudo rm -f /etc/apt/apt.conf.d/99proxy
    # Kill the SSH tunnel if running on port 1080
    pkill -f "ssh -D 1080"
    echo -e "${GREEN}Proxy settings cleared.${NC}"
}

check_install_proxy() {
    if pgrep -f "ssh -D 1080" > /dev/null; then
        echo -e "${YELLOW}Warning: Installation Proxy (port 1080) is currently active.${NC}"
        read -p "Do you want to remove it before configuring the tunnel? (y/n): " rm_proxy
        if [[ "$rm_proxy" == "y" ]]; then
            clear_proxy
            sleep 1
        fi
    fi
}

installation_proxy() {
    clear
    display_logo
    echo -e "${YELLOW}--- Installation Proxy Settings ---${NC}"
    echo -e "This helps if your server (Iran) cannot reach GitHub or foreign sites."
    echo ''
    echo -e "1. Set Up SSH SOCKS5 Proxy"
    echo -e "2. Clear Proxy Settings"
    echo -e "3. Back"
    echo ''
    read -p "Choose an option: " proxy_choice

    case $proxy_choice in
        1)
            read -p "Enter Foreign Server IP: " proxy_ip
            read -p "Enter SSH Username (default: root): " proxy_user
            proxy_user=${proxy_user:-root}
            read -p "Enter SSH Port (default: 22): " proxy_port
            proxy_port=${proxy_port:-22}

            echo -e "${CYAN}Establishing SSH tunnel... You may be prompted for password.${NC}"
            # Start SSH Dynamic Forwarding in background
            ssh -D 1080 -C -N -f -p "$proxy_port" "${proxy_user}@${proxy_ip}"

            if [ $? -eq 0 ]; then
                export http_proxy="socks5h://127.0.0.1:1080"
                export https_proxy="socks5h://127.0.0.1:1080"
                echo 'Acquire::http::Proxy "socks5h://127.0.0.1:1080/"; Acquire::https::Proxy "socks5h://127.0.0.1:1080/";' | sudo tee /etc/apt/apt.conf.d/99proxy > /dev/null
                echo -e "${GREEN}Proxy established! http_proxy/https_proxy set to socks5h://127.0.0.1:1080${NC}"
            else
                echo -e "${RED}Failed to establish SSH tunnel.${NC}"
            fi
            sleep 2
            ;;
        2)
            clear_proxy
            sleep 2
            ;;
        *) return ;;
    esac
}
cleanup_all() {
    echo -e "${RED}--- Destroying All Tunnels & Cleaning Up ---${NC}"

    # 1. Rathole
    echo -e "${YELLOW}Stopping Rathole services...${NC}"
    systemctl stop "rathole-*" 2>/dev/null
    systemctl disable "rathole-*" 2>/dev/null
    rm -f /etc/systemd/system/rathole-*.service

    # 2. SIT/GRE
    remove_sit_gre

    # 3. SSH Traffic
    remove_ssh_traffic

    # 4. Files
    echo -e "${YELLOW}Removing configuration files...${NC}"
    rm -rf "$CONFIG_DIR"

    # 5. Proxies
    clear_proxy

    systemctl daemon-reload
    echo -e "${GREEN}All tunnels destroyed and files cleaned up!${NC}"
    sleep 2
}

check_status() {
    clear
    display_logo
    echo -e "${CYAN}--- All Tunnels Status ---${NC}"
    echo ''
    echo -e "${YELLOW}[Rathole]${NC}"
    systemctl list-units --type=service --all | grep "rathole" || echo "No Rathole services."
    echo ''
    echo -e "${BLUE}[SIT/GRE]${NC}"
    ip link show "$TUNNEL_6TO4" 2>/dev/null && echo -e "${GREEN}SIT OK${NC}" || echo "SIT Offline"
    ip link show "$TUNNEL_GRE" 2>/dev/null && echo -e "${GREEN}GRE OK${NC}" || echo "GRE Offline"
    echo ''
    echo -e "${MAGENTA}[SSH Tunnels]${NC}"
    systemctl list-units --type=service --all | grep "ssh-tunnel" || echo "No SSH tunnels."
    echo ''
    read -p "Press Enter to continue..."
}

restart_all() {
    echo -e "${YELLOW}Restarting all services...${NC}"
    systemctl restart "rathole-*" 2>/dev/null
    systemctl restart "ssh-tunnel-*" 2>/dev/null
    echo -e "${GREEN}Done.${NC}"
    sleep 1
}

update_script() {
    echo -e "${CYAN}Updating script...${NC}"
    # Target URL for updates
    local script_url="https://raw.githubusercontent.com/Musixal/rathole-tunnel/main/iranbaxtunnel.sh"
    local temp_file="/tmp/iranbaxtunnel_new.sh"

    echo -e "Downloading latest version from ${script_url}..."
    if curl -sSL -o "$temp_file" "$script_url"; then
        chmod +x "$temp_file"
        # Check if the download was successful and not an error page
        if grep -q "display_logo" "$temp_file"; then
            mv "$temp_file" "$0"
            echo -e "${GREEN}Update successful! Please restart the script.${NC}"
            exit 0
        else
            echo -e "${RED}Update failed: Downloaded file seems invalid.${NC}"
            rm -f "$temp_file"
        fi
    else
        echo -e "${RED}Update failed: Could not download the script.${NC}"
        echo -e "${YELLOW}Try setting up the Installation Proxy (Option 5) if you are in Iran.${NC}"
    fi
    sleep 2
}

# Main loop
while true; do
    display_menu
    read -p "Enter your choice: " choice
    case $choice in
        1) manage_tunnels ;;
        2) manage_services ;;
        3) installation_proxy ;;
        4) cleanup_all ;;
        5) update_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
    esac
done
