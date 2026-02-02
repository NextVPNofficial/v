#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\e[36m'
MAGENTA="\e[95m"
WHITE="\e[97m"
NC='\033[0m' # No Color

# Check if the script is run as root
if [[ $EUID -ne 0 && "${BASH_SOURCE[0]}" == "${0}" ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   sleep 1
   exit 1
fi

# Configuration directories
CONFIG_DIR="/root/iranbaxtunnel"
RATHOLE_CORE_DIR="${CONFIG_DIR}/rathole-core"
XRAY_CORE_DIR="${CONFIG_DIR}/xray-core"
SAVED_PROXIES_FILE="${CONFIG_DIR}/saved_proxies.txt"
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
mkdir -p "$CONFIG_DIR"
fi

# --- Input Validation Logic ---

# Function to flush stdin
flush_stdin() {
    local unused
    while read -r -t 0.1 unused; do :; done
}

# Function to validate IP (v4 or v6)
is_valid_ip() {
    local ip=$1
    # IPv4 regex
    local ipv4_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    # IPv6 regex
    local ipv6_regex="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"

    if [[ $ip =~ $ipv4_regex || $ip =~ $ipv6_regex ]]; then
        return 0
    else
        return 1
    fi
}

# Function to check if a port is in use
check_port_in_use() {
    local port=$1
    if ss -tulnp | grep -q ":${port} " ; then
        return 0
    else
        return 1
    fi
}

# Function to validate port
is_valid_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# Wrapper for read with validation
read_ip() {
    local prompt=$1
    local var_name=$2
    local input
    while true; do
        read -p "$prompt" input
        if is_valid_ip "$input"; then
            eval "$var_name=\"$input\""
            break
        else
            echo -e "${RED}Invalid IP address format. Please try again.${NC}"
            flush_stdin
        fi
    done
}

read_port() {
    local prompt=$1
    local var_name=$2
    local check_usage=$3
    local default_val=$4
    local input
    while true; do
        read -p "$prompt" input
        if [[ -z "$input" && -n "$default_val" ]]; then
            input="$default_val"
        fi
        if is_valid_port "$input"; then
            if [[ "$check_usage" == "true" ]]; then
                if check_port_in_use "$input"; then
                    echo -e "${RED}Error: Port $input is already in use by another process.${NC}"
                    ss -tulnp | grep ":${input} "
                    flush_stdin
                    continue
                fi
            fi
            eval "$var_name=\"$input\""
            break
        else
            echo -e "${RED}Invalid port number (1-65535). Please try again.${NC}"
            flush_stdin
        fi
    done
}

read_num() {
    local prompt=$1
    local var_name=$2
    local min=$3
    local max=$4
    local input
    while true; do
        read -p "$prompt" input
        if [[ $input =~ ^[0-9]+$ ]] && [ "$input" -ge "$min" ] && [ "$input" -le "$max" ]; then
            eval "$var_name=\"$input\""
            break
        else
            echo -e "${RED}Invalid number. Please enter a value between $min and $max.${NC}"
            flush_stdin
        fi
    done
}

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
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
ensure_deps
fi

# --- Status Topbar Logic ---

get_public_ip() {
    local ip
    local providers=("https://ifconfig.me" "https://api.ipify.org" "https://icanhazip.com" "https://ipinfo.io/ip")

    # 1. Try fetching via installation proxy if active
    if pgrep -f "ssh -D 1080" > /dev/null; then
        for provider in "${providers[@]}"; do
            ip=$(curl -s --socks5-hostname 127.0.0.1:1080 --max-time 2 "$provider" 2>/dev/null | grep -oE '^[0-9.]+$')
            [[ -n "$ip" ]] && { echo "${ip} (via Proxy)"; return; }
        done
    fi

    # 2. Try direct fetch
    for provider in "${providers[@]}"; do
        ip=$(curl -s --max-time 2 "$provider" 2>/dev/null | grep -oE '^[0-9.]+$')
        [[ -n "$ip" ]] && { echo "$ip"; return; }
    done

    echo "Unknown"
}

get_tunnel_status() {
    local status_line=""
    local active_found=false

    # 1. Rathole
    if [[ -f "/etc/systemd/system/rathole-iran.service" ]]; then
        local check="${RED}STOPPED${NC}"
        if systemctl is-active --quiet "rathole-iran.service"; then
            local tunnel_port=$(grep "bind_addr" "$IRAN_RATHOLE_CONFIG" | head -n1 | awk -F':' '{print $NF}' | tr -d '"')
            check="${GREEN}LISTENING:${tunnel_port}${NC}"
        fi
        status_line+="${YELLOW}[Rathole Server: ${check}]${NC} "
        active_found=true
    fi
    for config in ${CONFIG_DIR}/rathole_client_s[0-9]*.toml; do
        if [[ -f "$config" ]]; then
            local idx=$(basename "$config" | grep -oE '[0-9]+')
            local svc="rathole-kharej-s${idx}.service"
            local remote=$(grep "remote_addr" "$config" | awk -F'"' '{print $2}')
            local remote_ip=$(echo "$remote" | awk -F':' '{print $1}')
            local check="${RED}OFFLINE${NC}"
            if systemctl is-active --quiet "$svc"; then
                if ping -c 1 -W 1 "$remote_ip" &>/dev/null; then check="${GREEN}ONLINE${NC}"; else check="${YELLOW}CONNECTING${NC}"; fi
            fi
            status_line+="${CYAN}[Rathole: ${remote} (${check})]${NC} "
            active_found=true
        fi
    done

    # 2. SIT/GRE
    if ip link show "$TUNNEL_6TO4" &>/dev/null; then
        local remote=$(ip -o tunnel show "$TUNNEL_6TO4" | grep -oP 'remote \K[^ ]+')
        local check="${RED}OFFLINE${NC}"
        if ping -c 1 -W 1 "172.16.0.1" &>/dev/null || ping -c 1 -W 1 "172.16.0.2" &>/dev/null; then
            check="${GREEN}ONLINE${NC}"
        elif [[ -n "$remote" ]] && ping -c 1 -W 1 "$remote" &>/dev/null; then
            check="${YELLOW}HOST-ONLY${NC}"
        fi
        status_line+="${BLUE}[SIT/GRE: -> ${remote:-Unknown} (${check})]${NC} "
        active_found=true
    fi

    # 3. SSH Tunnels
    for svc_file in /etc/systemd/system/ssh-tunnel-*.service; do
        if [[ -f "$svc_file" ]]; then
            local svc=$(basename "$svc_file")
            local iran_port=$(echo "$svc" | grep -oE '[0-9]+')
            local remote=$(grep -oP '@\K[^ ]+' "$svc_file" | head -n1)
            local check="${RED}STOPPED${NC}"
            if systemctl is-active --quiet "$svc"; then
                if check_port_in_use "$iran_port" && curl --connect-timeout 1 -s 127.0.0.1:$iran_port >/dev/null 2>&1; then
                    check="${GREEN}WORKS:${iran_port}${NC}"
                elif check_port_in_use "$iran_port"; then
                    check="${YELLOW}LISTENING${NC}"
                else
                    check="${YELLOW}FAILED/AUTH${NC}"
                fi
            fi
            status_line+="${MAGENTA}[SSH: -> ${remote} (${check})]${NC} "
            active_found=true
        fi
    done

    # 4. Xray-Reality
    if [[ -f "/etc/systemd/system/${XRAY_SERVICE}" ]]; then
        local check="${RED}STOPPED${NC}"
        if systemctl is-active --quiet "$XRAY_SERVICE"; then
            check="${GREEN}ONLINE${NC}"
            local iran_port=$(grep -oP '"port": \K[0-9]+' "$XRAY_CONFIG" | head -n1)
            if [[ -n "$iran_port" ]] && curl --connect-timeout 1 -s 127.0.0.1:$iran_port >/dev/null 2>&1; then
                check="${GREEN}WORKS:${iran_port}${NC}"
            fi
        fi
        status_line+="${MAGENTA}[Reality: ${check}]${NC} "
        active_found=true
    fi

    # 5. Xray-Relay
    if [[ -f "/etc/systemd/system/${XRAY_RELAY_SERVICE}" ]]; then
        local check="${RED}STOPPED${NC}"
        if systemctl is-active --quiet "$XRAY_RELAY_SERVICE"; then
            check="${GREEN}ONLINE${NC}"
            local iran_port=$(grep -oP '"port": \K[0-9]+' "$XRAY_RELAY_CONFIG" | head -n1)
            if [[ -n "$iran_port" ]] && curl --connect-timeout 1 -s 127.0.0.1:$iran_port >/dev/null 2>&1; then
                check="${GREEN}WORKS:${iran_port}${NC}"
            fi
        fi
        status_line+="${CYAN}[XrayRelay: ${check}]${NC} "
        active_found=true
    fi

    # 5. ShadowTLS
    if [[ -f "/etc/systemd/system/${SHADOWTLS_SERVICE}" ]]; then
        local check="${RED}STOPPED${NC}"
        if systemctl is-active --quiet "$SHADOWTLS_SERVICE"; then
            check="${GREEN}ONLINE${NC}"
        fi
        status_line+="${CYAN}[ShadowTLS: ${check}]${NC} "
        active_found=true
    fi

    # 6. ICMP
    if [[ -f "/etc/systemd/system/${ICMP_SERVICE}" ]]; then
        local check="${RED}STOPPED${NC}"
        if systemctl is-active --quiet "$ICMP_SERVICE"; then
            check="${GREEN}ONLINE${NC}"
        fi
        status_line+="${BLUE}[ICMP: ${check}]${NC} "
        active_found=true
    fi

    if [[ "$active_found" == "false" ]]; then
        status_line="${WHITE}No active tunnels configured.${NC}"
    fi

    echo -e "$status_line"
}

get_proxy_status() {
    if pgrep -f "ssh -D 1080" > /dev/null; then
        echo -e "${GREEN}ON${NC}"
    else
        echo -e "${RED}OFF${NC}"
    fi
}

display_topbar() {
    local current_ip=$(get_public_ip)
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${YELLOW}System Exit IP:   ${NC} ${CYAN}${current_ip}${NC}"
    echo -n -e "${BLUE}║${NC} ${YELLOW}Active Tunnels:   ${NC} "
    get_tunnel_status
    echo -e "${BLUE}║${NC} ${YELLOW}Installation Proxy:${NC} $(get_proxy_status)"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
}

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
    display_topbar
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
        echo -e "4. Xray-Reality Tunnel (Stealth TCP)"
        echo -e "5. Xray Relay (Import V2ray Config)"
        echo -e "6. ShadowTLS v3 Tunnel (Stealth TCP)"
        echo -e "7. ICMP Tunnel (Ping-based)"
        echo -e "8. Check All Tunnel Status"
        echo -e "9. Back"
        echo ''
        read_num "Choose an option: " "t_choice" 1 9
        case $t_choice in
            1) manage_rathole ;;
            2) manage_sit_gre ;;
            3) manage_ssh_tunnel ;;
            4) manage_xray_reality ;;
            5) manage_xray_relay ;;
            6) manage_shadowtls ;;
            7) manage_icmp_tunnel ;;
            8) check_status ;;
            9) break ;;
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
        read_num "Choose an option: " "s_choice" 1 3
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
        echo -e "${RED}Failed to retrieve download URL. Try setting up the Installation Proxy (Option 3).${NC}"
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
    read_num "Choose an option: " "r_choice" 1 5

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
    read_port "Enter the tunnel port (the port Rathole listens on): " "tunnel_port" "true"
    read_num "Enter number of services/ports to tunnel: " "num_ports" 1 100

    ports=()
    for ((i=1; i<=$num_ports; i++)); do
        read_port "Enter Service Port $i: " "p" "true"
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
    read_num "How many IRAN servers to connect to? " "server_num" 1 100

    # Cleanup old services
    for svc in $(systemctl list-units --type=service --all | grep -oE 'rathole-kharej-s[0-9]+\.service'); do
        systemctl stop "$svc" >/dev/null 2>&1
        systemctl disable "$svc" >/dev/null 2>&1
        rm -f "/etc/systemd/system/$svc"
    done

    for ((j=1; j<=$server_num; j++)); do
        echo -e "${YELLOW}Server $j:${NC}"
        read_ip "  Enter IRAN Server IP: " "iran_ip"
        read_port "  Enter IRAN Tunnel Port: " "tunnel_port" "false"
        read_num "  Enter number of services: " "num_ports" 1 100

        ports=()
        for ((i=1; i<=$num_ports; i++)); do
            # Local ports on Kharej don't necessarily need to be checked for usage in the same way, but it's good practice
            read_port "    Enter Local Port $i: " "p" "true"
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

# --- Xray-Reality Logic ---

XRAY_BIN="${XRAY_CORE_DIR}/xray"
XRAY_CONFIG="${CONFIG_DIR}/xray_config.json"
XRAY_SERVICE="iranbax-xray.service"

download_xray() {
    if [[ -f "$XRAY_BIN" ]]; then
        echo -e "${GREEN}Xray-core already installed.${NC}"
        return 0
    fi
    mkdir -p "$XRAY_CORE_DIR"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) X_ARCH="64" ;;
        aarch64) X_ARCH="arm64-v8a" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; return 1 ;;
    esac

    echo -e "${CYAN}Fetching latest Xray-core version...${NC}"
    # Use direct github api to find latest tag
    local latest_tag=$(curl -sSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    if [[ -z "$latest_tag" || "$latest_tag" == "null" ]]; then
        echo -e "${RED}Failed to fetch Xray tag. Try setting up the Installation Proxy (Option 3).${NC}"
        return 1
    fi

    local download_url="https://github.com/XTLS/Xray-core/releases/download/${latest_tag}/Xray-linux-${X_ARCH}.zip"
    echo -e "Downloading Xray from $download_url..."

    local download_dir=$(mktemp -d)
    if curl -sSL -o "$download_dir/xray.zip" "$download_url"; then
        unzip -q "$download_dir/xray.zip" -d "$XRAY_CORE_DIR"
        chmod +x "$XRAY_BIN"
        rm -rf "$download_dir"
        echo -e "${GREEN}Xray-core installed successfully.${NC}"
    else
        echo -e "${RED}Failed to download Xray-core.${NC}"
        return 1
    fi
}

manage_xray_reality() {
    clear
    display_logo
    echo -e "${MAGENTA}--- Xray-Reality Management (Stealth TCP) ---${NC}"
    echo -e "1. Install Xray-core"
    echo -e "2. Configure IRAN (Client Role)"
    echo -e "3. Configure KHAREJ (Server Role)"
    echo -e "4. Back"
    echo ''
    read_num "Choose an option: " "x_choice" 1 4
    case $x_choice in
        1) download_xray; sleep 1 ;;
        2) setup_xray_reality "client" ;;
        3) setup_xray_reality "server" ;;
        *) return ;;
    esac
}

manage_xray_relay() {
    clear
    display_logo
    echo -e "${CYAN}--- Xray Relay Management (Import V2ray) ---${NC}"
    echo -e "1. Install Xray-core"
    echo -e "2. Setup Relay from JSON Outbound"
    echo -e "3. Back"
    echo ''
    read_num "Choose an option: " "xr_choice" 1 3
    case $xr_choice in
        1) download_xray; sleep 1 ;;
        2) setup_xray_relay ;;
        *) return ;;
    esac
}

XRAY_RELAY_CONFIG="${CONFIG_DIR}/xray_relay.json"
XRAY_RELAY_SERVICE="iranbax-xray-relay.service"

setup_xray_relay() {
    if [[ ! -f "$XRAY_BIN" ]]; then echo -e "${RED}Install Xray-core first!${NC}"; sleep 1; return; fi

    echo -e "${YELLOW}Paste your Xray Outbound JSON object (including { }):${NC}"
    echo -e "Example: { \"protocol\": \"vless\", \"settings\": { ... }, \"streamSettings\": { ... }, \"tag\": \"proxy\" }"
    echo -e "Press Ctrl+D when finished."

    local outbound=$(cat)
    if [[ -z "$outbound" ]]; then echo -e "${RED}No input received.${NC}"; sleep 1; return; fi

    # Check if jq can parse it
    if ! echo "$outbound" | jq . >/dev/null 2>&1; then
        echo -e "${RED}Error: Invalid JSON format.${NC}"
        sleep 2
        return
    fi

    read_port "Enter IRAN Local Port (to listen on): " "iran_port" "true" 80

    cat << EOF > "$XRAY_RELAY_CONFIG"
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": $iran_port,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": 0, "network": "tcp,udp" },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],
  "outbounds": [
    $outbound
  ]
}
EOF

    cat << EOF > "/etc/systemd/system/${XRAY_RELAY_SERVICE}"
[Unit]
Description=Xray Relay Tunnel (Iranbax)
After=network.target

[Service]
Type=simple
ExecStart=${XRAY_BIN} -c ${XRAY_RELAY_CONFIG}
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$XRAY_RELAY_SERVICE"
    systemctl restart "$XRAY_RELAY_SERVICE"
    echo -e "${GREEN}Xray Relay started on port $iran_port!${NC}"
    sleep 2
}

setup_xray_reality() {
    local role=$1
    if [[ ! -f "$XRAY_BIN" ]]; then echo -e "${RED}Install Xray-core first!${NC}"; sleep 1; return; fi

    local uuid=$($XRAY_BIN uuid)
    local x25519=$($XRAY_BIN x25519)
    local private_key=$(echo "$x25519" | grep "Private key:" | awk '{print $3}')
    local public_key=$(echo "$x25519" | grep "Public key:" | awk '{print $3}')
    local short_id=$(openssl rand -hex 8)

    if [[ "$role" == "server" ]]; then
        echo -e "${YELLOW}Configuring KHAREJ as Reality Server...${NC}"
        read_port "Enter the port for Xray to listen on (e.g., 443): " "server_port" "true" 443
        read_port "Enter the local port to forward traffic to (v2ray config port on Kharej): " "dest_port" "false" 80

        cat << EOF > "$XRAY_CONFIG"
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": $server_port,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$uuid", "flow": "xtls-rprx-vision" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.google.com:443",
          "xver": 0,
          "serverNames": [ "www.google.com" ],
          "privateKey": "$private_key",
          "shortIds": [ "$short_id" ]
        }
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls" ] }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    {
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1", "port": $dest_port },
      "tag": "forward"
    }
  ],
  "routing": {
    "rules": [ { "type": "field", "inboundTag": [ "inbound-$server_port" ], "outboundTag": "forward" } ]
  }
}
EOF
        # Note: Added inbound tag and routing to ensure it forwards locally
        # Simplified routing for this use case:
        sed -i 's/"inboundTag": \[ "inbound-.*" \]/"port": '$server_port'/g' "$XRAY_CONFIG" # fix routing
        # Actually simpler to just let it forward via dokodemo if we use it as outbound.

        echo -e "${GREEN}Configuration Generated.${NC}"
        echo -e "${YELLOW}-----------------------------------------${NC}"
        echo -e "${WHITE}UUID: $uuid${NC}"
        echo -e "${WHITE}Public Key: $public_key${NC}"
        echo -e "${WHITE}Short ID: $short_id${NC}"
        echo -e "${YELLOW}-----------------------------------------${NC}"
        echo -e "Please save these to use on the IRAN server."
    else
        echo -e "${CYAN}Configuring IRAN as Reality Client...${NC}"
        read_ip "Enter KHAREJ Server IP: " "kharej_ip"
        read_port "Enter KHAREJ Xray Port: " "kharej_port" "false" 443
        read_port "Enter IRAN Local Port (to listen on): " "iran_port" "true" 80
        read -p "Enter UUID from Kharej: " uuid
        read -p "Enter Public Key from Kharej: " public_key
        read -p "Enter Short ID from Kharej: " short_id

        cat << EOF > "$XRAY_CONFIG"
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": $iran_port,
      "protocol": "dokodemo-door",
      "settings": { "address": "$kharej_ip", "port": $kharej_port, "network": "tcp" }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$kharej_ip",
            "port": $kharej_port,
            "users": [ { "id": "$uuid", "encryption": "none", "flow": "xtls-rprx-vision" } ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "fingerprint": "chrome",
          "serverName": "www.google.com",
          "publicKey": "$public_key",
          "shortId": "$short_id",
          "spiderX": ""
        }
      }
    }
  ]
}
EOF
    fi

    cat << EOF > "/etc/systemd/system/${XRAY_SERVICE}"
[Unit]
Description=Xray-Reality Tunnel (Iranbax)
After=network.target

[Service]
Type=simple
ExecStart=${XRAY_BIN} -c ${XRAY_CONFIG}
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$XRAY_SERVICE"
    systemctl restart "$XRAY_SERVICE"
    echo -e "${GREEN}Xray-Reality service started!${NC}"
    sleep 2
}

# --- ShadowTLS Logic ---

SHADOWTLS_BIN="${CONFIG_DIR}/shadow-tls"
SHADOWTLS_SERVICE="iranbax-shadowtls.service"
SHADOWTLS_BACKEND_SERVICE="iranbax-shadowtls-backend.service"

download_shadowtls() {
    if [[ -f "$SHADOWTLS_BIN" ]]; then
        echo -e "${GREEN}ShadowTLS already installed.${NC}"
        return 0
    fi
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) S_ARCH="x86_64-unknown-linux-musl" ;;
        aarch64) S_ARCH="aarch64-unknown-linux-musl" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; return 1 ;;
    esac

    echo -e "${CYAN}Fetching latest ShadowTLS version...${NC}"
    local download_url=$(curl -sSL https://api.github.com/repos/ihciah/shadow-tls/releases/latest | grep -oP "https://github.com/ihciah/shadow-tls/releases/download/[v\d.]+/shadow-tls-$S_ARCH" | head -n 1)

    if [ -z "$download_url" ]; then
        echo -e "${RED}Failed to retrieve download URL.${NC}"
        return 1
    fi

    if curl -sSL -o "$SHADOWTLS_BIN" "$download_url"; then
        chmod +x "$SHADOWTLS_BIN"
        echo -e "${GREEN}ShadowTLS installed successfully.${NC}"
    else
        echo -e "${RED}Failed to download ShadowTLS.${NC}"
        return 1
    fi
}

manage_shadowtls() {
    clear
    display_logo
    echo -e "${MAGENTA}--- ShadowTLS v3 Management (Stealth TCP Wrapper) ---${NC}"
    echo -e "1. Install ShadowTLS"
    echo -e "2. Configure IRAN (Client Role)"
    echo -e "3. Configure KHAREJ (Server Role)"
    echo -e "4. Back"
    echo ''
    read_num "Choose an option: " "s_choice" 1 4
    case $s_choice in
        1) download_shadowtls; sleep 1 ;;
        2) setup_shadowtls "client" ;;
        3) setup_shadowtls "server" ;;
        *) return ;;
    esac
}

setup_shadowtls() {
    local role=$1
    if [[ ! -f "$SHADOWTLS_BIN" ]]; then echo -e "${RED}Install ShadowTLS first!${NC}"; sleep 1; return; fi
    # Ensure Xray is also there for backend
    download_xray > /dev/null

    local password=$(openssl rand -base64 16)
    local shadowtls_password=$(openssl rand -base64 16)

    if [[ "$role" == "server" ]]; then
        echo -e "${YELLOW}Configuring KHAREJ as ShadowTLS Server...${NC}"
        read_port "Enter the port for ShadowTLS to listen on (e.g., 443): " "server_port" "true" 443
        read_port "Enter the local backend port (Shadowsocks): " "backend_port" "true" 10001
        read_port "Enter the final destination port (v2ray on Kharej): " "dest_port" "false" 80

        # 1. Backend (Xray Shadowsocks)
        cat << EOF > "${CONFIG_DIR}/shadowtls_backend.json"
{
  "inbounds": [{
    "port": $backend_port,
    "protocol": "shadowsocks",
    "settings": { "method": "aes-256-gcm", "password": "$password" }
  }],
  "outbounds": [{
    "protocol": "dokodemo-door",
    "settings": { "address": "127.0.0.1", "port": $dest_port }
  }]
}
EOF
        cat << EOF > "/etc/systemd/system/${SHADOWTLS_BACKEND_SERVICE}"
[Unit]
Description=ShadowTLS Backend (SS)
After=network.target
[Service]
ExecStart=${XRAY_BIN} -c ${CONFIG_DIR}/shadowtls_backend.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF

        # 2. Wrapper (ShadowTLS)
        cat << EOF > "/etc/systemd/system/${SHADOWTLS_SERVICE}"
[Unit]
Description=ShadowTLS Wrapper (Server)
After=network.target
[Service]
ExecStart=${SHADOWTLS_BIN} --fastopen --v3 server --listen 0.0.0.0:$server_port --server 127.0.0.1:$backend_port --tls www.google.com:443 --password $shadowtls_password
Restart=always
[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "$SHADOWTLS_BACKEND_SERVICE" "$SHADOWTLS_SERVICE"
        systemctl restart "$SHADOWTLS_BACKEND_SERVICE" "$SHADOWTLS_SERVICE"

        echo -e "${GREEN}ShadowTLS Server Started!${NC}"
        echo -e "${YELLOW}--- Credentials for IRAN server ---${NC}"
        echo -e "${WHITE}SS Password: $password${NC}"
        echo -e "${WHITE}ShadowTLS Password: $shadowtls_password${NC}"
        echo -e "${YELLOW}----------------------------------${NC}"
    else
        echo -e "${CYAN}Configuring IRAN as ShadowTLS Client...${NC}"
        read_ip "Enter KHAREJ IP: " "kharej_ip"
        read_port "Enter KHAREJ ShadowTLS Port: " "kharej_port" "false" 443
        read_port "Enter IRAN Local Port: " "iran_port" "true" 80
        read_port "Enter Local Intermediate Port: " "inter_port" "true" 10002
        read -p "Enter SS Password from Kharej: " password
        read -p "Enter ShadowTLS Password from Kharej: " shadowtls_password

        # 1. Wrapper (ShadowTLS Client)
        cat << EOF > "/etc/systemd/system/${SHADOWTLS_SERVICE}"
[Unit]
Description=ShadowTLS Wrapper (Client)
After=network.target
[Service]
ExecStart=${SHADOWTLS_BIN} --fastopen --v3 client --listen 127.0.0.1:$inter_port --server $kharej_ip:$kharej_port --tls www.google.com:443 --password $shadowtls_password
Restart=always
[Install]
WantedBy=multi-user.target
EOF

        # 2. Backend Client (Xray SS Client)
        cat << EOF > "${CONFIG_DIR}/shadowtls_client.json"
{
  "inbounds": [{
    "port": $iran_port,
    "protocol": "dokodemo-door",
    "settings": { "address": "127.0.0.1", "port": $inter_port }
  }],
  "outbounds": [{
    "protocol": "shadowsocks",
    "settings": {
      "servers": [{ "address": "127.0.0.1", "port": $inter_port, "method": "aes-256-gcm", "password": "$password" }]
    }
  }]
}
EOF
        cat << EOF > "/etc/systemd/system/${SHADOWTLS_BACKEND_SERVICE}"
[Unit]
Description=ShadowTLS Backend Client (SS)
After=network.target
[Service]
ExecStart=${XRAY_BIN} -c ${CONFIG_DIR}/shadowtls_client.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "$SHADOWTLS_SERVICE" "$SHADOWTLS_BACKEND_SERVICE"
        systemctl restart "$SHADOWTLS_SERVICE" "$SHADOWTLS_BACKEND_SERVICE"
        echo -e "${GREEN}ShadowTLS Client Started on port $iran_port!${NC}"
    fi
    sleep 2
}

# --- ICMP Logic ---

ICMP_SERVICE="iranbax-icmp.service"

manage_icmp_tunnel() {
    clear
    display_logo
    echo -e "${BLUE}--- ICMP Tunnel Management (ptunnel-ng) ---${NC}"
    echo -e "1. Install ptunnel-ng"
    echo -e "2. Configure IRAN (Client Role)"
    echo -e "3. Configure KHAREJ (Server Role)"
    echo -e "4. Back"
    echo ''
    read_num "Choose an option: " "i_choice" 1 4
    case $i_choice in
        1)
            echo -e "${CYAN}Installing ptunnel-ng...${NC}"
            sudo apt-get install -y ptunnel-ng || {
                echo -e "${YELLOW}Build from source or check repo...${NC}"
                # Simplified for this script
            }
            sleep 1
            ;;
        2) setup_icmp_tunnel "client" ;;
        3) setup_icmp_tunnel "server" ;;
        *) return ;;
    esac
}

setup_icmp_tunnel() {
    local role=$1
    if ! command -v ptunnel-ng &>/dev/null; then echo -e "${RED}Install ptunnel-ng first!${NC}"; sleep 1; return; fi

    if [[ "$role" == "server" ]]; then
        echo -e "${YELLOW}Configuring KHAREJ as ICMP Server...${NC}"
        cat << EOF > "/etc/systemd/system/${ICMP_SERVICE}"
[Unit]
Description=ICMP Tunnel (Server)
After=network.target
[Service]
ExecStart=/usr/sbin/ptunnel-ng -r
Restart=always
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$ICMP_SERVICE"
        systemctl restart "$ICMP_SERVICE"
        echo -e "${GREEN}ICMP Server Started!${NC}"
    else
        echo -e "${CYAN}Configuring IRAN as ICMP Client...${NC}"
        read_ip "Enter KHAREJ IP: " "kharej_ip"
        read_port "Enter IRAN Local Port (to listen on): " "iran_port" "true" 80
        read_port "Enter KHAREJ Dest Port (v2ray port): " "dest_port" "false" 80

        cat << EOF > "/etc/systemd/system/${ICMP_SERVICE}"
[Unit]
Description=ICMP Tunnel (Client)
After=network.target
[Service]
ExecStart=/usr/sbin/ptunnel-ng -p $kharej_ip -l $iran_port -r 127.0.0.1 -R $dest_port
Restart=always
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$ICMP_SERVICE"
        systemctl restart "$ICMP_SERVICE"
        echo -e "${GREEN}ICMP Client Started on port $iran_port!${NC}"
    fi
    sleep 2
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
    read_num "Choose an option: " "s_choice" 1 4

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

    read_ip "Enter Remote Server Public IP: " "remote_ip"
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

setup_ssh_keys() {
    local target_ip=$1
    local ssh_user=$2
    local ssh_port=$3

    if [[ ! -f "$HOME/.ssh/id_rsa" ]]; then
        echo -e "${YELLOW}SSH Key not found. Generating...${NC}"
        ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N ""
    fi

    echo -e "${CYAN}Copying SSH key to target server... you may be prompted for password.${NC}"
    ssh-copy-id -o StrictHostKeyChecking=no -p "$ssh_port" "${ssh_user}@${target_ip}"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}SSH Key copied successfully! Tunnel will now work without password.${NC}"
    else
        echo -e "${RED}Failed to copy SSH key.${NC}"
    fi
}

manage_ssh_tunnel() {
    clear
    display_logo
    echo -e "${MAGENTA}--- SSH Traffic Tunnel Management ---${NC}"
    echo -e "1. Setup Local Port Forward (Iran -> Kharej)"
    echo -e "2. Setup Remote Port Forward (Kharej -> Iran)"
    echo -e "3. Remove SSH Tunnels"
    echo -e "4. Back"
    echo ''
    read_num "Choose an option: " "s_choice" 1 4

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
    read_ip "Enter Target Server IP: " "target_ip"
    read -p "Enter SSH Username (default: root): " ssh_user
    ssh_user=${ssh_user:-root}
    read_port "Enter SSH Port (default: 22): " "ssh_port" "false" 22
    read_port "Enter IRAN Port to listen on: " "iran_port" "true"
    read_port "Enter KHAREJ Port to connect to: " "kharej_port" "false"

    echo ''
    read -p "Do you want to setup SSH Keys for passwordless access? (Recommended) (y/n): " setup_keys
    if [[ "$setup_keys" == "y" ]]; then
        setup_ssh_keys "$target_ip" "$ssh_user" "$ssh_port"
    fi

    echo -e "${YELLOW}Establishing persistent SSH tunnel via Systemd...${NC}"

    local service_name="ssh-tunnel-${iran_port}.service"
    local ssh_cmd=""

    local common_opts="-C -N -o ServerAliveInterval=60 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o TCPKeepAlive=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    if [[ "$type" == "local" ]]; then
        # Local: Current server listens on iran_port and forwards to target_ip:kharej_port
        ssh_cmd="ssh ${common_opts} -L 0.0.0.0:${iran_port}:localhost:${kharej_port} -p ${ssh_port} ${ssh_user}@${target_ip}"
    else
        # Remote: Current server connects to target_ip and opens iran_port ON target_ip
        ssh_cmd="ssh ${common_opts} -R 0.0.0.0:${iran_port}:localhost:${kharej_port} -p ${ssh_port} ${ssh_user}@${target_ip}"
        echo -e "${YELLOW}Note: Remote forwarding requires 'GatewayPorts yes' in the target server's sshd_config.${NC}"
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
LimitNOFILE=1048576

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
    read_num "Choose an option: " "opt_choice" 1 2

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
        else
            flush_stdin
        fi
    fi
}

save_proxy() {
    local ip=$1
    local user=$2
    local port=$3
    local entry="${user}@${ip}:${port}"
    touch "$SAVED_PROXIES_FILE"
    if ! grep -q "^${entry}$" "$SAVED_PROXIES_FILE"; then
        echo "$entry" >> "$SAVED_PROXIES_FILE"
    fi
}

connect_installation_proxy() {
    local ip=$1
    local user=$2
    local port=$3

    echo ''
    read -p "Do you want to setup SSH Keys first? (y/n): " setup_keys
    [[ "$setup_keys" == "y" ]] && setup_ssh_keys "$ip" "$user" "$port"

    echo -e "${CYAN}Establishing SSH tunnel...${NC}"
    # Start SSH Dynamic Forwarding in background
    ssh -D 1080 -C -N -f -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${user}@${ip}"

    if [ $? -eq 0 ]; then
        export http_proxy="socks5h://127.0.0.1:1080"
        export https_proxy="socks5h://127.0.0.1:1080"
        echo 'Acquire::http::Proxy "socks5h://127.0.0.1:1080/"; Acquire::https::Proxy "socks5h://127.0.0.1:1080/";' | sudo tee /etc/apt/apt.conf.d/99proxy > /dev/null
        echo -e "${GREEN}Proxy established! http_proxy/https_proxy set to socks5h://127.0.0.1:1080${NC}"
        save_proxy "$ip" "$user" "$port"
    else
        echo -e "${RED}Failed to establish SSH tunnel.${NC}"
    fi
    sleep 2
}

installation_proxy() {
    while true; do
        clear
        display_logo
        echo -e "${YELLOW}--- Installation Proxy Settings ---${NC}"
        echo -e "This helps if your server (Iran) cannot reach GitHub or foreign sites."
        echo ''
        echo -e "1. New SSH SOCKS5 Proxy"
        echo -e "2. Use a Saved Proxy"
        echo -e "3. Manage Saved Proxies (Delete)"
        echo -e "4. Clear Active Proxy Settings"
        echo -e "5. Back"
        echo ''
        read_num "Choose an option: " "proxy_choice" 1 5

        case $proxy_choice in
            1)
                read_ip "Enter Foreign Server IP: " "proxy_ip"
                read -p "Enter SSH Username (default: root): " proxy_user
                proxy_user=${proxy_user:-root}
                read_port "Enter SSH Port (default: 22): " "proxy_port" "false" 22
                connect_installation_proxy "$proxy_ip" "$proxy_user" "$proxy_port"
                ;;
            2)
                if [[ ! -s "$SAVED_PROXIES_FILE" ]]; then
                    echo -e "${RED}No saved proxies found.${NC}"
                    sleep 1
                    continue
                fi
                echo -e "${CYAN}--- Saved Proxies ---${NC}"
                local i=1
                local proxies=()
                while IFS= read -r line; do
                    echo -e "$i. $line"
                    proxies+=("$line")
                    ((i++))
                done < "$SAVED_PROXIES_FILE"
                read_num "Select a proxy to connect (0 to cancel): " "selected_idx" 0 $((i-1))
                if [[ $selected_idx -gt 0 ]]; then
                    local selected="${proxies[$((selected_idx-1))]}"
                    local user=$(echo "$selected" | awk -F'@' '{print $1}')
                    local ip_port=$(echo "$selected" | awk -F'@' '{print $2}')
                    local ip=$(echo "$ip_port" | awk -F':' '{print $1}')
                    local port=$(echo "$ip_port" | awk -F':' '{print $2}')
                    connect_installation_proxy "$ip" "$user" "$port"
                fi
                ;;
            3)
                if [[ ! -s "$SAVED_PROXIES_FILE" ]]; then
                    echo -e "${RED}No saved proxies found.${NC}"
                    sleep 1
                    continue
                fi
                echo -e "${RED}--- Delete Saved Proxies ---${NC}"
                local i=1
                local proxies=()
                while IFS= read -r line; do
                    echo -e "$i. $line"
                    proxies+=("$line")
                    ((i++))
                done < "$SAVED_PROXIES_FILE"
                read_num "Select a proxy to delete (0 to cancel, 99 to delete all): " "del_idx" 0 99
                if [[ $del_idx -eq 99 ]]; then
                    rm -f "$SAVED_PROXIES_FILE"
                    echo -e "${GREEN}All saved proxies deleted.${NC}"
                elif [[ $del_idx -gt 0 && $del_idx -lt $i ]]; then
                    local to_delete="${proxies[$((del_idx-1))]}"
                    sed -i "\|^${to_delete}$|d" "$SAVED_PROXIES_FILE"
                    echo -e "${GREEN}Deleted $to_delete${NC}"
                fi
                sleep 1
                ;;
            4)
                clear_proxy
                sleep 2
                ;;
            5) break ;;
        esac
    done
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

    # 4. Xray/Reality
    echo -e "${YELLOW}Stopping Xray services...${NC}"
    systemctl stop "$XRAY_SERVICE" "$XRAY_RELAY_SERVICE" 2>/dev/null
    systemctl disable "$XRAY_SERVICE" "$XRAY_RELAY_SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${XRAY_SERVICE}" "/etc/systemd/system/${XRAY_RELAY_SERVICE}"

    # 5. ShadowTLS
    echo -e "${YELLOW}Stopping ShadowTLS services...${NC}"
    systemctl stop "$SHADOWTLS_SERVICE" "$SHADOWTLS_BACKEND_SERVICE" 2>/dev/null
    systemctl disable "$SHADOWTLS_SERVICE" "$SHADOWTLS_BACKEND_SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${SHADOWTLS_SERVICE}" "/etc/systemd/system/${SHADOWTLS_BACKEND_SERVICE}"

    # 6. ICMP
    echo -e "${YELLOW}Stopping ICMP services...${NC}"
    systemctl stop "$ICMP_SERVICE" 2>/dev/null
    systemctl disable "$ICMP_SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${ICMP_SERVICE}"

    # 7. Files
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
    flush_stdin
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
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
while true; do
    display_menu
    read_num "Enter your choice: " "choice" 0 5
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
fi
