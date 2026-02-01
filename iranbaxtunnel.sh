#!/bin/bash

# IranBax Tunnel - Hysteria2 based Tunneling Script
# Designed for Iran <-> Kharej server bridging

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}Updating package list and installing dependencies...${NC}"
    apt-get update -y
    apt-get install -y curl openssl sed jq
}

# Main menu function
display_menu() {
    clear
    echo -e "${CYAN}==============================================${NC}"
    echo -e "${CYAN}       IranBax Tunnel (Hysteria2)            ${NC}"
    echo -e "${CYAN}==============================================${NC}"
    echo -e "1. Setup Kharej Server (Hysteria2 Server)"
    echo -e "2. Setup Iran Server (Hysteria2 Client/Forwarder)"
    echo -e "3. Check Tunnel Status"
    echo -e "4. Restart Tunnel Service"
    echo -e "5. Stop Tunnel Service"
    echo -e "6. Uninstall IranBax Tunnel"
    echo -e "7. Apply Network Optimizations (BBR)"
    echo -e "0. Exit"
    echo -e "${CYAN}----------------------------------------------${NC}"
}

# Global paths
HYSTERIA_BIN="/usr/local/bin/hysteria"
CONFIG_DIR="/etc/hysteria"
SERVER_CONFIG="${CONFIG_DIR}/server.yaml"
CLIENT_CONFIG="${CONFIG_DIR}/client.yaml"
SERVICE_FILE="/etc/systemd/system/iranbaxtunnel.service"

# Function to install Hysteria2
install_hysteria() {
    if [[ -f "$HYSTERIA_BIN" ]]; then
        echo -e "${GREEN}Hysteria2 is already installed.${NC}"
        return
    fi

    echo -e "${YELLOW}Downloading Hysteria2...${NC}"
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) HY_ARCH="amd64" ;;
        aarch64) HY_ARCH="arm64" ;;
        armv7l) HY_ARCH="arm" ;;
        i386|i686) HY_ARCH="386" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac

    # Get latest version tag
    LATEST_TAG=$(curl -sL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r .tag_name)
    if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
        LATEST_TAG="app/v2.7.0" # Fallback
    fi

    # URL encode the tag (replace / with %2F)
    ENCODED_TAG=$(echo $LATEST_TAG | sed 's/\//%2F/g')

    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${ENCODED_TAG}/hysteria-linux-${HY_ARCH}"

    curl -L -o "$HYSTERIA_BIN" "$DOWNLOAD_URL"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Failed to download Hysteria2 binary.${NC}"
        exit 1
    fi

    chmod +x "$HYSTERIA_BIN"
    mkdir -p "$CONFIG_DIR"
    echo -e "${GREEN}Hysteria2 installed successfully (Version: $LATEST_TAG).${NC}"
}

# Function to apply network optimizations
apply_optimizations() {
    echo -e "${YELLOW}Applying network optimizations...${NC}"

    # Check for BBR
    if ! lsmod | grep -q "tcp_bbr"; then
        modprobe tcp_bbr >/dev/null 2>&1
    fi

    # Apply sysctl settings
    cat << EOF > /etc/sysctl.d/99-iranbaxtunnel.conf
fs.file-max = 67108864
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65536
net.core.netdev_max_backlog = 32768
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
EOF

    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}Optimizations applied successfully.${NC}"
}

# Function to setup Kharej Server
setup_kharej() {
    install_dependencies
    install_hysteria
    apply_optimizations

    echo -e "${YELLOW}Configuring Kharej Server...${NC}"

    read -p "Enter UDP port for Hysteria2 (default 443): " port
    port=${port:-443}

    read -p "Enter authentication password: " password
    password=${password:-"iranbax_pass"}

    read -p "Enter XOR obfuscation password: " obfs_pass
    obfs_pass=${obfs_pass:-"iranbax_obfs"}

    # Generate self-signed certificate
    echo -e "${YELLOW}Generating self-signed certificate...${NC}"
    openssl req -x509 -nodes -newkey rsa:2048 -keyout "${CONFIG_DIR}/server.key" -out "${CONFIG_DIR}/server.crt" -subj "/CN=google.com" -days 3650 >/dev/null 2>&1

    # Generate server config
    cat << EOF > "$SERVER_CONFIG"
listen: :$port

auth:
  type: password
  password: $password

tls:
  cert: ${CONFIG_DIR}/server.crt
  key: ${CONFIG_DIR}/server.key

obfs:
  type: password
  password: $obfs_pass

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
EOF

    # Create systemd service
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=IranBax Tunnel Service (Hysteria2 Server)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$HYSTERIA_BIN server -c $SERVER_CONFIG
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable iranbaxtunnel
    systemctl restart iranbaxtunnel

    echo -e "${GREEN}Kharej Server setup completed and service started.${NC}"
    echo -e "${CYAN}Port: $port${NC}"
    echo -e "${CYAN}Password: $password${NC}"
    echo -e "${CYAN}OBFS Password: $obfs_pass${NC}"
    read -p "Press Enter to return to menu..."
}

# Function to setup Iran Server
setup_iran() {
    install_dependencies
    install_hysteria
    apply_optimizations

    echo -e "${YELLOW}Configuring Iran Server (Client)...${NC}"

    read -p "Enter Kharej Server IP: " kharej_ip
    if [[ -z "$kharej_ip" ]]; then
        echo -e "${RED}Server IP cannot be empty!${NC}"
        return
    fi

    read -p "Enter Kharej UDP port (default 443): " port
    port=${port:-443}

    read -p "Enter authentication password: " password
    password=${password:-"iranbax_pass"}

    read -p "Enter XOR obfuscation password: " obfs_pass
    obfs_pass=${obfs_pass:-"iranbax_obfs"}

    read -p "Enter Download Bandwidth (e.g., 100 mbps): " down_bw
    down_bw=${down_bw:-"100 mbps"}

    read -p "Enter Upload Bandwidth (e.g., 100 mbps): " up_bw
    up_bw=${up_bw:-"100 mbps"}

    echo -e "${YELLOW}Port Forwarding Configuration:${NC}"
    read -p "Enter ports to forward (local_port:remote_port, separated by comma): " port_mapping
    # Example: 8080:8080,9090:9090

    # Generate client config
    cat << EOF > "$CLIENT_CONFIG"
server: $kharej_ip:$port

auth: $password

tls:
  sni: google.com
  insecure: true

obfs:
  type: password
  password: $obfs_pass

bandwidth:
  up: $up_bw
  down: $down_bw

tcpForwarding:
EOF

    IFS=',' read -ra ADDR <<< "$port_mapping"
    for i in "${ADDR[@]}"; do
        IFS=':' read -ra PORTS <<< "$i"
        local_p=${PORTS[0]}
        remote_p=${PORTS[1]}
        cat << EOF >> "$CLIENT_CONFIG"
  - listen: :$local_p
    remote: 127.0.0.1:$remote_p
EOF
    done

    cat << EOF >> "$CLIENT_CONFIG"
udpForwarding:
EOF

    for i in "${ADDR[@]}"; do
        IFS=':' read -ra PORTS <<< "$i"
        local_p=${PORTS[0]}
        remote_p=${PORTS[1]}
        cat << EOF >> "$CLIENT_CONFIG"
  - listen: :$local_p
    remote: 127.0.0.1:$remote_p
EOF
    done

    # Create systemd service
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=IranBax Tunnel Service (Hysteria2 Client)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONFIG_DIR
ExecStart=$HYSTERIA_BIN client -c $CLIENT_CONFIG
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable iranbaxtunnel
    systemctl restart iranbaxtunnel

    echo -e "${GREEN}Iran Server setup completed and service started.${NC}"
    read -p "Press Enter to return to menu..."
}

# Function to check tunnel status
check_status() {
    echo -e "${YELLOW}Checking Tunnel Status...${NC}"
    if systemctl is-active --quiet iranbaxtunnel; then
        echo -e "${GREEN}Service is running.${NC}"
        systemctl status iranbaxtunnel --no-pager
    else
        echo -e "${RED}Service is NOT running.${NC}"
    fi
    read -p "Press Enter to return to menu..."
}

# Function to restart tunnel
restart_tunnel() {
    echo -e "${YELLOW}Restarting Tunnel Service...${NC}"
    systemctl restart iranbaxtunnel
    echo -e "${GREEN}Restarted.${NC}"
    sleep 2
}

# Function to stop tunnel
stop_tunnel() {
    echo -e "${YELLOW}Stopping Tunnel Service...${NC}"
    systemctl stop iranbaxtunnel
    echo -e "${GREEN}Stopped.${NC}"
    sleep 2
}

# Function to uninstall
uninstall_tunnel() {
    echo -e "${RED}Uninstalling IranBax Tunnel...${NC}"
    systemctl stop iranbaxtunnel >/dev/null 2>&1
    systemctl disable iranbaxtunnel >/dev/null 2>&1
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    rm -rf "$CONFIG_DIR"
    rm -f "$HYSTERIA_BIN"
    rm -f /etc/sysctl.d/99-iranbaxtunnel.conf
    sysctl --system >/dev/null 2>&1

    echo -e "${GREEN}Uninstallation completed.${NC}"
    read -p "Press Enter to return to menu..."
}

# Main execution loop
while true; do
    display_menu
    read -p "Enter your choice [0-7]: " choice
    case $choice in
        1) setup_kharej ;;
        2) setup_iran ;;
        3) check_status ;;
        4) restart_tunnel ;;
        5) stop_tunnel ;;
        6) uninstall_tunnel ;;
        7) apply_optimizations ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid choice!${NC}" && sleep 1 ;;
    esac
done
