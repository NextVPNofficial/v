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
    echo -e "${YELLOW}Checking and installing dependencies...${NC}"
    for pkg in curl openssl sed jq unzip; do
        if ! command -v $pkg &> /dev/null; then
            echo -e "${CYAN}Installing $pkg...${NC}"
            apt-get install -y $pkg >/dev/null 2>&1
        fi
    done
}

# Main menu function
display_menu() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${CYAN}        IranBax Tunnel (Multi-Protocol)           ${NC}"
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${GREEN}UDP (Hysteria2 - High Speed):${NC}"
    echo -e "  1. Setup Kharej Server"
    echo -e "  2. Setup Iran Server"
    echo -e "${YELLOW}TCP (Reality - Ultimate Stealth):${NC}"
    echo -e "  3. Setup Kharej Server"
    echo -e "  4. Setup Iran Server"
    echo -e "${CYAN}Management:${NC}"
    echo -e "  5. Check Tunnel Status"
    echo -e "  6. Restart Tunnel Service"
    echo -e "  7. Stop Tunnel Service"
    echo -e "  8. Uninstall IranBax Tunnel"
    echo -e "  9. Apply Network Optimizations (BBR)"
    echo -e "  0. Exit"
    echo -e "${CYAN}--------------------------------------------------${NC}"
}

# Global paths
HYSTERIA_BIN="/usr/local/bin/hysteria"
XRAY_BIN="/usr/local/bin/xray"
CONFIG_DIR="/etc/iranbaxtunnel"
HY_CONFIG_DIR="${CONFIG_DIR}/hysteria"
XR_CONFIG_DIR="${CONFIG_DIR}/xray"
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
        LATEST_TAG="app/v2.5.2" # Safe Fallback
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
    mkdir -p "$HY_CONFIG_DIR"
    echo -e "${GREEN}Hysteria2 installed successfully (Version: $LATEST_TAG).${NC}"
}

# Function to install Xray-core
install_xray() {
    if [[ -f "$XRAY_BIN" ]]; then
        echo -e "${GREEN}Xray-core is already installed.${NC}"
        return
    fi

    echo -e "${YELLOW}Downloading Xray-core...${NC}"
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) XR_ARCH="64" ;;
        aarch64) XR_ARCH="arm64-v8a" ;;
        armv7l) XR_ARCH="arm32-v7a" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac

    LATEST_TAG=$(curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
        LATEST_TAG="v1.8.24" # Safe Fallback
    fi

    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/${LATEST_TAG}/Xray-linux-${XR_ARCH}.zip"

    curl -L -o "/tmp/xray.zip" "$DOWNLOAD_URL"
    unzip -q "/tmp/xray.zip" -d "/tmp/xray"
    mv "/tmp/xray/xray" "$XRAY_BIN"
    chmod +x "$XRAY_BIN"
    mkdir -p "$XR_CONFIG_DIR"
    rm -rf "/tmp/xray" "/tmp/xray.zip"
    echo -e "${GREEN}Xray-core installed successfully (Version: $LATEST_TAG).${NC}"
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

# Function to setup Kharej Server (UDP/Hysteria2)
setup_kharej_udp() {
    install_dependencies
    install_hysteria
    apply_optimizations

    echo -e "${YELLOW}Configuring Kharej Server (Hysteria2)...${NC}"

    read -p "Enter UDP port for Hysteria2 (default 443): " port
    port=${port:-443}

    read -p "Enter authentication password: " password
    password=${password:-"iranbax_pass"}

    read -p "Enter XOR obfuscation password: " obfs_pass
    obfs_pass=${obfs_pass:-"iranbax_obfs"}

    # Generate self-signed certificate
    echo -e "${YELLOW}Generating self-signed certificate...${NC}"
    openssl req -x509 -nodes -newkey rsa:2048 -keyout "${HY_CONFIG_DIR}/server.key" -out "${HY_CONFIG_DIR}/server.crt" -subj "/CN=google.com" -days 3650 >/dev/null 2>&1

    # Generate server config
    cat << EOF > "${HY_CONFIG_DIR}/server.yaml"
listen: :$port

auth:
  type: password
  config:
    password: "$password"

tls:
  cert: ${HY_CONFIG_DIR}/server.crt
  key: ${HY_CONFIG_DIR}/server.key

obfs:
  type: password
  config:
    password: "$obfs_pass"

quic:
  init_stream_receive_window: 8388608
  max_stream_receive_window: 8388608
  init_conn_receive_window: 20971520
  max_conn_receive_window: 20971520
EOF

    # Create systemd service
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=IranBax Tunnel Service (Hysteria2 Server)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$HY_CONFIG_DIR
ExecStart=$HYSTERIA_BIN server -c ${HY_CONFIG_DIR}/server.yaml
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

# Function to setup Iran Server (UDP/Hysteria2)
setup_iran_udp() {
    install_dependencies
    install_hysteria
    apply_optimizations

    echo -e "${YELLOW}Configuring Iran Server (Hysteria2)...${NC}"

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
    cat << EOF > "${HY_CONFIG_DIR}/client.yaml"
server: $kharej_ip:$port

auth: "$password"

tls:
  sni: google.com
  insecure: true

obfs:
  type: password
  config:
    password: "$obfs_pass"

bandwidth:
  up: "$up_bw"
  down: "$down_bw"

tcp_forwarding:
EOF

    IFS=',' read -ra ADDR <<< "$port_mapping"
    for i in "${ADDR[@]}"; do
        if [[ $i =~ ^[0-9]+:[0-9]+$ ]]; then
            IFS=':' read -ra PORTS <<< "$i"
            local_p=${PORTS[0]}
            remote_p=${PORTS[1]}
            cat << EOF >> "${HY_CONFIG_DIR}/client.yaml"
  - listen: :$local_p
    remote: 127.0.0.1:$remote_p
EOF
        fi
    done

    cat << EOF >> "${HY_CONFIG_DIR}/client.yaml"
udp_forwarding:
EOF

    for i in "${ADDR[@]}"; do
        if [[ $i =~ ^[0-9]+:[0-9]+$ ]]; then
            IFS=':' read -ra PORTS <<< "$i"
            local_p=${PORTS[0]}
            remote_p=${PORTS[1]}
            cat << EOF >> "${HY_CONFIG_DIR}/client.yaml"
  - listen: :$local_p
    remote: 127.0.0.1:$remote_p
EOF
        fi
    done

    # Create systemd service
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=IranBax Tunnel Service (Hysteria2 Client)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$HY_CONFIG_DIR
ExecStart=$HYSTERIA_BIN client -c ${HY_CONFIG_DIR}/client.yaml
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

# Function to setup Kharej Server (TCP/Reality)
setup_kharej_tcp() {
    install_dependencies
    install_xray
    apply_optimizations

    echo -e "${YELLOW}Configuring Kharej Server (Reality)...${NC}"

    read -p "Enter TCP port for Reality (default 443): " port
    port=${port:-443}

    # Generate UUID and Keys
    UUID=$($XRAY_BIN uuid)
    KEYS=$($XRAY_BIN x25519)
    PRIVATE_KEY=$(echo "$KEYS" | grep "Private key" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEYS" | grep "Public key" | awk '{print $3}')
    SHORT_ID=$(openssl rand -hex 8)

    read -p "Enter destination address for masquerading (default google.com:443): " dest
    dest=${dest:-"google.com:443"}
    sni=$(echo $dest | cut -d: -f1)

    # Generate server config
    cat << EOF > "${XR_CONFIG_DIR}/server.json"
{
  "inbounds": [
    {
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$dest",
          "xver": 0,
          "serverNames": ["$sni"],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": ["$SHORT_ID"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

    # Create systemd service
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=IranBax Tunnel Service (Xray Reality Server)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$XR_CONFIG_DIR
ExecStart=$XRAY_BIN run -c ${XR_CONFIG_DIR}/server.json
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
    echo -e "${CYAN}UUID: $UUID${NC}"
    echo -e "${CYAN}Public Key: $PUBLIC_KEY${NC}"
    echo -e "${CYAN}Short ID: $SHORT_ID${NC}"
    echo -e "${CYAN}SNI: $sni${NC}"
    read -p "Press Enter to return to menu..."
}

# Function to setup Iran Server (TCP/Reality)
setup_iran_tcp() {
    install_dependencies
    install_xray
    apply_optimizations

    echo -e "${YELLOW}Configuring Iran Server (Reality)...${NC}"

    read -p "Enter Kharej Server IP: " kharej_ip
    read -p "Enter Kharej TCP port (default 443): " port
    port=${port:-443}
    read -p "Enter UUID: " uuid
    read -p "Enter Public Key: " pub_key
    read -p "Enter Short ID: " short_id
    read -p "Enter SNI (default google.com): " sni
    sni=${sni:-"google.com"}

    echo -e "${YELLOW}Port Forwarding Configuration:${NC}"
    read -p "Enter ports to forward (local_port:remote_port, separated by comma): " port_mapping

    # Prepare inbounds for port forwarding
    INBOUNDS=""
    IFS=',' read -ra ADDR <<< "$port_mapping"
    for i in "${ADDR[@]}"; do
        if [[ $i =~ ^[0-9]+:[0-9]+$ ]]; then
            IFS=':' read -ra PORTS <<< "$i"
            local_p=${PORTS[0]}
            remote_p=${PORTS[1]}
            INBOUNDS+="{ \"port\": $local_p, \"protocol\": \"dokodemo-door\", \"settings\": { \"address\": \"127.0.0.1\", \"port\": $remote_p, \"network\": \"tcp,udp\" } },"
        fi
    done
    # Remove trailing comma
    INBOUNDS=${INBOUNDS%,}

    # Generate client config
    cat << EOF > "${XR_CONFIG_DIR}/client.json"
{
  "inbounds": [
    $INBOUNDS
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "$kharej_ip",
            "port": $port,
            "users": [
              {
                "id": "$uuid",
                "flow": "xtls-rprx-vision",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "fingerprint": "chrome",
          "serverName": "$sni",
          "publicKey": "$pub_key",
          "shortId": "$short_id",
          "spiderX": "/"
        }
      }
    }
  ]
}
EOF

    # Create systemd service
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=IranBax Tunnel Service (Xray Reality Client)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$XR_CONFIG_DIR
ExecStart=$XRAY_BIN run -c ${XR_CONFIG_DIR}/client.json
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
    rm -f "$HYSTERIA_BIN" "$XRAY_BIN"
    rm -f /etc/sysctl.d/99-iranbaxtunnel.conf
    sysctl --system >/dev/null 2>&1

    echo -e "${GREEN}Uninstallation completed.${NC}"
    read -p "Press Enter to return to menu..."
}

# Main execution loop
while true; do
    display_menu
    read -p "Enter your choice [0-9]: " choice
    case $choice in
        1) setup_kharej_udp ;;
        2) setup_iran_udp ;;
        3) setup_kharej_tcp ;;
        4) setup_iran_tcp ;;
        5) check_status ;;
        6) restart_tunnel ;;
        7) stop_tunnel ;;
        8) uninstall_tunnel ;;
        9) apply_optimizations ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid choice!${NC}" && sleep 1 ;;
    esac
done
