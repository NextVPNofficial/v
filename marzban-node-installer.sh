#!/bin/bash

# Marzban Node Installer with SSH Proxy
# Created to bypass network restrictions in Iran during installation

# Configuration
PROXY_IP="185.140.14.84"
PROXY_PASS='Hm24532645@@$$'
PROXY_USER="root"
PROXY_PORT="22"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}Starting Marzban Node Installer with SSH Proxy...${NC}"

# 1. Install dependencies
echo -e "${CYAN}Installing dependencies (sshpass, curl, jq)...${NC}"
apt-get update -qq
apt-get install -y sshpass curl jq > /dev/null 2>&1

# 2. Configure Docker Mirrors
echo -e "${CYAN}Configuring Docker mirrors...${NC}"
mkdir -p /etc/docker
cat << EOF > /etc/docker/daemon.json
{
  "registry-mirrors": [
    "https://docker.arvancloud.ir",
    "https://registry.docker.ir",
    "https://mirror.gcr.io"
  ]
}
EOF

# Restart docker if it exists to apply mirrors
if systemctl is-active --quiet docker; then
    echo -e "${CYAN}Restarting Docker to apply mirrors...${NC}"
    systemctl restart docker
fi

# 3. Setup SSH Proxy
echo -e "${CYAN}Establishing SSH Proxy to ${PROXY_IP}...${NC}"
# Kill existing proxy if any
pkill -f "ssh -D 1080" || true
sshpass -p "$PROXY_PASS" ssh -D 1080 -C -N -f -p "$PROXY_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${PROXY_USER}@${PROXY_IP}"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Proxy established on port 1080.${NC}"
else
    echo -e "${RED}Failed to establish SSH proxy. Check connectivity to ${PROXY_IP}.${NC}"
    exit 1
fi

# 4. Install Marzban Node
echo -e "${CYAN}Installing Marzban Node via proxy...${NC}"
export ALL_PROXY="socks5h://127.0.0.1:1080"
export http_proxy="socks5h://127.0.0.1:1080"
export https_proxy="socks5h://127.0.0.1:1080"

# Run the installation
# Using bash -c with @ as arg0 as requested
sudo bash -c "$(curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban-node.sh)" @ install

# 5. Cleanup
echo -e "${YELLOW}Cleaning up proxy...${NC}"
pkill -f "ssh -D 1080"
unset ALL_PROXY http_proxy https_proxy

echo -e "${GREEN}Marzban Node installation script finished.${NC}"
