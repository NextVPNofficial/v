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
XRAY_CORE_DIR="${CONFIG_DIR}/xray-core"
SAVED_PROXIES_FILE="${CONFIG_DIR}/saved_proxies.txt"
SAVED_RELAYS_DIR="${CONFIG_DIR}/relays"

# Service names for cleanup/reference
XRAY_SERVICE="iranbax-xray.service"
XRAY_RELAY_SERVICE="iranbax-xray-relay.service"

XRAY_BIN="${XRAY_CORE_DIR}/xray"
XRAY_CONFIG="${CONFIG_DIR}/xray_config.json"
XRAY_RELAY_CONFIG="${CONFIG_DIR}/xray_relay.json"

# Ensure directories exist
mkdir -p "$CONFIG_DIR" "$SAVED_RELAYS_DIR"

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

# Helper to check if a port is used by our services
is_port_ours() {
    local port=$1
    # Check if port is in any of our config files
    if grep -q "\"port\": $port" "$XRAY_CONFIG" 2>/dev/null || grep -q "\"port\": $port" "$XRAY_RELAY_CONFIG" 2>/dev/null; then
        return 0
    fi
    return 1
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
                    local p_all=$(ss -tulnp | grep ":${input} ")
                    if echo "$p_all" | grep -iq "xray"; then
                        if is_port_ours "$input"; then
                             echo -e "${YELLOW}Notice: Port $input is currently used by an Iranbax tunnel. It will be updated.${NC}"
                        else
                             echo -e "${YELLOW}Warning: Port $input is used by an external Xray process.${NC}"
                             read -p "Replace it? (y/n, default: n): " force_x
                             [[ "$force_x" != "y" ]] && { flush_stdin; continue; }
                        fi
                    else
                        echo -e "${RED}Error: Port $input is already in use by another process:${NC}"
                        echo "$p_all"
                        read -p "Force use this port? (y/n, default: n): " force_port
                        if [[ "$force_port" != "y" ]]; then
                            flush_stdin
                            continue
                        fi
                    fi
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

    # 1. Xray-Relay (Priority)
    if [[ -f "/etc/systemd/system/${XRAY_RELAY_SERVICE}" ]]; then
        local check="${RED}STOPPED${NC}"
        local relay_name=$(grep -oP 'Description=Xray Relay Tunnel \(\K[^\)]+' "/etc/systemd/system/${XRAY_RELAY_SERVICE}")
        if systemctl is-active --quiet "$XRAY_RELAY_SERVICE"; then
            check="${GREEN}ONLINE${NC}"
            local iran_port=$(grep -oP '"port": \K[0-9]+' "$XRAY_RELAY_CONFIG" | head -n1)
            if [[ -n "$iran_port" ]] && curl --connect-timeout 1 -s 127.0.0.1:$iran_port >/dev/null 2>&1; then
                check="${GREEN}WORKS:${iran_port}${NC}"
            fi
        fi
        status_line+="${CYAN}[Relay(${relay_name:-Imported}): ${check}]${NC} "
        active_found=true
    fi

    # 2. Xray-Reality
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

    # 3. SSH Tunnels
    local ssh_count=$(ls /etc/systemd/system/iranbax-ssh-*.service 2>/dev/null | wc -l)
    if [[ $ssh_count -gt 0 ]]; then
        status_line+="${BLUE}[SSH: ${ssh_count} Active]${NC} "
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
    echo -e "${BLUE}║${NC}              ${MAGENTA}🛰️  IRANBAX TUNNELING SYSTEM - STATUS DASHBOARD${NC}                          ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
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
  _____                 _
 |_   _|               | |
   | |  _ __ __ _ _ __ | |__   __ ___  __
   | | | '__/ _` | '_ \| '_ \ / _` \ \/ /
  _| |_| | | (_| | | | | |_) | (_| |>  <
 |_____|_|  \__,_|_| |_|_.__/ \__,_/_/\_\
EOF
    echo -e "${NC}${GREEN}"
    echo -e "${YELLOW}IRANBAX TUNNELING SYSTEM${GREEN}"
    echo -e "Version: ${YELLOW}v3.0.0 (Xray Focused)${NC}"
}

# Function to display main menu
display_menu() {
    clear
    display_topbar
    display_logo
    echo ''
    echo -e "${CYAN}1. Xray Relay Management (V2ray Config/Link)${NC}"
    echo -e "${MAGENTA}2. Xray-Reality Management (Stealth TCP)${NC}"
    echo -e "${BLUE}3. SSH Tunnel Management (Simple TCP Forwarding)${NC}"
    echo -e "${YELLOW}4. Service & System Management (Optimizations, Restarts)${NC}"
    echo -e "${GREEN}5. Installation Proxy (Setup Helper)${NC}"
    echo -e "${RED}6. Remove All Tunnels & Cleanup${NC}"
    echo -e "7. Update Script"
    echo -e "0. Exit"
    echo ''
    echo "-------------------------------"
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

# Function to check if a given string is a valid IPv6 address
check_ipv6() {
    local ip=$1
    ipv6_pattern="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:)$"
    ip="${ip#[}"
    ip="${ip%]}"
    if [[ $ip =~ $ipv6_pattern ]]; then return 0; else return 1; fi
}

# --- Xray-Reality Logic ---

XRAY_SERVICE="iranbax-xray.service"

download_xray() {
    local custom_url=$1
    mkdir -p "$XRAY_CORE_DIR"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) X_ARCH="64" ;;
        aarch64) X_ARCH="arm64-v8a" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; return 1 ;;
    esac

    local download_url="$custom_url"
    if [[ -z "$download_url" ]]; then
        echo -e "${CYAN}Fetching latest Xray-core version from GitHub...${NC}"
        local latest_tag=$(curl -sSL --max-time 10 https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
        if [[ -z "$latest_tag" || "$latest_tag" == "null" ]]; then
            echo -e "${RED}Failed to fetch tag. Try Option 3 (Proxy) or provide a Custom URL.${NC}"
            return 1
        fi
        download_url="https://github.com/XTLS/Xray-core/releases/download/${latest_tag}/Xray-linux-${X_ARCH}.zip"
    fi

    echo -e "Downloading Xray from $download_url..."
    local download_dir=$(mktemp -d)
    if curl -L --progress-bar -o "$download_dir/xray.zip" "$download_url"; then
        unzip -q "$download_dir/xray.zip" -d "$XRAY_CORE_DIR"
        chmod +x "$XRAY_BIN"
        rm -rf "$download_dir"
        echo -e "${GREEN}Xray-core installed successfully.${NC}"
    else
        echo -e "${RED}Failed to download Xray-core.${NC}"
        rm -rf "$download_dir"
        return 1
    fi
}

install_xray_menu() {
    clear
    display_logo
    echo -e "${CYAN}--- Xray-core Installation ---${NC}"
    echo -e "1. Download Latest from GitHub"
    echo -e "2. Download from Custom URL"
    echo -e "3. Install from Local File (${CONFIG_DIR}/xray.zip)"
    echo -e "4. Back"
    echo ''
    read_num "Choose method: " "x_inst_choice" 1 4
    case $x_inst_choice in
        1) download_xray ;;
        2)
           read -p "Enter Custom URL: " x_url
           download_xray "$x_url"
           ;;
        3)
           local lzip="${CONFIG_DIR}/xray.zip"
           if [[ -f "$lzip" ]]; then
               mkdir -p "$XRAY_CORE_DIR"
               unzip -q "$lzip" -d "$XRAY_CORE_DIR"
               chmod +x "$XRAY_BIN"
               echo -e "${GREEN}Installed from local zip.${NC}"; sleep 1
           else
               echo -e "${RED}File $lzip not found!${NC}"; sleep 2
           fi
           ;;
    esac
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
        1) install_xray_menu ;;
        2) setup_xray_reality "client" ;;
        3) setup_xray_reality "server" ;;
        *) return ;;
    esac
}

create_relay_manual() {
    clear
    display_logo
    echo -e "${CYAN}--- Create New Xray Relay Config (Manual) ---${NC}"

    read -p "Enter a name for this config: " relay_name
    relay_name=$(echo "$relay_name" | sed 's/[^a-zA-Z0-9_]/_/g')
    [[ -z "$relay_name" ]] && { echo -e "${RED}Name cannot be empty.${NC}"; sleep 1; return; }

    read_ip "Enter Remote (Kharej) IP/Address: " "rem_addr"
    read_port "Enter Remote Port: " "rem_port" "false"

    echo -e "Choose Protocol:"
    echo "1. VLESS"
    echo "2. VMESS"
    echo "3. Plain TCP (Simple Bridge)"
    read_num "Choice: " "proto_choice" 1 3
    local proto="vless"
    [[ $proto_choice -eq 2 ]] && proto="vmess"
    [[ $proto_choice -eq 3 ]] && proto="plain"

    local uuid=""
    if [[ "$proto" != "plain" ]]; then
        read -p "Enter UUID: " uuid
        [[ -z "$uuid" ]] && { echo -e "${RED}UUID cannot be empty.${NC}"; sleep 1; return; }
    fi

    echo -e "Choose Transport:"
    echo "1. TCP"
    echo "2. WebSocket (WS)"
    read_num "Choice: " "trans_choice" 1 2
    local transport="tcp"
    [[ $trans_choice -eq 2 ]] && transport="ws"

    local path=""
    if [[ "$transport" == "ws" ]]; then
        read -p "Enter WS Path (default: /): " path
        path=${path:-/}
    fi

    echo -e "Choose Security:"
    echo "1. None"
    echo "2. TLS"
    echo "3. Reality"
    read_num "Choice: " "sec_choice" 1 3
    local security="none"
    [[ $sec_choice -eq 2 ]] && security="tls"
    [[ $sec_choice -eq 3 ]] && security="reality"

    local sni=""
    if [[ "$security" != "none" ]]; then
        read -p "Enter SNI / ServerName: " sni
    fi

    # Build the outbound JSON using jq
    local outbound=""
    if [[ "$proto" == "plain" ]]; then
        outbound=$(jq -n \
            --arg addr "$rem_addr" \
            --argjson port "$rem_port" \
            '{
                "protocol": "freedom",
                "settings": {
                    "redirect": ($addr + ":" + ($port|tostring))
                }
            }')
    else
        outbound=$(jq -n \
            --arg proto "$proto" \
            --arg addr "$rem_addr" \
            --argjson port "$rem_port" \
            --arg uuid "$uuid" \
            --arg transport "$transport" \
            --arg security "$security" \
            --arg sni "$sni" \
            --arg path "$path" \
            '{
                "protocol": $proto,
                "settings": {
                    "vnext": [{"address": $addr, "port": $port, "users": [{"id": $uuid, "encryption": "none"}]}]
                },
                "streamSettings": {
                    "network": $transport,
                    "security": $security,
                    "tlsSettings": (if $security == "tls" then {"serverName": $sni} else null end),
                    "realitySettings": (if $security == "reality" then {"serverName": $sni} else null end),
                    "wsSettings": (if $transport == "ws" then {"path": $path, "headers": {"Host": $sni}} else null end)
                }
            } | del(..|nulls)')
    fi

    # Fix VMESS security if needed
    if [[ "$proto" == "vmess" ]]; then
        outbound=$(echo "$outbound" | jq '.settings.vnext[0].users[0].security = "auto" | del(.settings.vnext[0].users[0].encryption)')
    fi

    mkdir -p "$SAVED_RELAYS_DIR"
    echo "$outbound" > "${SAVED_RELAYS_DIR}/${relay_name}.json"
    echo -e "${GREEN}Config saved as ${relay_name}.json${NC}"
    sleep 1

    activate_relay "$relay_name"
}

manage_xray_relay() {
    while true; do
        clear
        display_logo
        echo -e "${CYAN}--- Xray Relay Management ---${NC}"
        echo -e "1. Create New Config (Manual)"
        echo -e "2. Import New Config (JSON or Link)"
        echo -e "3. Saved Relays (List, Connect, Edit, Delete)"
        echo -e "4. Install Xray-core"
        echo -e "5. Back"
        echo ''
        read_num "Choose an option: " "xr_choice" 1 5
        case $xr_choice in
            1) create_relay_manual ;;
            2) setup_xray_relay ;;
            3) saved_relays_menu ;;
            4) install_xray_menu ;;
            *) return ;;
        esac
    done
}

XRAY_RELAY_SERVICE="iranbax-xray-relay.service"

# URL decode helper
urldecode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}

parse_vmess_link() {
    local link=$1
    local body=$(echo "$link" | sed 's/vmess:\/\///')
    local decoded=$(echo "$body" | base64 -d 2>/dev/null)
    [[ -z "$decoded" ]] && return 1

    jq -c --argjson d "$decoded" '
        {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": ($d.add | tostring),
                    "port": ($d.port | tonumber),
                    "users": [{
                        "id": ($d.id | tostring),
                        "alterId": ($d.aid | tonumber // 0),
                        "security": ($d.scy // "auto")
                    }]
                }]
            },
            "streamSettings": {
                "network": ($d.net // "tcp"),
                "security": (if $d.tls == "tls" then "tls" else "none" end),
                "tlsSettings": (if $d.tls == "tls" then {
                    "serverName": ($d.sni // $d.host // $d.add),
                    "allowInsecure": true,
                    "alpn": (if $d.alpn != null and $d.alpn != "" then ($d.alpn | split(",")) else ["h2", "http/1.1"] end)
                } else null end),
                "wsSettings": (if $d.net == "ws" then {
                    "path": ($d.path // "/"),
                    "headers": {"Host": ($d.host // $d.sni // $d.add)}
                } else null end)
            }
        } | del(..|nulls)' 2>/dev/null
}

parse_vless_link() {
    local link=$1
    local body=$(echo "$link" | sed 's/vless:\/\///')
    local uuid=$(echo "$body" | awk -F'@' '{print $1}')
    local rest=$(echo "$body" | awk -F'@' '{print $2}')
    local host_port=$(echo "$rest" | awk -F'?' '{print $1}')
    local params_str=$(echo "$rest" | awk -F'?' '{print $2}' | awk -F'#' '{print $1}')
    local host=$(echo "$host_port" | awk -F':' '{print $1}')
    local port=$(echo "$host_port" | awk -F':' '{print $2}')

    # Extract params into a JSON object for easier handling
    local params_json=$(echo "$params_str" | sed 's/&/\n/g' | jq -R -s '
        split("\n") | map(select(length > 0) | split("=")) | map({(.[0]): .[1]}) | add
    ')

    jq -n \
        --arg uuid "$uuid" \
        --arg host "$host" \
        --arg port "$port" \
        --argjson p "$params_json" \
        '
        def get_p(k; d): ($p[k] // d);
        def decode(s): (if s != null then s | sub("%2F"; "/"; "g") | sub("%2B"; "+"; "g") else null end);

        ($p["type"] // "tcp") as $type |
        ($p["security"] // "none") as $sec |
        (decode($p["sni"] // $p["peer"] // $p["host"]) // $host) as $sni |
        (decode($p["path"]) // "/") as $path |
        (decode($p["host"]) // $sni) as $ws_host |
        ($p["insecure"] == "1" or $p["allowInsecure"] == "1" or $p["insecure"] == "true") as $allow_ins |

        {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": $host,
                    "port": ($port|tonumber),
                    "users": [{
                        "id": $uuid,
                        "encryption": "none",
                        "flow": (if $p["flow"] != "" and $p["flow"] != null then $p["flow"] else null end)
                    }]
                }]
            },
            "streamSettings": {
                "network": $type,
                "security": $sec,
                "tlsSettings": (if $sec == "tls" then {
                    "serverName": $sni,
                    "fingerprint": ($p["fp"] // "chrome"),
                    "allowInsecure": $allow_ins,
                    "alpn": (if $p["alpn"] != null and $p["alpn"] != "" then ($p["alpn"] | decode | split(",")) else ["h2", "http/1.1"] end)
                } else null end),
                "realitySettings": (if $sec == "reality" then {
                    "serverName": $sni,
                    "fingerprint": ($p["fp"] // "chrome"),
                    "publicKey": $p["pbk"],
                    "shortId": $p["sid"],
                    "spiderX": (decode($p["spx"]) // "/")
                } else null end),
                "wsSettings": (if $type == "ws" then {
                    "path": $path,
                    "headers": {"Host": $ws_host}
                } else null end),
                "xhttpSettings": (if $type == "xhttp" then {
                    "path": $path,
                    "host": $ws_host,
                    "mode": ($p["mode"] // "auto")
                } else null end)
            }
        } | del(..|nulls)' 2>/dev/null
}

setup_xray_relay() {
    if [[ ! -f "$XRAY_BIN" ]]; then echo -e "${RED}Install Xray-core first!${NC}"; sleep 1; return; fi

    echo -e "${YELLOW}Paste your Xray Outbound JSON or VLESS/VMESS Link:${NC}"
    echo -e "Press Ctrl+D followed by Enter when finished."
    echo -e "${BLUE}(Pro Tip: If pasting large text, ensure it ends with a newline before Ctrl+D)${NC}"

    local input=$(cat)
    if [[ -z "$input" ]]; then echo -e "${RED}No input received.${NC}"; sleep 1; return; fi

    local outbound=""
    if [[ "$input" == vless://* ]]; then
        outbound=$(parse_vless_link "$input")
    elif [[ "$input" == vmess://* ]]; then
        outbound=$(parse_vmess_link "$input")
    elif echo "$input" | jq . >/dev/null 2>&1; then
        outbound="$input"
        # Fix flat JSON format (address directly in settings)
        if echo "$outbound" | jq -e '.settings.address' >/dev/null 2>&1; then
             echo -e "${YELLOW}Converting flat JSON to standard Xray outbound...${NC}"
             outbound=$(echo "$outbound" | jq '
                if .protocol == "vless" or .protocol == "vmess" then
                    if .settings.address then
                        .settings = {
                            "vnext": [{
                                "address": (.settings.address | tostring),
                                "port": (.settings.port | tonumber),
                                "users": [{
                                    "id": ((.settings.id // .settings.users[0].id) | tostring),
                                    "encryption": ((.settings.encryption // "none") | tostring),
                                    "flow": ((.settings.flow // "") | tostring),
                                    "security": ((.settings.security // "auto") | tostring)
                                }]
                            }]
                        }
                    else . end
                else . end
             ')
        fi
    else
        echo -e "${RED}Error: Invalid format. Paste JSON or vless/vmess link.${NC}"
        sleep 2
        return
    fi

    local random_name="relay_$(openssl rand -hex 4)"
    read -p "Enter a name for this config (default: $random_name): " relay_name
    relay_name=${relay_name:-$random_name}
    relay_name=$(echo "$relay_name" | sed 's/[^a-zA-Z0-9_]/_/g')

    mkdir -p "$SAVED_RELAYS_DIR"
    echo "$outbound" > "${SAVED_RELAYS_DIR}/${relay_name}.json"
    echo -e "${GREEN}Saved as $relay_name!${NC}"
    sleep 1

    activate_relay "$relay_name"
}

# Stop any of our services using a specific port
stop_conflicting_service() {
    local port=$1
    if grep -q "\"port\": $port" "$XRAY_CONFIG" 2>/dev/null; then
        echo -e "${YELLOW}Stopping Reality tunnel on port $port...${NC}"
        systemctl stop "$XRAY_SERVICE" 2>/dev/null
    fi
    if grep -q "\"port\": $port" "$XRAY_RELAY_CONFIG" 2>/dev/null; then
        echo -e "${YELLOW}Stopping existing Relay tunnel on port $port...${NC}"
        systemctl stop "$XRAY_RELAY_SERVICE" 2>/dev/null
    fi
}

activate_relay() {
    local name=$1
    local config_file="${SAVED_RELAYS_DIR}/${name}.json"
    if [[ ! -f "$config_file" ]]; then echo -e "${RED}Config $name not found!${NC}"; return; fi

    local outbound=$(cat "$config_file")
    local proto=$(echo "$outbound" | jq -r '.protocol')
    local remote_addr=$(echo "$outbound" | jq -r '.settings.vnext[0].address // .settings.redirect // empty' | cut -d':' -f1)
    local remote_port=$(echo "$outbound" | jq -r '.settings.vnext[0].port // .settings.redirect // 0' | awk -F':' '{print $NF}')
    [[ -z "$remote_port" || "$remote_port" == "0" || "$remote_port" == "null" ]] && remote_port=2053

    local security=$(echo "$outbound" | jq -r '.streamSettings.security // "none"')
    local transport=$(echo "$outbound" | jq -r '.streamSettings.network // "tcp"')
    local id=$(echo "$outbound" | jq -r '.settings.vnext[0].users[0].id // empty')

    read_port "Enter IRAN Local Port (to listen on): " "iran_port" "true" 80

    local in_proto_choice=1
    if [[ "$proto" != "freedom" ]]; then
        echo -e "\nChoose Entry Protocol for Iran Server:"
        echo -e "1. Bridge Mode (Simple Forwarding - Use original link on phone)"
        echo -e "2. SOCKS5 + HTTP Proxy (Use as proxy in Apps/Phone)"
        echo -e "3. ${proto^^} Relay (UUID Protected - Generate new link for phone)"
        read_num "Choice (default: 1): " "in_proto_choice" 1 3
    else
        echo -e "\nProtocol is Plain TCP. Defaulting to Bridge Mode."
        in_proto_choice=1
    fi
    in_proto_choice=${in_proto_choice:-1}

    local final_json=""
    case $in_proto_choice in
        1)
            # Bridge Mode: If config is encrypted, we must just forward RAW bits
            if [[ "$security" != "none" || "$transport" != "tcp" ]]; then
                echo -e "${YELLOW}Detected encrypted/complex tunnel. Using Simple Transparent Bridge.${NC}"
                final_json=$(jq -n --argjson p "$iran_port" --arg addr "$remote_addr" --argjson rp "$remote_port" '
                {
                    "log": { "loglevel": "warning" },
                    "inbounds": [{
                        "port": $p,
                        "protocol": "dokodemo-door",
                        "settings": { "address": $addr, "port": $rp, "network": "tcp,udp" }
                    }],
                    "outbounds": [{ "protocol": "freedom" }]
                }')
            else
                # Plain TCP config, we can use the outbound as-is
                final_json=$(jq -n --argjson p "$iran_port" --argjson outb "$outbound" '
                {
                    "log": { "loglevel": "warning" },
                    "inbounds": [{
                        "port": $p,
                        "protocol": "dokodemo-door",
                        "settings": { "address": "127.0.0.1", "port": 0, "network": "tcp,udp" },
                        "tag": "in"
                    }],
                    "outbounds": [($outb | .tag = "out")],
                    "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "out", "type": "field" }] }
                }')
            fi
            ;;
        2)
            # SOCKS Mode
            final_json=$(jq -n --argjson p "$iran_port" --argjson outb "$outbound" '
            {
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "port": $p,
                    "protocol": "socks",
                    "settings": { "auth": "noauth", "udp": true },
                    "tag": "in"
                }],
                "outbounds": [($outb | .tag = "out")],
                "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "out", "type": "field" }] }
            }')
            ;;
        3)
            # Protocol specific Relay
            local inbound_proto="$proto"
            local inbound_settings="{ \"clients\": [ { \"id\": \"$id\" } ] }"
            [[ "$proto" == "vless" ]] && inbound_settings="{ \"clients\": [ { \"id\": \"$id\" } ], \"decryption\": \"none\" }"

            final_json=$(jq -n --argjson p "$iran_port" --arg pr "$inbound_proto" --argjson ps "$inbound_settings" --argjson outb "$outbound" '
            {
                "log": { "loglevel": "warning" },
                "inbounds": [{
                    "port": $p,
                    "protocol": $pr,
                    "settings": $ps,
                    "tag": "in"
                }],
                "outbounds": [($outb | .tag = "out")],
                "routing": { "rules": [{ "inboundTag": ["in"], "outboundTag": "out", "type": "field" }] }
            }')
            ;;
    esac

    echo "$final_json" | jq 'del(..|nulls)' > "$XRAY_RELAY_CONFIG"

    cat << EOF > "/etc/systemd/system/${XRAY_RELAY_SERVICE}"
[Unit]
Description=Xray Relay Tunnel ($name)
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

    read -p "Apply changes and restart Xray Relay now? (y/n, default: y): " apply_now
    apply_now=${apply_now:-y}
    if [[ "$apply_now" != "y" ]]; then
        echo -e "${YELLOW}Changes saved but not applied. Service not restarted.${NC}"
        sleep 2
        return
    fi

    stop_conflicting_service "$iran_port"
    systemctl daemon-reload
    systemctl enable "$XRAY_RELAY_SERVICE"
    systemctl restart "$XRAY_RELAY_SERVICE"

    echo -e "${CYAN}Checking service status...${NC}"
    sleep 3
    if systemctl is-active --quiet "$XRAY_RELAY_SERVICE"; then
        echo -e "${GREEN}Xray Relay ($name) is now ACTIVE on port $iran_port!${NC}"

        if [[ "$in_proto_choice" == "3" ]]; then
            local my_ip=$(get_public_ip | awk '{print $1}')
            echo -e "\n${YELLOW}--- Client Configuration ---${NC}"
            echo -e "Use these settings in your V2ray client to connect to this Iran server:"
            echo -e "${WHITE}Address:${NC} $my_ip"
            echo -e "${WHITE}Port:${NC} $iran_port"
            echo -e "${WHITE}Protocol:${NC} $proto"
            [[ -n "$id" ]] && echo -e "${WHITE}UUID:${NC} $id"
            echo -e "${WHITE}Transport:${NC} TCP (Plain)"
            echo -e "${WHITE}Security:${NC} None"

            # Generate a link
            local link=""
            if [[ "$proto" == "vless" ]]; then
                link="vless://${id}@${my_ip}:${iran_port}?encryption=none&security=none&type=tcp#Iranbax_${name}"
            elif [[ "$proto" == "vmess" ]]; then
                local v_json=$(jq -n --arg add "$my_ip" --arg port "$iran_port" --arg id "$id" --arg ps "Iranbax_${name}" \
                    '{"v":"2","ps":$ps,"add":$add,"port":$port,"id":$id,"aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"","sni":"","alpn":"","fp":""}')
                link="vmess://$(echo -n "$v_json" | base64 -w 0)"
            fi
            [[ -n "$link" ]] && echo -e "\n${CYAN}Import Link:${NC}\n$link"
        fi

        # End-to-end check
        echo -e "${CYAN}Performing end-to-end connectivity test...${NC}"
        local test_cmd="curl -L --connect-timeout 5 -s -o /dev/null -w \"%{http_code}\""
        local fetch_ok=false

        if [[ "$in_proto_choice" == "1" ]]; then
            # Test via SOCKS5
            if [[ $($test_cmd --proxy socks5h://127.0.0.1:$iran_port http://www.google.com/generate_204) == "204" ]]; then
                fetch_ok=true
            fi
        else
            # For VLESS/VMESS, we can't easily test with curl without a client,
            # so we check if the port is at least listening and responding
            if ss -tulnp | grep -q ":$iran_port "; then
                echo -e "${YELLOW}[!] Protocol-specific relay is listening. Connect your V2ray client to verify.${NC}"
                sleep 2
                return
            fi
        fi

        if [[ "$fetch_ok" == "true" ]]; then
             echo -e "${GREEN}[✔] End-to-end connectivity verified! Proxy is working.${NC}"
        else
             echo -e "${RED}[!] Service is running but internet fetch failed.${NC}"
             echo -e "${YELLOW}Possible reasons: Kharej server down, wrong UUID/Port, or blocked.${NC}"
        fi
    else
        echo -e "${RED}[✘] Failed to start Xray Relay service.${NC}"
        echo -e "${YELLOW}Generated Configuration ($XRAY_RELAY_CONFIG):${NC}"
        cat "$XRAY_RELAY_CONFIG"
        echo -e "\n${YELLOW}Fetching last 20 lines of logs for $XRAY_RELAY_SERVICE:${NC}"
        journalctl -u "$XRAY_RELAY_SERVICE" -n 20 --no-pager
    fi
    sleep 3
}

saved_relays_menu() {
    while true; do
        local count=$(ls -1 "${SAVED_RELAYS_DIR}"/*.json 2>/dev/null | wc -l)
        if [[ $count -eq 0 ]]; then
            echo -e "${RED}No saved relays found.${NC}"
            sleep 1
            return
        fi

        clear
        display_logo
        echo -e "${CYAN}--- Saved Xray Relays ---${NC}"
        local i=1
        local names=()
        for f in "${SAVED_RELAYS_DIR}"/*.json; do
            local name=$(basename "$f" .json)
            echo "$i. $name"
            names+=("$name")
            ((i++))
        done
        echo "$i. Back"

        read_num "Choose a relay: " "r_idx" 1 $i
        if [[ $r_idx -eq $i ]]; then break; fi

        local selected="${names[$((r_idx-1))]}"

        echo -e "\n${YELLOW}Selected: $selected${NC}"
        echo "1. Connect (Activate)"
        echo "2. Edit (Address/Host/Port)"
        echo "3. Rename"
        echo "4. Delete"
        echo "5. Back"
        read_num "Choose action: " "a_idx" 1 5

        case $a_idx in
            1) activate_relay "$selected"; return ;;
            2) edit_relay "$selected" ;;
            3)
               read -p "Enter new name: " new_name
               if [[ -n "$new_name" ]]; then
                   mv "${SAVED_RELAYS_DIR}/${selected}.json" "${SAVED_RELAYS_DIR}/${new_name}.json"
                   echo -e "${GREEN}Renamed.${NC}"; sleep 1
               fi
               ;;
            4)
               rm "${SAVED_RELAYS_DIR}/${selected}.json"
               echo -e "${RED}Deleted.${NC}"; sleep 1
               ;;
            *) continue ;;
        esac
    done
}

edit_relay() {
    local name=$1
    local file="${SAVED_RELAYS_DIR}/${name}.json"

    clear
    echo -e "${YELLOW}Editing $name...${NC}"
    local current_addr=$(jq -r '.settings.vnext[0].address // empty' "$file")
    local current_port=$(jq -r '.settings.vnext[0].port // empty' "$file")
    local current_host=$(jq -r '.streamSettings.wsSettings.headers.Host // .streamSettings.tlsSettings.serverName // empty' "$file")

    echo -e "1. Change Remote Address (currently: ${current_addr:-N/A})"
    echo -e "2. Change Remote Port (currently: ${current_port:-N/A})"
    echo -e "3. Change Host/SNI (currently: ${current_host:-N/A})"
    echo -e "4. Back"

    read_num "Choice: " "e_choice" 1 4
    case $e_choice in
        1)
            read -p "Enter new Address: " n_addr
            if [[ -n "$n_addr" ]]; then
                jq --arg a "$n_addr" '.settings.vnext[0].address = $a' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
            fi
            ;;
        2)
            read_port "Enter new Port: " "n_port" "false"
            jq --argjson p "$n_port" '.settings.vnext[0].port = $p' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
            ;;
        3)
            read -p "Enter new Host/SNI: " n_host
            if [[ -n "$n_host" ]]; then
                # Update both SNI and WS Host if they exist
                jq --arg h "$n_host" '
                    if .streamSettings.tlsSettings then .streamSettings.tlsSettings.serverName = $h else . end |
                    if .streamSettings.wsSettings then .streamSettings.wsSettings.headers.Host = $h | .streamSettings.wsSettings.host = $h else . end |
                    if .streamSettings.realitySettings then .streamSettings.realitySettings.serverNames = [$h] else . end
                ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
            fi
            ;;
    esac

    activate_relay "$name"
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

        jq -n \
            --argjson p "$server_port" \
            --arg id "$uuid" \
            --arg pk "$private_key" \
            --arg sid "$short_id" \
            --argjson dp "$dest_port" \
            '{
                "log": { "loglevel": "warning" },
                "inbounds": [
                    {
                        "port": $p,
                        "protocol": "vless",
                        "settings": {
                            "clients": [ { "id": $id, "flow": "xtls-rprx-vision" } ],
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
                                "privateKey": $pk,
                                "shortIds": [ $sid ]
                            }
                        },
                        "sniffing": { "enabled": true, "destOverride": [ "http", "tls" ] }
                    }
                ],
                "outbounds": [
                    {
                        "protocol": "dokodemo-door",
                        "settings": { "address": "127.0.0.1", "port": $dp },
                        "tag": "forward"
                    }
                ],
                "routing": {
                    "rules": [ { "type": "field", "port": $p, "outboundTag": "forward" } ]
                }
            }' > "$XRAY_CONFIG"

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

        jq -n \
            --argjson p "$iran_port" \
            --arg kip "$kharej_ip" \
            --argjson kp "$kharej_port" \
            --arg id "$uuid" \
            --arg pk "$public_key" \
            --arg sid "$short_id" \
            '{
                "log": { "loglevel": "warning" },
                "inbounds": [
                    {
                        "port": $p,
                        "protocol": "dokodemo-door",
                        "settings": { "address": $kip, "port": $kp, "network": "tcp" }
                    }
                ],
                "outbounds": [
                    {
                        "protocol": "vless",
                        "settings": {
                            "vnext": [
                                {
                                    "address": $kip,
                                    "port": $kp,
                                    "users": [ { "id": $id, "encryption": "none", "flow": "xtls-rprx-vision" } ]
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
                                "publicKey": $pk,
                                "shortId": $sid,
                                "spiderX": ""
                            }
                        }
                    }
                ]
            }' > "$XRAY_CONFIG"
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
    local port_to_check="$iran_port"
    [[ "$role" == "server" ]] && port_to_check="$server_port"
    stop_conflicting_service "$port_to_check"
    systemctl daemon-reload
    systemctl enable "$XRAY_SERVICE"
    systemctl restart "$XRAY_SERVICE"
    echo -e "${CYAN}Checking service status...${NC}"
    sleep 3
    if systemctl is-active --quiet "$XRAY_SERVICE"; then
        echo -e "${GREEN}Xray-Reality service started!${NC}"
    else
        echo -e "${RED}[✘] Failed to start Xray-Reality service.${NC}"
        echo -e "${YELLOW}Fetching last 20 lines of logs for $XRAY_SERVICE:${NC}"
        journalctl -u "$XRAY_SERVICE" -n 20 --no-pager
    fi
    sleep 2
}

setup_proxy_keys() {
    local target_ip=$1
    local user=$2
    local port=$3

    if [[ ! -f "$HOME/.ssh/id_rsa" ]]; then
        echo -e "${YELLOW}Auth key not found. Generating...${NC}"
        ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N ""
    fi

    echo -e "${CYAN}Copying auth key to target server... you may be prompted for password.${NC}"
    ssh-copy-id -o StrictHostKeyChecking=no -p "$port" "${user}@${target_ip}"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Auth key copied successfully!${NC}"
    else
        echo -e "${RED}Failed to copy auth key.${NC}"
    fi
}

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
    # Kill the setup proxy if running on port 1080
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
    read -p "Do you want to setup Auth Keys first? (y/n): " setup_keys
    [[ "$setup_keys" == "y" ]] && setup_proxy_keys "$ip" "$user" "$port"

    echo -e "${CYAN}Establishing setup proxy...${NC}"
    # Start Dynamic Forwarding in background
    ssh -D 1080 -C -N -f -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${user}@${ip}"

    if [ $? -eq 0 ]; then
        export http_proxy="socks5h://127.0.0.1:1080"
        export https_proxy="socks5h://127.0.0.1:1080"
        echo 'Acquire::http::Proxy "socks5h://127.0.0.1:1080/"; Acquire::https::Proxy "socks5h://127.0.0.1:1080/";' | sudo tee /etc/apt/apt.conf.d/99proxy > /dev/null
        echo -e "${GREEN}Proxy established! http_proxy/https_proxy set to socks5h://127.0.0.1:1080${NC}"
        save_proxy "$ip" "$user" "$port"
    else
        echo -e "${RED}Failed to establish setup proxy.${NC}"
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
        echo -e "1. New SOCKS5 Setup Proxy"
        echo -e "2. Use a Saved Proxy"
        echo -e "3. Manage Saved Proxies (Delete)"
        echo -e "4. Clear Active Proxy Settings"
        echo -e "5. Back"
        echo ''
        read_num "Choose an option: " "proxy_choice" 1 5

        case $proxy_choice in
            1)
                read_ip "Enter Foreign Server IP: " "proxy_ip"
                read -p "Enter Username (default: root): " proxy_user
                proxy_user=${proxy_user:-root}
                read_port "Enter Port (default: 22): " "proxy_port" "false" 22
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

    # Stop all services
    echo -e "${YELLOW}Stopping all tunnel services...${NC}"
    systemctl stop "$XRAY_SERVICE" "$XRAY_RELAY_SERVICE" 2>/dev/null
    systemctl disable "$XRAY_SERVICE" "$XRAY_RELAY_SERVICE" 2>/dev/null

    # SSH tunnels
    local ssh_services=$(ls /etc/systemd/system/iranbax-ssh-*.service 2>/dev/null)
    for s in $ssh_services; do
        systemctl stop "$(basename "$s")" 2>/dev/null
        systemctl disable "$(basename "$s")" 2>/dev/null
        rm -f "$s"
    done

    # Remove systemd files
    rm -f "/etc/systemd/system/${XRAY_SERVICE}" "/etc/systemd/system/${XRAY_RELAY_SERVICE}"

    # Remove ACTIVE config files but NOT the whole directory or zip/relays
    echo -e "${YELLOW}Removing active configuration files...${NC}"
    rm -f "${CONFIG_DIR}/xray_config.json" "${CONFIG_DIR}/xray_relay.json"

    # Proxies
    clear_proxy

    systemctl daemon-reload
    echo -e "${GREEN}All active tunnels destroyed! (Folder and saved relays were preserved)${NC}"
    sleep 2
}

check_status() {
    clear
    display_topbar
    display_logo
    echo -e "${CYAN}--- Xray Tunnel Status ---${NC}"
    echo ''
    systemctl list-units --type=service --all | grep -E "iranbax-xray" || echo "No Xray services configured."
    echo ''
    read -p "Press Enter to continue..."
    flush_stdin
}

restart_all() {
    echo -e "${YELLOW}Restarting all services...${NC}"
    systemctl restart "$XRAY_SERVICE" "$XRAY_RELAY_SERVICE" 2>/dev/null
    echo -e "${GREEN}Done.${NC}"
    sleep 1
}

update_script() {
    echo -e "${CYAN}Updating script...${NC}"
    # Target URL for updates
    local script_url="https://raw.githubusercontent.com/Musixal/iranbaxtunnel/main/iranbaxtunnel.sh"
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

manage_ssh_tunnels() {
    while true; do
        clear
        display_logo
        echo -e "${BLUE}--- SSH Tunnel Management ---${NC}"
        echo -e "1. Create New SSH Tunnel (Local Forwarding: Iran -> Kharej)"
        echo -e "2. List & Stop Active SSH Tunnels"
        echo -e "3. Back"
        echo ''
        read_num "Choice: " "ssh_t_choice" 1 3
        case $ssh_t_choice in
            1) create_ssh_tunnel ;;
            2) list_ssh_tunnels ;;
            3) break ;;
        esac
    done
}

create_ssh_tunnel() {
    clear
    display_logo
    echo -e "${BLUE}--- Create SSH Tunnel ---${NC}"
    echo -e "This uses 'ssh -L' to forward an Iran port to a Kharej port."
    echo ''
    read_ip "Enter KHAREJ Server IP: " "kharej_ip"
    read -p "Enter SSH Username (default: root): " kharej_user
    kharej_user=${kharej_user:-root}
    read_port "Enter KHAREJ SSH Port (default: 22): " "kharej_ssh_port" "false" 22
    read_port "Enter IRAN Local Port (to listen on): " "iran_port" "true" 80
    read_port "Enter KHAREJ Target Port (e.g., 2053): " "kharej_target_port" "false" 2053

    echo -e "\n${YELLOW}Setting up Auth Keys...${NC}"
    setup_proxy_keys "$kharej_ip" "$kharej_user" "$kharej_ssh_port"

    local service_name="iranbax-ssh-${iran_port}.service"
    cat << EOF > "/etc/systemd/system/${service_name}"
[Unit]
Description=SSH Tunnel Iran:${iran_port} -> Kharej:${kharej_target_port}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -L 0.0.0.0:${iran_port}:127.0.0.1:${kharej_target_port} -N -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -p ${kharej_ssh_port} ${kharej_user}@${kharej_ip}
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$service_name"
    systemctl restart "$service_name"

    sleep 2
    if systemctl is-active --quiet "$service_name"; then
        echo -e "${GREEN}SSH Tunnel established! Iran:${iran_port} is now bridged to Kharej:${kharej_target_port}${NC}"
    else
        echo -e "${RED}Failed to start SSH Tunnel service.${NC}"
        journalctl -u "$service_name" -n 10 --no-pager
    fi
    sleep 2
}

list_ssh_tunnels() {
    clear
    display_logo
    echo -e "${BLUE}--- Active SSH Tunnels ---${NC}"
    local services=$(ls /etc/systemd/system/iranbax-ssh-*.service 2>/dev/null)
    if [[ -z "$services" ]]; then
        echo -e "${RED}No active SSH tunnels found.${NC}"
        sleep 1
        return
    fi

    local i=1
    local s_names=()
    for s in $services; do
        local name=$(basename "$s")
        local status=$(systemctl is-active "$name")
        echo -e "$i. $name [$status]"
        s_names+=("$name")
        ((i++))
    done
    echo "$i. Back"

    read_num "Choose a tunnel to stop (0 for none): " "s_idx" 0 $i
    [[ $s_idx -eq 0 || $s_idx -eq $i ]] && return

    local selected="${s_names[$((s_idx-1))]}"
    systemctl stop "$selected"
    systemctl disable "$selected"
    rm -f "/etc/systemd/system/$selected"
    systemctl daemon-reload
    echo -e "${GREEN}Tunnel stopped and removed.${NC}"
    sleep 1
}

# Main loop
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
while true; do
    display_menu
    read_num "Enter your choice: " "choice" 0 7
    case $choice in
        1) manage_xray_relay ;;
        2) manage_xray_reality ;;
        3) manage_ssh_tunnels ;;
        4) manage_services ;;
        5) installation_proxy ;;
        6) cleanup_all ;;
        7) update_script ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option!${NC}" && sleep 1 ;;
    esac
done
fi
