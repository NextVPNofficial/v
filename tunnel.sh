#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Constants
TUNNEL_6TO4="tun6to4"
TUNNEL_GRE="gre1"
IPV6_IRAN="fd01::2/64"
IPV6_KHAREJ="fd01::1/64"
IPV4_IRAN_TUN="172.16.0.2/30"
IPV4_KHAREJ_TUN="172.16.0.1/30"
TABLE_ID=4

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

check_ipv6_support() {
    # Check if disabled via sysctl (value 1 means disabled)
    local all_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)

    if [ ! -f /proc/net/if_inet6 ] || [ "$all_disabled" == "1" ]; then
        log_error "IPv6 is disabled or not supported by the kernel."
        log_info "SIT and GRE-over-IPv6 require the system's IPv6 stack to be active."

        echo -n -e "${YELLOW}Would you like to attempt to enable IPv6 now? [y/n]: ${NC}"
        read -r fix_choice
        if [[ "$fix_choice" == "y" || "$fix_choice" == "Y" ]]; then
            log_info "Applying sysctl fixes..."
            sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
            sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
            sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1

            if [ -f /proc/net/if_inet6 ] && [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" == "0" ]; then
                log_success "IPv6 has been enabled in the current session!"
            else
                log_error "Sysctl attempt failed. IPv6 is likely hard-disabled in GRUB."
            fi

            log_warn "To make this permanent and ensure full support, you MUST check GRUB:"
            echo -e "  1. Run: ${CYAN}sudo nano /etc/default/grub${NC}"
            echo -e "  2. Find the line starting with: ${YELLOW}GRUB_CMDLINE_LINUX_DEFAULT${NC}"
            echo -e "  3. Remove ${RED}ipv6.disable=1${NC} from inside the quotes."
            echo -e "  4. Save (Ctrl+O, Enter) and Exit (Ctrl+X)."
            echo -e "  5. Run: ${CYAN}sudo update-grub${NC}"
            echo -e "  6. Run: ${CYAN}sudo reboot${NC}"

            # If it's now working in session, we can proceed, otherwise fail
            [ -f /proc/net/if_inet6 ] && return 0 || return 1
        else
            log_warn "IPv6 remains disabled. Tunneling will likely fail."
            return 1
        fi
    fi
    return 0
}

load_module() {
    local module=$1
    if ! modprobe "$module" 2>/dev/null; then
        log_warn "Could not load module $module with modprobe. Checking if it's already built-in..."
        if ! grep -q "$module" /proc/modules 2>/dev/null && [ ! -d "/sys/module/$module" ]; then
             log_error "Kernel module $module is not available."
             log_info "On Ubuntu/Debian, try: sudo apt update && sudo apt install linux-modules-extra-\$(uname -r)"
             return 1
        fi
    fi
    return 0
}

# Detect default interface
detect_interface() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$interface" ]; then
        interface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n1)
    fi
    echo "$interface"
}

MAIN_IFACE=$(detect_interface)

log_success() { echo -e "${GREEN}[✔] $1${NC}"; }
log_info() { echo -e "${CYAN}[ℹ] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
log_error() { echo -e "${RED}[✘] $1${NC}"; }

check_settings_consistency() {
    # If no tunnels exist, it's "Ready to Set"
    if ! ip link show "$TUNNEL_6TO4" >/dev/null 2>&1 && ! ip link show "$TUNNEL_GRE" >/dev/null 2>&1; then
        echo -e "${CYAN}Ready to Set${NC}"
        return
    fi

    local missing=()

    # 1. Check SIT
    if ! ip link show "$TUNNEL_6TO4" >/dev/null 2>&1; then
        missing+=("SIT-Interface")
    fi

    # 2. Check GRE
    if ! ip link show "$TUNNEL_GRE" >/dev/null 2>&1; then
        missing+=("GRE-Interface")
    fi

    # 4. Check Table 4 route
    if ! ip route show table "$TABLE_ID" 2>/dev/null | grep -q "default via"; then
        missing+=("Routing-Table-$TABLE_ID")
    fi

    # 5. Check NAT rules
    if ! iptables -t nat -S | grep -q "tunnel_wizard"; then
        missing+=("NAT-Rules")
    fi

    # 6. Check IP Forwarding
    if [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) != "1" ]]; then
        missing+=("IP-Forwarding")
    fi

    if [ ${#missing[@]} -eq 0 ]; then
        echo -e "${GREEN}Correct${NC}"
    else
        # Join array elements with comma
        local joined=$(IFS=, ; echo "${missing[*]}")
        echo -e "${RED}Incorrect (Missing: $joined)${NC}"
    fi
}

show_menu() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}       ${CYAN}🚀 TUNNEL WIZARD v2.0${NC}            ${BLUE}║${NC}"
    echo -e "${BLUE}╠════════════════════════════════════════╝${NC}"
    echo -e "  ${YELLOW}Interface:${NC} $MAIN_IFACE"
    echo -e "  ${YELLOW}Status:${NC}    $(ip link show $TUNNEL_6TO4 >/dev/null 2>&1 && echo -e "${GREEN}Connected${NC}" || echo -e "${RED}Disconnected${NC}")"
    echo -e "  ${YELLOW}Settings:${NC}  $(check_settings_consistency)"
    echo -e "${BLUE}╟────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}[1]${NC} 🇮🇷 Setup Iran Server (Relay)"
    echo -e "  ${CYAN}[2]${NC} 🌍 Setup Kharej Server (Endpoint)"
    echo -e "  ${CYAN}[3]${NC} 🔓 Manage Exemptions (IPs & Ports)"
    echo -e "  ${CYAN}[4]${NC} 🗑️  Remove Tunnel & Cleanup"
    echo -e "  ${CYAN}[5]${NC} 📊 Show Status & Ping"
    echo -e "  ${CYAN}[6]${NC} 🔗 Install 'iranbaxv6' Shortcut"
    echo -e "  ${CYAN}[7]${NC} ❌ Exit"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo -n "Select an option [1-7]: "
}

validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

select_ipv6() {
    echo -e "\n${CYAN}Select IPv6 Tunnel Network (Must be same on both servers):${NC}"
    echo -e "1) fd01:: (Iran: ::2, Kharej: ::1) - Default"
    echo -e "2) fd02:: (Iran: ::2, Kharej: ::1)"
    echo -e "3) fd03:: (Iran: ::2, Kharej: ::1)"
    echo -e "4) Manual Entry"
    echo -n "Select option [1-4] or type manual prefix (Default is 1): "
    read -r ipv6_choice

    case $ipv6_choice in
        2) PREFIX="fd02::" ;;
        3) PREFIX="fd03::" ;;
        4)
            echo -n "Enter IPv6 Prefix (e.g., fd04::): "
            read -r manual_prefix
            PREFIX=$manual_prefix
            ;;
        *)
            if [[ -z "$ipv6_choice" || "$ipv6_choice" == "1" ]]; then
                PREFIX="fd01::"
            else
                PREFIX=$ipv6_choice
            fi
            ;;
    esac

    # Validation and formatting
    if [[ -z "$PREFIX" ]]; then PREFIX="fd01::"; fi
    if [[ ! "$PREFIX" == *":"* ]]; then
        log_warn "Invalid prefix format, defaulting to fd01::"
        PREFIX="fd01::"
    fi
    # Ensure it ends with ::
    if [[ ! "$PREFIX" == *"::" ]]; then
        if [[ "$PREFIX" == *":" ]]; then PREFIX="${PREFIX}:"; else PREFIX="${PREFIX}::"; fi
    fi
}

setup_iran() {
    check_ipv6_support || return

    echo -n "Enter Kharej (Server 2) Public IP: "
    read -r REMOTE_IP
    if ! validate_ip "$REMOTE_IP"; then
        log_error "Invalid IP address format."
        return
    fi

    local local_ips=$(hostname -I)
    if [[ " $local_ips " =~ " $REMOTE_IP " ]]; then
        log_warn "The IP ($REMOTE_IP) seems to belong to this server!"
        echo -n -e "${YELLOW}Proceed anyway? [y/n]: ${NC}"
        read -r self_confirm
        [[ ! "$self_confirm" =~ ^[yY]$ ]] && return
    fi

    select_ipv6

    # Summary and Confirmation
    echo -e "\n${BLUE}┌─ Configuration Summary (IRAN ROLE)${NC}"
    echo -e "  ${BLUE}├─${NC} Remote Server IP: ${YELLOW}$REMOTE_IP${NC}"
    echo -e "  ${BLUE}├─${NC} Tunnel Network:   ${YELLOW}${PREFIX}${NC}"
    echo -e "  ${BLUE}├─${NC} Local SIT IP:     ${CYAN}${PREFIX}2${NC}"
    echo -e "  ${BLUE}├─${NC} Remote SIT IP:    ${CYAN}${PREFIX}1${NC}"
    echo -e "  ${BLUE}├─${NC} Local GRE IP:     ${CYAN}172.16.0.2${NC}"
    echo -e "  ${BLUE}└─${NC} Remote GRE IP:    ${CYAN}172.16.0.1${NC}"

    echo -n -e "\n${YELLOW}Proceed with this configuration? [y/n]: ${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        log_warn "Setup cancelled."
        return
    fi

    log_info "Cleaning up old configuration..."
    remove_tunnel > /dev/null 2>&1

    log_info "Setting up Iran Server..."

    load_module sit
    load_module ip6_gre

    # Set MTU
    ip link set dev "$MAIN_IFACE" mtu 1500 2>/dev/null

    # SIT Tunnel
    log_info "Creating SIT tunnel..."
    if ! ip tunnel add "$TUNNEL_6TO4" mode sit ttl 254 remote "$REMOTE_IP"; then
        log_error "Failed to create SIT tunnel. Your kernel might not support SIT (Simple Internet Transition)."
        return
    fi
    ip link set dev "$TUNNEL_6TO4" up
    ip addr add "${PREFIX}2/64" dev "$TUNNEL_6TO4"
    ip link set dev "$TUNNEL_6TO4" mtu 1480

    sleep 2

    # GRE Tunnel
    log_info "Creating GRE tunnel..."
    if ! ip tunnel add "$TUNNEL_GRE" mode ip6gre remote "${PREFIX}1" local "${PREFIX}2"; then
        log_error "Failed to create GRE tunnel. Your kernel might not support GRE over IPv6."
        return
    fi
    ip link set "$TUNNEL_GRE" up
    ip addr add "$IPV4_IRAN_TUN" dev "$TUNNEL_GRE"
    ip link set dev "$TUNNEL_GRE" mtu 1476

    log_success "Iran Server Tunnels established (Prefix: $PREFIX)"
    configure_routing_nat "iran"
}

setup_kharej() {
    check_ipv6_support || return

    echo -n "Enter Iran (Server 1) Public IP: "
    read -r REMOTE_IP
    if ! validate_ip "$REMOTE_IP"; then
        log_error "Invalid IP address format."
        return
    fi

    local local_ips=$(hostname -I)
    if [[ " $local_ips " =~ " $REMOTE_IP " ]]; then
        log_warn "The IP ($REMOTE_IP) seems to belong to this server!"
        echo -n -e "${YELLOW}Proceed anyway? [y/n]: ${NC}"
        read -r self_confirm
        [[ ! "$self_confirm" =~ ^[yY]$ ]] && return
    fi

    select_ipv6

    # Summary and Confirmation
    echo -e "\n${BLUE}┌─ Configuration Summary (KHAREJ / ENDPOINT ROLE)${NC}"
    echo -e "  ${BLUE}├─${NC} Remote Server IP: ${YELLOW}$REMOTE_IP${NC}"
    echo -e "  ${BLUE}├─${NC} Tunnel Network:   ${YELLOW}${PREFIX}${NC}"
    echo -e "  ${BLUE}├─${NC} Local SIT IP:     ${CYAN}${PREFIX}1${NC}"
    echo -e "  ${BLUE}├─${NC} Remote SIT IP:    ${CYAN}${PREFIX}2${NC}"
    echo -e "  ${BLUE}├─${NC} Local GRE IP:     ${CYAN}172.16.0.1${NC}"
    echo -e "  ${BLUE}└─${NC} Remote GRE IP:    ${CYAN}172.16.0.2${NC}"

    echo -n -e "\n${YELLOW}Proceed with this configuration? [y/n]: ${NC}"
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        log_warn "Setup cancelled."
        return
    fi

    log_info "Cleaning up old configuration..."
    remove_tunnel > /dev/null 2>&1

    log_info "Setting up Kharej Server..."

    load_module sit
    load_module ip6_gre

    # Set MTU
    ip link set dev "$MAIN_IFACE" mtu 1500 2>/dev/null

    # SIT Tunnel
    log_info "Creating SIT tunnel..."
    if ! ip tunnel add "$TUNNEL_6TO4" mode sit ttl 254 remote "$REMOTE_IP"; then
        log_error "Failed to create SIT tunnel. Your kernel might not support SIT (Simple Internet Transition)."
        return
    fi
    ip link set dev "$TUNNEL_6TO4" up
    ip addr add "${PREFIX}1/64" dev "$TUNNEL_6TO4"
    ip link set dev "$TUNNEL_6TO4" mtu 1480

    sleep 2

    # GRE Tunnel
    log_info "Creating GRE tunnel..."
    if ! ip tunnel add "$TUNNEL_GRE" mode ip6gre remote "${PREFIX}2" local "${PREFIX}1"; then
        log_error "Failed to create GRE tunnel. Your kernel might not support GRE over IPv6."
        return
    fi
    ip link set "$TUNNEL_GRE" up
    ip addr add "$IPV4_KHAREJ_TUN" dev "$TUNNEL_GRE"
    ip link set dev "$TUNNEL_GRE" mtu 1476

    log_success "Kharej Server Tunnels established (Prefix: $PREFIX)"
    configure_routing_nat "kharej"
}

configure_routing_nat() {
    local role=$1
    log_info "Configuring routing and NAT for $role..."

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Remove existing rules with our comment to avoid duplicates
    iptables -t nat -S | grep "tunnel_wizard" | sed 's/-A/-D/' | while read line; do
        iptables -t nat $line 2>/dev/null
    done

    if [ "$role" == "iran" ]; then
        # Routing (Table 4)
        ip route add default via 172.16.0.1 table $TABLE_ID 2>/dev/null || ip route replace default via 172.16.0.1 table $TABLE_ID

        # NAT Rules
        # Keep SSH local (port 22) - Important to avoid lockout!
        iptables -t nat -A PREROUTING -p tcp --dport 22 -m comment --comment "tunnel_wizard" -j ACCEPT

        # Forward everything else to Kharej tunnel IP
        iptables -t nat -A PREROUTING -p tcp --dport 1:65535 -m comment --comment "tunnel_wizard" -j DNAT --to-destination 172.16.0.1
        iptables -t nat -A PREROUTING -p udp --dport 1:65535 -m comment --comment "tunnel_wizard" -j DNAT --to-destination 172.16.0.1

        # Masquerade traffic going out
        iptables -t nat -A POSTROUTING -m comment --comment "tunnel_wizard" -j MASQUERADE

    elif [ "$role" == "kharej" ]; then
        # Routing (Table 4)
        ip route add default via 172.16.0.2 table $TABLE_ID 2>/dev/null || ip route replace default via 172.16.0.2 table $TABLE_ID

        # Use an ip rule to use this table for traffic coming from the tunnel
        ip rule del from 172.16.0.0/30 table $TABLE_ID 2>/dev/null
        ip rule add from 172.16.0.0/30 table $TABLE_ID

        # NAT Rules for the tunnel subnet
        iptables -t nat -A POSTROUTING -s 172.16.0.0/30 -m comment --comment "tunnel_wizard" -j MASQUERADE
    fi

    log_success "Routing and NAT configured."
}

remove_tunnel() {
    log_warn "Starting tunnel removal and cleanup..."

    # Remove IPTables rules
    log_info "Cleaning up IPTables..."
    iptables -t nat -S | grep "tunnel_wizard" | sed 's/-A/-D/' | while read line; do
        iptables -t nat $line 2>/dev/null
    done

    # Remove IP Rules
    log_info "Removing IP rules..."
    ip rule del from 172.16.0.0/30 table $TABLE_ID 2>/dev/null

    # Remove Routes
    log_info "Removing routes from table $TABLE_ID..."
    ip route flush table $TABLE_ID 2>/dev/null

    # Remove Interfaces
    log_info "Deleting tunnel interfaces..."
    ip tunnel del "$TUNNEL_GRE" 2>/dev/null
    ip tunnel del "$TUNNEL_6TO4" 2>/dev/null

    log_success "Tunnel removed and system cleaned."
}

show_status() {
    echo -e "${BLUE}┌────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC}                   ${CYAN}NETWORK TUNNEL STATUS${NC}                    ${BLUE}│${NC}"
    echo -e "${BLUE}├────────────────────────────────────────────────────────────┘${NC}"

    # Detected Role
    local detected_role="${RED}None / Disconnected${NC}"
    local role_type="unknown"
    if ip link show "$TUNNEL_6TO4" >/dev/null 2>&1; then
        if ip addr show dev "$TUNNEL_6TO4" | grep -qE "::2/"; then
            detected_role="${GREEN}🇮🇷 Iran (Relay)${NC}"
            role_type="iran"
        elif ip addr show dev "$TUNNEL_6TO4" | grep -qE "::1/"; then
            detected_role="${GREEN}🌍 Kharej (Endpoint)${NC}"
            role_type="kharej"
        fi
    fi
    echo -e "  ${YELLOW}Detected Role:${NC} $detected_role"

    # SIT Tunnel
    if ip link show "$TUNNEL_6TO4" >/dev/null 2>&1; then
        local sit_ip=$(ip -6 addr show "$TUNNEL_6TO4" | grep "inet6 fd" | awk '{print $2}' | cut -d'/' -f1 | head -n1)
        echo -e "  ${YELLOW}SIT Tunnel ($TUNNEL_6TO4):${NC}  ${GREEN}● ONLINE${NC}"
        echo -e "  ${BLUE}└─${NC} IPv6 Address: ${CYAN}${sit_ip:-N/A}${NC}"
    else
        echo -e "  ${YELLOW}SIT Tunnel ($TUNNEL_6TO4):${NC}  ${RED}○ OFFLINE${NC}"
    fi

    # GRE Tunnel
    if ip link show "$TUNNEL_GRE" >/dev/null 2>&1; then
        local gre_ip=$(ip addr show "$TUNNEL_GRE" | grep "inet 172" | awk '{print $2}' | cut -d'/' -f1)
        echo -e "  ${YELLOW}GRE Tunnel ($TUNNEL_GRE):${NC}    ${GREEN}● ONLINE${NC}"
        echo -e "  ${BLUE}└─${NC} IPv4 Address: ${CYAN}${gre_ip:-N/A}${NC}"
    else
        echo -e "  ${YELLOW}GRE Tunnel ($TUNNEL_GRE):${NC}    ${RED}○ OFFLINE${NC}"
    fi

    echo -e "\n${BLUE}┌─${NC} ${BLUE}Connectivity Check${NC}"
    local sit_addr=$(ip -6 addr show "$TUNNEL_6TO4" 2>/dev/null | grep "inet6 fd" | awk '{print $2}' | cut -d'/' -f1 | head -n1)

    if [ -n "$sit_addr" ]; then
        local prefix="${sit_addr%[12]}"
        if [ "$role_type" == "iran" ]; then
            check_ping "${prefix}2" "SIT Local  (${prefix}2)"
            check_ping "${prefix}1" "SIT Remote (${prefix}1)"
            check_ping "172.16.0.2" "GRE Local  (172.16.0.2)"
            check_ping "172.16.0.1" "GRE Remote (172.16.0.1)"
        elif [ "$role_type" == "kharej" ]; then
            check_ping "${prefix}1" "SIT Local  (${prefix}1)"
            check_ping "${prefix}2" "SIT Remote (${prefix}2)"
            check_ping "172.16.0.1" "GRE Local  (172.16.0.1)"
            check_ping "172.16.0.2" "GRE Remote (172.16.0.2)"
        else
            check_ping "${prefix}1" "SIT Endpoint (${prefix}1)"
            check_ping "${prefix}2" "SIT Endpoint (${prefix}2)"
        fi
    else
        check_ping "fd01::2" "SIT Iran   (fd01::2)"
        check_ping "fd01::1" "SIT Kharej (fd01::1)"
        check_ping "172.16.0.2" "GRE Iran   (172.16.0.2)"
        check_ping "172.16.0.1" "GRE Kharej (172.16.0.1)"
    fi

    echo -e "\n${BLUE}┌─${NC} ${BLUE}Routing (Table $TABLE_ID)${NC}"
    local route_info=$(ip route show table $TABLE_ID)
    if [ -z "$route_info" ]; then
        echo -e "  ${RED}No routes found in table $TABLE_ID${NC}"
    else
        echo "$route_info" | sed 's/^/  /'
    fi

    echo -e "\n${BLUE}┌─${NC} ${BLUE}Active NAT Rules${NC}"
    iptables -t nat -L PREROUTING -n --line-numbers | grep "tunnel_wizard" | sed 's/^/  /' || echo -e "  ${RED}No PREROUTING rules${NC}"
    iptables -t nat -L POSTROUTING -n --line-numbers | grep "tunnel_wizard" | sed 's/^/  /' || echo -e "  ${RED}No POSTROUTING rules${NC}"
    echo -e "${BLUE}└────────────────────────────────────────────────────────────┘${NC}"
}

check_ping() {
    local target=$1
    local name=$2
    if [[ "$target" == *":"* ]]; then
        # IPv6
        if ping6 -c 1 -W 1 "$target" >/dev/null 2>&1; then
            echo -e "  ${BLUE}├─${NC} $name: ${GREEN}REACHABLE${NC}"
        else
            echo -e "  ${BLUE}├─${NC} $name: ${RED}UNREACHABLE${NC}"
        fi
    else
        # IPv4
        if ping -c 1 -W 1 "$target" >/dev/null 2>&1; then
            echo -e "  ${BLUE}├─${NC} $name: ${GREEN}REACHABLE${NC}"
        else
            echo -e "  ${BLUE}├─${NC} $name: ${RED}UNREACHABLE${NC}"
        fi
    fi
}

manage_exemptions() {
    while true; do
        clear
        echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║${NC}       ${CYAN}🔓 MANAGE EXEMPTIONS${NC}              ${BLUE}║${NC}"
        echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"

        echo -e "${CYAN}Current Local Exemptions (Will NOT go through tunnel):${NC}"
        local port_rules=$(iptables -t nat -S PREROUTING | grep "tunnel_wizard_local_port" | awk -F'--dports ' '{print $2}' | awk '{print $1}' | sort -u | xargs)
        local ip_rules=$(iptables -t nat -S PREROUTING | grep "tunnel_wizard_local_ip" | awk -F'-d ' '{print $2}' | awk '{print $1}' | sort -u | xargs)

        if [ -z "$port_rules" ] && [ -z "$ip_rules" ]; then
            echo -e "  ${YELLOW}No exemptions configured.${NC}"
        else
            [[ -n "$port_rules" ]] && echo -e "  ${BLUE}Ports:${NC} ${GREEN}${port_rules}${NC}"
            [[ -n "$ip_rules" ]]   && echo -e "  ${BLUE}IPs:${NC}   ${GREEN}${ip_rules}${NC}"
        fi

        echo -e "${BLUE}╟────────────────────────────────────────${NC}"
        echo -e "  ${CYAN}[1]${NC} ➕ Add Local Port(s)"
        echo -e "  ${CYAN}[2]${NC} ➖ Remove Local Port(s)"
        echo -e "  ${CYAN}[3]${NC} ➕ Add Local IP(s)"
        echo -e "  ${CYAN}[4]${NC} ➖ Remove Local IP(s)"
        echo -e "  ${CYAN}[5]${NC} 🧹 Clear All Exemptions"
        echo -e "  ${CYAN}[6]${NC} 🔙 Back to Main Menu"
        echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
        echo -n "Select an option [1-6]: "
        read -r ex_choice

        case $ex_choice in
            1)
                echo -n "Enter Port(s) to keep local (e.g. 2000 or 2000,2001): "
                read -r ports
                [[ -z "$ports" ]] && continue
                iptables -t nat -I PREROUTING 1 -p tcp -m multiport --dports "$ports" -m comment --comment "tunnel_wizard_local_port" -j ACCEPT
                iptables -t nat -I PREROUTING 1 -p udp -m multiport --dports "$ports" -m comment --comment "tunnel_wizard_local_port" -j ACCEPT
                log_success "Ports $ports exempted."
                sleep 1
                ;;
            2)
                echo -n "Enter Port(s) to remove: "
                read -r ports
                [[ -z "$ports" ]] && continue
                iptables -t nat -D PREROUTING -p tcp -m multiport --dports "$ports" -m comment --comment "tunnel_wizard_local_port" -j ACCEPT 2>/dev/null
                iptables -t nat -D PREROUTING -p udp -m multiport --dports "$ports" -m comment --comment "tunnel_wizard_local_port" -j ACCEPT 2>/dev/null
                log_success "Port exemptions removed."
                sleep 1
                ;;
            3)
                echo -n "Enter IP(s) to keep local (e.g. 1.2.3.4): "
                read -r ips
                [[ -z "$ips" ]] && continue
                iptables -t nat -I PREROUTING 1 -d "$ips" -m comment --comment "tunnel_wizard_local_ip" -j ACCEPT
                log_success "IPs $ips exempted."
                sleep 1
                ;;
            4)
                echo -n "Enter IP(s) to remove: "
                read -r ips
                [[ -z "$ips" ]] && continue
                iptables -t nat -D PREROUTING -d "$ips" -m comment --comment "tunnel_wizard_local_ip" -j ACCEPT 2>/dev/null
                log_success "IP exemptions removed."
                sleep 1
                ;;
            5)
                iptables -t nat -S PREROUTING | grep -E "tunnel_wizard_local_port|tunnel_wizard_local_ip" | sed 's/-A/-D/' | while read line; do
                    iptables -t nat $line 2>/dev/null
                done
                log_success "All exemptions cleared."
                sleep 1
                ;;
            6) break ;;
        esac
    done
}

install_shortcut() {
    local script_path=$(realpath "$0")
    log_info "Installing shortcut..."
    if sudo ln -sf "$script_path" /usr/local/bin/iranbaxv6; then
        log_success "Shortcut installed! You can now run this script by typing 'iranbaxv6' in your terminal."
    else
        log_error "Failed to install shortcut. Try running with sudo or check permissions."
    fi
}

main_loop() {
    while true; do
        show_menu
        read -r choice
        case $choice in
            1) setup_iran ;;
            2) setup_kharej ;;
            3) manage_exemptions ;;
            4) remove_tunnel ;;
            5) show_status ;;
            6) install_shortcut ;;
            7) log_info "Exiting..."; exit 0 ;;
            *) log_warn "Invalid option. Press any key to continue."; read -r -n 1 ;;
        esac
        echo -e "\n${YELLOW}Press any key to return to menu...${NC}"
        read -r -n 1
    done
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_loop
fi
