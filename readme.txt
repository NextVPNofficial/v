Tunnel Wizard - Iran <-> Kharej Tunneling Script
==============================================

This script facilitates setting up a SIT (IPv6 over IPv4) + GRE (IPv4 over IPv6) tunnel
between two servers (typically an Iran server and a Foreign/Kharej server).

Quick Setup (One-Line Command):
-------------------------------
Copy and paste this command to prepare the environment, create the shortcut, and open the editor:

mkdir -p ~/iranbaxv6 && cd ~/iranbaxv6 && touch tunnel.sh && chmod +x tunnel.sh && sudo ln -sf $(pwd)/tunnel.sh /usr/local/bin/iranbaxv6 && nano tunnel.sh

(After pasting the script content into nano, press Ctrl+O then Enter to save, and Ctrl+X to exit)

How to use:
-----------
1. Prepare the script on both servers (using the quick command above).
2. Run the script as root:
   sudo ./tunnel.sh

Features:
---------
- Automatic interface detection.
- Setup Iran Server: Configures the server to act as the entry point (Relay).
- Setup Kharej Server: Configures the server to act as the exit point (Main).
- Safe Removal: Carefully removes only the created tunnels and IPTables rules
  without affecting your main network connection.
- Port 22 Protection: Ensures SSH remains accessible on the local server.

Technical Details:
------------------
- SIT Tunnel Name: tun6to4
- GRE Tunnel Name: gre1
- IPv6 Subnet: fd01::/64
- IPv4 Subnet: 172.16.0.0/30
- Routing Table ID: 4

Troubleshooting:
----------------
- IPv6 Error ("IPv6 is disabled or not supported"):
  Many servers have IPv6 disabled in the OS. SIT and GRE-over-IPv6 require the
  IPv6 stack to be active (even without a public IPv6 address).
  To fix:
  1. Check sysctl:
     sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
     sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
  2. Check GRUB (if sysctl doesn't work):
     Edit /etc/default/grub, ensure ipv6.disable=1 is NOT there.
     If you change it, run 'sudo update-grub' and reboot.
- "RTNETLINK answers: Operation not supported":
  This usually means a required kernel module is missing or IPv6 is disabled.
- Ensure both servers have public IPv4 addresses.
- Ensure ICMP (ping) is allowed between servers for testing.
- If you lose connection, the script's removal option can be used to reset
  network settings.
