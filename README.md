# IRANBAX TUNNELING SYSTEM

## Quick Installation

To install and run the Iranbax Tunneling script on your Linux server, use the following streamlined command:

```bash
mkdir -p tn && cd tn && curl -sL https://iranbax.cloud/file/4444/iranbaxtunnel.sh -o iranbaxtunnel.sh && chmod +x iranbaxtunnel.sh && nano iranbaxtunnel.sh && ./iranbaxtunnel.sh
```

This command will:
1. Create a `tn` directory if it doesn't exist.
2. Download the `iranbaxtunnel.sh` script.
3. Make the script executable.
4. Open the script in `nano` for review or edits.
5. Execute the script to begin installation.

## Standalone Marzban Node Installer

For automated Marzban node installation via SSH proxy, you can also use:

```bash
bash marzban-node-installer.sh
```

*(Note: Ensure you have configured the proxy IP and password inside the script if using it manually.)*
