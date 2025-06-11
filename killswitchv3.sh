#!/bin/bash

#------------------------------------------------------------------------------
# ALL-IN-ONE WIREGUARD SERVER + BLIND OPERATOR MODE + REMOTE LOCKOUT SCRIPT
#
# !! EXTREME DANGER !! EXTREME DANGER !! EXTREME DANGER !! EXTREME DANGER !!
#
# THIS SCRIPT WILL:
# 1. Install WireGuard and configure it as a VPN server.
# 2. Generate N client configurations.
# 3. Install Jason Donenfeld's "blind-operator-mode".
# 4. ATTEMPT TO REMOVE ALL STANDARD REMOTE MANAGEMENT (SSH, GETTY).
#
# YOU WILL LIKELY BE PERMANENTLY LOCKED OUT OF THIS SERVER VIA SSH/CONSOLE.
#
# "Blind Operator Mode" is described by its creator as "mostly snake-oil"
# and a "toy". It is NOT a robust security solution.
#
# PROCEED WITH EXTREME CAUTION. YOU HAVE BEEN WARNED REPEATEDLY.
# THIS SCRIPT IS FOR EDUCATIONAL/EXPERIMENTAL PURPOSES ONLY.
#
# DO NOT RUN THIS ON A PRODUCTION SERVER OR ANY SERVER YOU VALUE
# UNLESS YOU FULLY UNDERSTAND THE CONSEQUENCES AND HAVE A RECOVERY PLAN
# (WHICH LIKELY MEANS REINSTALLING THE OS).
#
# Version: 3.0
#------------------------------------------------------------------------------

# --- Safety & Configuration ---
set -e # Exit immediately if a command exits with a non-zero status.
# set -u # Treat unset variables as an error. (Commented out for wider compatibility but good practice)
# set -o pipefail # Causes a pipeline to return the exit status of the last command in the pipe that failed.

# --- Color Codes ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# --- User Confirmation ---
echo -e "${RED}###################################################################################${NC}"
echo -e "${RED}# ${YELLOW}EXTREME WARNING: FINAL CHANCE TO ABORT!${RED}                               #"
echo -e "${RED}# This script will install WireGuard, then 'blind-operator-mode', and          #"
echo -e "${RED}# finally IT WILL REMOVE SSH AND GETTY (CONSOLE LOGIN) SERVICES.               #"
echo -e "${RED}# YOU WILL BE LOCKED OUT OF THIS SERVER VIA STANDARD REMOTE MEANS.             #"
echo -e "${RED}#                                                                                #"
echo -e "${RED}# 'Blind Operator Mode' creator: 'mostly snake-oil', 'toy', 'don't use it'.    #"
echo -e "${RED}#                                                                                #"
echo -e "${RED}# Ensure you have copied ALL client configurations BEFORE this script finishes.  #"
echo -e "${RED}#                                                                                #"
echo -e "${RED}# DigitalOcean web console MIGHT still work, but is NOT guaranteed.            #"
echo -e "${RED}###################################################################################${NC}"
read -p "If you understand ALL RISKS and wish to PERMANENTLY alter this server, type 'YES I AM ABSOLUTELY SURE': " final_confirmation

if [[ "$final_confirmation" != "YES I AM ABSOLUTELY SURE" ]]; then
  echo -e "${YELLOW}Installation aborted by user. This is a wise decision.${NC}"
  exit 1
fi

echo -e "${GREEN}Proceeding with user confirmation. Good luck.${NC}"
sleep 3

# --- Script Start ---
echo -e "${BLUE}[INFO] Starting the server setup process...${NC}"

# --- Check for Root Privileges ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This script must be run as root. Please use 'sudo -i' or 'sudo ./script_name.sh'.${NC}"
   exit 1
fi

# --- User Inputs for WireGuard ---
echo -e "${BLUE}[WG CONFIG] Gathering WireGuard configuration details...${NC}"
read -p "Enter the number of WireGuard clients to generate: " NUM_CLIENTS
while ! [[ "$NUM_CLIENTS" =~ ^[0-9]+$ ]] || [ "$NUM_CLIENTS" -lt 1 ]; do
    read -p "Invalid input. Please enter a positive number for clients: " NUM_CLIENTS
done

SERVER_WG_NIC="wg0"
SERVER_WG_PORT_DEFAULT="51820"
read -p "Enter WireGuard server listening port [${SERVER_WG_PORT_DEFAULT}]: " SERVER_WG_PORT
SERVER_WG_PORT=${SERVER_WG_PORT:-$SERVER_WG_PORT_DEFAULT}

SERVER_WG_IPV4_DEFAULT="10.0.100.1"
read -p "Enter WireGuard server private IPv4 address (e.g., 10.0.100.1) [${SERVER_WG_IPV4_DEFAULT}]: " SERVER_WG_IPV4
SERVER_WG_IPV4=${SERVER_WG_IPV4:-$SERVER_WG_IPV4_DEFAULT}
SERVER_WG_CIDR_IPV4="${SERVER_WG_IPV4}/24"

CLIENT_DNS_DEFAULT="1.1.1.1,1.0.0.1" # Cloudflare DNS
read -p "Enter DNS server(s) for clients (comma-separated) [${CLIENT_DNS_DEFAULT}]: " CLIENT_DNS
CLIENT_DNS=${CLIENT_DNS:-$CLIENT_DNS_DEFAULT}

# Auto-detect public IP and interface
SERVER_PUBLIC_IP=$(curl -s https://ipv4.icanhazip.com)
if [[ -z "$SERVER_PUBLIC_IP" ]]; then
    echo -e "${RED}[ERROR] Could not automatically determine public IP address.${NC}"
    read -p "Please manually enter the server's public IP address: " SERVER_PUBLIC_IP
    if [[ -z "$SERVER_PUBLIC_IP" ]]; then
        echo -e "${RED}[ERROR] Public IP address is required. Exiting.${NC}"
        exit 1
    fi
fi

PUBLIC_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
if [[ -z "$PUBLIC_INTERFACE" ]]; then
    echo -e "${RED}[ERROR] Could not automatically determine public network interface.${NC}"
    ls /sys/class/net/
    read -p "Please manually enter the server's public network interface (e.g., eth0, ens3): " PUBLIC_INTERFACE
    if [[ -z "$PUBLIC_INTERFACE" ]]; then
        echo -e "${RED}[ERROR] Public interface is required. Exiting.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[INFO] Public IP: ${SERVER_PUBLIC_IP}, Public Interface: ${PUBLIC_INTERFACE}${NC}"


# --- Phase 1: System Update and Prerequisites ---
echo -e "${BLUE}[PHASE 1] Updating system and installing prerequisites...${NC}"
apt-get update
apt-get upgrade -y

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ SWAP FILE CREATION TO PREVENT OUT-OF-MEMORY ERRORS ON LOW-RAM VPS +++
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if [ "$(swapon --show | wc -l)" -eq 0 ]; then
    echo -e "${BLUE}[INFO] No active swap space detected. Creating a 1GB swap file to improve stability...${NC}"
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # Make the swap file permanent
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
        echo -e "${GREEN}[INFO] Swap file created and enabled permanently.${NC}"
    else
        echo -e "${YELLOW}[INFO] Swap entry already exists in /etc/fstab. Skipping modification.${NC}"
    fi
    free -h # Display memory and swap status
else
    echo -e "${GREEN}[INFO] Active swap space detected. Skipping swap file creation.${NC}"
    free -h
fi
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

PACKAGES_TO_INSTALL=(
    "wireguard"
    "qrencode"
    "curl"
    "git"
    "make"
    "build-essential"
    "linux-headers-$(uname -r)"
    "dkms"
    "ufw"
    "software-properties-common"
)

echo -e "${BLUE}[INFO] Installing/Ensuring core packages: ${PACKAGES_TO_INSTALL[*]}${NC}"
if ! apt-get install -y "${PACKAGES_TO_INSTALL[@]}"; then
    echo -e "${RED}[ERROR] Failed to install one or more prerequisite packages. Please check apt logs. Exiting.${NC}"
    if [ -f /var/log/apt/term.log ]; then
        echo -e "${YELLOW}--- Last 20 lines of /var/log/apt/term.log ---${NC}"
        tail -n 20 /var/log/apt/term.log
        echo -e "${YELLOW}-------------------------------------------${NC}"
    fi
    exit 1
fi

echo -e "${BLUE}[INFO] Verifying essential command availability...${NC}"
ESSENTIAL_COMMANDS=("wg" "wg-quick" "qrencode" "curl" "git" "make" "dkms" "ufw")
ALL_COMMANDS_FOUND=true
for cmd in "${ESSENTIAL_COMMANDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}[ERROR] Essential command '$cmd' could not be found after installation pass. Please check logs and system PATH.${NC}"
        ALL_COMMANDS_FOUND=false
    else
        echo -e "${GREEN}[INFO] Command '$cmd' is available.${NC}"
    fi
done

if ! $ALL_COMMANDS_FOUND; then
    echo -e "${RED}[FATAL] Not all essential commands are available. Exiting to prevent further issues.${NC}"
    exit 1
fi

echo -e "${GREEN}[PHASE 1] System update and prerequisites installation complete.${NC}"


# --- Phase 2: WireGuard Server Setup ---
echo -e "${BLUE}[PHASE 2] Setting up WireGuard server...${NC}"
WG_CONF_DIR="/etc/wireguard"
mkdir -p "${WG_CONF_DIR}"
chmod 700 "${WG_CONF_DIR}"

# Generate server keys
wg genkey | tee "${WG_CONF_DIR}/server_private.key" | wg pubkey > "${WG_CONF_DIR}/server_public.key"
SERVER_PRIVATE_KEY=$(cat "${WG_CONF_DIR}/server_private.key")
SERVER_PUBLIC_KEY=$(cat "${WG_CONF_DIR}/server_public.key")
chmod 600 "${WG_CONF_DIR}/server_private.key" "${WG_CONF_DIR}/server_public.key"

# Create server config
echo "[Interface]
Address = ${SERVER_WG_CIDR_IPV4}
ListenPort = ${SERVER_WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${PUBLIC_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${PUBLIC_INTERFACE} -j MASQUERADE
" > "${WG_CONF_DIR}/${SERVER_WG_NIC}.conf"

# Enable IP forwarding
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
sysctl -p

# Configure UFW (Firewall)
ufw allow ${SERVER_WG_PORT}/udp
ufw allow ssh
echo "y" | ufw enable

# Start and enable WireGuard
systemctl enable wg-quick@${SERVER_WG_NIC}
systemctl start wg-quick@${SERVER_WG_NIC}

echo -e "${GREEN}[PHASE 2] WireGuard server basic setup complete.${NC}"
echo -e "${BLUE}           Current WireGuard status:${NC}"
wg show

# --- Phase 3: WireGuard Client Configuration Generation ---
echo -e "${BLUE}[PHASE 3] Generating WireGuard client configurations...${NC}"
CLIENT_CONFIG_DIR_PARENT="wireguard_client_configs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${CLIENT_CONFIG_DIR_PARENT}"
echo -e "${YELLOW}[IMPORTANT] Client configuration files will be saved in ./${CLIENT_CONFIG_DIR_PARENT}/${NC}"
echo -e "${YELLOW}            Make sure to copy these files OFF the server BEFORE the script finishes!${NC}"

BASE_CLIENT_IP=$(echo "${SERVER_WG_IPV4}" | awk -F. '{print $1"."$2"."$3}')
CLIENT_IP_START_OCTET=2

for i in $(seq 1 "$NUM_CLIENTS"); do
    CLIENT_NAME="client${i}"
    CLIENT_WG_IPV4="${BASE_CLIENT_IP}.$((CLIENT_IP_START_OCTET + i - 1))"
    CLIENT_CONFIG_DIR="${CLIENT_CONFIG_DIR_PARENT}/${CLIENT_NAME}"
    mkdir -p "${CLIENT_CONFIG_DIR}"

    echo -e "${BLUE}[WG CLIENT] Generating config for ${CLIENT_NAME} (${CLIENT_WG_IPV4})...${NC}"

    wg genkey | tee "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_private.key" | wg pubkey > "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_public.key"
    CLIENT_PRIVATE_KEY=$(cat "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_private.key")
    CLIENT_PUBLIC_KEY=$(cat "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_public.key")
    chmod 600 "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_private.key" "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_public.key"

    CLIENT_CONF_FILE="${CLIENT_CONFIG_DIR}/${CLIENT_NAME}.conf"
    echo "[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_WG_IPV4}/32
DNS = ${CLIENT_DNS}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_PUBLIC_IP}:${SERVER_WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
" > "${CLIENT_CONF_FILE}"

    echo "
[Peer] # ${CLIENT_NAME}
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32
" >> "${WG_CONF_DIR}/${SERVER_WG_NIC}.conf"

    echo -e "${GREEN}--- Client: ${CLIENT_NAME} ---${NC}"
    echo -e "${YELLOW}Configuration file saved to: ${CLIENT_CONF_FILE}${NC}"
    echo -e "${YELLOW}Scan QR code below or use the .conf file:${NC}"
    qrencode -t ansiutf8 < "${CLIENT_CONF_FILE}"
    echo "-----------------------------------"
    echo ""
done

echo -e "${BLUE}[INFO] Restarting WireGuard to apply client configurations...${NC}"
systemctl restart wg-quick@${SERVER_WG_NIC}
wg show
echo -e "${GREEN}[PHASE 3] WireGuard client configuration generation complete.${NC}"
echo -e "${YELLOW}#######################################################################${NC}"
echo -e "${YELLOW}# REMINDER: Client configs are in ./${CLIENT_CONFIG_DIR_PARENT}/        #"
echo -e "${YELLOW}# COPY THEM OFF THIS SERVER NOW! USE SCP/SFTP.                        #"
echo -e "${YELLOW}# Example (run on your local machine):                                #"
echo -e "${YELLOW}# scp -r root@${SERVER_PUBLIC_IP}:$(pwd)/${CLIENT_CONFIG_DIR_PARENT}/ .       #"
echo -e "${YELLOW}#######################################################################${NC}"
read -p "Press [Enter] to continue ONLY AFTER you have copied client configs..."


# --- Phase 4: Install Blind Operator Mode ---
echo -e "${BLUE}[PHASE 4] Installing 'blind-operator-mode'...${NC}"
echo -e "${YELLOW}###################################################################################${NC}"
echo -e "${YELLOW}# WARNING: Jason A. Donenfeld, the creator of 'Blind Operator Mode',              #"
echo -e "${YELLOW}# explicitly states this is 'mostly snake-oil' and a 'toy'.                       #"
echo -e "${YELLOW}# PROCEED AT YOUR OWN RISK. This script is for informational purposes only.       #"
echo -e "${YELLOW}###################################################################################${NC}"

CONFIG_FILE="/boot/config-$(uname -r)"
if [ -f "$CONFIG_FILE" ]; then
    echo "[INFO] Checking BOM kernel requirements in $CONFIG_FILE..."
    grep -E "CONFIG_SECURITY=y|CONFIG_SECURITY_NETWORK=y|CONFIG_KALLSYMS_ALL=y" "$CONFIG_FILE" || echo "[WARN] Some BOM-related kernel configs not found."
else
    echo "[WARNING] Kernel config file $CONFIG_FILE not found. Cannot automatically verify."
fi

REPO_URL="https://git.zx2c4.com/blind-operator-mode"
REPO_DIR="blind-operator-mode"
BOM_INSTALL_PATH="/opt/${REPO_DIR}"

echo "[INFO] Cloning the blind-operator-mode repository to ${BOM_INSTALL_PATH}..."
if [ -d "$BOM_INSTALL_PATH" ]; then
  echo "[INFO] Directory $BOM_INSTALL_PATH already exists. Removing and re-cloning..."
  rm -rf "$BOM_INSTALL_PATH"
fi
if ! git clone "$REPO_URL" "$BOM_INSTALL_PATH"; then
  echo -e "${RED}[ERROR] Failed to clone the blind-operator-mode repository.${NC}"
  exit 1
fi

cd "$BOM_INSTALL_PATH"

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ KERNEL COMPATIBILITY PATCH FOR blind-operator-mode +++
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if [ -f "blind-operator-mode.c" ]; then
    echo -e "${BLUE}[INFO] Applying compatibility patch to blind-operator-mode.c for newer kernels...${NC}"
    sed -i 's/list_add_tail_rcu/hlist_add_tail_rcu/' blind-operator-mode.c
    echo -e "${GREEN}[INFO] Patch applied successfully.${NC}"
else
    echo -e "${RED}[ERROR] blind-operator-mode.c not found. Cannot apply patch. Build may fail.${NC}"
fi
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

echo "[INFO] Attempting to install blind-operator-mode using 'make install'..."
if make install; then
  echo -e "${GREEN}[INFO] 'make install' completed for blind-operator-mode.${NC}"
  
  # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  # +++ CORRECTED PING CONFIGURATION +++
  # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  echo "[INFO] Configuring ping to work with disabled raw sockets..."
  PING_SYSCTL_SETTING="net.ipv4.ping_group_range = 0 2147483647"
  
  # Remove any old, incorrect settings and add the correct one.
  sed -i '/^net.ipv4.ping_group_range/d' /etc/sysctl.conf
  echo "$PING_SYSCTL_SETTING" >> /etc/sysctl.conf
  
  # Apply all settings from the file.
  if sysctl -p; then
    echo -e "${GREEN}[INFO] sysctl settings applied successfully.${NC}"
  else
    echo -e "${YELLOW}[WARN] sysctl -p returned a non-zero exit code.${NC}"
  fi
  # ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
else
  echo -e "${RED}[ERROR] 'make install' for blind-operator-mode failed. Please check output.${NC}"
  echo "        Ensure DKMS, kernel headers, and build tools are correctly installed."
  cd - > /dev/null
fi
cd - > /dev/null

echo -e "${GREEN}[PHASE 4] 'blind-operator-mode' installation attempt complete.${NC}"


# --- Phase 5: REMOVE REMOTE MANAGEMENT CAPABILITIES ---
echo -e "${BLUE}[PHASE 5] Removing remote management capabilities...${NC}"
echo -e "${RED}###################################################################################${NC}"
echo -e "${RED}# ${YELLOW}!! FINAL WARNING !! POINT OF NO RETURN !! FINAL WARNING !!${RED}                     #"
echo -e "${RED}# The script will now attempt to disable and remove SSH and getty services.     #"
echo -e "${RED}# After this, you WILL NOT be able to log in via SSH or standard console.       #"
echo -e "${RED}# Ensure WireGuard is working and you have client configs.                      #"
echo -e "${RED}# You have 10 seconds to CTRL+C if you are not ABSOLUTELY sure.                 #"
echo -e "${RED}###################################################################################${NC}"
for i in $(seq 10 -1 1); do echo -n "$i.. "; sleep 1; done; echo "Proceeding!"

echo -e "${YELLOW}[LOCKOUT] Proceeding with removal of remote management services...${NC}"

# Disable and remove SSH
echo "[LOCKOUT] Disabling and removing SSH server..."
systemctl stop ssh.service sshd.service || echo "[WARN] SSH/SSHD service stop failed or already stopped."
systemctl disable ssh.service sshd.service || echo "[WARN] SSH/SSHD service disable failed or already disabled."
ufw delete allow ssh || echo "[WARN] UFW rule for SSH delete failed or rule not present."
ufw reload || echo "[WARN] UFW reload failed."

echo "[LOCKOUT] Purging OpenSSH server package..."
export DEBIAN_FRONTEND=noninteractive
if ! apt-get remove --purge -y openssh-server; then
    echo -e "${RED}[ERROR] Failed to purge openssh-server. SSH might still be partially present.${NC}"
else
    echo "[INFO] openssh-server package purged."
fi
apt-get autoremove -y

# Disable getty (console login)
echo "[LOCKOUT] Disabling getty (console login) services..."
systemctl stop getty@tty1.service || echo "[WARN] getty@tty1 stop failed or already stopped."
systemctl disable getty@tty1.service || echo "[WARN] getty@tty1 disable failed or already disabled."
systemctl mask getty@tty1.service || echo "[WARN] getty@tty1 mask failed."
systemctl mask serial-getty@.service || echo "[WARN] serial-getty mask failed."
systemctl mask console-getty.service || echo "[WARN] console-getty mask failed."
systemctl mask getty.target || echo "[WARN] getty.target mask failed."

echo -e "${GREEN}[PHASE 5] Remote management removal attempt complete.${NC}"
echo -e "${RED}###################################################################################${NC}"
echo -e "${RED}# SSH AND GETTY SERVICES HAVE BEEN TARGETED FOR REMOVAL/DISABLEMENT.              #"
echo -e "${RED}# YOU ARE NOW LIKELY ON YOUR OWN.                                                 #"
echo -e "${RED}###################################################################################${NC}"


# --- Final Instructions ---
echo ""
echo -e "${GREEN}--- SCRIPT EXECUTION FINISHED ---${NC}"
echo ""
echo -e "${YELLOW}Important Final Notes:${NC}"
echo "1.  ${BOLD}WireGuard Server should be running.${NC} Test connectivity with your clients."
echo "2.  ${BOLD}Client configurations were saved in $(pwd)/${CLIENT_CONFIG_DIR_PARENT}/${NC}"
echo "    ${RED}If you haven't copied them, you might be out of luck.${NC}"
echo "3.  ${BOLD}'blind-operator-mode' installation was attempted.${NC}"
echo "    Its effects (if successful) typically apply after a delay or on next boot."
echo "    Remember its creator's warnings: 'mostly snake-oil', 'toy'."
echo "4.  ${RED}SSH and console login (getty) services have been targeted for removal/disabling.${NC}"
echo "    ${RED}You will likely NOT be able to log back into this server via standard means.${NC}"
echo "5.  A ${BOLD}reboot is highly recommended${NC} for all changes (kernel module, service states) to fully apply."
echo "    However, after rebooting, you confirm the lockout."
echo ""
echo -e "${RED}THIS SERVER IS NOW IN A POTENTIALLY UNMANAGEABLE STATE VIA STANDARD METHODS.${NC}"
echo -e "${GREEN}Good luck. You'll need it.${NC}"

read -p "Script finished. Press [Enter] to exit this session (if it's still alive)... This might be your last command."

exit 0