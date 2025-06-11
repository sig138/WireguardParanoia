#!/bin/bash

#------------------------------------------------------------------------------
# ALL-IN-ONE WIREGUARD SERVER + BLIND OPERATOR MODE + REMOTE LOCKOUT SCRIPT
# Version: 4.0 - Added wait for dpkg lock
#------------------------------------------------------------------------------
# !! EXTREME DANGER !!
# This script installs WireGuard, then 'blind-operator-mode', and finally
# attempts to REMOVE ALL STANDARD REMOTE MANAGEMENT (SSH, GETTY).
# YOU WILL LIKELY BE PERMANENTLY LOCKED OUT OF THIS SERVER.
#
# "Blind Operator Mode" is described by its creator as "mostly snake-oil"
# and a "toy". It is NOT a robust security solution.
#
# PROCEED WITH EXTREME CAUTION. THIS SCRIPT IS FOR EDUCATIONAL PURPOSES ONLY.
#------------------------------------------------------------------------------

# --- Safety & Configuration ---
set -e
# set -u
# set -o pipefail

# --- Color Codes ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# --- User Confirmation ---
echo -e "${RED}###################################################################################${NC}"
echo -e "${RED}# ${YELLOW}EXTREME WARNING: FINAL CHANCE TO ABORT!${RED}                               #"
echo -e "${RED}# This script will install WireGuard, then 'blind-operator-mode', and          #"
echo -e "${RED}# finally IT WILL REMOVE SSH AND GETTY (CONSOLE LOGIN) SERVICES.               #"
echo -e "${RED}# YOU WILL BE LOCKED OUT OF THIS SERVER VIA STANDARD REMOTE MEANS.             #"
echo -e "${RED}#                                                                                #"
echo -e "${RED}# Ensure you have copied ALL client configurations BEFORE this script finishes.  #"
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

CLIENT_DNS_DEFAULT="1.1.1.1,1.0.0.1"
read -p "Enter DNS server(s) for clients (comma-separated) [${CLIENT_DNS_DEFAULT}]: " CLIENT_DNS
CLIENT_DNS=${CLIENT_DNS:-$CLIENT_DNS_DEFAULT}

SERVER_PUBLIC_IP=$(curl -s https://ipv4.icanhazip.com)
PUBLIC_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
echo -e "${GREEN}[INFO] Public IP: ${SERVER_PUBLIC_IP}, Public Interface: ${PUBLIC_INTERFACE}${NC}"


# --- Phase 1: System Update and Prerequisites ---
echo -e "${BLUE}[PHASE 1] Updating system and installing prerequisites...${NC}"

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ NEW: Wait for any existing package manager locks to be released. +++
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 ; do
   echo -e "${YELLOW}[INFO] Waiting for other package manager processes to finish...${NC}"
   sleep 10
done
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

apt-get update
apt-get upgrade -y

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ SWAP FILE CREATION TO PREVENT OUT-OF-MEMORY ERRORS ON LOW-RAM VPS +++
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if [ "$(swapon --show | wc -l)" -eq 0 ]; then
    echo -e "${BLUE}[INFO] No active swap space detected. Creating a 1GB swap file...${NC}"
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
        echo -e "${GREEN}[INFO] Swap file created and enabled permanently.${NC}"
    fi
    free -h
else
    echo -e "${GREEN}[INFO] Active swap space detected. Skipping swap file creation.${NC}"
fi
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

PACKAGES_TO_INSTALL=( "wireguard" "qrencode" "curl" "git" "make" "build-essential" "linux-headers-$(uname -r)" "dkms" "ufw" "software-properties-common" )

echo -e "${BLUE}[INFO] Installing/Ensuring core packages: ${PACKAGES_TO_INSTALL[*]}${NC}"
apt-get install -y "${PACKAGES_TO_INSTALL[@]}"

echo -e "${GREEN}[PHASE 1] System update and prerequisites installation complete.${NC}"


# --- Phase 2: WireGuard Server Setup ---
echo -e "${BLUE}[PHASE 2] Setting up WireGuard server...${NC}"
WG_CONF_DIR="/etc/wireguard"
mkdir -p "${WG_CONF_DIR}"
chmod 700 "${WG_CONF_DIR}"

wg genkey | tee "${WG_CONF_DIR}/server_private.key" | wg pubkey > "${WG_CONF_DIR}/server_public.key"
SERVER_PRIVATE_KEY=$(cat "${WG_CONF_DIR}/server_private.key")
SERVER_PUBLIC_KEY=$(cat "${WG_CONF_DIR}/server_public.key")
chmod 600 "${WG_CONF_DIR}/server_private.key" "${WG_CONF_DIR}/server_public.key"

echo "[Interface]
Address = ${SERVER_WG_CIDR_IPV4}
ListenPort = ${SERVER_WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${PUBLIC_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${PUBLIC_INTERFACE} -j MASQUERADE
" > "${WG_CONF_DIR}/${SERVER_WG_NIC}.conf"

if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf; fi
sed -i '/^#net.ipv4.ip_forward=1/s/^#//' /etc/sysctl.conf
sysctl -p

ufw allow ${SERVER_WG_PORT}/udp
ufw allow ssh
echo "y" | ufw enable

systemctl enable wg-quick@${SERVER_WG_NIC}
systemctl start wg-quick@${SERVER_WG_NIC}

echo -e "${GREEN}[PHASE 2] WireGuard server basic setup complete.${NC}"


# --- Phase 3: WireGuard Client Configuration Generation ---
echo -e "${BLUE}[PHASE 3] Generating WireGuard client configurations...${NC}"
CLIENT_CONFIG_DIR_PARENT="wireguard_client_configs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${CLIENT_CONFIG_DIR_PARENT}"
echo -e "${YELLOW}[IMPORTANT] Client configs are in $(pwd)/${CLIENT_CONFIG_DIR_PARENT}/${NC}"

BASE_CLIENT_IP=$(echo "${SERVER_WG_IPV4}" | awk -F. '{print $1"."$2"."$3}')
CLIENT_IP_START_OCTET=2

for i in $(seq 1 "$NUM_CLIENTS"); do
    CLIENT_NAME="client${i}"
    CLIENT_WG_IPV4="${BASE_CLIENT_IP}.$((CLIENT_IP_START_OCTET + i - 1))"
    CLIENT_CONFIG_DIR="${CLIENT_CONFIG_DIR_PARENT}/${CLIENT_NAME}"
    mkdir -p "${CLIENT_CONFIG_DIR}"
    
    wg genkey | tee "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_private.key" | wg pubkey > "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_public.key"
    CLIENT_PRIVATE_KEY=$(cat "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_private.key")
    CLIENT_PUBLIC_KEY=$(cat "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}_public.key")
    
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

    echo -e "\n[Peer] # ${CLIENT_NAME}\nPublicKey = ${CLIENT_PUBLIC_KEY}\nAllowedIPs = ${CLIENT_WG_IPV4}/32\n" >> "${WG_CONF_DIR}/${SERVER_WG_NIC}.conf"
    
    echo -e "${GREEN}--- Client: ${CLIENT_NAME} ---${NC}"
    qrencode -t ansiutf8 < "${CLIENT_CONF_FILE}"
    echo "-----------------------------------"
done

systemctl restart wg-quick@${SERVER_WG_NIC}
echo -e "${GREEN}[PHASE 3] WireGuard client configuration generation complete.${NC}"
echo -e "${YELLOW}#######################################################################${NC}"
echo -e "${YELLOW}# REMINDER: Client configs are in $(pwd)/${CLIENT_CONFIG_DIR_PARENT}/   #"
echo -e "${YELLOW}# COPY THEM OFF THIS SERVER NOW!                                        #"
echo -e "${YELLOW}#######################################################################${NC}"
read -p "Press [Enter] to continue ONLY AFTER you have copied client configs..."


# --- Phase 4: Install Blind Operator Mode ---
echo -e "${BLUE}[PHASE 4] Installing 'blind-operator-mode'...${NC}"
REPO_URL="https://git.zx2c4.com/blind-operator-mode"
BOM_INSTALL_PATH="/opt/blind-operator-mode"

echo "[INFO] Cloning the blind-operator-mode repository to ${BOM_INSTALL_PATH}..."
if [ -d "$BOM_INSTALL_PATH" ]; then rm -rf "$BOM_INSTALL_PATH"; fi
git clone "$REPO_URL" "$BOM_INSTALL_PATH"

cd "$BOM_INSTALL_PATH"

echo -e "${BLUE}[INFO] Applying compatibility patch to blind-operator-mode.c...${NC}"
sed -i 's/list_add_tail_rcu/hlist_add_tail_rcu/' blind-operator-mode.c

echo "[INFO] Attempting to install blind-operator-mode using 'make install'..."
if make install; then
  echo -e "${GREEN}[INFO] 'make install' completed for blind-operator-mode.${NC}"
  
  echo "[INFO] Configuring ping to work with disabled raw sockets..."
  PING_SYSCTL_SETTING="net.ipv4.ping_group_range = 0 2147483647"
  sed -i '/^net.ipv4.ping_group_range/d' /etc/sysctl.conf
  echo "$PING_SYSCTL_SETTING" >> /etc/sysctl.conf
  sysctl -p

else
  echo -e "${RED}[ERROR] 'make install' for blind-operator-mode failed. Module is NOT active.${NC}"
fi
cd - > /dev/null

echo -e "${GREEN}[PHASE 4] 'blind-operator-mode' installation attempt complete.${NC}"


# --- Phase 5: REMOVE REMOTE MANAGEMENT CAPABILITIES ---
echo -e "${BLUE}[PHASE 5] Removing remote management capabilities...${NC}"
echo -e "${RED}###################################################################################${NC}"
echo -e "${RED}# ${YELLOW}!! FINAL WARNING !! POINT OF NO RETURN !! FINAL WARNING !!${RED}                     #"
echo -e "${RED}# After this, you WILL NOT be able to log in via SSH or standard console.       #"
echo -e "${RED}###################################################################################${NC}"
for i in $(seq 10 -1 1); do echo -n "$i.. "; sleep 1; done; echo "Proceeding!"

systemctl stop ssh.service sshd.service || echo "[WARN] SSH/SSHD service stop failed."
systemctl disable ssh.service sshd.service || echo "[WARN] SSH/SSHD service disable failed."
ufw delete allow ssh || echo "[WARN] UFW rule for SSH delete failed."
ufw reload || echo "[WARN] UFW reload failed."

export DEBIAN_FRONTEND=noninteractive
apt-get remove --purge -y openssh-server
apt-get autoremove -y

systemctl stop getty@tty1.service || echo "[WARN] getty@tty1 stop failed."
systemctl disable getty@tty1.service || echo "[WARN] getty@tty1 disable failed."
systemctl mask getty@tty1.service || echo "[WARN] getty@tty1 mask failed."
systemctl mask serial-getty@.service || echo "[WARN] serial-getty mask failed."
systemctl mask console-getty.service || echo "[WARN] console-getty mask failed."
systemctl mask getty.target || echo "[WARN] getty.target mask failed."

echo -e "${GREEN}[PHASE 5] Remote management removal attempt complete.${NC}"


# --- Final Instructions ---
echo -e "\n${GREEN}--- SCRIPT EXECUTION FINISHED ---${NC}\n"
echo -e "${YELLOW}Important Final Notes:${NC}"
echo "1.  ${BOLD}WireGuard Server should be running.${NC} Test connectivity with your clients."
echo "2.  ${BOLD}'blind-operator-mode' installation was attempted.${NC}"
echo "    If it failed, the primary protection of this setup is NOT active."
echo "3.  ${RED}SSH and console login services have been targeted for removal.${NC}"
echo "    ${RED}You will likely NOT be able to log back into this server via standard means.${NC}"
echo "4.  A ${BOLD}reboot is recommended${NC} for all changes to fully apply."
echo ""
echo -e "${RED}THIS SERVER IS NOW IN A POTENTIALLY UNMANAGEABLE STATE VIA STANDARD METHODS.${NC}"
echo -e "${GREEN}Good luck.${NC}"

read -p "Script finished. Press [Enter] to exit this session (if it's still alive)..."

exit 0