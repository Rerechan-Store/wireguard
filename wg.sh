#!/bin/bash
# =================================== #
# Wireguard CloudFlare By PR Aiman    #
# =================================== #
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
# Link Hosting Kalian
beginner="https://raw.githubusercontent.com/Rerechan-Store/wireguard/main"
# Check OS version
if [[ -e /etc/debian_version ]]; then
	source /etc/os-release
	OS=$ID # debian or ubuntu
elif [[ -e /etc/centos-release ]]; then
	source /etc/os-release
	OS=centos
fi

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[information]${Font_color_suffix}"

if [[ -e /etc/wireguard/params ]]; then
	echo -e "${Info} WireGuard sudah diinstal, silahkan ketik addwg untuk menambah client."
	exit 1
fi

echo -e "${Info} Wireguard Script By Akbar Maulana"
# Detect public IPv4 address and pre-fill for the user

# Detect public interface and pre-fill for the user
SERVER_PUB_NIC=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# Install WireGuard tools and module
	if [[ $OS == 'ubuntu' ]]; then
	apt install -y wireguard
elif [[ $OS == 'debian' ]]; then
	echo "deb http://deb.debian.org/debian/ unstable main" >/etc/apt/sources.list.d/unstable.list
	printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' >/etc/apt/preferences.d/limit-unstable
	apt update
	apt install -y wireguard-tools iptables iptables-persistent
	apt install -y linux-headers-$(uname -r)
elif [[ ${OS} == 'centos' ]]; then
	curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
	yum -y update
	yum -y install wireguard-dkms wireguard-tools
	fi
apt install iptables iptables-persistent -y
# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard >/dev/null 2>&1

chmod 600 -R /etc/wireguard/

SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Save WireGuard settings
echo "SERVER_PUB_NIC=$SERVER_PUB_NIC
SERVER_WG_NIC=wg0
SERVER_WG_IPV4=10.66.66.1
SERVER_PORT=2048
SERVER_PRIV_KEY=$SERVER_PRIV_KEY
SERVER_PUB_KEY=$SERVER_PUB_KEY" >/etc/wireguard/params

source /etc/wireguard/params

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE;
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE;" >>"/etc/wireguard/wg0.conf"

iptables -t nat -I POSTROUTING -s 10.66.66.1/24 -o $SERVER_PUB_NIC -j MASQUERADE
iptables -I INPUT 1 -i wg0 -j ACCEPT
iptables -I FORWARD 1 -i $SERVER_PUB_NIC -o wg0 -j ACCEPT
iptables -I FORWARD 1 -i wg0 -o $SERVER_PUB_NIC -j ACCEPT
iptables -I INPUT 1 -i $SERVER_PUB_NIC -p udp --dport 2048 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

systemctl start "wg-quick@wg0"
systemctl enable "wg-quick@wg0"

# Check if WireGuard is running
systemctl is-active --quiet "wg-quick@wg0"
WG_RUNNING=$?

# Installation WireGuard Cloudflare
clear
echo ""
echo " Next Installation Is Wireguard Cloudflare..."
sleep 0.9
clear
echo " Install Wireguard Cloudflare Is Begin..."
echo ""
sleep 0.9
clear

# Install Requirements Warp
WGCF_Profile='wgcf-profile.conf'
WGCF_ProfileDir="/etc/warp"
WGCF_ProfilePath="${WGCF_ProfileDir}/${WGCF_Profile}"

WireGuard_Interface='wgcf'
WireGuard_ConfPath="/etc/wireguard/${WireGuard_Interface}.conf"

WireGuard_Interface_DNS_IPv4='8.8.8.8,8.8.4.4'
WireGuard_Interface_DNS_IPv6='2001:4860:4860::8888,2001:4860:4860::8844'
WireGuard_Interface_DNS_46="${WireGuard_Interface_DNS_IPv4},${WireGuard_Interface_DNS_IPv6}"
WireGuard_Interface_DNS_64="${WireGuard_Interface_DNS_IPv6},${WireGuard_Interface_DNS_IPv4}"
WireGuard_Interface_Rule_table='51888'
WireGuard_Interface_Rule_fwmark='51888'
WireGuard_Interface_MTU='1280'

WireGuard_Peer_Endpoint_IP4='162.159.192.1'
WireGuard_Peer_Endpoint_IP6='2606:4700:d0::a29f:c001'
WireGuard_Peer_Endpoint_IPv4="${WireGuard_Peer_Endpoint_IP4}:2408"
WireGuard_Peer_Endpoint_IPv6="[${WireGuard_Peer_Endpoint_IP6}]:2408"
WireGuard_Peer_Endpoint_Domain='engage.cloudflareclient.com:2408'
WireGuard_Peer_AllowedIPs_IPv4='0.0.0.0/0'
WireGuard_Peer_AllowedIPs_IPv6='::/0'
WireGuard_Peer_AllowedIPs_DualStack='0.0.0.0/0,::/0'

TestIPv4_1='1.0.0.1'
TestIPv4_2='9.9.9.9'
TestIPv6_1='2606:4700:4700::1001'
TestIPv6_2='2620:fe::fe'
CF_Trace_URL='https://www.cloudflare.com/cdn-cgi/trace'

Get_System_Info() {
    source /etc/os-release
    SysInfo_OS_CodeName="${VERSION_CODENAME}"
    SysInfo_OS_Name_lowercase="${ID}"
    SysInfo_OS_Name_Full="${PRETTY_NAME}"
    SysInfo_RelatedOS="${ID_LIKE}"
    SysInfo_Kernel="$(uname -r)"
    SysInfo_Kernel_Ver_major="$(uname -r | awk -F . '{print $1}')"
    SysInfo_Kernel_Ver_minor="$(uname -r | awk -F . '{print $2}')"
    SysInfo_Arch="$(uname -m)"
    SysInfo_Virt="$(systemd-detect-virt)"
    case ${SysInfo_RelatedOS} in
    *fedora* | *rhel*)
        SysInfo_OS_Ver_major="$(rpm -E '%{rhel}')"
        ;;
    *)
        SysInfo_OS_Ver_major="$(echo ${VERSION_ID} | cut -d. -f1)"
        ;;
    esac
}

Print_System_Info() {
    echo -e "
System Information
---------------------------------------------------
  Operating System: ${SysInfo_OS_Name_Full}
      Linux Kernel: ${SysInfo_Kernel}
      Architecture: ${SysInfo_Arch}
    Virtualization: ${SysInfo_Virt}
---------------------------------------------------
"
}
Check_WireGuard_Peer_Endpoint() {
    if ping -c1 -W1 ${WireGuard_Peer_Endpoint_IP4} >/dev/null 2>&1; then
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_IPv4}"
    elif ping6 -c1 -W1 ${WireGuard_Peer_Endpoint_IP6} >/dev/null 2>&1; then
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_IPv6}"
    else
        WireGuard_Peer_Endpoint="${WireGuard_Peer_Endpoint_Domain}"
    fi
}

Install_Requirements_Debian() }
    if [[ ! $(command -v gpg) ]]; then
        apt update
        apt install gnupg -y
    fi
    if [[ ! $(apt list 2>/dev/null | grep apt-transport-https | grep installed) ]]; then
        apt update
        apt install apt-transport-https -y
    fi
    {

# Enable_IPv6_Support
    if [[ $(sysctl -a | grep 'disable_ipv6.*=.*1') || $(cat /etc/sysctl.{conf,d/*} | grep 'disable_ipv6.*=.*1') ]]; then
        sed -i '/disable_ipv6/d' /etc/sysctl.{conf,d/*}
        echo 'net.ipv6.conf.all.disable_ipv6 = 0' >/etc/sysctl.d/ipv6.conf
        sysctl -w net.ipv6.conf.all.disable_ipv6=0
    fi
    
Check_Network_Status_IPv4() {
    if ping -c1 -W1 ${TestIPv4_1} >/dev/null 2>&1 || ping -c1 -W1 ${TestIPv4_2} >/dev/null 2>&1; then
        IPv4Status='on'
    else
        IPv4Status='off'
    fi
}

Check_Network_Status_IPv6() {
    if ping6 -c1 -W1 ${TestIPv6_1} >/dev/null 2>&1 || ping6 -c1 -W1 ${TestIPv6_2} >/dev/null 2>&1; then
        IPv6Status='on'
    else
        IPv6Status='off'
    fi
}
    
    Install_WARP_Client_Debian() {
    if [[ ${SysInfo_OS_Name_lowercase} = ubuntu ]]; then
        case ${SysInfo_OS_CodeName} in
        bionic | focal | jammy) ;;
        *)
            log ERROR "This operating system is not supported."
            exit 1
            ;;
        esac
    elif [[ ${SysInfo_OS_Name_lowercase} = debian ]]; then
        case ${SysInfo_OS_CodeName} in
        bookworm | buster | bullseye) ;;
        *)
            log ERROR "This operating system is not supported."
            exit 1
            ;;
        esac
    fi
    Install_Requirements_Debian
    curl https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${SysInfo_OS_CodeName} main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    apt update
    apt install cloudflare-warp -y
    }
    
   Install_WARP_Client_CentOS() {
    if [[ ${SysInfo_OS_Ver_major} = 8 ]]; then
        rpm -ivh http://pkg.cloudflareclient.com/cloudflare-release-el8.rpm
        yum install cloudflare-warp -y
    else
        log ERROR "This operating system is not supported."
        exit 1
    fi
   }
 
Check_WARP_Client() {
    WARP_Client_Status=$(systemctl is-active warp-svc)
    WARP_Client_SelfStart=$(systemctl is-enabled warp-svc 2>/dev/null)
     }
      
Install_WARP_Client() {
    Print_System_Info
    log INFO "Installing Cloudflare WARP Client..."
    if [[ ${SysInfo_Arch} != x86_64 ]]; then
        log ERROR "This CPU architecture is not supported: ${SysInfo_Arch}"
        exit 1
    fi
    case ${SysInfo_OS_Name_lowercase} in
    *debian* | *ubuntu*)
        Install_WARP_Client_Debian
        ;;
    *centos* | *rhel*)
        Install_WARP_Client_CentOS
        ;;
    *)
        if [[ ${SysInfo_RelatedOS} = *rhel* || ${SysInfo_RelatedOS} = *fedora* ]]; then
            Install_WARP_Client_CentOS
        else
            log ERROR "This operating system is not supported."
            exit 1
        fi
        ;;
    esac
    Check_WARP_Client
    if [[ ${WARP_Client_Status} = active ]]; then
        log INFO "Cloudflare WARP Client installed successfully!"
    else
        log ERROR "warp-svc failure to run!"
        journalctl -u warp-svc --no-pager
        exit 1
    fi
    }
    
    Restart_WARP_Client() {
    log INFO "Restarting Cloudflare WARP Client..."
    systemctl restart warp-svc
    Check_WARP_Client
    if [[ ${WARP_Client_Status} = active ]]; then
        log INFO "Cloudflare WARP Client has been restarted."
    else
        log ERROR "Cloudflare WARP Client failure to run!"
        journalctl -u warp-svc --no-pager
        exit 1
    fi
}

Init_WARP_Client() {
    Check_WARP_Client
    if [[ ${WARP_Client_SelfStart} != enabled || ${WARP_Client_Status} != active ]]; then
        Install_WARP_Client
    fi
    if [[ $(warp-cli --accept-tos account) = *Missing* ]]; then
        log INFO "Cloudflare WARP Account Registration in progress..."
        warp-cli --accept-tos register
    fi
}

Connect_WARP() {
    log INFO "Connecting to WARP..."
    warp-cli --accept-tos connect
    log INFO "Enable WARP Always-On..."
    warp-cli --accept-tos enable-always-on
}
    
  Check_Network_Status_IPv4() {
    if ping -c1 -W1 ${TestIPv4_1} >/dev/null 2>&1 || ping -c1 -W1 ${TestIPv4_2} >/dev/null 2>&1; then
        IPv4Status='on'
    else
        IPv4Status='off'
    fi
}
Check_Network_Status_IPv6() {
    if ping6 -c1 -W1 ${TestIPv6_1} >/dev/null 2>&1 || ping6 -c1 -W1 ${TestIPv6_2} >/dev/null 2>&1; then
        IPv6Status='on'
    else
        IPv6Status='off'
    fi
}
Check_IPv4_addr () {
    IPv4_addr=$(
        ip route get ${TestIPv4_1} 2>/dev/null | grep -oP 'src \K\S+' ||
            ip route get ${TestIPv4_2} 2>/dev/null | grep -oP 'src \K\S+'
    )
}
 Check_IPv6_addr() {
    IPv6_addr=$(
        ip route get ${TestIPv6_1} 2>/dev/null | grep -oP 'src \K\S+' ||
            ip route get ${TestIPv6_2} 2>/dev/null | grep -oP 'src \K\S+'
    )
}
Get_IP_addr() {
    Check_Network_Status
    if [[ ${IPv4Status} = on ]]; then
        log INFO "Getting the network interface IPv4 address..."
        Check_IPv4_addr
        if [[ ${IPv4_addr} ]]; then
            log INFO "IPv4 Address: ${IPv4_addr}"
        else
            log WARN "Network interface IPv4 address not obtained."
        fi
    fi
    if [[ ${IPv6Status} = on ]]; then
        log INFO "Getting the network interface IPv6 address..."
        Check_IPv6_addr
        if [[ ${IPv6_addr} ]]; then
            log INFO "IPv6 Address: ${IPv6_addr}"
        else
            log WARN "Network interface IPv6 address not obtained."
        fi
    fi
    }
    
    Get_WireGuard_Interface_MTU() {
    log INFO "Getting the best MTU value for WireGuard..."
    MTU_Preset=1500
    MTU_Increment=10
    if [[ ${IPv4Status} = off && ${IPv6Status} = on ]]; then
        CMD_ping='ping6'
        MTU_TestIP_1="${TestIPv6_1}"
        MTU_TestIP_2="${TestIPv6_2}"
    else
        CMD_ping='ping'
        MTU_TestIP_1="${TestIPv4_1}"
        MTU_TestIP_2="${TestIPv4_2}"
    fi
    while true; do
        if ${CMD_ping} -c1 -W1 -s$((${MTU_Preset} - 28)) -Mdo ${MTU_TestIP_1} >/dev/null 2>&1 || ${CMD_ping} -c1 -W1 -s$((${MTU_Preset} - 28)) -Mdo ${MTU_TestIP_2} >/dev/null 2>&1; then
            MTU_Increment=1
            MTU_Preset=$((${MTU_Preset} + ${MTU_Increment}))
        else
            MTU_Preset=$((${MTU_Preset} - ${MTU_Increment}))
            if [[ ${MTU_Increment} = 1 ]]; then
                break
            fi
        fi
        if [[ ${MTU_Preset} -le 1360 ]]; then
            log WARN "MTU is set to the lowest value."
            MTU_Preset='1360'
            break
        fi
    done
    WireGuard_Interface_MTU=$((${MTU_Preset} - 80))
    log INFO "WireGuard MTU: ${WireGuard_Interface_MTU}"
}

Generate_WireGuardProfile_Interface() {
    Get_WireGuard_Interface_MTU
    log INFO "WireGuard profile (${WireGuard_ConfPath}) generation in progress..."
    cat <<EOF >${WireGuard_ConfPath}
# Generated by P3TERX/warp.sh
# Visit https://github.com/P3TERX/warp.sh for more information

[Interface]
PrivateKey = ${WireGuard_Interface_PrivateKey}
Address = ${WireGuard_Interface_Address}
DNS = ${WireGuard_Interface_DNS_46}
MTU = ${WireGuard_Interface_MTU}
EOF
}

  Print_Delimiter() {
    printf '=%.0s' $(seq $(tput cols))
    echo
    
    # Register_WARP_Account
    while [[ ! -f wgcf-account.toml ]]; do
        Install_wgcf
        log INFO "Cloudflare WARP Account registration in progress..."
        yes | wgcf register
        sleep 5
    done
    }

Generate_WGCF_Profile() {
    while [[ ! -f ${WGCF_Profile} ]]; do
        Register_WARP_Account
        log INFO "WARP WireGuard profile (wgcf-profile.conf) generation in progress..."
        wgcf generate
    done
    }
 
 Backup_WGCF_Profile () {
    mkdir -p ${WGCF_ProfileDir}
    mv -f wgcf* ${WGCF_ProfileDir}
    }

Read_WGCF_Profile() {
    WireGuard_Interface_PrivateKey=$(cat ${WGCF_ProfilePath} | grep ^PrivateKey | cut -d= -f2- | awk '$1=$1')
    WireGuard_Interface_Address=$(cat ${WGCF_ProfilePath} | grep ^Address | cut -d= -f2- | awk '$1=$1' | sed ":a;N;s/\n/,/g;ta")
    WireGuard_Peer_PublicKey=$(cat ${WGCF_ProfilePath} | grep ^PublicKey | cut -d= -f2- | awk '$1=$1')
    WireGuard_Interface_Address_IPv4=$(echo ${WireGuard_Interface_Address} | cut -d, -f1 | cut -d'/' -f1)
    WireGuard_Interface_Address_IPv6=$(echo ${WireGuard_Interface_Address} | cut -d, -f2 | cut -d'/' -f1)
    }

 Load_WGCF_Profile() {
    if [[ -f ${WGCF_Profile} ]]; then
        Backup_WGCF_Profile
        Read_WGCF_Profile
    elif [[ -f ${WGCF_ProfilePath} ]]; then
        Read_WGCF_Profile
    else
        Generate_WGCF_Profile
        Backup_WGCF_Profile
        Read_WGCF_Profile
    fi
    }
  

# Status
Check_WireGuard() {
    WireGuard_Status=$(systemctl is-active wg-quick@${WireGuard_Interface})
    WireGuard_SelfStart=$(systemctl is-enabled wg-quick@${WireGuard_Interface} 2>/dev/null)
}

Check_WireGuard_Status() {
    Check_WireGuard
    case ${WireGuard_Status} in
    active)
        WireGuard_Status_en="${FontColor_Green}Running${FontColor_Suffix}"
        WireGuard_Status_zh="${FontColor_Green}运行中${FontColor_Suffix}"
        ;;
    *)
        WireGuard_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}"
        WireGuard_Status_zh="${FontColor_Red}未运行${FontColor_Suffix}"
        ;;
    esac
}

Check_WARP_WireGuard_Status() {
    Check_Network_Status_IPv4
    if [[ ${IPv4Status} = on ]]; then
        WARP_IPv4_Status=$(curl -s4 ${CF_Trace_URL} --connect-timeout 2 | grep warp | cut -d= -f2)
    else
        unset WARP_IPv4_Status
    fi
    case ${WARP_IPv4_Status} in
    on)
        WARP_IPv4_Status_en="${FontColor_Green}WARP${FontColor_Suffix}"
        WARP_IPv4_Status_zh="${WARP_IPv4_Status_en}"
        ;;
    plus)
        WARP_IPv4_Status_en="${FontColor_Green}WARP+${FontColor_Suffix}"
        WARP_IPv4_Status_zh="${WARP_IPv4_Status_en}"
        ;;
    off)
        WARP_IPv4_Status_en="Normal"
        WARP_IPv4_Status_zh="正常"
        ;;
    *)
        Check_Network_Status_IPv4
        if [[ ${IPv4Status} = on ]]; then
            WARP_IPv4_Status_en="Normal"
            WARP_IPv4_Status_zh="正常"
        else
            WARP_IPv4_Status_en="${FontColor_Red}Unconnected${FontColor_Suffix}"
            WARP_IPv4_Status_zh="${FontColor_Red}未连接${FontColor_Suffix}"
        fi
        ;;
    esac
    Check_Network_Status_IPv6
    if [[ ${IPv6Status} = on ]]; then
        WARP_IPv6_Status=$(curl -s6 ${CF_Trace_URL} --connect-timeout 2 | grep warp | cut -d= -f2)
    else
        unset WARP_IPv6_Status
    fi
    case ${WARP_IPv6_Status} in
    on)
        WARP_IPv6_Status_en="${FontColor_Green}WARP${FontColor_Suffix}"
        WARP_IPv6_Status_zh="${WARP_IPv6_Status_en}"
        ;;
    plus)
        WARP_IPv6_Status_en="${FontColor_Green}WARP+${FontColor_Suffix}"
        WARP_IPv6_Status_zh="${WARP_IPv6_Status_en}"
        ;;
    off)
        WARP_IPv6_Status_en="Normal"
        WARP_IPv6_Status_zh="正常"
        ;;
    *)
        Check_Network_Status_IPv6
        if [[ ${IPv6Status} = on ]]; then
            WARP_IPv6_Status_en="Normal"
            WARP_IPv6_Status_zh="正常"
        else
            WARP_IPv6_Status_en="${FontColor_Red}Unconnected${FontColor_Suffix}"
            WARP_IPv6_Status_zh="${FontColor_Red}未连接${FontColor_Suffix}"
        fi
        ;;
    esac
    if [[ ${IPv4Status} = off && ${IPv6Status} = off ]]; then
        log ERROR "Cloudflare WARP network anomaly, WireGuard tunnel established failed."
        exit 1
    fi
}

# Set IPV6 & IPV4 WARP
# Set_WARP_DualStack
    Get_IP_addr
    Load_WGCF_Profile
    WireGuard_Interface_DNS="${WireGuard_Interface_DNS_46}"
    WireGuard_Peer_AllowedIPs="${WireGuard_Peer_AllowedIPs_DualStack}"
    Check_WireGuard_Peer_Endpoint
    Generate_WireGuardProfile_Interface
    if [[ -n ${IPv4_addr} ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv4_Global_srcIP
    fi
    if [[ -n ${IPv6_addr} ]]; then
        Generate_WireGuardProfile_Interface_Rule_IPv6_Global_srcIP
    fi
    
 # Generate_WireGuardProfile_Peer
    cat <<EOF >>${WireGuard_ConfPath}

[Peer]
PublicKey = ${WireGuard_Peer_PublicKey}
AllowedIPs = ${WireGuard_Peer_AllowedIPs}
Endpoint = ${WireGuard_Peer_Endpoint}
EOF

 # View_WireGuard_Profile()
    Print_Delimiter
    cat ${WireGuard_ConfPath}
    Print_Delimiter
    
    Check_WireGuard_Status() {
    Check_WireGuard
    case ${WireGuard_Status} in
    active)
        WireGuard_Status_en="${FontColor_Green}Running${FontColor_Suffix}"
        WireGuard_Status_zh="${FontColor_Green}运行中${FontColor_Suffix}"
        ;;
    *)
        WireGuard_Status_en="${FontColor_Red}Stopped${FontColor_Suffix}"
        WireGuard_Status_zh="${FontColor_Red}未运行${FontColor_Suffix}"
        ;;
    esac
}

# Print_WARP_WireGuard_Status
clear
 echo ""
    log INFO "Status check in progress..."
    Check_WireGuard_Status
    Check_WARP_WireGuard_Status
    echo -e "
 ----------------------------
 WireGuard\t: ${WireGuard_Status_en}
 IPv4 Network\t: ${WARP_IPv4_Status_en}
 IPv6 Network\t: ${WARP_IPv6_Status_en}
 ----------------------------
"
    log INFO "Done."
    echo ""
    echo " Will Download Extra File After this Information Wait 1/2 Seconds"
    echo ""
    sleep 1.0
    clear
# Tambahan
cd /usr/bin
wget -O addwg "https://${beginner}/addwg.sh"
wget -O delwg "https://${beginner}/delwg.sh"
wget -O renewwg "https://${beginner}/renewwg.sh"
chmod +x addwg
chmod +x delwg
chmod +x renewwg
cd
rm -f /root/wg.sh
