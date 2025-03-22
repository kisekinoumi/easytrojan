#!/bin/bash
#
# Notes: EasyTrojan for CentOS/RedHat 7+ Debian 9+ and Ubuntu 16+
# Modified for IPv6-only VPS
#
# Project home page:
#        https://github.com/eastmaple/easytrojan

trojan_passwd=$1
caddy_domain="legend.250606.xyz"
address_ipv6=$(curl -s -6 https://ipv6.icanhazip.com)
check_port=$(ss -Hlnp sport = :80 or sport = :443)

[ "$trojan_passwd" = "" ] && { echo "Error: You must enter a trojan's password to run this script"; exit 1; }
[ "$(id -u)" != "0" ] && { echo "Error: You must be root to run this script"; exit 1; }
[ "$check_port" != "" ] && { echo "Error: Port 80 or 443 is already in use"; exit 1; }

# Verify domain resolves to the server's IPv6 address
if ! host -t AAAA "$caddy_domain" | grep -q "$address_ipv6"; then
    echo "Warning: Your domain $caddy_domain doesn't resolve to this server's IPv6 address ($address_ipv6)"
    echo "Please make sure you've set up the AAAA record correctly before continuing."
    read -p "Continue anyway? (y/n): " confirm
    [ "$confirm" != "y" ] && { echo "Installation aborted"; exit 1; }
fi

check_cmd () { command -v "$1" &>/dev/null; }

# Install required packages
for cmd in tar host curl; do
    if ! check_cmd $cmd; then
        echo "$cmd: command not found, installing..."
        if check_cmd yum; then
            yum install -y $cmd bind-utils
        elif check_cmd apt-get; then
            apt-get update
            apt-get install -y $cmd dnsutils
        elif check_cmd dnf; then
            dnf install -y $cmd bind-utils
        else
            echo "Error: Unable to install $cmd"; exit 1
        fi
    fi
done

case $(uname -m) in
    x86_64)
        caddy_url=https://raw.githubusercontent.com/eastmaple/easytrojan/caddy/caddy_trojan_linux_amd64.tar.gz
        ;;
    aarch64)
        caddy_url=https://raw.githubusercontent.com/eastmaple/easytrojan/caddy/caddy_trojan_linux_arm64.tar.gz
        ;;
    *) 
        echo "Error: Your system version does not support"
        exit 1
        ;;
esac

curl -L $caddy_url | tar -zx -C /usr/local/bin caddy

if ! id caddy &>/dev/null; then groupadd --system caddy; useradd --system -g caddy -s "$(command -v nologin)" caddy; fi

mkdir -p /etc/caddy/trojan && chown -R caddy:caddy /etc/caddy && chmod 700 /etc/caddy

# Remove old certificates if they exist
rm -rf /etc/caddy/certificates

# Configure Caddy with IPv6 support
cat > /etc/caddy/Caddyfile <<EOF
{
    order trojan before respond
    https_port 443
    servers :443 {
        listener_wrappers {
            trojan
        }
        protocols h2 h1
    }
    servers :80 {
        protocols h1
    }
    trojan {
        caddy
        no_proxy
    }
}
:443, $caddy_domain {
    tls {
        protocols tls1.2 tls1.3
        ciphers TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    }
    log {
        level ERROR
    }
    trojan {
        websocket
    }
    respond "Service Unavailable" 503 {
        close
    }
}
:80 {
    redir https://{host}{uri} permanent
}
EOF

cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
Environment=XDG_CONFIG_HOME=/etc XDG_DATA_HOME=/etc
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Make sure loopback interface is up
if ip link show lo | grep -q DOWN; then ip link set lo up; fi
systemctl daemon-reload && systemctl restart caddy.service && systemctl enable caddy.service

# Add trojan user
curl -X POST -H "Content-Type: application/json" -d "{\"password\": \"$trojan_passwd\"}" http://127.0.0.1:2019/trojan/users/add
echo "$trojan_passwd" >> /etc/caddy/trojan/passwd.txt && sort /etc/caddy/trojan/passwd.txt | uniq > /etc/caddy/trojan/passwd.tmp && mv -f /etc/caddy/trojan/passwd.tmp /etc/caddy/trojan/passwd.txt

echo "Obtaining and Installing an SSL Certificate..."
count=0
sslfail=0
until [ -d /etc/caddy/certificates ]; do
count=$((count + 1))
sleep 3
(( count > 20 )) && sslfail=1 && break
done

[ "$sslfail" = "1" ] && { echo "Certificate application failed, please check your server firewall and network settings"; exit 1; }

# System optimization
sed -i '/^# End of file/,$d' /etc/security/limits.conf

cat >> /etc/security/limits.conf <<EOF
# End of file
*     soft   nofile    1048576
*     hard   nofile    1048576
*     soft   nproc     1048576
*     hard   nproc     1048576
*     soft   core      1048576
*     hard   core      1048576
*     hard   memlock   unlimited
*     soft   memlock   unlimited

root     soft   nofile    1048576
root     hard   nofile    1048576
root     soft   nproc     1048576
root     hard   nproc     1048576
root     soft   core      1048576
root     hard   core      1048576
root     hard   memlock   unlimited
root     soft   memlock   unlimited
EOF

sed -i '/fs.file-max/d' /etc/sysctl.conf
sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
sed -i '/net.ipv4.udp_rmem_min/d' /etc/sysctl.conf
sed -i '/net.ipv4.udp_wmem_min/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_no_metrics_save/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_frto/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_rfc1337/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_sack/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fack/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_window_scaling/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_adv_win_scale/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_moderate_rcvbuf/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_notsent_lowat/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.route_localnet/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.all.forwarding/d' /etc/sysctl.conf
sed -i '/net.ipv4.conf.default.forwarding/d' /etc/sysctl.conf
sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.all.forwarding/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.default.forwarding/d' /etc/sysctl.conf

cat >> /etc/sysctl.conf << EOF
fs.file-max = 1048576
fs.inotify.max_user_instances = 8192
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_frto = 0
net.ipv4.tcp_mtu_probing = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.conf.all.route_localnet = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
# IPv6 forwarding
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
EOF

modprobe tcp_bbr &>/dev/null
if grep -wq bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
fi

sysctl -p

# Check if service is running
if ! curl -s -o /dev/null -w "%{http_code}" "http://$caddy_domain" | grep -q "301\|503"; then
    echo "Warning: HTTP service check failed. Please make sure ports 80 and 443 are open in your firewall."
    echo "You may need to run: ip6tables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT"
    echo "And for permanent changes: apt install -y iptables-persistent netfilter-persistent"
fi

clear

echo "You have successfully installed EasyTrojan 2.0 with IPv6 support"
echo "Address: $caddy_domain | Port: 443 | Password: $trojan_passwd | Alpn: h2,http/1.1"
echo "IPv6 Address: [$address_ipv6]"
