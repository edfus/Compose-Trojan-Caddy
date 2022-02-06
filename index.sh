#!/bin/bash

# set -e

blue () {
    echo -e "\033[34m\033[01m$1\033[0m"
}
green () {
    echo -e "\033[32m\033[01m$1\033[0m"
}
red () {
    echo -e "\033[31m\033[01m$1\033[0m"
}

if [[ -f /etc/redhat-release ]]; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
fi

function up () {
  docker-compose down

  port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
  port443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`
  if [ -n "$port80" ]; then
      process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
      red "==========================================================="
      red "Port 80 is already in use by process ${process80}"
      red "==========================================================="
      exit 1
  fi

  if [ -n "$port443" ]; then
      process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
      red "============================================================="
      red "Port 443 is already in use by process ${process443}"
      red "============================================================="
      exit 1
  fi

  CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
  if [ "$CHECK" == "SELINUX=enforcing" ] || [ "$CHECK" == "SELINUX=permissive" ]; then
      red "======================================================================="
      red "SELinux is enabled and may hamper the process of requesting site certificates"
      red "======================================================================="
      read -p "Disable SELinux and reboot the machine? [Y/n]:" yn
    [ -z "${yn}" ] && yn="y"
    if [[ $yn == [Yy] ]]; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
              setenforce 0
        echo -e "Rebooting..."
        reboot
    fi
      exit
  fi

  read -p "$(blue 'Enter the domain name: ')" DOMAIN_NAME

  green "Checking for possible DNS resolution failures..."
  real_addr=`ping ${DOMAIN_NAME} -c 1 2> /dev/null | sed '1{s/[^(]*(//;s/).*//;q}'`
  local_addr=`curl ipv4.icanhazip.com`

  if [ "$real_addr" != "$local_addr" ] ; then
    red "================================"
    red "$real_addr != $local_addr"
    red "================================"
  fi

  green "Generating a good random password..."
  readonly TROJAN_PASSWORD="$(uuidgen)-2022-v1.0"

  green "Intalling packages..."

  install_docker
  install_docker_compose

  green "Creating Trojan config..."
  mkdir -p ./trojan/config
	cat > ./trojan/config/config.json <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "caddy",
    "remote_port": 4433,
    "password": [
        "$TROJAN_PASSWORD"
    ],
    "log_level": 2,
    "ssl": {
        "cert": "/ssl/$DOMAIN_NAME/$DOMAIN_NAME.crt",
        "key": "/ssl/$DOMAIN_NAME/$DOMAIN_NAME.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        "prefer_server_cipher": true,
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false
    }
}
EOF
  read -e -i "$DOMAIN_NAME" -p "$(blue 'Enter the profile name: ')" PROFILE_NAME
  read -e -i "$(date "+%m/%d/%Y" -d "3 months")" -p "$(blue 'Any determined expiration date? [%m/%d/%Y] ')" DISCONTINUATION_DATE 
  set +e
  date -d "${DISCONTINUATION_DATE:-??}" "+%m/%d/%Y" >/dev/null 2>&1
  if [ $? != 0 ]; then
    DISCONTINUATION_DATE=$(date "+%m/%d/%Y" -d "2 years")
  fi
  DISCONTINUATION_DATE=$(date "+%s" -d "$DISCONTINUATION_DATE")
  
  read -e -i "/$(cat /dev/urandom | head -c 4 | hexdump -e '"%x"')" -p "$(blue 'Enter the DoH URI path: ')" DOH_PATH 
  DOH_PATH="$(echo "$DOH_PATH" | sed -r 's/^\/*([^\/])/\/\1/')"

  mkdir -p ./caddy/config
  cat >./caddy/config/clash.yml<< EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090
experimental:
  ignore-resolve-fail: true
proxies:
  - name: "$PROFILE_NAME"
    type: trojan
    server: $DOMAIN_NAME
    port: 443
    password: "$TROJAN_PASSWORD"
    udp: true
    alpn:
      - h2
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - "$PROFILE_NAME"
      - "Auto - UrlTest"
  - name: "Auto - UrlTest"
    type: url-test
    proxies:
      - "$PROFILE_NAME"
    url: http://www.gstatic.com/generate_204
    interval: "3600"
  - name: Microsoft Network Connectivity Status Indicator (NCSI)
    type: select
    proxies:
      - "$PROFILE_NAME"
      - DIRECT
rules:
  - DOMAIN,localhost,DIRECT
  - DOMAIN,dns.msftncsi.com,Microsoft Network Connectivity Status Indicator (NCSI)
  - DOMAIN,www.msftncsi.com,Microsoft Network Connectivity Status Indicator (NCSI)
  - DOMAIN,www.msftconnecttest.com,Microsoft Network Connectivity Status Indicator (NCSI)
  - IP-CIDR,0.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.0.0.0/24,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,198.18.0.0/15,DIRECT,no-resolve
  - IP-CIDR,224.0.0.0/3,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
  - MATCH,Proxy
hosts:
  # https://github.com/curl/curl/wiki/DNS-over-HTTPS
  # https://en.wikipedia.org/wiki/Public_recursive_name_server
  $DOMAIN_NAME: $local_addr
  dns.google: 8.8.8.8
  dns-unfiltered.adguard.com: 94.140.14.140
  sandbox.opendns.com: 208.67.222.2
  dns10.quad9.net: 9.9.9.10
  security-filter-dns.cleanbrowsing.org: 185.228.168.9
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  use-hosts: true
  nameserver:
    - https://dns10.quad9.net/dns-query
    - https://sandbox.opendns.com/dns-query
    - https://${DOMAIN_NAME}${DOH_PATH}
  fallback-filter:
    geoip: false
EOF

  readonly CONFIG_USERNAME=clash
  readonly CONFIG_FILENAME="$PROFILE_NAME $local_addr"
  readonly CONFIG_PASSWORD=$(uuidgen)
  readonly CONFIG_PASSWORD_BCRYPTED=$(docker run caddy/caddy:alpine caddy hash-password --plaintext "$CONFIG_PASSWORD")

  cat > .env <<EOF
DOMAIN_NAME=$DOMAIN_NAME
DOH_PATH=$DOH_PATH
USERNAME=$CONFIG_USERNAME
FILENAME=$CONFIG_FILENAME
EXPIRE=$DISCONTINUATION_DATE
PASSWD_BCRYPTED=$CONFIG_PASSWORD_BCRYPTED
EOF
	green "Starting docker containers..."
	docker-compose --env-file .env up -d --build
	
	green "======================="
  blue "USER: $CONFIG_USERNAME"
  blue "PASSWD: ${CONFIG_PASSWORD}"
  blue "TROJAN PASSWD: ${TROJAN_PASSWORD}"
  blue "Config files are available at https://$CONFIG_USERNAME:${CONFIG_PASSWORD}@${DOMAIN_NAME}/config/clash.yml"
  green "======================="
}

function install_docker () {  
  docker -v >/dev/null 2>&1
  if [ $? != 0 ]; then
    curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh
    systemctl start docker
    systemctl enable docker
    usermod -aG docker $USER
  fi
}

function install_docker_compose () {
  set +e
  docker-compose -v >/dev/null 2>&1
  if [ $? != 0 ]; then
    $systemPackage -y install  python-pip
    pip install --upgrade pip
    pip install docker-compose

    if [ $? != 0 ]; then
      curl -L "https://github.com/docker/compose/releases/download/v2.2.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
      chmod +x /usr/local/bin/docker-compose
      ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    fi
  fi
}

up