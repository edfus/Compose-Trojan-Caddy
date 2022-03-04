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

urandom () {
  cat /dev/urandom | head -c $1 | hexdump -e '"%x"'
}

if [[ -f /etc/redhat-release ]]; then
    RELEASE="centos"
    PKGMANAGER="yum"
    SYSTEMPWD="/usr/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "debian"; then
    RELEASE="debian"
    PKGMANAGER="apt-get"
    SYSTEMPWD="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    RELEASE="ubuntu"
    PKGMANAGER="apt-get"
    SYSTEMPWD="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    RELEASE="centos"
    PKGMANAGER="yum"
    SYSTEMPWD="/usr/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "debian"; then
    RELEASE="debian"
    PKGMANAGER="apt-get"
    SYSTEMPWD="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    RELEASE="ubuntu"
    PKGMANAGER="apt-get"
    SYSTEMPWD="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    RELEASE="centos"
    PKGMANAGER="yum"
    SYSTEMPWD="/usr/lib/systemd/system/"
fi

function up () {
  set +e
  # docker-compose -p "trojan-caddy" down
  # docker-compose -p "caddy-archivebox" down
  # docker-compose down

  # https://stackoverflow.com/a/30969768
  set -o allexport
  [ -f .env ] && source .env
  set +o allexport

  netstat --version >/dev/null 2>&1
  if [ $? != 0 ]; then
    $PKGMANAGER install -y net-tools
  fi

  port80=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 80`
  port443=`netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w 443`
  if [ -n "$port80" ]; then
      process80=`netstat -tlpn | awk -F '[: ]+' '$5=="80"{print $9}'`
      red "==========================================================="
      red "Port 80 is already in use by process ${process80}"
      red "==========================================================="
  fi

  if [ -n "$port443" ]; then
      process443=`netstat -tlpn | awk -F '[: ]+' '$5=="443"{print $9}'`
      red "============================================================="
      red "Port 443 is already in use by process ${process443}"
      red "============================================================="
  fi

  # # https://github.com/FaithPatrick/trojan-caddy-docker-compose/blob/master/install_beta.sh
  # CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
  # if [ "$CHECK" == "SELINUX=enforcing" ] || [ "$CHECK" == "SELINUX=permissive" ]; then
  #     red "======================================================================="
  #     red "SELinux is enabled and may hamper the process of requesting site certificates"
  #     red "======================================================================="
  #     read -p "Disable SELinux and reboot the machine? [Y/n]:" yn
  #   [ -z "${yn}" ] && yn="y"
  #   if [[ $yn == [Yy] ]]; then
  #       sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
  #       sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
  #             setenforce 0
  #       echo -e "Rebooting..."
  #       reboot
  #   fi
  #     exit
  # fi

  read -e -i "$DOMAIN_NAME" -p "$(blue 'Enter the domain name: ')" DOMAIN_NAME

  green "Checking for possible DNS resolution failures..."
  real_addr=`dig +short "$DOMAIN_NAME"`
  dig_rtcode=$?
  if [ $dig_rtcode != 0 ]; then
    $PKGMANAGER -y install dnsutils
    $PKGMANAGER -y install bind-utils
    real_addr=`dig +short "$DOMAIN_NAME"`
    dig_rtcode=$?
  fi
  local_addr=`curl -4 --silent ipv4.icanhazip.com`

  if [ $dig_rtcode != 0 ]; then
    red "Unrecoverable error: dig is not available"
    read -p "$(red 'Type y to continue: ')" yn
    [ -z "${yn}" ] && yn="n"
    if [[ $yn != [Yy] ]]; then
      return 1
    fi
  fi

  if [ $dig_rtcode == 0 ] && [ "$real_addr" != "$local_addr" ] ; then
    red "================================"
    red "$real_addr != $local_addr"
    red "================================"
    return 1
  fi

  green "Generating a good random password..."
  readonly TROJAN_PASSWORD="$(urandom 10)"

  green "Intalling packages..."

  install_docker
  install_docker_compose

  ipv6_enabled="false"
  network_interface="0.0.0.0"
  ipv6_disabled=`sysctl net.ipv6.conf.all.disable_ipv6 | sed -r 's/net.ipv6.conf.all.disable_ipv6\s=\s//'`
  ipv6_cidr=`ip -6 addr | awk '/inet6/{print $2}' | grep -v ^::1 | grep -v ^fe80 | head -n 1`
  ipv6_addr=`curl -6 --silent https://ipv6.icanhazip.com`
  if [ $? != 0 ] || [ $ipv6_disabled != 0 ]; then
    red "IPv6 is not available, falling back to IPv4 only"
    network_interface="0.0.0.0"
  elif [ "$ipv6_cidr" == "" ]; then
    red "Can't find a public IPv6 address on this machine,"
    red "but IPv6 is enabled."
    red "Falling back to IPv4 only."
    network_interface="0.0.0.0"
  else
    green "Enabling IPv6 support in Docker containers..."
    green "IPv6 addresses at hand: $ipv6_addr - $ipv6_cidr"
    jq -h > /dev/null
    if [ $? != 0 ]; then
      $PKGMANAGER install -y jq
    fi
    test -f /etc/docker/daemon.json || echo '{}' > /etc/docker/daemon.json
    jq -s add <(cat <<EOF
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:dead:beef:abcd::/64",
  "experimental": true,
  "ip6tables": true
}
EOF
) /etc/docker/daemon.json | tee /etc/docker/daemon.json
    systemctl reload docker
    # [ "`docker ps -aqf "name=ipv6nat"`" == "" ] \
    # && docker run -d --name ipv6nat --privileged --network host --restart unless-stopped -v /var/run/docker.sock:/var/run/docker.sock:ro -v /lib/modules:/lib/modules:ro robbertkl/ipv6nat

    caddy_backends=`docker ps -qf "network=caddy"`
    caddy_ipv6_enabled=`docker network inspect caddy | jq '.[0].EnableIPv6'`

    IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_cidr"

    if [ "$ipv6_cidr_subnet" -gt 80 ]; then
      echo "It is said taht the IPv6 subnet should at least have a size of /80 (Docker 17.09)"
      ipv6_caddy_block="$ipv6_cidr_addr/$ipv6_cidr_subnet"
    else
      ipv6_caddy_block="$ipv6_cidr_addr/80"
    fi

    if ! [ "$caddy_ipv6_enabled" == "true" ]; then
      for backend in $caddy_backends; do
        docker network disconnect -f caddy $backend
      done
      docker network rm caddy
      docker network create --ipv6 --subnet "$ipv6_caddy_block" caddy > /dev/null
      for backend in $caddy_backends; do
        docker network connect caddy $backend
      done
    fi
    network_interface="::"
    ipv6_enabled="true"
  fi

  green "Creating Trojan config..."
  mkdir -p ./trojan/config
	cat > ./trojan/config/config.json <<-EOF
{
    "run_type": "server",
    "local_addr": "$network_interface",
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
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
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
  read -e -i "${PROFILE_NAME:-$DOMAIN_NAME}" -p "$(blue 'Enter the profile name: ')" PROFILE_NAME
  set +e
  EXPIRE_TIMESTAMP="${EXPIRE:+@$EXPIRE}"
  read -e -i "$(date "+%m/%d/%Y" -d "${EXPIRE_TIMESTAMP:-3 months}")" -p "$(blue 'Any determined expiration date? [%m/%d/%Y] ')" DISCONTINUATION_DATE 
  date -d "${DISCONTINUATION_DATE:-??}" "+%m/%d/%Y" >/dev/null 2>&1
  if [ $? != 0 ]; then
    DISCONTINUATION_DATE=$(date "+%m/%d/%Y" -d "2 years")
  fi
  DISCONTINUATION_DATE=$(date "+%s" -d "$DISCONTINUATION_DATE")
  
  read -e -i "${DOH_PATH:-/$(urandom 4)}" -p "$(blue 'Enter the DoH URI path: ')" DOH_PATH 
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
  - name: Quick UDP Internet Connections
    type: select
    proxies:
      - REJECT
      - Proxy
  - name: Microsoft Network Connectivity Status Indicator
    type: select
    proxies:
      - "$PROFILE_NAME"
      - DIRECT
script:
  shortcuts:
    QUIC: network == 'udp' and dst_port == 443

rules:
  - SCRIPT,QUIC,Quick UDP Internet Connections
  - DOMAIN,localhost,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN,dns.msftncsi.com,Microsoft Network Connectivity Status Indicator
  - DOMAIN,www.msftncsi.com,Microsoft Network Connectivity Status Indicator
  - DOMAIN,www.msftconnecttest.com,Microsoft Network Connectivity Status Indicator
  - DOMAIN,ipv6.msftconnecttest.com,Microsoft Network Connectivity Status Indicator
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
  $([ "$ipv6_enabled" == "true" ] && echo "# $DOMAIN_NAME: \"[$ipv6_addr]\"")
  $([ "$ipv6_enabled" == "true" ] && echo "# ")$DOMAIN_NAME: $local_addr
  # dns.google: 8.8.8.8
  # dns-unfiltered.adguard.com: 94.140.14.140
  # sandbox.opendns.com: 208.67.222.2
  # dns10.quad9.net: 9.9.9.10
  # security-filter-dns.cleanbrowsing.org: 185.228.168.9
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  use-hosts: true
  nameserver:
    - https://${DOMAIN_NAME}${DOH_PATH}
  fallback-filter:
    geoip: false
EOF

  readonly CONFIG_USERNAME=clash
  readonly CONFIG_FILENAME="$PROFILE_NAME $local_addr"
  readonly CONFIG_PASSWORD="${PASSWORD:-$(urandom 6)}"
  readonly CONFIG_PASSWORD_BCRYPTED=$(docker run caddy/caddy:2.4.0-alpine caddy hash-password -algorithm "bcrypt" -plaintext "$CONFIG_PASSWORD")

  cat > .env <<EOF
DOMAIN_NAME=$DOMAIN_NAME
DOH_PATH=$DOH_PATH
USERNAME=$CONFIG_USERNAME
PROFILE_NAME="$PROFILE_NAME"
FILENAME="$CONFIG_FILENAME"
EXPIRE=$DISCONTINUATION_DATE
PASSWORD=$CONFIG_PASSWORD
PASSWD_BCRYPTED=$CONFIG_PASSWORD_BCRYPTED
EOF

  set -o allexport
  source .env
  set +o allexport

  if ! [ -f "./docker-proxy.yml"  ] && [ "$ipv6_enabled" == "true" ]; then
    red "Can't find ./docker-proxy.yml while IPv6 is enabled"
    red "Please check the integrity of $PWD"
    read -p "$(red 'Type y to continue the script: ')" yn
    [ -z "${yn}" ] && yn="n"
    if [[ $yn != [Yy] ]]; then
      return 1
    fi
  fi

  if [ -f "./docker-proxy.yml" ]; then
    if ! [ "$ipv6_enabled" == "true" ]; then
      read -p "$(blue 'Set up an Archive Box decoy site? (Y/n) ')" yn
      [ -z "${yn}" ] && yn="n"
    else
      yn="y"
    fi
    
    if [[ $yn == [Yy] ]]; then
      test -f "./docker-compose.yml" && mv "./docker-compose.yml" "./docker-compose.yml.bak"
      cp "./docker-proxy.yml" "./docker-compose.yml"
      green "Starting docker containers..."
      set +e
      [ "`docker ps -qf "network=caddy" | head -c 1`" == "" ] \
      && docker network create caddy
      docker-compose -p "trojan-caddy" --env-file .env up -d
      if [ $? != 0 ]; then
        docker-compose -p "trojan-caddy" --env-file .env down
        docker-compose -p "trojan-caddy" --env-file .env up -d
      fi 
      read -p "$(blue 'Any URL for scheduled regular imports? ')" yn
      [ -z "${yn}" ] && yn="n"
      if [[ $yn == [Nn] ]]; then
        ENABLE_SCHEDULE=/bin/false
        VAR_ARCHIVE_TARGET=""
      else
        ENABLE_SCHEDULE=
        VAR_ARCHIVE_TARGET="$yn"
      fi   
cat>./archivebox.yml<<EOF
version: '3.9'
services:
  archivebox:
    image: archivebox/archivebox:sha-bf432d4
    command: server --quick-init 0.0.0.0:8000
    expose:
      - 8000
    environment:
      - ALLOWED_HOSTS=*
      - MEDIA_MAX_SIZE=750m
    volumes:
      - ./archivebox-data:/data
    networks:
      - caddy
    restart: unless-stopped
    labels:
      caddy: "http://:4433"
      # https://github.com/lucaslorentz/caddy-docker-proxy/issues/208#issuecomment-762333788
      caddy.reverse_proxy: http://archivebox:8000
  scheduler:
    image: archivebox/archivebox:sha-bf432d4
    command: ${ENABLE_SCHEDULE} schedule --foreground --every=month --depth=0 '${VAR_ARCHIVE_TARGET}'
    environment:
      - USE_COLOR=True
      - SHOW_PROGRESS=False
    networks:
      - caddy
    restart: "no"
    volumes:
      - ./archivebox-data:/data
networks:
  caddy:
    external: true
EOF
      docker-compose -p "caddy-archivebox" -f ./archivebox.yml --env-file /dev/null run archivebox init --setup
      docker-compose -p "caddy-archivebox" -f ./archivebox.yml --env-file /dev/null up -d
      if [ $? != 0 ]; then
        docker-compose -p "caddy-archivebox" -f ./archivebox.yml --env-file /dev/null down
        docker-compose -p "caddy-archivebox" -f ./archivebox.yml --env-file /dev/null up -d
      fi
      docker exec $(docker ps | grep archivebox-archivebox | awk '{ print $1 }') \
      archivebox config --set YOUTUBEDL_ARGS='["--write-description", "--write-info-json", "--write-annotations", "--write-thumbnail", "--no-call-home", "--write-sub", "--all-subs", "--write-auto-sub", "--convert-subs=srt", "--yes-playlist", "--continue", "--ignore-errors", "--geo-bypass", "--add-metadata", "--max-filesize=500m", "--sub-lang=en"]'
      green "======================="
      blue "USER: $CONFIG_USERNAME"
      blue "PASSWD: ${CONFIG_PASSWORD}"
      blue "TROJAN PASSWD: ${TROJAN_PASSWORD}"
      blue "Config files are available at https://$CONFIG_USERNAME:${CONFIG_PASSWORD}@${DOMAIN_NAME}/.config/clash.yml"
      green "======================="
      return
    fi
  fi

  green "Starting docker containers..."
  docker-compose --env-file .env up -d
  if [ $? != 0 ]; then
    docker-compose --env-file .env down
    docker-compose --env-file .env up -d
  fi
  
  green "======================="
  blue "USER: $CONFIG_USERNAME"
  blue "PASSWD: ${CONFIG_PASSWORD}"
  blue "TROJAN PASSWD: ${TROJAN_PASSWORD}"
  blue "Config files are available at https://$CONFIG_USERNAME:${CONFIG_PASSWORD}@${DOMAIN_NAME}/.config/clash.yml"
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
    $PKGMANAGER -y install python-pip
    pip install --upgrade pip
    pip install docker-compose

    if [ $? != 0 ]; then
      curl -L "https://github.com/docker/compose/releases/download/v2.2.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
      chmod +x /usr/local/bin/docker-compose
      ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    fi
  fi
}

function consolidate () {
  git --version > /dev/null 2>&1
  if [ $? != 0 ]; then
    set -e
    $PKGMANAGER -y install git
  fi
  set -e
  REPOSITORY=consolidate-clash-profiles
  if [ -d "$REPOSITORY" ]; then
    CWD=$PWD
    cd "$REPOSITORY"
    set +e
    git fetch --all
    git reset --hard origin/master
    set -e
    cd "$CWD"
  else
    git clone --depth 1 https://github.com/edfus/"$REPOSITORY"
  fi

  if [ "`docker ps -qf "network=caddy" | head -c 1`" == "" ]; then
    red "Unrecoverable error: can't find a pre-existing caddy network"
    red "If you are settng up a server dedicated to Trojan services,"
    red "run this script again with switch --up on AND choose to set up"
    red "an Archivebox decoy site or an IPv6 interface when prompted."
    red ""
    red "Or create a caddy dynamic reverse proxy network manually."
    red "Refer to lucaslorentz/caddy-docker-proxy and docker-proxy.yml"
    red "for details, if that's the case."
    return 1
  fi

  COMPOSE_FILE="./$REPOSITORY/docker-compose.yml"
  ENV_FILE="./$REPOSITORY/.env"

  set +e
  set -o allexport
  test -f "$ENV_FILE" && source "$ENV_FILE"
  set +o allexport

  cat>"$COMPOSE_FILE"<<'EOF'
version: '3.9'
services:
  clash-profiles:
    expose:
      - "80"
    restart: unless-stopped
    build: .
    environment:
      NODE_ENV: production
      EXPIRE: ${EXPIRE}
    networks:
      - caddy
    logging:
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./external-rulesets:/app/external-rulesets
      - ${PROFILES_OUTPUT:-./profiles}:/app/output
      - ${PROFILES_SRC:-./profiles.js}:/app/profiles.js
      - ${INJECTIONS_SRC:-./injections.yml}:/app/injections.yml
      - ${WRANGLER_CONFIG:-./wrangler.toml}:/app/wrangler.toml
    labels:
      - caddy=http://:4433
      - caddy.1_route=/.profiles
      - caddy.1_route.0_basicauth=bcrypt
      - caddy.1_route.0_basicauth.${USERNAME}="${PASSWD_BCRYPTED}"
      - caddy.1_route.reverse_proxy=http://clash-profiles:80
networks:
  caddy:
    external: true
EOF

  if [ "$PROFILES_SRC" == "" ]; then
    if ! [ -f profiles.js ]; then
      cat>profiles.js<<EOF
export default [

]
EOF
    fi
    nano profiles.js
    PROFILES_SRC=profiles.js
  fi

  if [ "$INJECTIONS_SRC" == "" ]; then
    if ! [ -f injections.yml ]; then
      cat>injections.yml<<EOF
Microsoft Network Connectivity Status Indicator:
  payload:
    - DOMAIN,dns.msftncsi.com,Microsoft Network Connectivity Status Indicator
    - DOMAIN,www.msftncsi.com,Microsoft Network Connectivity Status Indicator
    - DOMAIN,www.msftconnecttest.com,Microsoft Network Connectivity Status Indicator

EOF
    fi
    nano injections.yml
    INJECTIONS_SRC=injections.yml
  fi

  if [ "$WRANGLER_CONFIG" == "" ]; then
    if [ -f wrangler.toml ]; then
      WRANGLER_CONFIG=wrangler.toml
    elif [ -f "$REPOSITORY/wrangler.toml" ]; then
      WRANGLER_CONFIG="$REPOSITORY/wrangler.toml"
    else
      # docker-compose -f "$COMPOSE_FILE" --env-file /dev/null run clash-profiles ./init-wrangler.sh
      chmod +x "./$REPOSITORY/init-wrangler.sh"
      "./$REPOSITORY/init-wrangler.sh"
      WRANGLER_CONFIG="./$REPOSITORY/wrangler.toml"
      # docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" run clash-profiles wrangler config
    fi
  fi

  readonly CONFIG_USERNAME=${USERNAME:-$(urandom 2)}
  readonly CONFIG_PASSWORD=${PASSWORD:-$(urandom 4)}
  readonly CONFIG_PASSWORD_BCRYPTED=$(docker run caddy/caddy:2.4.0-alpine caddy hash-password -algorithm "bcrypt" -plaintext "$CONFIG_PASSWORD")

  cat > "$ENV_FILE" <<EOF
PROFILES_OUTPUT=${PROFILES_OUTPUT:+$(readlink -f "$PROFILES_OUTPUT")}
PROFILES_SRC=$(readlink -f "$PROFILES_SRC")
INJECTIONS_SRC=$(readlink -f "$INJECTIONS_SRC")
WRANGLER_CONFIG=${WRANGLER_CONFIG:+$(readlink -f "$WRANGLER_CONFIG")}
USERNAME="$CONFIG_USERNAME"
PASSWORD="$CONFIG_PASSWORD"
PASSWD_BCRYPTED=$CONFIG_PASSWORD_BCRYPTED
EXPIRE=${EXPIRE:-$DISCONTINUATION_DATE}
EOF

  set -o allexport
  test -f .env &&  source .env
  source "$ENV_FILE"
  set +o allexport

  docker-compose -p "$REPOSITORY" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d >/dev/null
  if [ $? != 0 ]; then
    docker-compose -p "$REPOSITORY" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
    docker-compose -p "$REPOSITORY" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d
  fi
  if [ "$DOMAIN_NAME" == "" ]; then
    read -e -i "$DOMAIN_NAME" -p "$(blue 'Enter the domain name: ')" DOMAIN_NAME
  fi

  green "======================="
  blue "USER: $CONFIG_USERNAME"
  blue "PASSWD: ${CONFIG_PASSWORD}"
  blue "Config files are available at https://$CONFIG_USERNAME:${CONFIG_PASSWORD}@${DOMAIN_NAME}/.profiles?code=vanilla"
  green "======================="

  wrangler_container=$(docker ps | grep clash | head -n 1  | awk '{ print $1 }')
  docker exec -it "$wrangler_container" wrangler config
  docker exec -it "$wrangler_container" wrangler publish
  docker logs $(docker ps | grep clash | head -n 1 | awk '{ print $1 }') --follow
}

function down () {
  caddy_backends=`docker ps -qf "network=caddy"`
  if [ "$caddy_backends" == "" ]; then
    docker-compose down
    return
  fi
  for backend in $caddy_backends; do
    docker network disconnect -f caddy $backend
    docker stop $backend && docker rm $backend
  done
  docker network rm caddy
}

if [[ $# -eq 0 ]]; then
  up
  exit
fi

# https://stackoverflow.com/a/14203146/13910382
POSITIONAL_ARGS=()

UP=
DOWN=
CONSOLIDATE=

while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--consolidate)
      CONSOLIDATE=YES
      shift # past argument
      ;;
    -u|--up)
      UP=YES
      shift # past argument
      ;;
    -d|--down)
      DOWN=YES
      shift # past argument
      ;;
    -i|--injections)
      INJECTIONS_SRC="$2"
      shift # past argument
      shift # past value
      ;;
    -p|--profiles|--config)
      PROFILES_SRC="$2"
      shift # past argument
      shift # past value
      ;;
    -w|--wranger|--wranger-config)
      WRANGLER_CONFIG="$2"
      shift # past argument
      shift # past value
      ;;
    -o|--output)
      PROFILES_OUTPUT="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      sed -n '/POSITIONAL_ARGS=\(\)/,$p' $0
      exit 0
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "$DOWN" == YES ]; then
  down
fi

if [ "$UP" == YES ]; then
  up
fi

if [ "$CONSOLIDATE" == YES ]; then
  consolidate
fi
