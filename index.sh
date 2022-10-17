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

urandom_lc () {
  cat /dev/urandom | head -c $1 | hexdump -e '"%x"'
}

urandom () {
  tr -dc A-Za-z0-9 </dev/urandom | head -c $(( $1 * 2 ))
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

get_ipv6_cidr () {
  ip -6 addr | awk '/inet6/{print $2}' | grep -v ^::1 | grep -v ^fe80 | grep -v ^fd00 | awk -F'/' '
    NR==1 || $2<max_block_size {max_block_size=$2; line=$1"/"$2}
    END {print line}
  '
}

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" $2 $3
}

compose_up () {
  compose_cmd "$1" "$2" "up -d $3"
  if [ $? != 0 ]; then
    compose_cmd "$1" "$2" "down"
    compose_cmd "$1" "$2" "up -d $3"
  fi
}

# https://stackoverflow.com/a/18451819/13910382
ls_all_envfiles () {
  LC_ALL=C ls .env .*.env
}

stat_files () {
  stat -c "%U:%G %a %n" $1
}

check_env () {
  if [ -f .profiles.env.stat ]; then
    echo "$(stat_files `ls_all_envfiles`)" > ".tmp.profiles.env.stat"
    green "Comparing status of all environment files..."
    cmp .profiles.env.stat ".tmp.profiles.env.stat"
    if [ $? != "0" ]; then
      green "====================="
      green "before: (.profiles.env.stat)"
      green "$(cat .profiles.env.stat)"
      green
      blue  "========V.S.=========="
      red "after: (.tmp.profiles.env.stat)"
      red "$(cat .tmp.profiles.env.stat)"
      red
      read -e -p "$(blue 'Press Enter to continue at your own risk.')" 
      mv .profiles.env.stat .profiles.env.stat.bak
      mv .tmp.profiles.env.stat .profiles.env.stat
      chmod 0744 .profiles.env.stat
    else 
      rm .tmp.profiles.env.stat
    fi
  fi
}

function initialize () {
  install_docker
  install_docker_compose
}

function up () {
  set +e

  initialize

  check_env

  all_envfiles="`ls_all_envfiles`"
  # https://stackoverflow.com/a/30969768
  set -o allexport
  for envfile in $all_envfiles; do source "$envfile"; done
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

  read -e -i "$DOMAIN_NAME" -p "$(blue 'Enter the domain name: ')" DOMAIN_NAME

  green "Checking for possible DNS resolution failures..."
  real_addr=`dig +short "$DOMAIN_NAME"`
  dig_rtcode=$?
  if [ $dig_rtcode != 0 ]; then
    $PKGMANAGER -y install dnsutils
    $PKGMANAGER -y install bind-utils
    $PKGMANAGER -y install bind9-utils
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

  green "Checking if IPv6 is supported..."

  ipv6_enabled="false"
  network_interface="0.0.0.0"
  ipv6_disabled=`sysctl net.ipv6.conf.all.disable_ipv6 | sed -r 's/net.ipv6.conf.all.disable_ipv6\s=\s//'`
  ipv6_cidr=`get_ipv6_cidr`
  if [ $? != 0 ] || [ $ipv6_disabled != 0 ]; then
    red "IPv6 is not available, falling back to IPv4 only"
    network_interface="0.0.0.0"
  elif [ "$ipv6_cidr" == "" ]; then
    red "IPv6 is enabled on this machine,"
    red "but not a single public IPv6 address can be found."
    red "Falling back to IPv4 only."
    network_interface="0.0.0.0"
  else
    green "Enabling IPv6 support in Docker containers..."
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

    docker network inspect caddy >/dev/null 2>&1
    caddy_network_exists=`[ $? == 0 ] && echo "true" || echo "false"`

    if [ "$caddy_network_exists" == "true" ]; then
      caddy_ipv6_enabled=`docker network inspect caddy | jq '.[0].EnableIPv6'`
      caddy_backends=`docker ps -qf "network=caddy"`

      if [ "$caddy_ipv6_enabled" == "false" ]; then
        for backend in $caddy_backends; do
          docker network disconnect -f caddy $backend
        done
        docker network rm caddy > /dev/null
      fi
    fi

    if [ "$caddy_network_exists" != "true" ] || [ "$caddy_ipv6_enabled" == "false" ]; then
      IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_cidr"
      ipv6_addr_split=`awk -F'::' '{for(i=1;i<=NF;i++){print $i}}'  <<< "$ipv6_cidr_addr"`
      IFS=$'\n' read ipv6_network_addr ipv6_trailing_addr <<< "$ipv6_addr_split"

      ipv6_network_addr_colon_occurrences=`tr -dc ':' <<<"$ipv6_network_addr" | wc -c`
      ipv6_network_prefix="$(( "$ipv6_network_addr_colon_occurrences" * 16 + 16 ))"

      # https://github.com/Jimdo/facter/blob/534ee7f7d9ff62c31a32664258af89c8e1f95c37/lib/facter/util/manufacturer.rb#L7
      if [ "`/usr/sbin/dmidecode 2>/dev/null | grep Droplet`" != "" ]; then 
        ipv6_network_prefix=124 # Digital ocean droplet
      else
        if [ "${ipv6_network_prefix}" -ge 112 ]; then
          if [ "${ipv6_cidr_subnet}" -lt 112 ]; then
            ipv6_network_prefix=$(( $ipv6_cidr_subnet + 16 )) #NOTE
          else
            ipv6_network_prefix=$ipv6_cidr_subnet
          fi
        else
          ipv6_network_prefix=$(( $ipv6_network_prefix + 16 )) #NOTE
        fi
      fi

      read -e -i "${ipv6_cidr_addr}/${ipv6_network_prefix}" -p "$(blue 'IPv6 subnet range for the caddy network: ')" ipv6_range

      # if [ "$ipv6_cidr_subnet" -gt 80 ]; then
      #   # red "It is said that the IPv6 subnet should at least have a size of /80 (Docker 17.09)"
      #   ipv6_caddy_block="$ipv6_cidr_addr/$ipv6_cidr_subnet"
      # else
      #   ipv6_caddy_block="$ipv6_cidr_addr/80"
      # fi

      echo "+ docker network create --ipv6 --subnet $ipv6_range caddy"
      docker network create --ipv6 --subnet "$ipv6_range" caddy > /dev/null
      echo "+ docker run --rm --network caddy curlimages/curl curl -s -6 -m 5 icanhazip.com"
    fi

    ipv6_addr_result=`docker run --rm --network caddy curlimages/curl curl -s -6 -m 5 icanhazip.com`
    if [ "$ipv6_addr_result" == "" ]; then
      red "+ docker run --rm --network caddy curlimages/curl curl -s -6 -m 5 icanhazip.com"
      red "+ failed"
      red "`printf '=%.0s' $(seq 1 $(tput cols))`"
      red "`docker network inspect caddy`"
      red "`printf '=%.0s' $(seq 1 $(tput cols))`"
      red "+ IP configurations:"
      red "`ip -6 addr | grep global | grep -v '\s::1' | grep -v '\sfe80' | grep -v '\sfd00'`"
      blue "+ systemctl restart docker"
      systemctl restart docker
      blue "+ docker run --rm --network caddy curlimages/curl curl -s -6 -m 5 icanhazip.com"
      ipv6_addr_result=`docker run --rm --network caddy curlimages/curl curl -s -6 -m 5 icanhazip.com`
      if [ "$ipv6_addr_result" == "" ]; then
        red "+ docker run --rm --network caddy curlimages/curl curl -s -6 -m 5 icanhazip.com"
        red "+ failed"
        return 1
      fi
    fi
    caddy_ipv6_cidr="`docker network inspect caddy | jq -c '(.[0].IPAM.Config[] | select(.Subnet | contains(":")).Subnet)'`"
    # stripping double quotes
    caddy_ipv6_cidr="${caddy_ipv6_cidr%\"}"
    caddy_ipv6_cidr="${caddy_ipv6_cidr#\"}" 

    echo "IPv6 subnet assigned: $caddy_ipv6_cidr"
    echo "IPv6 address in containers: $ipv6_addr_result"

    if [ "$caddy_network_exists" == "true" ]; then
      if [ "$caddy_ipv6_enabled" == "false" ]; then
        for backend in $caddy_backends; do
          docker network connect caddy $backend
        done
      fi
    fi

    network_interface="::"
    ipv6_enabled="true"
  fi

  green "Generating a good random password..."
  TROJAN_PASSWORD="$(urandom 12)"

  green "Creating Trojan config..."
  mkdir -p ./trojan/config
	cat > ./trojan/config/config.json <<-EOF
{
    "run_type": "server",
    "local_addr": "$network_interface",
    "local_port": 443,
    "remote_addr": "caddy",
    "remote_port": 8080,
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

  cat > .profile-caddy-trojan.env <<EOF
DOMAIN_NAME=$DOMAIN_NAME
EOF

  green "Spinning up the reverse proxy..."
  set +e
  [ "`docker network inspect caddy >/dev/null 2>&1; echo $?`" != 0 ] \
  && docker network create caddy
  
  compose_up "profile-caddy-trojan"

  green "Starting docker services..."

# --- Config

  read -e -i "${CONFIG_PROFILE_NAME:-$DOMAIN_NAME}" -p "$(blue 'Enter the profile name: ')" CONFIG_PROFILE_NAME
  set +e
  POSSIBLE_DUE_TIMESTAMP="${CONFIG_DUE_TIMESTAMP:+@$CONFIG_DUE_TIMESTAMP}"
  read -e -i "$(date "+%m/%d/%Y" -d "${POSSIBLE_DUE_TIMESTAMP:-3 months}")" -p "$(blue 'Any determined due date? [%m/%d/%Y] ')" DUE_DATE 
  # Test if input is valid 
  date -d "${DUE_DATE:-"No input is given."}" "+%m/%d/%Y" >/dev/null
  if [ $? != 0 ]; then
    DUE_DATE=$(date "+%m/%d/%Y" -d "2 years")
    red "Due date has been set to dummy date $DUE_DATE"
  fi

  CONFIG_DUE_TIMESTAMP=$(date "+%s" -d "${DUE_DATE}")
  
  read -e -i "${DOH_PATH-/$(urandom_lc 4)}" -p "$(blue 'Enter the DoH URI path (Leave empty to disable): ')" DOH_PATH 
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
  - name: "$CONFIG_PROFILE_NAME"
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
      - "$CONFIG_PROFILE_NAME"
  - name: Quick UDP Internet Connections
    type: select
    proxies:
      - REJECT
      - Proxy
  - name: Microsoft Network Connectivity Status Indicator
    type: select
    proxies:
      - "$CONFIG_PROFILE_NAME"
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
  $DOMAIN_NAME: $local_addr
  # dns.google: 8.8.8.8
  # dns-unfiltered.adguard.com: 94.140.14.140
  # sandbox.opendns.com: 208.67.222.2
  # dns10.quad9.net: 9.9.9.10
  # security-filter-dns.cleanbrowsing.org: 185.228.168.9

EOF

  CONFIG_USERNAME=clash
  CONFIG_FILENAME="$CONFIG_PROFILE_NAME $local_addr"
  CONFIG_PASSWORD="${CONFIG_PASSWORD:-$(urandom 8)}"
  CONFIG_PASSWORD_BCRYPTED=$(docker run --rm caddy/caddy:2.4.0-alpine caddy hash-password -algorithm "bcrypt" -plaintext "$CONFIG_PASSWORD")

  cat > .env <<EOF
CONFIG_PASSWORD="$CONFIG_PASSWORD"
EOF

  cat > .profile-trojan-config.env <<EOF
CONFIG_USERNAME="$CONFIG_USERNAME"
CONFIG_PROFILE_NAME="$CONFIG_PROFILE_NAME"
CONFIG_FILENAME="$CONFIG_FILENAME"
CONFIG_DUE_TIMESTAMP="$CONFIG_DUE_TIMESTAMP"
CONFIG_PASSWORD_BCRYPTED="$CONFIG_PASSWORD_BCRYPTED"
EOF

  compose_up "profile-trojan-config"

#--- DoH

  cat > .profile-doh.env <<EOF
DOH_PATH="$DOH_PATH"
EOF

  if [ "$DOH_PATH" != "" ]; then 
    cat >>./caddy/config/clash.yml<<EOF
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
    compose_up "profile-doh"
  fi

#--- Decoys

  read -e -i "y" -p "$(blue 'Set up a decoy site? (Y/n) ')" decoy
  [ -z "${decoy}" ] && decoy="y"

  if [[ $decoy == [Yy] ]]; then
    read -e -i "1" -p "$(blue '1) Goscrape website copier 2) Archivebox') " choice

    case $choice in
      1) # Goscrape
        read -e -i "${GOSCRAPE_HOST:-"nic.eu.org"}" -p "$(blue 'Web host to be cloned: ')" GOSCRAPE_HOST
        [ -z "${GOSCRAPE_HOST}" ] && echo "An input is required" && exit 1
        read -e -i "${GOSCRAPE_ARGS:-"--depth 3 --imagequality 4"}" -p "$(blue 'Arguments for Goscrape: ')" GOSCRAPE_ARGS
       ;;
      2) # Archivebox
        read -e -i "${ARCHIVEBOX_SCHEDULE_ENABLE:-n}" -p "$(blue 'Any URL for scheduled regular imports? ')" yn
        [ -z "${yn}" ] && yn="n"
        if [[ $yn == [Nn] ]]; then
          ARCHIVEBOX_SCHEDULE_ENABLE="n"
          ARCHIVEBOX_SCHEDULE_PRECEDING_CMD="sleep infinity; /bin/false"
        else
          ARCHIVEBOX_SCHEDULE_ENABLE="$yn"
          ARCHIVEBOX_SCHEDULE_PRECEDING_CMD=""
          ARCHIVEBOX_SCHEDULE_TARGET="$yn"
          read -e -i "${ARCHIVEBOX_SCHEDULE_ARGS:-"--every=month --depth=0"}" -p "$(blue 'Schedule configuration parameters: ')" ARCHIVEBOX_SCHEDULE_ARGS
        fi
      ;;
      *) echo "Unrecognized selection: $choice" return 1 ;;
    esac

      cat > .profile-decoys.env <<EOF
GOSCRAPE_HOST="$GOSCRAPE_HOST"
GOSCRAPE_ARGS="$GOSCRAPE_ARGS"
ARCHIVEBOX_SCHEDULE_ENABLE="$ARCHIVEBOX_SCHEDULE_ENABLE"
ARCHIVEBOX_SCHEDULE_PRECEDING_CMD="$ARCHIVEBOX_SCHEDULE_PRECEDING_CMD"
ARCHIVEBOX_SCHEDULE_TARGET="$ARCHIVEBOX_SCHEDULE_TARGET"
ARCHIVEBOX_SCHEDULE_ARGS="$ARCHIVEBOX_SCHEDULE_ARGS"
EOF
    case $choice in
      1) # Goscrape
        compose_up "profile-decoys" "--profile decoy-goscrape"
       ;;
      2) # Archivebox
        compose_cmd "profile-decoys" "--profile decoy-archivebox run" "archivebox init --setup"
        compose_up "profile-decoys" "--profile decoy-archivebox"
      ;;
      *) echo "Unrecognized selection: $choice" return 1 ;;
    esac
  fi

  green "======================="
  blue "USER: $CONFIG_USERNAME"
  blue "PASSWORD: ${CONFIG_PASSWORD}"
  blue "TROJAN PASSWORD: ${TROJAN_PASSWORD}"
  blue "Config files are available at https://$CONFIG_USERNAME:${CONFIG_PASSWORD}@${DOMAIN_NAME}/.config/clash.yml"
  green "======================="

  check_env
  all_envfiles="`ls_all_envfiles`"
  chmod 0700 $all_envfiles
  echo "$(stat_files $all_envfiles)" > .profiles.env.stat
  chmod 0744 .profiles.env.stat
}

function consolidate () {
  ./srv-clash-consolidation.sh "$@"
}

function add-ipv4-preferred () {
  ./srv-ipv4-fallback.sh "$@"
}

function schedule-ipv6-rotation () {
  ./srv-ipv6-rotation.sh "$@"
}

function down () {
  set +e
  caddy_backends=`docker ps -qf "network=caddy"`
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
INITIALIZE=YES

while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--consolidate|consolidate)
      CONSOLIDATE=YES
      shift # past argument
      ;;
    -i|--initialize|--install|initialize|install)
      INITIALIZE=YES # By default YES
      shift # past argument
      ;;
    -p|--port|--add-port|--fallback-port|--alternate-port)
      ALTERNATE_PORT="$2"
      shift # past argument
      shift # past value
#NOTE
#       http://localhost:3010 {
# 	reverse_proxy /graphql https://prom.ua {
# 		header_up Host {http.reverse_proxy.upstream.hostport}
# 	}
# }
      ;;
    --prefer-ipv4)
      PREFER_IPV4=YES
      shift # past argument
      ;;
    -u|--up|up)
      UP=YES
      shift # past argument
      ;;
    -d|--down|down)
      DOWN=YES
      shift # past argument
      ;;
    -I|--injections)
      CONSOLIDATION_INJECTIONS_SRC="$2"
      shift # past argument
      shift # past value
      ;;
    -P|--profiles|--config)
      CONSOLIDATION_PROFILES_SRC="$2"
      shift # past argument
      shift # past value
      ;;
    -W|--wranger|--wranger-config)
      CONSOLIDATION_WRANGLER_CONFIG="$2"
      shift # past argument
      shift # past value
      ;;
    -O|--output)
      CONSOLIDATION_PROFILES_OUTPUT="$2"
      shift # past argument
      shift # past value
      ;;
    update)
      UPDATE=YES
      ;;
    -h|--help)
      sed -n '/POSITIONAL_ARGS=\(\)/,$p' "$0"
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

if [ "$UPDATE" == YES ]; then
  git reset --hard HEAD
  git pull origin master
  chmod +x *.sh
fi

if [ "$UP" == YES ]; then
  up
fi


if [ "$CONSOLIDATE" == YES ]; then
  consolidate
fi
