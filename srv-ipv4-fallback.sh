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

warn () {
  red "Unrecoverable error: can't find a pre-existing caddy network"
  red "If you are settng up a server dedicated to Trojan services,"
  red "run index.sh again with switch --up on AND choose to set up"
  red "an Archivebox decoy site or an IPv6 interface when prompted."
  red ""
  red "Or create a caddy dynamic reverse proxy network manually."
  red "Refer to lucaslorentz/caddy-docker-proxy and docker-proxy.yml"
  red "for details, if that's the case."
  return 1
}

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

POSITIONAL_ARGS=()

BUILD=
PORT=6443
ORIGINS=https://prom.ua

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--build|--rebuild|--force-rebuild)
      BUILD=YES
      shift # past argument
      ;;
    -p|--port)
      PORT="$2"
      shift # past argument
      shift # past argument
      ;;
    -o|--origins|--origin)
      ORIGINS="$2"
      shift # past argument
      shift # past argument
      ;;
    -h|--help)
      awk '/^POSITIONAL_ARGS=\(\)/{flag=1;next}/-h|--help)/{flag=0}flag' "$0"
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

# restore positional parameters
set -- "${POSITIONAL_ARGS[@]}"

docker network inspect caddy >/dev/null 2>&1
caddy_network_exists=`[ $? == 0 ] && echo "true" || echo "false"`

set -e
if [ "$caddy_network_exists" == "true" ]; then
  check_env

  all_envfiles="`ls_all_envfiles`"
  # https://stackoverflow.com/a/30969768
  set -o allexport
  for envfile in $all_envfiles; do source "$envfile"; done
  set +o allexport

  green "Creating Trojan config..."
  jq -s add ./trojan/config/config.json <(cat <<EOF
{
  "tcp": {
    "prefer_ipv4": true,
    "no_delay": true,
    "keep_alive": true,
    "fast_open": false,
    "fast_open_qlen": 20
  }
}
EOF
)  > "./trojan/config/config-v4-$PORT.json"

  green "Checking the validity of Clash config..."
  proxy_exists=$(docker run --rm -v "${PWD}":/workdir mikefarah/yq \
  'contains({"proxies": [{"name": "'"$CONFIG_PROFILE_NAME"'"}]})' ./caddy/config/clash.yml)
  if [ "$proxy_exists" != "true" ]; then
    red "\$PROFILE_NAME '$CONFIG_PROFILE_NAME' does not exist"
    red "Trying the first item in the proxies array instead"
    CONFIG_PROFILE_NAME=$(docker run --rm -v "${PWD}":/workdir mikefarah/yq \
  '.proxies[0].name' ./caddy/config/clash.yml)
    if [ "$CONFIG_PROFILE_NAME" == "" ]; then
      red "./caddy/config/clash.yml is malformed"
      cat ./caddy/config/clash.yml
      exit 1
    fi
  fi

  green "Appending new access credentials..."
  
  docker run -i --rm -v "${PWD}":/workdir mikefarah/yq \
  'del(
      .proxy-groups[] | select(.name == "Proxy") | 
      .proxies[] | select(.name == "'"$CONFIG_PROFILE_NAME"' IPv4 '"$PORT"'")
      ) |
    del(.proxies[] | select(.name == "'"$CONFIG_PROFILE_NAME"' IPv4 '"$PORT"'")) |
    .proxies = .proxies + ( 
      .proxies[] | select(.name == "'"$CONFIG_PROFILE_NAME"'") | {
        "name": .name + " IPv4 '"$PORT"'",
        "type": .type,
        "server": .server,
        "port": '"$PORT"',
        "password": .password,
        "udp": .udp,
        "alpn": .alpn
      }
    ) |
    (
      (.proxy-groups[] | select(.name == "Proxy"))
      .proxies += "'"$CONFIG_PROFILE_NAME"' IPv4 '"$PORT"'" 
    )
  ' ./caddy/config/clash.yml > "./caddy/config/clash-v4-$PORT.yml"
  
  mv ./caddy/config/clash.yml ./caddy/config/clash-v6-before-"$PORT".yml
  mv "./caddy/config/clash-v4-$PORT.yml" ./caddy/config/clash.yml

  cat>"./profile-trojan-ipv4-$PORT.yml"<<EOF
version: '3.9'
services:
  trojan:
    image: trojangfw/trojan:latest
    ports:
      - "$PORT:443"
    volumes:
      - ./trojan/config:/config
      - ./ssl:/ssl
    working_dir: /config
    labels:
      - caddy=http://:8080
      - caddy.@port-$PORT.expression={http.request.port} == $PORT
      - caddy.@port-$PORT.path=/*
      - caddy.reverse_proxy=@port-$PORT $ORIGINS
      - caddy.reverse_proxy.header_up=Host {http.reverse_proxy.upstream.hostport}
      - caddy.reverse_proxy.method=GET
      - caddy.reverse_proxy.transport=http
      - caddy.reverse_proxy.transport.dial_timeout=3s
      - caddy.reverse_proxy.transport.response_header_timeout=1s
      - caddy.reverse_proxy.transport.keepalive_idle_conns=10
      - caddy.reverse_proxy.transport.max_conns_per_host=20
      - caddy.reverse_proxy.transport.write_timeout=5s
    networks:
      - caddy
    command: [ "trojan", "config-v4-$PORT.json" ]
    logging:
      options:
        max-size: "10m"
        max-file: "3"
    restart: unless-stopped
networks:
  caddy:
    external: true
EOF
  # additional_options="$( [ "$BUILD" == "YES" ] && echo "--build" || /bin/true )"
  if [ "$BUILD" == "YES" ]; then
    docker-compose -p "trojan-caddy-ipv4-$PORT" -f "./profile-trojan-ipv4-$PORT.yml" --env-file /dev/null down
  fi
  docker-compose -p "trojan-caddy-ipv4-$PORT" -f "./profile-trojan-ipv4-$PORT.yml" --env-file /dev/null up -d
  if [ $? != 0 ]; then
    docker-compose -p "trojan-caddy-ipv4-$PORT" -f "./profile-trojan-ipv4-$PORT.yml" --env-file /dev/null down
    docker-compose -p "trojan-caddy-ipv4-$PORT" -f "./profile-trojan-ipv4-$PORT.yml" --env-file /dev/null up -d
  fi
else
  warn
  exit $?
fi