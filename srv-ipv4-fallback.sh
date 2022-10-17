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

POSITIONAL_ARGS=()

BUILD=

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--build|--rebuild|--force-rebuild)
      BUILD=YES
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
  caddy_ipv6_enabled=`docker network inspect caddy | jq '.[0].EnableIPv6'`
  if [ "$caddy_ipv6_enabled" != "true" ]; then
    warn
    exit $?
  fi

  set -o allexport
  source .env
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
)  > ./trojan/config/config-v4.json

  green "Checking the validity of Clash config..."
  proxy_exists=$(docker run --rm -v "${PWD}":/workdir mikefarah/yq \
  'contains({"proxies": [{"name": "'"$PROFILE_NAME"'"}]})' ./caddy/config/clash.yml)
  if [ "$proxy_exists" != "true" ]; then
    red "\$PROFILE_NAME '$PROFILE_NAME' does not exist"
    red "Trying the first item in the proxies array instead"
    PROFILE_NAME=$(docker run --rm -v "${PWD}":/workdir mikefarah/yq \
  '.proxies[0].name' ./caddy/config/clash.yml)
    if [ "$PROFILE_NAME" == "" ]; then
      red "./caddy/config/clash.yml is malformed"
      cat ./caddy/config/clash.yml
      exit 1
    fi
  fi

  green "Appending new access credentials..."
  
  docker run -i --rm -v "${PWD}":/workdir mikefarah/yq \
  'del(
      .proxy-groups[] | select(.name == "Proxy") | 
      .proxies[] | select(.name == "'"$PROFILE_NAME"' IPv4")
      ) |
    del(.proxies[] | select(.name == "'"$PROFILE_NAME"' IPv4")) |
    .proxies = .proxies + ( 
      .proxies[] | select(.name == "'"$PROFILE_NAME"'") | {
        "name": .name + " IPv4",
        "type": .type,
        "server": .server,
        "port": 56790,
        "password": .password,
        "udp": .udp,
        "alpn": .alpn
      }
    ) |
    (
      (.proxy-groups[] | select(.name == "Proxy"))
      .proxies += "'"$PROFILE_NAME"' IPv4" 
    )
  ' ./caddy/config/clash.yml > ./caddy/config/clash-v4.yml
  
  mv ./caddy/config/clash.yml ./caddy/config/clash-v6.yml
  mv ./caddy/config/clash-v4.yml ./caddy/config/clash.yml

  cat>./profile-trojan-ipv4.yml<<EOF
version: '3.9'
services:
  trojan:
    image: trojangfw/trojan:latest
    ports:
      - "56790:443"
    volumes:
      - ./trojan/config:/config
      - ./ssl:/ssl
    working_dir: /config
    labels:
      - caddy=http://:8080
      - caddy.@intruders.expression={http.request.port} == 56790
      - caddy.redir=@intruders https://{http.request.host} permanent
    networks:
      - caddy
    command: [ "trojan", "config-v4.json" ]
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
    docker-compose -p "trojan-caddy-ipv4" -f ./profile-trojan-ipv4.yml --env-file /dev/null down
  fi
  docker-compose -p "trojan-caddy-ipv4" -f ./profile-trojan-ipv4.yml --env-file /dev/null up -d
  if [ $? != 0 ]; then
    docker-compose -p "trojan-caddy-ipv4" -f ./profile-trojan-ipv4.yml --env-file /dev/null down
    docker-compose -p "trojan-caddy-ipv4" -f ./profile-trojan-ipv4.yml --env-file /dev/null up -d
  fi

  green "======================="
  blue "USER: $USERNAME"
  blue "PASSWORD: ${PASSWORD}"
  blue "Config files are available at https://$USERNAME:${PASSWORD}@${DOMAIN_NAME}/.config/clash.yml"
  green "======================="

  # reload
  docker exec $(docker ps | grep trojan[-_]caddy[-_]ipv4[-_]trojan | awk '{ print $1 }' | head -n 1) \
    kill -s SIGHUP 1
else
  warn
  exit $?
fi