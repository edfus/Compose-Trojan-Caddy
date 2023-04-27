#!/bin/bash

blue () {
    echo -e "\033[34m\033[01m$1\033[0m"
}
green () {
    echo -e "\033[32m\033[01m$1\033[0m"
}
red () {
    echo -e "\033[31m\033[01m$1\033[0m"
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

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file "$(test -f ".$1.env" && echo ".$1.env" || echo /dev/null)" $2 $3
}

background_spawn () {
  nohup $@ > ".nohup-$(basename "$1").log" 2>&1 & 
}

# List of safe service ports (excluding 21, 22, 25, 80, and 443)
SAFE_PORTS=(465 587 993 995 1433 1521 3306 3389 5432 6379 11211 27017 9200 9300 5601 27018 8080 8443 8888 9443 1080 1194 6000 6100 7000 7100 8000 8100 9000 9100)

# Function to check if a port is free
is_port_free() {
    local port=$1
    # Check if the port is in use, if not return 0 (free), else return 1 (in use)
    (echo >/dev/tcp/127.0.0.1/$port) &>/dev/null && return 1 || return 0
}

# Function to get a random safe port
get_random_safe_port() {
    index=$(($RANDOM % ${#SAFE_PORTS[@]}))
    echo ${SAFE_PORTS[$index]}
}

# Function to get a random available port
get_random_available_port() {
    while true; do
        random_safe_port=$(get_random_safe_port)
        is_port_free $random_safe_port
        if [[ $? -eq 0 ]]; then
            echo $random_safe_port
            break
        fi
    done
}

check_env
envfile=".`basename -s .sh "$0"`.env"

set +e
set -o allexport
test -f "$envfile" && source "$envfile"
set +o allexport

set +e
# ./srv-crontab-reload.sh --clear-compose-cmd

# ipv4
PORT_NUMBER="${$(get_random_available_port):-$(shuf -i 2000-65000 -n 1)}"
./srv-fallback.sh --port "${PORT_NUMBER}" --ipv4 --origins "https://helpcenter.taxcaddy.com https://batcaddy.com"
background_spawn ./srv-watch-and-reload.sh "profile-trojan-v4-$PORT_NUMBER" "trojan"
./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v4-$PORT_NUMBER" restart "trojan"

PORT_NUMBER="${$(get_random_available_port):-$(shuf -i 2000-65000 -n 1)}"
./srv-fallback.sh --port "${PORT_NUMBER}" --ipv4 --origins "https://www.papercut.com"
background_spawn ./srv-watch-and-reload.sh "profile-trojan-v4-$PORT_NUMBER" "trojan"
./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v4-$PORT_NUMBER" restart "trojan"

# warp
PORT_NUMBER="${$(get_random_available_port):-$(shuf -i 2000-65000 -n 1)}"
./srv-fallback.sh --port "${PORT_NUMBER}" --warp --ipv4 --origins "https://chopra.com"
background_spawn ./srv-watch-and-reload.sh "profile-trojan-warp-v4-$PORT_NUMBER" "trojan"
./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-warp-v4-$PORT_NUMBER" restart "trojan"

caddy_ipv6_enabled=`docker network inspect caddy | jq '.[0].EnableIPv6'`
if [ "$caddy_ipv6_enabled" == "true" ]; then
  # ipv6
  PORT_NUMBER="${$(get_random_available_port):-$(shuf -i 2000-65000 -n 1)}"
  ./srv-fallback.sh --port "${PORT_NUMBER}" --origins "https://www.ua-region.com.ua https://evo.company https://prom.ua"
  background_spawn ./srv-watch-and-reload.sh "profile-trojan-v6-$PORT_NUMBER" "trojan"
  ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v6-$PORT_NUMBER" restart "trojan"

  PORT_NUMBER="${$(get_random_available_port):-$(shuf -i 2000-65000 -n 1)}"
  ./srv-fallback.sh --port "${PORT_NUMBER}" --origins "https://fridgecablecaddy.com.au https://www.republicservices.com"
  background_spawn ./srv-watch-and-reload.sh "profile-trojan-v6-$PORT_NUMBER" "trojan"
  ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v6-$PORT_NUMBER" restart "trojan"

  # warp
  PORT_NUMBER="${$(get_random_available_port):-$(shuf -i 2000-65000 -n 1)}"
  ./srv-fallback.sh --port "${PORT_NUMBER}" --warp --origins "https://www.japanla.com"
  background_spawn ./srv-watch-and-reload.sh "profile-trojan-warp-v6-$PORT_NUMBER" "trojan"
  ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-warp-v6-$PORT_NUMBER" restart "trojan"
fi