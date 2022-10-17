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

  if [ "`docker network inspect caddy >/dev/null 2>&1; echo $?`" != 0 ]; then
    red "Unrecoverable error: can't find a pre-existing network named 'caddy'"
    red "If you are settng up a server dedicated to Trojan services,"
    red "run this script again with switch --up"
    red "Or create a lucaslorentz/caddy-docker-proxy network manually."
    return 1
  fi

  check_env

  all_envfiles="`ls_all_envfiles`"
  # https://stackoverflow.com/a/30969768
  set -o allexport
  for envfile in $all_envfiles; do source "$envfile"; done
  set +o allexport

  if [ "$CONSOLIDATION_PROFILES_SRC" == "" ] || ! [ -f  "$CONSOLIDATION_PROFILES_SRC" ]; then
    if ! [ -f profiles.js ]; then
      cat>profiles.js<<EOF
export default [

]
EOF
    fi
    nano profiles.js
    CONSOLIDATION_PROFILES_SRC=profiles.js
  fi

  if [ "$CONSOLIDATION_INJECTIONS_SRC" == "" ] || ! [ -f  "$CONSOLIDATION_INJECTIONS_SRC" ]; then
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
    CONSOLIDATION_INJECTIONS_SRC=injections.yml
  fi

  if [ "$CONSOLIDATION_WRANGLER_CONFIG" == "" ] || ! [ -f  "$CONSOLIDATION_WRANGLER_CONFIG" ]; then
    if [ -f wrangler.toml ]; then
      CONSOLIDATION_WRANGLER_CONFIG=wrangler.toml
    elif [ -f "$REPOSITORY/wrangler.toml" ]; then
      CONSOLIDATION_WRANGLER_CONFIG="$REPOSITORY/wrangler.toml"
    else
      # docker-compose -f "$COMPOSE_FILE" --env-file /dev/null run clash-profiles ./init-wrangler.sh
      chmod +x "./$REPOSITORY/init-wrangler.sh"
      "./$REPOSITORY/init-wrangler.sh"
      CONSOLIDATION_WRANGLER_CONFIG="./$REPOSITORY/wrangler.toml"
    fi
  fi

  CONSOLIDATION_ACCESS_USERNAME=${CONSOLIDATION_ACCESS_USERNAME:-$(urandom_lc 2)}
  CONSOLIDATION_ACCESS_PASSWORD=${CONSOLIDATION_ACCESS_PASSWORD:-$(urandom 6)}
  CONSOLIDATION_PASSWORD_BCRYPTED=$(docker run --rm caddy/caddy:2.4.0-alpine caddy hash-password -algorithm "bcrypt" -plaintext "$CONFIG_PASSWORD")

  cat > ".profile-clash-consolidation.env" <<EOF
CONSOLIDATION_PROFILES_OUTPUT=${CONSOLIDATION_PROFILES_OUTPUT:+$(readlink -f "$CONSOLIDATION_PROFILES_OUTPUT")}
CONSOLIDATION_PROFILES_SRC=$(readlink -f "$CONSOLIDATION_PROFILES_SRC")
CONSOLIDATION_INJECTIONS_SRC=$(readlink -f "$CONSOLIDATION_INJECTIONS_SRC")
CONSOLIDATION_WRANGLER_CONFIG=${CONSOLIDATION_WRANGLER_CONFIG:+$(readlink -f "$CONSOLIDATION_WRANGLER_CONFIG")}
CONSOLIDATION_ACCESS_USERNAME="$CONSOLIDATION_ACCESS_USERNAME"
CONSOLIDATION_ACCESS_PASSWORD="$CONSOLIDATION_ACCESS_PASSWORD"
CONSOLIDATION_PASSWORD_BCRYPTED=$CONSOLIDATION_PASSWORD_BCRYPTED
EOF

  cat >> ".profile-clash-consolidation.env" <<EOF
CONSOLIDATION_CUTOFF_TIMESTAMP=${CONFIG_DUE_TIMESTAMP:-$CONSOLIDATION_CUTOFF_TIMESTAMP}
EOF

  compose_up "profile-clash-consolidation" "" "--build"

  if [ "$DOMAIN_NAME" == "" ]; then
    read -e -p "$(blue 'Enter the domain name: ')" DOMAIN_NAME
  fi

  green "======================="
  blue "USERNAME: $CONSOLIDATION_ACCESS_USERNAME"
  blue "PASSWORD: ${CONSOLIDATION_ACCESS_PASSWORD}"
  blue "Config files are available at https://$CONSOLIDATION_ACCESS_USERNAME:${CONSOLIDATION_ACCESS_PASSWORD}@${DOMAIN_NAME}/.profiles?code=$(echo "TWFpbmxhbmQlMjBDaGluYQo=" | base64 -d)"
  green "======================="

  compose_cmd "profile-clash-consolidation" "exec -it clash-profiles" "wrangler config"
  compose_cmd "profile-clash-consolidation" "exec -it clash-profiles" "wrangler publish"

  compose_cmd "profile-clash-consolidation" "logs --follow clash-profiles"
}

consolidate "$@"