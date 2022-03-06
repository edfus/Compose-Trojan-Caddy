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

show_ipv6_settings () {
  ip -6 addr | grep global | grep -v ::1 | grep -v fe80 | grep -v fd00
}

envfile="`basename "$0"`.env"

set +e
set -o allexport
source "$envfile"
set +o allexport

set -e
if [ "$ipv6_range" == "" ]; then
  set +e
  ipv6_cidr=`ip -6 addr | awk '/inet6/{print $2}' | grep -v ^::1 | grep -v ^fe80 | head -n 1`
  IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_cidr"
  ipv6_addr_split=`awk -F'::' '{for(i=1;i<=NF;i++){print $i}}'  <<< "$ipv6_cidr_addr"`
  IFS=$'\n' read ipv6_network_addr ipv6_trailing_addr <<< "$ipv6_addr_split"
  if [ "$ipv6_trailing_addr" != "" ]; then
    show_ipv6_settings
  fi
  
  ipv6_network_addr_colon_occurrences=`tr -dc ':' <<<"$ipv6_network_addr" | wc -c`
  ipv6_network_prefix="$(( "$ipv6_network_addr_colon_occurrences" * 16 + 16 ))"
  if [ "$ipv6_network_prefix" -gt 124 ]; then
    show_ipv6_settings
  fi
  set -e
  read -e -i "eth0" -p "$(blue 'Device: ')" ipv6_dev
  read -e -i "${ipv6_cidr_addr}/${ipv6_network_prefix}" -p "$(blue 'IPv6 subnet range: ')" ipv6_range
else
  if [ "$ipv6_range" == "" ]; then
    read -e -i "$ipv6_range" -p "$(blue 'IPv6 subnet range: ')" ipv6_range
  fi
  ipv6_dev=${ipv6_dev:-eth0}
  ipv6_network_previous_cidr="$ipv6_network_cidr"
fi

#TODO: use ipv6calc
IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_range"
if [ "$(which python3)" != "" ]; then
  ipv6_addr_exploded=`$(which python3) -c "import ipaddress
print(ipaddress.ip_address('$ipv6_cidr_addr').exploded)
"`
else
  ipv6_addr_split=`awk -F'::' '{for(i=1;i<=NF;i++){print $i}}'  <<< "$ipv6_cidr_addr"`
  IFS=$'\n' read ipv6_network_addr ipv6_trailing_addr <<< "$ipv6_addr_split"
  ipv6_addr_exploded="$ipv6_network_addr:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
fi

ipv6_network_hextet_num=$(( "$ipv6_cidr_subnet" / 16 ))
readarray -d ":"  ipv6_hextets <<< "$ipv6_addr_exploded"
ipv6_hextets=("${ipv6_hextets[@]:0:$ipv6_network_hextet_num}")
ipv6_network_addr=$(IFS= ; echo "${ipv6_hextets[*]}" | sed -r 's/:+$//')
for i in `seq 1 $(( 8 - $ipv6_network_hextet_num ))`; do      
  ipv6_network_addr="$ipv6_network_addr:$(printf "%.4x" $(shuf -i 2000-65000 -n 1))"  
done
ipv6_network_cidr="$ipv6_network_addr/$ipv6_cidr_subnet"
cat >"$envfile" <<EOF
ipv6_dev=${ipv6_dev:-eth0}
ipv6_range=$ipv6_range
ipv6_network_cidr=$ipv6_network_cidr
EOF
printf '=%.0s' $(seq 1 $(tput cols))
blue "$(cat "$envfile")"
green "$(show_ipv6_settings)"

set +e

if [ "$ipv6_network_previous_cidr" != "" ]; then
  echo "+ ip addr del $ipv6_network_previous_cidr dev $ipv6_dev"
  ip addr del "$ipv6_network_previous_cidr" dev $ipv6_dev
fi
echo "+ ip addr add $ipv6_network_cidr dev $ipv6_dev"
ip addr add "$ipv6_network_cidr" dev $ipv6_dev

set -e
blue "$(show_ipv6_settings)"

printf '=%.0s' $(seq 1 $(tput cols))

echo "+ sleep 5"
sleep 5
echo "+ curl -s -m 5 --interface $ipv6_network_addr -6 icanhazip.com"
curl -s -m 5 -6 --interface "$ipv6_network_addr" icanhazip.com
echo "+ curl -s -m 5 -6 icanhazip.com"
curl -s -m 5 -6 icanhazip.com
echo "+ curl -s -m 5 icanhazip.com"
curl -s -m 5 icanhazip.com
