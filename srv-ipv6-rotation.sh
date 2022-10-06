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

if [[ -f /etc/redhat-release ]]; then
  PKGMANAGER="yum"
elif cat /etc/issue | grep -Eqi "debian"; then
  PKGMANAGER="apt-get"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
  PKGMANAGER="apt-get"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
  PKGMANAGER="yum"
elif cat /proc/version | grep -Eqi "debian"; then
  PKGMANAGER="apt-get"
elif cat /proc/version | grep -Eqi "ubuntu"; then
  PKGMANAGER="apt-get"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
  PKGMANAGER="yum"
fi

POSITIONAL_ARGS=()

RM=
ADD=
SHOW=

while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--rm|--del|-d|del|rm|--rm-prev-only)
      RM=YES
      shift # past argument
      ;;
    -a|--add|add|--add-only)
      ADD=YES
      shift # past argument
      ;;
    -s|--show|show)
      SHOW=YES
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

get_ipv6_cidr () {
  ip -6 addr | awk '/inet6/{print $2}' | grep -v ^::1 | grep -v ^fe80 | grep -v ^fd00 | awk -F'/' '
    NR==1 || $2<max_block_size {max_block_size=$2; line=$1"/"$2}
    END {print line}
  '
}

show_ipv6_settings () {
  ip -6 addr | grep global | grep -v '\s::1' | grep -v '\sfe80' | grep -v '\sfd00'
}

if [ "$SHOW" == "YES" ]; then
  show_ipv6_settings
  exit $?
fi

random_ipv6_address_from () {
  ipv6_cidr_addr=$1
  ipv6_cidr_subnet=$2
  is_recursive=$3

  if [ "$(which python3)" != "" ]; then
    "$(which python3)" -c "
import random
import ipaddress
ipv6_addr_exploded = ipaddress.ip_address('$ipv6_cidr_addr').exploded
block_size = $ipv6_cidr_subnet
mask = '1' * block_size + '0' * (128 - block_size)
binary_ipv6 = bin(int(ipv6_addr_exploded.replace(':', ''), 16))[2:].zfill(128)
generated_bin=''.join(list(map(lambda x, y: y if x == '1' else '0', list(binary_ipv6), list(mask))))[0:block_size] + bin(random.randint(0,  2 ** (128 - block_size) - 1))[2:].zfill(128 - block_size)
generated_hex='{:0{}x}'.format(int(generated_bin, 2), len(generated_bin) // 4)
print(':'.join(generated_hex[i:i+4] for i in range(0, len(generated_hex), 4)))
"
  else
    if [ "$is_recursive" == "true" ]; then
      return 1
    fi
    "$PKGMANAGER" install -y python3
    random_ipv6_address_from $1 $2 true
    return $?

    ipv6_addr_split=`awk -F'::' '{for(i=1;i<=NF;i++){print $i}}'  <<< "$ipv6_cidr_addr"`
    IFS=$'\n' read ipv6_network_addr ipv6_trailing_addr <<< "$ipv6_addr_split"
    ipv6_addr_exploded="$ipv6_network_addr:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
  fi

  # ipv6_network_hextet_num=$(( "$ipv6_cidr_subnet" / 16 ))
  # readarray -d ":"  ipv6_hextets <<< "$ipv6_addr_exploded"
  # ipv6_hextets=("${ipv6_hextets[@]:0:$ipv6_network_hextet_num}")
  # ipv6_network_addr=$(IFS= ; echo "${ipv6_hextets[*]}" | sed -r 's/:+$//')
  # for i in `seq 1 $(( 8 - $ipv6_network_hextet_num ))`; do      
  #   ipv6_network_addr="$ipv6_network_addr:$(printf "%.4x" $(shuf -i 2000-65000 -n 1))"  
  # done

  # echo "$ipv6_network_addr"
}

ipv6calc_anonymize () {
  if ! ipv6calc -v; then
    "$PKGMANAGER" install -y ipv6calc
  fi

  ipv6calc --in ipv6addr --out ipv6addr  --action anonymize $1/$2
}

envfile="`basename "$0"`.env"

set +e
set -o allexport
source "$envfile"
set +o allexport

set -e
if [ "$ipv6_range" == "" ]; then
  set +e
  ipv6_cidr=`get_ipv6_cidr`
  IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_cidr"
  ipv6_addr_split=`awk -F'::' '{for(i=1;i<=NF;i++){print $i}}'  <<< "$ipv6_cidr_addr"`
  IFS=$'\n' read ipv6_network_addr ipv6_trailing_addr <<< "$ipv6_addr_split"
  if [ "$ipv6_trailing_addr" != "" ]; then
    show_ipv6_settings
  fi
  
  ipv6_network_addr_colon_occurrences=`tr -dc ':' <<<"$ipv6_network_addr" | wc -c`
  ipv6_network_prefix="$(( "$ipv6_network_addr_colon_occurrences" * 16 + 16 ))"
  
  # https://github.com/Jimdo/facter/blob/534ee7f7d9ff62c31a32664258af89c8e1f95c37/lib/facter/util/manufacturer.rb#L7
  if [ "`/usr/sbin/dmidecode 2>/dev/null | grep Droplet`" != "" ]; then 
    ipv6_network_prefix=124 # Digital ocean droplet
  fi

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

if [ "$RM" == "YES" ]; then
  echo "+ ip addr del $ipv6_network_previous_cidr dev $ipv6_dev"
  ip addr del "$ipv6_network_previous_cidr" dev "$ipv6_dev"
  exit $?
fi

IFS=/ read ipv6_cidr_addr ipv6_cidr_subnet <<< "$ipv6_range"
ipv6_network_addr=`random_ipv6_address_from "$ipv6_cidr_addr" "$ipv6_cidr_subnet"`
ipv6_network_cidr="$ipv6_network_addr/$ipv6_cidr_subnet"

cat >"$envfile" <<EOF
ipv6_dev=${ipv6_dev:-eth0}
ipv6_range=$ipv6_range
ipv6_network_cidr=$( [ "$ADD" == "YES" ] && echo "$ipv6_network_previous_cidr" || echo "$ipv6_network_cidr" ) 
EOF
printf '=%.0s' $(seq 1 $(tput cols))
blue "$(cat "$envfile")"
green "$(show_ipv6_settings)"

set +e

if [ "$ADD" != "YES" ] && [ "$ipv6_network_previous_cidr" != "" ]; then
  echo "+ ip addr del $ipv6_network_previous_cidr dev $ipv6_dev"
  ip addr del "$ipv6_network_previous_cidr" dev "$ipv6_dev"
fi
echo "+ ip addr add $ipv6_network_cidr dev $ipv6_dev"
ip addr add "$ipv6_network_cidr" dev "$ipv6_dev"

set -e
blue "$(show_ipv6_settings)"

printf '=%.0s' $(seq 1 $(tput cols))

echo "+ sleep 3"
sleep 3
echo "+ curl -s -m 5 --interface $ipv6_network_addr -6 icanhazip.com"
curl -s -m 5 -6 --interface "$ipv6_network_addr" icanhazip.com
echo "+ curl -s -m 5 -6 icanhazip.com"
curl -s -m 5 -6 icanhazip.com
echo "+ curl -s -m 5 icanhazip.com"
curl -s -m 5 icanhazip.com

set +e
docker -v >/dev/null 2>&1
if [ $? == 0 ]; then 
  set -e
  for network in `docker network ls --format "{{.Name}}"`; do 
    if [ "$network" != "host" ] && [ "$network" != "none" ]; then 
      if [ "`docker network inspect \"$network\" | jq '.[0].EnableIPv6'`" == "true" ]; then  
        set +e
        network_ipv6_cidr="`docker network inspect "$network" | jq -c '(.[0].IPAM.Config[] | select(.Subnet | contains(":")).Subnet)'`"
        # stripping double quotes
        network_ipv6_cidr="${network_ipv6_cidr%\"}"
        network_ipv6_cidr="${network_ipv6_cidr#\"}"
        if [ "$network_ipv6_cidr" != "" ]; then
          set -e
          IFS=/ read network_ipv6_addr network_ipv6_cidr_prefix <<< "$network_ipv6_cidr"
          if [ "$network_ipv6_cidr_prefix" -le "$ipv6_cidr_subnet" ]; then
            filtered_addr="$(grep -v ::1 <<< "$network_ipv6_addr" | grep -v fe80 | grep -v fd00 | echo)"
            if [ "$filtered_addr" != "" ]; then
              red "For some reason, IPv6 enabled docker bridge network won't work"
              red "with IPv6 subnets that have a size equal to or less than"
              red "the size of allocated host device $ipv6_dev's subnet when"
              red "multiple interfaces are presented" 
              red "- The subnet of network $network: $network_ipv6_cidr"
              red "- IP configurations:"
              red "`show_ipv6_settings`"
              red "- Type ip addr del $ipv6_network_cidr dev $ipv6_dev"
              red "  or $0 --rm"
              red "  for manual IPv6 interface removal, if following commands failed"
            fi
          fi
        fi
        set -e
        echo "+ docker run --rm --network $network curlimages/curl curl -s -m 5 icanhazip.com"
        docker run --rm --network "$network" curlimages/curl curl -s -m 5 icanhazip.com 
        echo "+ docker run --rm --network $network curlimages/curl curl -6 -s -m 5 icanhazip.com"
        docker run --rm --network "$network" curlimages/curl curl -6 -s -m 5 icanhazip.com 
      fi
    fi 
  done
fi