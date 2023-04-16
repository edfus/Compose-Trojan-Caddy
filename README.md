One liner kickstart: `export REPO=Trojan-Caddy-DoH && git clone --depth 1 "https://github.com/edfus/$REPO" && cd "$REPO" && chmod +x index.sh && ./index.sh -h`
One liner deploying: `sudo ./index.sh down update up consolidate`
One liner debugging: `. helpers; debug_consolidate`

Supports IPv6 address rotation for outgoing requests.
Supports Dockerized Cloudflare Warp forwarding for both IPv4 and IPv6 on demand.
All choices are memorized, with crontab jobs properly configured and SSL Certificate renewal watched in background.

Can automatically listen on as many ports as feasible with camouflage:

```bash
  if [[ $fallback == [Yy] ]]; then
     ./srv-crontab-reload.sh --clear-compose-cmd

      # ipv6
      PORT_NUMBER="$(shuf -i 2000-65000 -n 1)"
      ./srv-ipv4-fallback.sh --port "${PORT_NUMBER}"
      background_spawn ./srv-watch-and-reload.sh "profile-trojan-v6-$PORT_NUMBER" "trojan"
      ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v6-$PORT_NUMBER" restart "trojan"

      PORT_NUMBER="$(shuf -i 2000-65000 -n 1)"
      ./srv-ipv4-fallback.sh --port "${PORT_NUMBER}"
      background_spawn ./srv-watch-and-reload.sh "profile-trojan-v6-$PORT_NUMBER" "trojan"
      ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v6-$PORT_NUMBER" restart "trojan"

      # ipv4
      PORT_NUMBER="$(shuf -i 2000-65000 -n 1)"
      ./srv-ipv4-fallback.sh --port "${PORT_NUMBER}" --ipv4
      background_spawn ./srv-watch-and-reload.sh "profile-trojan-v4-$PORT_NUMBER" "trojan"
      ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v4-$PORT_NUMBER" restart "trojan"

      PORT_NUMBER="$(shuf -i 2000-65000 -n 1)"
      ./srv-ipv4-fallback.sh --port "${PORT_NUMBER}" --ipv4
      background_spawn ./srv-watch-and-reload.sh "profile-trojan-v4-$PORT_NUMBER" "trojan"
      ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-v4-$PORT_NUMBER" restart "trojan"
  
      # warp
      PORT_NUMBER="$(shuf -i 2000-65000 -n 1)"
      ./srv-ipv4-fallback.sh --port "${PORT_NUMBER}" --warp
      background_spawn ./srv-watch-and-reload.sh "profile-trojan-warp-v6-$PORT_NUMBER" "trojan"
      ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-warp-v6-$PORT_NUMBER" restart "trojan"

      
      PORT_NUMBER="$(shuf -i 2000-65000 -n 1)"
      ./srv-ipv4-fallback.sh --port "${PORT_NUMBER}" --warp --ipv4
      background_spawn ./srv-watch-and-reload.sh "profile-trojan-warp-v4-$PORT_NUMBER" "trojan"
      ./srv-crontab-reload.sh --add-compose-cmd "profile-trojan-warp-v4-$PORT_NUMBER" restart "trojan"
  fi

    read -e -i "n" -p "$(blue 'Set up crontab jobs? (Y/n) ')" crontab
  [ -z "${crontab}" ] && crontab="n"

  if [[ $crontab == [Yy] ]]; then
    ./srv-crontab-reload.sh --bind
    ./srv-crontab-reload.sh --insert "0 5 * * *" "./srv-ipv6-rotation.sh"
  fi

```

Tested on Ubuntu 20.04 LTS as root on multiple servers

https://github.com/moby/moby/issues/43296
https://github.com/trojan-gfw/trojan/issues/628
