```bash
REPO=Trojan-Caddy-DoH
if [ "$(basename "$PWD")" == "$REPO" ]; then
  git fetch && git reset --hard origin/master
elif [ -d "$REPO" ]; then
  cd "$REPO"
  git fetch && git reset --hard origin/master
else
  git clone --depth 1 "https://github.com/edfus/$REPO"
  cd "$REPO"
fi

chmod +x index.sh
./index.sh -h
# ./index.sh up
# ./index.sh up -c
# ./index.sh down && ./index.sh up
# ⬆️ when container aliases got messed up
```

Tested on Ubuntu 20.04 LTS as root

https://github.com/moby/moby/issues/43296
https://github.com/trojan-gfw/trojan/issues/628

IPv6 address rotation for outgoing requests:
```bash
chmod +x ipv6-rotation.sh
./ipv6-rotation.sh
# it has a dependency on envfile="`basename "$0"`.env"
```

Additional Trojan container with prefer_ipv4 on:
```bash
chmod +x ipv4-fallback.sh
./ipv4-fallback.sh
```