```bash
if [ -d "Trojan-Caddy-DoH" ]; then
cd Trojan-Caddy-DoH
git fetch && git reset --hard origin/master && chmod +x index.sh
else
git clone --depth 1 https://github.com/edfus/Trojan-Caddy-DoH
cd Trojan-Caddy-DoH
chmod +x index.sh
fi

./index.sh -h
# ./index.sh up
# ./index.sh up -c
# ./index.sh down && ./index.sh up
# ⬆️ when container aliases got messed up
```

Tested on Ubuntu 20.04 LTS as root