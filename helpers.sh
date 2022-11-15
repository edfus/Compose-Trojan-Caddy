#!/bin/sh

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" $2 $3 $4 $5 $6 $7 $8 $9
}

compose_exec () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" exec $2 sh -c "$3"
}

compose_up () {
  compose_cmd "$1" "$2" "up -d $3"
  if [ $? != 0 ]; then
    compose_cmd "$1" "$2" "down"
    compose_cmd "$1" "$2" "up -d $3"
  fi
}

pino_pretty () {
  docker run -i --rm gildas/pino
}

debug_consolidate () {
  compose_exec "profile-clash-consolidation" "clash-profiles" \
   "sed -i 's/info/debug/' logger.conf.js && kill -s SIGHUP 1"
  ID="$(compose_cmd "profile-clash-consolidation" "ps -q clash-profiles")"
  docker logs "$ID" -f --tail 100 | pino_pretty
}

reset_consolidate () {
  compose_exec "profile-clash-consolidation" "clash-profiles" \
   "sed -i 's/debug/info/' logger.conf.js && kill -s SIGHUP 1"
}

doh_domains () {
  ID="$(compose_cmd "profile-doh" "ps -q doh")"
  docker logs "${ID}" -f --tail 600 2>/dev/null | grep -v -E "HTTP/" | sed 's/[^"]*"\(.*\)\.[^."]*".*/\1/'
}

doh_errors () {
  ID="$(compose_cmd "profile-doh" "ps -q doh")"
  docker logs "${ID}" -f --tail 600 1>/dev/null
}

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

location="$(realpath "$SOURCE")"
folder="${DIR}"
list="$folder/doh_domains.list"
pid="$folder/nohup_doh_domains.pid"
nohup_doh_domains () {
set +e
test -f "${pid}" && kill "`cat ${pid}`" 2>/dev/null
tmpfile=$(mktemp /tmp/nohup_doh_domains.XXXXXX)
cat > "$tmpfile" <<EOF
#!/bin/bash
set -e
source "$location"
set +e
rm "$tmpfile"
set -e
doh_domains > "$list"
EOF
chmod +x "$tmpfile"
nohup "$tmpfile" & echo $! > "${pid}"
echo "Check $list for result"
}

tail_list () {
  tail -f -n +1 "${1:-"$list"}"
}

show_list () {
  cat "${1:-"$list"}"
}

select_trackers () {
  grep --line-buffered -x -v -E '[[:lower:].0-9-]*'
}

no_duplicates () {
  sort -u
}

to_lowercase () {
  tr "[:upper:]" "[:lower:]"
}

select_udp () {
  grep --line-buffered -x -E '[[:lower:].0-9-]*' \
  | grep --line-buffered -v -E 'cn|qq|tao|xyz|bili'
}