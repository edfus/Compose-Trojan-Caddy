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