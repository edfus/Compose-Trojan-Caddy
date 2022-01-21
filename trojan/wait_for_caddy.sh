#!/bin/sh

set -e

until [ `ls -A /ssl | wc -w` -eq 1 ]
do
  >&2 echo "[$(date)]: Folder /ssl is still empty..."
  sleep 1
done

exec $@