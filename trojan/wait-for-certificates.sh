#!/bin/sh

set -e

until [ `ls -A "/ssl/$DOMAIN_NAME" | wc -w` -ne 0 ]
do
  >&2 echo "[$(date)]: Folder /ssl/$DOMAIN_NAME is still empty..."
  sleep 1
done

exec $@