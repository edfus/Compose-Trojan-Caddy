#!/bin/sh

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" $2 $3
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

# Replace these with the appropriate values for your setup
service_profile_1=${1:-profile-caddy-trojan}
service_name_1=${2:-trojan}
certificates_path="$(dirname "$(realpath "$0")")/${3:-ssl}"

# Install inotify-tools if not already installed
if ! command -v inotifywait >/dev/null; then
  echo "Installing inotify-tools..."
  $PKGMANAGER -y install inotify-tools
fi

# compose_cmd "$service_profile_1" restart "$service_name_1"

# Monitor the certificate files for changes
while inotifywait -r -e close_write "$certificates_path"; do
  # Restart the containers
  echo "Restarting $service_profile_1 and $service_name_1..."
  compose_cmd "$service_profile_1" restart "$service_name_1"
done


