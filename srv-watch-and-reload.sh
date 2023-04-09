#!/bin/sh

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" $2 $3
}

# Replace these with the appropriate values for your setup
service_profile_1=profile-caddy-trojan
service_name_1=trojan
# service_profile_2=profile-caddy-trojan
# service_name_2=trojan
certificates_path=./ssl

# Install inotify-tools if not already installed
if ! command -v inotifywait >/dev/null; then
  echo "Installing inotify-tools..."
  sudo apt-get update && sudo apt-get install -y inotify-tools
fi

compose_cmd "$service_profile_1" restart "$service_name_1"

cron_job="0 0 1 * * docker-compose -p "$service_profile_1" -f "$service_profile_1.yml" --env-file ".$service_profile_1.env" restart $service_name_1"

# Add the cron job to the current user's crontab
(crontab -l 2>/dev/null; echo "$cron_job") | crontab -

# Monitor the certificate files for changes
while inotifywait -r -e close_write "$certificates_path"; do
  # Restart the containers
  echo "Restarting $service_profile_1 and $service_name_1..."
  compose_cmd "$service_profile_1" restart "$service_name_1"
done


