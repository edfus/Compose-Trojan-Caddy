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

ls_all_envfiles () {
  LC_ALL=C ls .env .*.env
}

stat_files () {
  stat -c "%U:%G %a %n" $1
}

check_env () {
  if [ -f .profiles.env.stat ]; then
    echo "$(stat_files `ls_all_envfiles`)" > ".tmp.profiles.env.stat"
    green "Comparing status of all environment files..."
    cmp .profiles.env.stat ".tmp.profiles.env.stat"
    if [ $? != "0" ]; then
      green "====================="
      green "before: (.profiles.env.stat)"
      green "$(cat .profiles.env.stat)"
      green
      blue  "========V.S.=========="
      red "after: (.tmp.profiles.env.stat)"
      red "$(cat .tmp.profiles.env.stat)"
      red
      read -e -p "$(blue 'Press Enter to continue at your own risk.')" 
      mv .profiles.env.stat .profiles.env.stat.bak
      mv .tmp.profiles.env.stat .profiles.env.stat
      chmod 0744 .profiles.env.stat
    else 
      rm .tmp.profiles.env.stat
    fi
  fi
}

compose_cmd () {
  docker-compose -p "$1" -f "$1.yml" --env-file ".$1.env" $2 $3
}


POSITIONAL_ARGS=()

RELOAD=FALSE
ADD=FALSE
INSERT=FALSE
PERIOD="0 0 1 * *"
COMMAND="bash -c \"cd '$(dirname "$(realpath "$0")")' && $0 reload\""
JOB=FALSE
CLEAR=FALSE

while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--add|add|--add-only|--bind)
      ADD=TRUE
      RELOAD=FALSE
      shift # past argument
      ;;
    -i|--insert|insert)
      INSERT="TRUE"
      RELOAD=FALSE
      PERIOD="$2"
      COMMAND="bash -c \"cd '$(dirname "$(realpath "$0")")' && $3\""
      shift # past argument
      shift # past argument
      shift # past argument
      ;;
    -r|--reload|reload)
      RELOAD=TRUE
      shift # past argument
      ;;
    --clear-compose-cmd)
      CLEAR=TRUE
      shift # past argument
      ;;
    --add-compose-cmd)
      JOB=TRUE
      JOB_PROFILE_NAME="$2"
      JOB_CMD_ACTION="$3"
      JOB_SERVICE_NAME="$4"
      shift # past argument
      shift # past argument
      shift # past argument
      shift # past argument
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

check_env
envfile=".`basename -s .sh "$0"`.env"

set +e
set -o allexport
test -f "$envfile" && source "$envfile"
set +o allexport


set -e
if [ "$ADD" == "TRUE" ] || [ "$INSERT" == "TRUE" ]; then
  cron_job="${PERIOD} ${COMMAND}"

  # Add the cron job to the current user's crontab
  (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
  crontab -l
fi

set +e
if [ "$CLEAR" == "TRUE" ]; then
declare -a CRONTAB_RELOAD_JOBS=()
elif [[ ! "$(declare -p CRONTAB_RELOAD_JOBS)" =~ "declare -a" ]]; then
  echo "No array CRONTAB_RELOAD_JOBS found."
  declare -a CRONTAB_RELOAD_JOBS=()
fi

if [ "$JOB" == "TRUE" ]; then
  CRONTAB_RELOAD_JOBS+=("$JOB_PROFILE_NAME $JOB_CMD_ACTION $JOB_SERVICE_NAME")
fi

if [ "$RELOAD" == "TRUE" ]; then
  jobnum=${#CRONTAB_RELOAD_JOBS[@]}

  # use for loop to read all values and indexes
  for (( i=0; i<${jobnum}; i++ ));
  do
    compose_cmd ${CRONTAB_RELOAD_JOBS[$i]}  
  done
fi

  cat > "${envfile}" <<EOF
$(declare -p CRONTAB_RELOAD_JOBS)
EOF