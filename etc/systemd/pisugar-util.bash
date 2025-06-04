#!/bin/bash

# documentation
#   https://github.com/PiSugar/PiSugar/wiki/PiSugar-Power-Manager-(Software)#installation
#
# make sure to update /etc/default/pisugar-server with the right pisugar model before enabling this
#
# server config in /etc/pisugar-server/config.json

# https://stackoverflow.com/questions/1715137/what-is-the-best-way-to-ensure-only-one-instance-of-a-bash-script-is-running
LOCKFILE="/var/lock/`basename $0`.pid"
LOCKFD=99

if [ -z "$FORCE" ]; then
  FORCE=false
fi
if [ -z "$SHUTDOWN_TIMER_SECONDS" ]; then
  SHUTDOWN_TIMER_SECONDS=300
fi
if [ -z "$SHUTDOWN_SSH_COMMAND" ]; then
  SHUTDOWN_SSH_COMMAND="shutdown -h +0"
fi
if [ -z "$DRY_RUN" ]; then
  DRY_RUN="false"
fi


curr_epoch_s() {
  date +%s
}


log_info() {
  printf "[$(curr_epoch_s)] \e[32m[INFO]\e[0m $@\n"
}


log_warn() {
  printf "[$(curr_epoch_s)] \e[33m[WARN]\e[0m $@\n"
}


log_error() {
  printf "[$(curr_epoch_s)] \e[31m[ERRO]\e[0m $@\n"
}


seconds_since() {
  start=$1
  now=$(curr_epoch_s)

  # standard sh integer arithmetics
  delta=$((now - start))
  echo "$delta"
}


# also added these to .envrc, too nice
get_pisugar_field() {
  echo "get $@" | nc -q 0 127.0.0.1 8423
}


get_pisugar_field_val() {
  get_pisugar_field $@ | cut -d':' -f2 | xargs
}


pisugar-info() {
  echo $(get_pisugar_field model)
  echo $(get_pisugar_field battery_power_plugged)
  echo $(get_pisugar_field battery_allow_charging)
  echo $(get_pisugar_field battery_charging)
  echo $(get_pisugar_field battery_charging_range) "(percentage)"
  echo $(get_pisugar_field battery)"%"
  echo $(get_pisugar_field battery_i) "Amps"
  echo $(get_pisugar_field battery_v) "Volts"
  echo $(get_pisugar_field safe_shutdown_level)"%"
  echo $(get_pisugar_field safe_shutdown_delay) "seconds"
  echo "Button Shell:"
  echo $(get_pisugar_field button_shell single)
  echo $(get_pisugar_field button_shell double)
  echo $(get_pisugar_field button_shell long)
}


list_shutdown() {
  # file list with servers like
  #   <pipeable conn command>
  # e.g.:
  #   ssh root@nas.lan
  #
  # you can (and should) be very careful with these kinds of lists!
  IFS=$'\n'
  for server_cmd in $(cat /etc/pisugar-server/pisugar-shutdown-commands); do
    log_info "${server_cmd}"
    if [ "$DRY_RUN" != "true" ]; then
      bash -c "${server_cmd}" || :
    fi
    log_info
  done
  unset IFS
}

check() {
  if [[ -f $LOCKFILE ]]; then
    if [[ "$FORCE" -eq "true" ]]; then
      log_warn "FORCE=true, IGNORING LOCK AND CONTINUING"
    else
      log_error "$LOCKFILE exists, exiting after 4s"
      sleep 4
      exit 1
    fi
  fi

  # bro does this even work
  flock -n -E 1 $LOCKFILE echo "$$" > $LOCKFILE
  log_info "Wrote lockfile $LOCKFILE"
  log_info "Starting timer - $SHUTDOWN_TIMER_SECONDS seconds before shutting down servers in /etc/pisuger-server/server-list ..."
  start_s=$(curr_epoch_s)

  log_info "polling for status while timer going..."
  while true; do
    batt_plug_status=$(get_pisugar_field_val battery_power_plugged)
    if [ "$batt_plug_status" = "true" ]; then
      log_warn "pihole battery_power_plugged = 'true'"
      log_warn "NOT shutting down!"
      rm $LOCKFILE # giving other files attempts to shutdown if something really is wrong
      exit 0
    fi

    sleep 1
    if [[ "$(seconds_since "$start_s")" -gt "$SHUTDOWN_TIMER_SECONDS" ]]; then
      log_info "TIMER UP"
      break
    fi
  done

  batt_plug_status=$(get_pisugar_field_val battery_power_plugged)
  log_info "battery plugged in: $batt_plug_status"
  log_info "SHUTTING DOWN ALL THE THINGS; IGNORING ERRORS"

  if [ "$DRY_RUN" != "true" ]; then
    log_info "DRY_RUN=true, only printing commands"
  fi

  list_shutdown

  log_info "Indefinitely polling on battery plug status until power comes back on..."
  log_info "...or I die"
  while true; do
    batt_plug_status=$(get_pisugar_field_val battery_power_plugged)
    # log_info "battery plugged in: $batt_plug_status"
    if [ "$batt_plug_status" = "true" ]; then
      log_warn "PLUGGED IN - running commands in /etc/pisugar-server/powerup-list!"

      # TODO: rpi4s do not support WoL :(
      IFS=$'\n'
      for server_cmd in $(cat /etc/pisugar-server/powerup-powerup-commands); do
        log_info "${server_cmd}"
        if [ "$DRY_RUN" != "true" ]; then
          bash -c "${server_cmd}" || :
        fi
        log_info
      done
      unset IFS

      rm $LOCKFILE
      exit 0
    fi
    sleep 4
  done
}


script_fpath=$(realpath "$BASH_SOURCE")
case $1 in
  check)
    check
    ;;
  shutdown)
    list_shutdown
    ;;
  poweronline)
    log_info "power back online (battery charging)"
    exit 0
    #etherwake 00:e0:4c:34:b5:1d
    ;;
  info)
    pisugar-info
    exit 0
    ;;
  help)
    cat <<- EOF
Usage:   script_path [command]
Example: DRY_RUN=true FORCE=true SHUTDOWN_TIMER_SECONDS=4 script_path shutdown

Commands:

shutdown              Uses /etc/pisugar-server/shutdown-list - plain file where
                      each line is an executable script.

check                 check pisugar battery. If it's not plugged in, start
                      a timer for SHUTDOWN_TIMER_SECONDS
                      (default: $SHUTDOWN_TIMER_SECONDS)
                      shutdown the system if the power never comes back
                      and the time is up.

                      when time is up, runs list_shutdown

                      Available env-var configurations:
                        - DRY_RUN=[true|false]    don't run shutdown cmds

                        - SHUTDOWN_TIMER_SECONDS  time to wait in seconds

                        - FORCE                   ignore any lockfiles

poweronline           NOT YET IMPLEMENTED

info                  Pull a variety of data from the pisugar-server

help                  Show this message.
EOF
    exit 0
    ;;
esac

$script_fpath help
