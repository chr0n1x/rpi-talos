#!/bin/bash -xe

# utility script to
# 1. fetch the etcd cluster status based on all kubectl nodes
# 2. defrag each node using talosctl
#
# writes results into /tmp/etcd-defrag.log
#
# personally install this via crontab, e.g.:
# 1. crontab -e
# 2. add the following:
#
#   @daily <user> TALOSCONFIG=<path to config> /bin/bash ~/Code/chr0n1x/rpi-talos/etc/scripts/etcd-defrag.bash 
# 3. or use the systemctl service/timer in ../systemd

NODES=$(kubectl get nodes -o=wide | grep control | awk '{ print $1 }')
# LOG_FILE=/tmp/etcd-defrag.log

started=false
info() {
  if [ $started = false ]; then
    echo -e "[$(date)] $@" # > $LOG_FILE
    started=true
    return
  fi
  echo -e "[$(date)] $@" # >> $LOG_FILE
}

info "Found control nodes:\n\n$NODES\n"
info
info "----------------------------"
info "ETCD STATUS OF CONTROL PLANE"
info "----------------------------"
info
info "Starting defrag run..."

talosctl \
  -n "$(echo $NODES | tr ' ' ',' | sed 's/,$//g')" etcd status # >> $LOG_FILE

for cnode in $NODES; do
  info
  info "- defragging control-node $cnode..."
  talosctl -n $cnode etcd defrag # >> $LOG_FILE
done 

info
info "--- DONE"
