#!/bin/bash -e

# etcd defrag for Talos control-plane nodes.
# Run via systemd timer (etc/systemd/etcd-defrag.timer).
#
# Requires: TALOSCONFIG, KUBECONFIG in env.

export PATH="/usr/local/bin:$PATH"

info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# Discover control-plane nodes from the Talos cluster member list.
NODES=$(talosctl get members -o yaml 2>/dev/null \
  | awk '/machineType: controlplane/{cp=1} /hostname:/{h=$2} /^---$/{if(cp)print h; cp=0; h=""}')

if [ -z "$NODES" ]; then
  info "ERROR: no control-plane nodes found"
  exit 1
fi

NODES_CSV=$(echo $NODES | tr ' ' ',' | sed 's/,$//g')

info "Control-plane nodes: $NODES"
info "---"
info "etcd status:"

# Capture status output once. Used for both display and leader detection.
# Table: NODE MEMBER DB_SIZE UNIT IN_USE UNIT (PCT) LEADER RAFT_INDEX ...
# Leader is the row where MEMBER ($2) == LEADER ($8).
STATUS=$(talosctl etcd status -n "$NODES_CSV")
echo "$STATUS"

LEADER=$(echo "$STATUS" | awk 'NR>1 && $2==$8 {print $1; exit}')
[ -z "$LEADER" ] && LEADER=$(echo "$NODES" | tail -1)

info "---"
info "Defrag order: non-leaders first, leader ($LEADER) last"

for cnode in $NODES; do
  [ "$cnode" = "$LEADER" ] && continue
  info "Defragging $cnode..."
  talosctl -n "$cnode" etcd defrag
done

info "Defragging leader $LEADER last..."
talosctl -n "$LEADER" etcd defrag

info "--- DONE"
