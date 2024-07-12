# SEED_NODE_IPV4 is the local ip of the node that you have on and are actively
# monitoring while you go through this process
#
# TODO: dynamic IPs?

# generates a fresh set of configs
#   - a talosconfig, which defines creds & spinup configs for your cluster
#   - worker & controlplane configs to be applied to the respective nodes
# TODO: account for TALOSCONFIG env var
talosconfig:
	talosctl gen config $$SEED_NODE_IPV4 --role controlplane --insecure
	talosctl bootstrap --nodes $$SEED_NODE_IPV4
	talosctl kubeconfig

talos/nodes-all.csv:
	# ?

talos/nodes-worker.csv: talos/nodes-all.csv
	# ?

talos/nodes-control.csv: talos/nodes-all.csv
	# ?

talos-control: talos/nodes-control.csv
	talosctl apply-config \
	  --nodes $(CONTROL_NODE_IPS) \
	  --insecure --file controlplane.yaml

talos-workers: talos/nodes-worker.csv
	talosctl apply-config \
	  --nodes $(WORKER_NODE_IPS) \
	  --insecure --file worker.yaml


# WARNING: this will NUKE AN ENTIRE DEVICE
#          this is how I format external drives for use with longhorn
#
# in the worker-config that talosctl generates on cluster bootstrap:
#
# machine:
#   type: worker
#   # ...
#   # ...
#   # ...
#   kubelet:
#       # ...
#       # ...
#       # ...
#       extraMounts:
#         # separate reserved mount for longhorn itself
#         - destination: /var/lib/longhorn
#           type: bind
#           source: /var/lib/longhorn
#           options:
#             - bind
#             - rshared
#             - rw

#   # longhorn mount for hdd
#   # look at machine/kubelet/extraMounts
#   disks:
#     # path fetched via
#     # talosctl -n <node IP> disks
#     - device: /dev/sda
#       partitions:
#         - mountpoint: /var/lib/longhorn
#
# Make sure to have an image that supports scsi:
#   https://www.talos.dev/v1.7/kubernetes-guides/configuration/storage/#others-iscsi
#
format-disc:
	# note that this will be the extra storage that you mount
	lsblk | grep sda
	mount /dev/sda /media/
	chmod -R o+rwx /media/
	umount /media
