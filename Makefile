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
