default: .validate-tools

# NOTE: install things via snap, apt, yum, whatever
#
#       e.g.:
#         snap install helm --classic
#         snap install kubectl --classic
#
#       but there are a few exceptions here
#
# kustomize: do NOT install via snap, causes symlink issues in helmfile
#   curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
#   mv kustomize ~/.local/bin/.
#   wget https://github.com/helmfile/helmfile/releases/download/v1.0.0-rc.2/helmfile_1.0.0-rc.2_linux_amd64.tar.gz
#
# helmfile:
#   tar -xzf helmfile_1.0.0-rc.2_linux_amd64.tar.gz helmfile
#   mv helmfile ~/.local/bin/.
#
# talosctl:
#   curl -sL https://talos.dev/install | sh
.validate-tools:
	@which kubectl $&> /dev/null || \
	  (echo "❌ Missing kubectl; sudo snap install kubectl --classic" && exit 1)
	@echo "kubectl   ✅"

	@which helm $&> /dev/null || \
	  (echo "❌ Missing helm; sudo snap install helm --classic" && exit 1)
	@echo "helm      ✅"

	@helm plugin list | grep "^x.*Kustomization.*" $&> /dev/null || \
	  (echo "❌ Missing helm-x plugin; helm plugin install https://github.com/mumoshu/helm-x" && exit 1)
	@echo "helm-x    ✅"

	@helm plugin list | grep "^diff.*" $&> /dev/null || \
      (echo "❌ Missing helm-diff plugin; helm plugin install https://github.com/databus23/helm-diff" && exit 1)
	@echo "helm-diff ✅"

	@which kustomize $&> /dev/null || \
	  (echo "❌ Missing kustomize; run 'make install-kustomize'" && exit 1)
	@echo "kustomize ✅"

	@which helmfile $&> /dev/null || \
	  (echo "❌ Missing helmfile; run 'make install-helmfile'" && exit 1)
	@echo "helmfile  ✅"

	@which talosctl $&> /dev/null || \
	  (echo "❌ Missing talosctl; curl -sL https://talos.dev/install | sh" && exit 1)

	@git rev-parse HEAD > .validate-tools
	@echo "All Set!  🚀🚀"


install-helmfile:
	tar -xzf helmfile_1.0.0-rc.2_linux_amd64.tar.gz helmfile
	mv helmfile ~/.local/bin/.


install-kustomize:
	curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
	mv kustomize ~/.local/bin/.
	wget https://github.com/helmfile/helmfile/releases/download/v1.0.0-rc.2/helmfile_1.0.0-rc.2_linux_amd64.tar.gz


sync:
	helmfile --file k8s/helmfile.yaml sync


apply:
	helmfile --file k8s/helmfile.yaml apply


#
# INITIAL NODE BOOTSTRAPPING TARGETS - WORKS AS OF TALOS 1.7.6
#
# CLUSTER_NAME   whatever you want to call this cluster
# SEED_NODE_IPV4 the local ip of the node that you have on and are actively
#                monitoring while you go through this process
#
# generates a fresh set of configs
#   - a talosconfig, which defines creds & spinup configs for your cluster
#   - worker & controlplane configs to be applied to the respective nodes
#   - kubeconfig
#
# ex command:
#
# 	CLUSTER_NAME=px-experimental SEED_NODE_IPV4=192.168.86.34 make init-node-0
#
# TODO / NOTE: these targets need to be run in order. I have no automated the
# 			   sequence & monitoring of events yet
init-node-0:
	talosctl gen config $$CLUSTER_NAME https://$$SEED_NODE_IPV4:6443
	yq -i ".contexts.px-experimental.endpoints = [\"$$SEED_NODE_IPV4\"]" talosconfig
	yq -i ".contexts.px-experimental.nodes = [\"$$SEED_NODE_IPV4\"]" talosconfig
	talosctl --talosconfig talosconfig apply-config --nodes $$SEED_NODE_IPV4 --file controlplane.yaml --insecure
# after the above, first control node will reboot; wait for it to come up before running this
prep-node-0:
	talosctl --talosconfig talosconfig apply-config --nodes $$SEED_NODE_IPV4 --file controlplane.yaml --insecure
# after second apply above, node will ask to bootstrap
bootstrap:
	talosctl --talosconfig talosconfig bootstrap --nodes $$SEED_NODE_IPV4
	talosctl --talosconfig talosconfig kubeconfig ./kubeconfig
	talosctl --talosconfig talosconfig -n $$SEED_NODE_IPV4 health
# after all of this, you'll have all configs ready to go
# convenience; dangerous, don't use unless you know what you're doing and/or have backed up yo shiiiii
clean:
	rm -f controlplane.yaml worker.yaml talosconfig kubeconfig


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
	# THIS WILL NUKE THE ENTIRE DRIVE
	mkfs.ext4 /dev/sda
	mount /dev/sda /media/
	chmod -R o+rwx /media/
	umount /media
