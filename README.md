Talos on RPi
====

![rpi k8s cluster via talos!](docs/img/rpi-talos-k8s.jpg?raw=true)

Dumping ground for notes/scripts(?) for my RPi K8s cluster running on Talos.

DISCLAIMER: also using this to learn K8s so things are going to look dumb.

# Tools / Goals

- Leveraging talos/k8s with the [pi.hole](https://pi-hole.net/) stack.
- Playground for tinkering w/ on-prem bare-metal clusters; eventually want to start adding various node types for different workloads (e.g.: CUDA cores)
- K8s playground because I'm bad.
- [Talos](https://www.talos.dev/v1.7/talos-guides/install/single-board-computers/rpi_generic/) is pretty cool.
- Using cluster to run personal automations (plant waterer, ambient sounds via GitHub activity, etc)
- Playground for moar app development, AI/ML/mining.
- Pretending to be a 1337 dev rack operator with all the smex appeal.

# Prerequisites

## Acknowledge Caveats

I currently have some DNS names that are hard-coded in the ingresses for the bootstrapped services in this setup.

Specifically:
- `home.k8s` points to a subset of my k8s nodes (for general cluster access)
- I access everything via `NodePort` -- didn't want to setup TLS/SSL & a reverse proxy (yet)
- all traffic is accessed via the kubernetes ingress-nginx controller
    - `https` is on `30443`
    - `http` is on `30080`
- all services are behind CNAMEs to `home.k8s`
    - the dashboard is at `https://dashboard.home.k8s:30443`
    - longhorn is at `https://longhorn.home.k8s:30443`
    - etc

this doesn't sit will with me either so stay tuned for an actual solution that's...close to fully automated. Maybe.

## Hardware

- A couple of machines that you can install [TalosOS](https://www.talos.dev/) on.
    - Ideally >= RPi Model 3B
- A couple of micro SD cards for these machines. Or if you've got bank, [RPi HATs](https://www.raspberrypi.com/news/introducing-raspberry-pi-hats/) with harddrives attached.
    - if you have EXTRA harddrives on any machines, make sure that they're formatted appropriately. Check out the `make.format-disc` target.
- A primary work machine:
    - should be able to flash your boot devices
    - either `dd` or [rufus](https://rufus.ie/en/) for you windows folk
- it helps IMMENSELY if you have a small screen that you can attach/detach quickly for your RPis. I use [this one](https://www.amazon.com/gp/product/B00N0SNVQE).
    - make sure you have the right cables

The rest is really up to you. You can get fancy with switches, if you're using proxmox you can set up your own vLAN with reserved IPs for VMs. Whatever.

## Software (Prep/Configuration)

- For these machines make sure that you can address them via static IPs and/or hostnames on your lan.
    - if you're already running pi-hole you can do this via the [Local DNS Configuration Page](http://pi.hole/admin/dns_records.php)
    - if you just want something up and running, you can reserve IPs in your router DHCP settings
- Whether you're imaging an ISO onto a bootable USB drive, SD card, DVD, whatever - you will need the appropriate image.
    - generate and download the image via the [Talos Image Factory](https://factory.talos.dev/)
    - an example image: [`factory.talos.dev/installer/f8a903f101ce10f686476024898734bb6b36353cc4d41f348514db9004ec0a9d:v1.7.5`](https://factory.talos.dev/image/f8a903f101ce10f686476024898734bb6b36353cc4d41f348514db9004ec0a9d/v1.7.5/metal-arm64.raw.xz)
        - image above is for Raspberry Pi with extensions required for longhorn
        - while creating these images yourself, if you WANT persistent storage just make sure to include the `iscsi-tools` and `util-linux-tools` extentions.
- make sure that you have the appropriate tools installed. Running `make` in this repository will do a check for you, and give you more pointers on how to install anything that's missing.

## Initial Setup

As said above, I _HIGHLY_ recommend running at least Raspberry Pi Model 3B for your cluster. It seems to to have specs that result in smoother boot-up speeds, respnsiveness, etc. I personally have Model 4Bs and the overall experience has been very smooth.

Steps:

1. flash the image for your machines onto their respective devices.
    - for *nix folks:
        - determine your `<device blk/name>` based on `lsblk` BE CAREFUL HERE, YOU CAN WIPE YOUR MAIN DRIVE LOL
        - ```
            wget https://factory.talos.dev/image/f8a903f101ce10f686476024898734bb6b36353cc4d41f348514db9004ec0a9d/v1.7.5/metal-arm64.raw.xz
            xz -d metal-arm64.raw.xz
            dd if=metal-arm64.raw of=<device blk/name> conv=fsync bs=4M
            eject <device blk/name>
            ```
        - might have to `sudo` for the above
1. `export TALOSCONFIG=$(pwd)/talos/talosconfig`
    - this will make the next couple of steps easier
    - if you use `direnv`, `cp envrc.sample .envrc` and `direnv allow` to make this automatic in the future
1. pick a pretty pretty VIP machine. Actually any machine will do. This node/IP will be your first K8s control node.
    - at this point we're really just following [the guide](https://www.talos.dev/v1.7/introduction/getting-started/#define-the-kubernetes-endpoint) <- AT LEAST SKIM OVER THIS
    - `cd talos` -- so that everything generated ends up in this dir
    - define your VIP control endpoint. e.g.: `https://<VIP Node IP>:6443`
    - figure out a name that you want to give this cluster. e.g.: `<cluster-name>
    - `talosctl gen config <cluster-name> https://<VIP Node IP>:6443`

1. update the install device on the node:
```yaml
# THIS IS APPLICABLE FOR BOTH worker.yaml AND controlplane.yaml !
machine:
    # ...
    # the stuff from above
    # ...
    # this already exists
    install:
        disk: /dev/mmcblk0 # this should be your boot device. find it via `talosctl -n <node ip> disks`
        image: ghcr.io/siderolabs/installer:v1.7.5
        wipe: false
```

1. OPTIONAL: for longhorn, update your generated worker config to include the required mounts (I recommened `cp worker.yaml worker-longhorn.yaml` for these kinds of changes)
```yaml
machine:
    kubelet:
        extraMounts:
          # separate reserved mount for longhorn itself
          # this will use the machine's local disk for longhorm PVs/PVCs
          - destination: /var/lib/longhorn
            type: bind
            source: /var/lib/longhorn
            options:
              - bind
              - rshared
              - rw


          # EVERYTHING BELOW IS OPTIONAL IF YOU HAVE AN EXTERNAL HDD
          # and AGAIN - make sure it's formatted appropriately with something
          # akin to the make.format-disc target
          - destination: /mounts/storage
            type: bind
            source: /mount/storage
            options:
              - bind
              - rshared
              - rw
    disks:
      # path fetched via
      # talosctl -n <node IP> disks
      - device: /dev/sda
        partitions:
          - mountpoint: /mount/storage
```
1. Bootstrap your first node:
```sh
talosctl apply-config --insecure \
    --nodes <Node IP> \
    --file controlplane.yaml

talosctl bootstrap --nodes <Node IP> --endpoints <Node IP> \
  --talosconfig=./talosconfig
```

1. Wait for your first control node to become healthy/ready in the `dmesg` logs (the screen)

And at this point, you just have to apply the machine configs to the various machines!
```sh
talosctl --nodes <comma-delimeted list of controlplane node IPs> \
    apply-config -f controlplane.yaml --insecure


talosctl --nodes <comma-delimeted list of WORKER node IPs> \
    apply-config -f worker.yaml --insecure
```

and to play around with it, `talosctl kubeconfig --nodes <Node IP> --endpoints <Node IP>` to merge this cluster kubeconfig with your existing config. Instructions on how to generate a separate `kubeconfig.yaml` file in the docs [HERE](https://www.talos.dev/v1.7/introduction/getting-started/#kubernetes-bootstrap)

## Going Further

I use `helmfile` to install a bunch of "essentials". The `make sync` and `make apply` targets will execute those respective `helmfile` operations via `k8s/helmfile.yaml`. Take a look, things should work out of the box.

TODO: moar details to come.

# Troubleshooting

- Use [RPi Imager](https://www.raspberrypi.com/software/) to wipe and troubleshoot any defective cards before `dd`ing your image
    - insert SD card into system
    - select your device
    - for OS -> Misc utility images -> Bootloader -> SD Card Boot
    - select your SD card, flash it
- SLOT THE SD CARD INTO YOUR RPi
    - VERIFY THAT ON POWERUP THE GREEN LED CONTINUOUSLY FLASHES and/or THE HDMI SCREEN IS FULLY GREEN.
    - after this, poweroff/unplug the RPi, take our your SD card
- try `dd`ing the image again via the above


Rest of the setup is pretty much in [the guide](https://www.talos.dev/v1.7/talos-guides/install/single-board-computers/rpi_generic/). I'm keeping extensive notes and util scripts in `Makefile` though to record what's been working for me. The guides are still a bit messy to follow.
