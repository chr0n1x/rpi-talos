Talos on RPi
====

Dumping ground for notes/scripts(?) for my RPi K8s cluster running on Talos.

DISCLAIMER: also using this to learn K8s so things are going to look dumb.

# Tools / Goals

- Leveraging talos/k8s with the [pi.hole](https://pi-hole.net/) stack.
- Playground for tinkering w/ on-prem bare-metal clusters; eventually want to start adding various node types for different workloads (e.g.: CUDA cores)
- K8s playground because I'm bad.
- [Talos](https://www.talos.dev/v1.7/talos-guides/install/single-board-computers/rpi_generic/) is pretty cool.
- Using cluster to run personal automations (plant waterer, ambient sounds via GitHub activity, etc)
- Playground for moar app development, AI/ML/mining.

# RPi Card Setup

- Running the `metal-arm64.raw.xz` image on RPi >= 3 model B. Downloaded from [here](https://github.com/siderolabs/talos/releases/tag/v1.7.5)
- [RPi Imager](https://www.raspberrypi.com/software/)
    - insert SD card into system
    - select your device
    - for OS -> Misc utility images -> Bootloader -> SD Card Boot
    - select your SD card, flash it
- SLOT THE SD CARD INTO YOUR RPi
    - VERIFY THAT ON POWERUP THE GREEN LED CONTINUOUSLY FLASHES and/or THE HDMI SCREEN IS FULLY GREEN.
    - after this, poweroff/unplug the RPi, take our your SD card
- Use a `*nix` machine:
    - plug in your SD card that you flashed above
    - as `sudo`:
        - `xz -d metal-arm64.raw.xz`
        - `dd if=metal-arm64.raw of=<device blk/name> conv=fsync bs=4M`
        - for the `of=` argument above, use `lsblk` BEFORE AND AFTER plugging in your SD card to figure out the device.
    - after `dd` is done (you may have to hit `<enter>` a few times in CLI to confirm that it's done) `eject <device blk/name>`
- slot SD card back into RPi, power it on and watch the talos OS logs


Rest of the setup is pretty much in [the guide](https://www.talos.dev/v1.7/talos-guides/install/single-board-computers/rpi_generic/). I'm keeping extensive notes and util scripts in `Makefile` though to record what's been working for me. The guides are still a bit messy to follow.
