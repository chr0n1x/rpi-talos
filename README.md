Talos on RPi
====

Dumping ground for notes/scripts(?) for my RPi K8s cluster running on Talos.

- Also using this to learn K8s so things are going to look dumb.
- Talos is pretty cool.

# RPi Card Setup

- Running the `metal-arm64.raw.xz` image on RPi >= 3 model B. Downloaded from [here](https://github.com/siderolabs/talos/releases/tag/v1.7.5)
- First use [RPi Imager](https://www.raspberrypi.com/software/) -> Boot Utils -> SD Boot on your SD card
- SLOT THE SD CARD INTO YOUR RPi, VERIFY THAT ON POWERUP THE GREEN LED CONTINUOUSLY FLASHES and/or THE HDMI SCREEN IS FULLY GREEN.
    - after this, power off the RPi
- Use a `*nix` machine:
    - plug in your SD card that you flashed above
    - as `sudo`:
        - `xz -d metal-arm64.raw.xz`
        - `dd if=metal-arm64.raw of=/dev/mmcblk0 conv=fsync bs=4M`

Rest of the setup is pretty much in [the guide](https://www.talos.dev/v1.7/talos-guides/install/single-board-computers/rpi_generic/). I'm keeping extensive notes and util scripts in `Makefile` though to record what's been working for me. The guides are still a bit messy to follow.
