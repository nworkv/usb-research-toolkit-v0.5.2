#!/usr/bin/env bash
set -euo pipefail

cat <<'MSG'
USB Research Toolkit: Raspberry Pi 4 preflight

This script is diagnostic only. It does not modify boot configuration or load drivers.
Run it directly on the Raspberry Pi 4 running a 64-bit Raspberry Pi OS/Linux kernel.
MSG

printf '\nKernel: '; uname -a
printf '\nUSB Device Controller(s):\n'
if compgen -G '/sys/class/udc/*' >/dev/null; then
  for entry in /sys/class/udc/*; do
    [[ -e "$entry" ]] || continue
    printf '  %s\n' "${entry##*/}"
    if [[ -L "$entry/device/driver" ]]; then printf '    kernel module=%s\n' "$(basename "$(readlink -f "$entry/device/driver")")"; fi
    if [[ -r "$entry/uevent" ]]; then grep '^USB_UDC_NAME=' "$entry/uevent" | sed 's/^/    /' || true; fi
  done
else
  echo '  none visible under /sys/class/udc'
fi

printf '\nRaw Gadget device: '
if [[ -e /dev/raw-gadget ]]; then echo '/dev/raw-gadget exists'; else echo 'missing'; fi
printf '\nKernel options if exposed:\n'
if [[ -r /proc/config.gz ]]; then zgrep -E 'CONFIG_USB_RAW_GADGET|CONFIG_USB_DWC2' /proc/config.gz || true
elif [[ -r "/boot/config-$(uname -r)" ]]; then grep -E 'CONFIG_USB_RAW_GADGET|CONFIG_USB_DWC2' "/boot/config-$(uname -r)" || true
else echo '  Kernel config file not found; inspect /boot or /proc/config.gz.'; fi

cat <<'MSG'

Next steps:
  1. Ensure the Pi 4 board USB-C port is connected to the test host with a data-capable cable.
  2. If needed, review /boot/firmware/config.txt and set the DWC2 controller to peripheral mode:
       dtoverlay=dwc2,dr_mode=peripheral
     Check the Raspberry Pi OS version and existing overlays first; do not blindly duplicate entries.
  3. Reboot if boot configuration changed.
  4. Ensure Raw Gadget is available in the kernel (CONFIG_USB_RAW_GADGET) and /dev/raw-gadget is accessible.
  5. Stop/disable any other gadget service that has already claimed the same UDC.
  6. Build the project and run: sudo ./build/usb-connect probe

Raw Gadget is a kernel debugging interface. Keep research profiles on your own isolated test bench.
MSG
