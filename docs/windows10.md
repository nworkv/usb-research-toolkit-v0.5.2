# Windows 10 host testing notes

The Pi runs `usb-connect` on Linux. Windows 10 is only the USB host under test.

## Host capture

1. Install Wireshark with USBPcap selected in the installer.
2. Start Wireshark as Administrator if needed and select the USBPcap interface attached to the USB controller used by the Pi.
3. Capture enumeration and the test run; save as PCAPNG.
4. Normalize with `scripts/normalize-capture.ps1 -InputPcapng runs\host-windows.pcapng -OutputJsonl runs\host.jsonl -Source windows_host`, or use `scripts/normalize-capture.sh` from Git Bash/MSYS2.

The normalizer uses `usb.*` field names that are common to Wireshark builds. Check `tshark -G fields` if your version differs. USBPcap is a host-stack capture mechanism; it does not expose every on-wire ACK/NAK/CRC packet.

## Vendor-specific interface access

The example interface is vendor-specific. Windows does not automatically choose a generic bulk driver for a vendor-specific interface. If using the optional libusb-based `usb-host-test`, install a compatible WinUSB/libusbK binding for that test device, following the organization's driver-signing and device-management policy. Do not replace drivers for unrelated devices.

Build `usb-config` and `usb-trace` with CMake and MSVC/Visual Studio (C++20). `usb-connect` is Linux-only. For `usb-host-test`, install libusb development files and configure CMake so it can find the package; otherwise the target is intentionally omitted.
