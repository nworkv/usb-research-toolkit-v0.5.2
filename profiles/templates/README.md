# Built-in USB device profiles

These templates target an isolated lab and use illustrative VID/PID values. Replace them with identifiers you are authorized to use.

| File | Runtime implementation | Purpose |
|---|---|---|
| `hid-mouse.json` | HID report protocol | Relative mouse, neutral zero-motion report |
| `hid-keyboard.json` | HID boot protocol | 8-byte neutral keyboard report; does not type keys |
| `hid-gamepad.json` | Generic HID | 16 buttons, 4 signed axes and hat switch, neutral report |
| `hid-joystick.json` | Generic HID | Joystick Usage with common axes/buttons report layout |
| `hid-consumer-control.json` | Generic HID | Consumer-control collection, neutral 16-bit usage |
| `cdc-acm-serial.json` | CDC ACM requests + bulk loopback | GET/SET_LINE_CODING, SET_CONTROL_LINE_STATE, SEND_BREAK; OUT data can be echoed on paired IN endpoint |
| `msc-bot-disk.json` | MSC BOT + common SCSI commands | File-backed disk image; create `runs/storage/usb-lab.img` before running |
| `composite-cdc-hid-keyboard.json` | CDC ACM + HID keyboard | One configuration, 3 interfaces (CDC control/data + keyboard) |
| `composite-msc-hid-gamepad.json` | MSC BOT + HID gamepad | One configuration, storage and gamepad interfaces |
| `composite-hid-keyboard-mouse-consumer.json` | HID keyboard + mouse + consumer control | One configuration with three HID interfaces |
| `composite-cdc-msc-hid-gamepad.json` | CDC ACM + MSC BOT + HID gamepad | Four interfaces; requires storage image and enough UDC endpoints |
| `multi-config-keyboard-mouse.json` | HID | Two configurations; host selects keyboard OR mouse configuration |
| `vendor-bulk.json` | Generic endpoint worker | Vendor-specific bulk IN/OUT experiment |
| `msc-bot-descriptor-only.json` | None (descriptors only) | Old descriptor-only MSC example; not a functional disk |

## Implementation boundaries

- HID report descriptors are configurable, but the toolkit does not automatically emulate every proprietary HID device. To add another HID, supply a valid report descriptor, a report matching its bit layout, and the correct interface class/protocol metadata. Boot keyboard, mouse, generic gamepad/joystick and consumer-control examples are included.
- CDC support in this toolkit is **CDC ACM**, not every CDC subclass (e.g. ECM/NCM networking). The provided serial profile handles the common ACM control requests and includes an optional bulk OUT-to-IN loopback pair.
- MSC implements USB Mass Storage Bulk-Only Transport (CBW/CSW) and common SCSI commands including INQUIRY, TEST UNIT READY, REQUEST SENSE, MODE SENSE(6/10), READ FORMAT CAPACITIES, READ CAPACITY(10/16), READ/WRITE(10/12/16), START STOP UNIT, PREVENT/ALLOW MEDIUM REMOVAL and SYNCHRONIZE CACHE. It supports one LUN and a regular backing file. It is not a production storage implementation.
- Multiple configurations and multiple interfaces are represented in the descriptor compiler. Runtime alternate-setting switching and isochronous endpoints are not implemented. UDC endpoint counts, direction/type capability and packet-size limits may prevent a composite profile from binding on a particular board.
- Real device/Windows interoperability must be tested on the target Raspberry Pi, cable, UDC, host and Windows build. A successful process start does not prove the host configured the device.
