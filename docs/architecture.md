# Architecture — v0.5.0

## Layers

1. `Json` is a small self-contained parser/writer so the main C++ tools do not require a third-party JSON dependency.
2. `profile.cpp` validates ranges, descriptor counts/lengths, endpoint metadata, HID report descriptor references and runtime class metadata. Validation can check structure, but it cannot prove a descriptor is accepted by every host or UDC.
3. `raw_gadget_backend_linux.cpp` adapts the profile to `/dev/raw-gadget` and Linux `USB_RAW_IOCTL_*` operations.
4. `TraceLogger` records control requests, endpoint transfers, class runtime events, UDC events and errors as JSONL.
5. Python tools generate profiles, orchestrate campaigns, normalize tshark output, correlate host/device observations and summarize mutations.

## Runtime paths

`profile JSON -> validate/compile -> Raw Gadget GET_DESCRIPTOR/control path -> SET_CONFIGURATION -> endpoint workers -> JSONL trace`.

Runtime control handling includes common CDC ACM line-coding/control-line requests, HID class report/idle/protocol requests, and MSC BOT Get Max LUN/Reset. Endpoint runtime includes configurable HID IN reports, a CDC-style bulk OUT-to-IN loopback, and a file-backed MSC BOT worker that parses CBW/CSW and implements a bounded set of common SCSI disk commands.

## Profile metadata

- `runtime.interfaces` maps a configuration/interface number to class runtime (`hid`, `cdc-acm`, `cdc-data`, or `msc-bot`).
- `runtime.mass_storage` selects a backing-file image, block size, read-only flag, LUN-0 endpoints, interface and configuration.
- `interface_descriptors` allows HID report descriptors to be keyed by `configuration:interface`; `raw_descriptors` is the fallback for generic descriptor types.
- `endpoint_io.in_payloads` configures endpoint IN reports, `repeat_in_addresses` keeps explicitly selected static IN reports available, and `loopback_pairs` links matching bulk OUT/IN endpoints for CDC serial tests.
- `control_responses` remains available for explicit matching of additional control-IN requests.

## Concurrency and state

The Raw Gadget event loop processes UDC connect, control, suspend/resume, reset and disconnect notifications. Endpoint workers handle blocking endpoint I/O. Reset/disconnect cancellation is UDC/kernel dependent and must be validated on the actual board. A trace `CONTROL_REQUEST` proves that the Raw Gadget event loop observed a request; a process state or UDC CONNECT event alone does not prove that Windows configured the device.

## Implemented examples and limits

- HID: neutral boot-keyboard, relative mouse, generic gamepad/joystick and consumer-control reports. Custom HID devices require an appropriate report descriptor, correct report layout and endpoint payload. HID has no universal report layout for every commercial device.
- CDC ACM: common control requests and optional bulk echo loopback. CDC ECM/NCM networking and unrelated CDC subclasses are not implemented.
- MSC BOT: single LUN, regular-file backing storage, CBW/CSW, and common SCSI commands. This is a research/test implementation, not a production block-storage stack; it may not implement every SCSI command and recovery edge case required by all operating systems.
- Composite and multiple configurations: descriptors/runtime for included templates are supported subject to UDC endpoint capabilities. Only alternate setting 0 is activated; runtime alternate-setting switching and isochronous I/O are not implemented.
- Hardware/host interoperability cannot be proven by static tests. `EP_ENABLE` and real enumeration on the target UDC are the final compatibility checks.

## Capture correlation

Wireshark/USBPcap or Linux capture output is normalized using `tshark`, then compared to the device-side JSONL trace. Correlation statuses describe observed data only: an empty capture may indicate the wrong capture interface; STALL/reset may be ordinary enumeration behavior; no status in this tool proves or disproves Windows BSOD/kernel crash.
