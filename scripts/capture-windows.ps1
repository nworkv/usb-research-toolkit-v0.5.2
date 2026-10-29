param(
    [Parameter(Mandatory=$true)][string]$OutputPcapng,
    [string]$Interface
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    throw 'tshark was not found. Install Wireshark with USBPcap and add tshark.exe to PATH.'
}
Write-Host 'Available capture interfaces:'
tshark -D
if (-not $Interface) { $Interface = Read-Host 'Enter the USBPcap interface number or name (for example, 5)' }
$parent = Split-Path -Parent $OutputPcapng
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
Write-Host "Capturing on $Interface to $OutputPcapng. Press Ctrl+C to stop."
tshark -i $Interface -w $OutputPcapng
