param(
    [Parameter(Mandatory=$true)][string]$InputPcapng,
    [Parameter(Mandatory=$true)][string]$OutputJsonl,
    [ValidateSet('linux_host','windows_host')][string]$Source = 'windows_host'
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) { throw 'tshark was not found in PATH.' }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'python was not found in PATH.' }
$parent = Split-Path -Parent $OutputJsonl
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
$fieldLines = & tshark -G fields 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Could not query TShark field registry with `tshark -G fields`.' }
$availableFields = @($fieldLines | ForEach-Object {
    $parts = $_ -split "`t"
    if ($parts.Length -ge 3 -and $parts[0] -eq 'F') { $parts[2] }
})
if ($availableFields -contains 'usb.bmRequestType') {
    $requestTypeField = 'usb.bmRequestType'
} elseif ($availableFields -contains 'usb.setup.bmRequestType') {
    $requestTypeField = 'usb.setup.bmRequestType'
} else {
    throw 'TShark field bmRequestType not found (expected usb.bmRequestType or legacy usb.setup.bmRequestType).'
}
$tsharkArgs = @('-r',$InputPcapng,'-T','fields','-E','header=y','-E','separator=/t','-E','quote=d','-E','occurrence=f',
  '-e','frame.time_epoch','-e','usb.device_address','-e','usb.endpoint_address','-e','usb.transfer_type','-e','usb.urb_type','-e','usb.data_len',
  '-e',$requestTypeField,'-e','usb.setup.bRequest','-e','usb.setup.wValue','-e','usb.setup.wIndex','-e','usb.setup.wLength','-e','usb.capdata')
& tshark @tsharkArgs | & python (Join-Path $PSScriptRoot 'normalize-tshark.py') --source $Source | Set-Content -Encoding utf8 $OutputJsonl
Write-Host "Normalized events written to $OutputJsonl"
