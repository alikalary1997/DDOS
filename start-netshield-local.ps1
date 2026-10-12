param([ValidateRange(1, 65535)][int]$Port = 8000)
$ErrorActionPreference = "Stop"
# Local mode is explicit and can only bind to this PC's loopback interface.
& (Join-Path $PSScriptRoot "start-netshield.ps1") -Address "127.0.0.1:$Port" -LocalDevelopment
