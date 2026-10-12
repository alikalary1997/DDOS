param([string]$Address = "127.0.0.1:8000", [switch]$LocalDevelopment)
$ErrorActionPreference = "Stop"
$settingsArguments = @()
if ($LocalDevelopment) {
    if ($Address -notmatch "^(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})$" -or [int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535) {
        throw "Local development mode requires a loopback address and a valid port."
    }
    $settingsArguments = @("--settings=netshield.settings_local")
}
$projectDirectory = $PSScriptRoot
$pythonExecutable = Join-Path $projectDirectory "venv\Scripts\python.exe"
# Read the same persistent key on every launch; never generate one at startup.
$persistentDeviceKey = [Environment]::GetEnvironmentVariable("NETSHIELD_DEVICE_ENCRYPTION_KEY", "User")
if ($persistentDeviceKey) {
    if ($env:NETSHIELD_DEVICE_ENCRYPTION_KEY -and $env:NETSHIELD_DEVICE_ENCRYPTION_KEY -ne $persistentDeviceKey) {
        Write-Error "Process and persistent device keys differ. Resolve configuration before starting NetShield."
    }
    $env:NETSHIELD_DEVICE_ENCRYPTION_KEY = $persistentDeviceKey
}
$persistentDeviceKey = $null
Push-Location $projectDirectory
try {
    & $pythonExecutable manage.py configure_device_encryption @settingsArguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $pythonExecutable manage.py runserver $Address @settingsArguments
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
