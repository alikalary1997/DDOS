$ErrorActionPreference = "Stop"
$rawPollingPython = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
$rawPollingKey = [Environment]::GetEnvironmentVariable("NETSHIELD_DEVICE_ENCRYPTION_KEY", "User")
if (-not $rawPollingKey) {
    throw "The persistent device encryption key is missing. Configure it securely before starting polling."
}
if ($env:NETSHIELD_DEVICE_ENCRYPTION_KEY -and $env:NETSHIELD_DEVICE_ENCRYPTION_KEY -cne $rawPollingKey) {
    throw "The process and persistent device encryption keys differ. Restart with the correct server environment."
}
$env:NETSHIELD_DEVICE_ENCRYPTION_KEY = $rawPollingKey
$rawPollingKey = $null
Push-Location $PSScriptRoot
try {
    & $rawPollingPython manage.py configure_device_encryption --settings=netshield.settings_local
    if ($LASTEXITCODE -ne 0) { throw "Device encryption verification failed." }
    & $rawPollingPython manage.py poll_raw_firewall --settings=netshield.settings_local
    if ($LASTEXITCODE -ne 0) { throw "RAW polling could not start. It remains disabled pending approval." }
} finally {
    Pop-Location
}
