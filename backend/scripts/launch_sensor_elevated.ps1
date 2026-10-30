<#
.SYNOPSIS
    ThreatTrack Approved Elevated Windows Sensor Launcher
    SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

.DESCRIPTION
    Runs the ThreatTrack passive local Windows packet sniffer with the least required privileges.
    Windows Npcap requires administrative privileges to open raw network adapter sockets.
    This script verifies elevation, requests UAC prompt if needed, and launches the sensor
    associated with the authenticated user account.

.PARAMETER Interface
    Network interface name to sniff (e.g. 'Wi-Fi 3'). If omitted, auto-selects active adapter.

.PARAMETER BackendUrl
    ThreatTrack backend URL for telemetry transmission (default: http://127.0.0.1:8000)

.PARAMETER ApiKey
    Sensor API Key generated during device enrollment.

.PARAMETER SensorId
    Unique Sensor ID assigned to the user device.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Interface = "",

    [Parameter(Mandatory=$false)]
    [string]$BackendUrl = "http://127.0.0.1:8000",

    [Parameter(Mandatory=$false)]
    [string]$ApiKey = "",

    [Parameter(Mandatory=$false)]
    [string]$SensorId = ""
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# Check for Administrator elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[*] Windows Npcap packet capture requires elevated privileges to access raw sockets." -ForegroundColor Yellow
    Write-Host "[*] Requesting UAC elevation for ThreatTrack Local Sensor..." -ForegroundColor Cyan

    $argList = "-NoExit -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    if ($Interface) { $argList += " -Interface `"$Interface`"" }
    if ($BackendUrl) { $argList += " -BackendUrl `"$BackendUrl`"" }
    if ($ApiKey) { $argList += " -ApiKey `"$ApiKey`"" }
    if ($SensorId) { $argList += " -SensorId `"$SensorId`"" }

    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

Write-Host "========================================================================" -ForegroundColor Green
Write-Host "   ThreatTrack - Elevated Local Windows Threat Sensor" -ForegroundColor Green
Write-Host "   AI-Based Threat Detection in Unidirectional IP Traffic (SIH PS 26145)" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "[SAFETY POLICY] Passive Ingress Sniffing Only | Zero Packet Injection | Zero Payload Retention" -ForegroundColor Gray

# Locate Python in venv
$pythonExe = Join-Path $projectRoot "venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "python.exe"
}

$runScript = Join-Path $scriptDir "run_sensor.py"

$pythonArgs = @("$runScript")
if ($Interface) {
    $pythonArgs += @("--interface", "$Interface")
}
if ($BackendUrl) {
    $pythonArgs += @("--backend-url", "$BackendUrl")
}
if ($ApiKey) {
    $pythonArgs += @("--api-key", "$ApiKey")
}
if ($SensorId) {
    $pythonArgs += @("--sensor-id", "$SensorId")
}

Write-Host "[*] Launching: $pythonExe $($pythonArgs -join ' ')" -ForegroundColor Cyan
& $pythonExe $pythonArgs
