@echo off
setlocal
cd /d "%~dp0"
if exist "backend\src\sensor\cli.py" (
    cd backend
)
title ThreatTrack Local Windows Sensor Launcher

:: 1. Verify / Request Windows Administrator Elevation (Required for Npcap socket binding)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Windows packet capture requires Administrator privileges.
    echo [*] Requesting standard UAC elevation...
    powershell -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: 2. Verify Python Installation
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] Python was not found on your system PATH.
    echo [*] Please install Python 3.9+ from https://www.python.org/downloads/
    echo [*] Ensure 'Add Python to PATH' is checked during installation.
    pause
    exit /b
)

:: 3. Verify Npcap Driver
if not exist "%SystemRoot%\System32\Npcap" (
    if not exist "%SystemRoot%\System32\wpcap.dll" (
        echo [!] WARNING: Npcap packet capture driver was not detected.
        echo [*] Passive packet sniffing requires Npcap (https://npcap.com/#download).
        echo [*] Opening Npcap download page in browser...
        start https://npcap.com/#download
        echo [*] Please install Npcap with 'Install Npcap in WinPcap API-compatible Mode' enabled.
        pause
    )
)

:: 4. Verify / Install Dependencies
python -c "import scapy" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing required sensor dependencies (scapy)...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [X] Dependency installation failed. Check internet connection.
        pause
        exit /b
    )
)

:: 5. Launch ThreatTrack Sensor
echo [*] Launching ThreatTrack Sensor Engine...
python -m src.sensor.cli
if %errorlevel% neq 0 (
    echo [!] Sensor exited with status code %errorlevel%.
    pause
)
