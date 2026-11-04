@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title ThreatTrack Local Windows Sensor

:: ============================================================================
::  ThreatTrack - One-Click Local Windows Sensor Launcher (Passive Sniffer)
::  SIH Problem Statement 26145: AI-Based Detection in Unidirectional Traffic
:: ============================================================================

:: 1. Verify / Request Windows Administrator Elevation (Required for Npcap packet capture)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Windows packet capture requires Administrator privileges for Npcap socket binding.
    echo [*] Requesting Administrator elevation via UAC...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/k cd /d \"\"%~dp0\"\" && \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo ========================================================================
echo    ThreatTrack - Local Windows Network Threat Sensor (Passive Sniffer)
echo    AI-Based Threat Detection in Unidirectional IP Traffic (SIH PS 26145)
echo ========================================================================
echo [SAFETY POLICY]
echo  - Strict Passive Ingress Sniffing (Npcap / Scapy)
echo  - Zero packet injection or transmission onto monitored network.
echo  - Zero packet payload stored; flow statistics and telemetry only.
echo ========================================================================
echo.

:: 2. Verify Virtual Environment
set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
    echo [X] ERROR: Virtual environment not found at:
    echo     %~dp0venv
    echo.
    echo [*] Please verify that the virtual environment exists.
    echo     You can create it by running:
    echo     python -m venv venv
    echo     venv\Scripts\pip install -r backend\requirements.txt
    echo.
    pause
    exit /b 1
)

:: 3. Verify Npcap Driver
if not exist "%SystemRoot%\System32\Npcap" (
    if not exist "%SystemRoot%\System32\wpcap.dll" (
        if not exist "%SystemRoot%\System32\Packet.dll" (
            echo [!] WARNING: Npcap packet capture driver was not detected in System32.
            echo [*] Passive packet capture on Windows requires Npcap with 'WinPcap API-compatible Mode'.
            echo [*] Download and install Npcap from: https://npcap.com/#download
            echo.
        )
    )
)

:: 4. Verify / Initialize Sensor Configuration
set "CONFIG_FILE=%~dp0sensor_config.json"
set "EXAMPLE_FILE=%~dp0sensor_config.example.json"

if not exist "%CONFIG_FILE%" (
    echo [!] NOTE: 'sensor_config.json' was not found in project root.
    if exist "%EXAMPLE_FILE%" (
        echo [*] Initializing '%CONFIG_FILE%' from template...
        copy "%EXAMPLE_FILE%" "%CONFIG_FILE%" >nul
        echo [*] Created '%CONFIG_FILE%'.
        echo.
        echo [!] ACTION REQUIRED:
        echo     Please open 'sensor_config.json' and enter your enrolled 'sensor_id' and 'api_key'.
        echo     Alternatively, copy 'sensor_config.json' from your downloaded sensor package:
        echo     Downloads\ThreatTrack-Sensor\sensor_config.json
        echo.
    )
)

:: 5. Default Network and Backend Settings
set "DEFAULT_INTERFACE=Wi-Fi 3"
set "DEFAULT_BACKEND_URL=https://threattrack-kxqt.onrender.com"

echo [*] Target Interface : %DEFAULT_INTERFACE%
echo [*] Telemetry Backend: %DEFAULT_BACKEND_URL%
echo [*] Configuration   : %CONFIG_FILE%
echo.
echo [*] Launching ThreatTrack Sensor Engine via:
echo     backend\scripts\run_sensor.py
echo.

:: 6. Launch Sensor Engine
"%PYTHON_EXE%" "%~dp0backend\scripts\run_sensor.py" --interface "%DEFAULT_INTERFACE%" --backend-url "%DEFAULT_BACKEND_URL%"

:: 7. Keep terminal open on exit / shutdown
set "EXIT_CODE=%errorlevel%"
echo.
if %EXIT_CODE% neq 0 (
    echo [!] Sensor exited with error code: %EXIT_CODE%
) else (
    echo [*] Sensor stopped cleanly.
)
echo [*] Press any key to close this terminal...
pause >nul
exit /b %EXIT_CODE%

