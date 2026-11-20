@echo off
setlocal
echo ==============================================================
echo   ITMS Endpoint Agent Daemon v0.2.3 - Service Installer
echo ==============================================================
echo.

:: Memeriksa hak akses Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Script ini memerlukan hak akses Administrator!
    echo Silakan klik kanan file ini lalu pilih "Run as Administrator".
    echo.
    pause
    exit /b 1
)

:: Cek keberadaan file konfigurasi
if not exist "%~dp0agent.toml" (
    if exist "%~dp0agent.toml.example" (
        echo [INFO] Menduplikasi agent.toml.example menjadi agent.toml...
        copy "%~dp0agent.toml.example" "%~dp0agent.toml" >nul
        echo [IMPORTANT] Harap sesuaikan URL server dan agent_key pada file agent.toml!
    )
)

echo [INFO] Mendaftarkan ITMS Endpoint Agent ke Windows Service Control Manager...
sc.exe create ITMSAgentService binPath= "\"%~dp0itms-agents-daemon.exe\" service" DisplayName= "ITMS Endpoint Telemetry Daemon" start= auto
if %errorLevel% neq 0 goto :failed

sc.exe description ITMSAgentService "ITMS Windows Endpoint Agent for Application and DNS Telemetry Tracking" >nul
echo.
echo [SUCCESS] Windows Service 'ITMSAgentService' berhasil didaftarkan!
echo.
choice /M "Apakah Anda ingin langsung menyalakan service sekarang?"
if errorlevel 2 goto :end
if errorlevel 1 (
    echo [INFO] Menyalakan service 'ITMSAgentService'...
    sc.exe start ITMSAgentService
)
goto :end

:failed
echo.
echo [FAILED] Gagal mendaftarkan service. Periksa pesan kesalahan di atas.

:end
echo.
pause
