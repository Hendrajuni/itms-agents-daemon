@echo off
setlocal
echo ==============================================================
echo   ITMS Endpoint Agent Daemon v0.2.0 - Foreground Debug Runner
echo ==============================================================
echo.
echo Mode ini menjalankan agent langsung di jendela konsol saat ini.
echo Cocok untuk pengujian koneksi, verifikasi log telemetri, dan debug.
echo Tekan Ctrl+C untuk menghentikan daemon secara graceful.
echo.

if not exist "%~dp0agent.toml" (
    if exist "%~dp0agent.toml.example" (
        echo [INFO] Menyalin template agent.toml.example ke agent.toml...
        copy "%~dp0agent.toml.example" "%~dp0agent.toml" >nul
    )
)

"%~dp0itms-agents-daemon.exe" run
pause
