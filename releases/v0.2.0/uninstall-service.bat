@echo off
setlocal
echo ==============================================================
echo   ITMS Endpoint Agent Daemon v0.2.0 - Service Uninstaller
echo ==============================================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Script ini memerlukan hak akses Administrator!
    echo Silakan klik kanan file ini lalu pilih "Run as Administrator".
    echo.
    pause
    exit /b 1
)

echo [INFO] Menghentikan dan menghapus Windows Service 'ITMSAgentService'...
"%~dp0itms-agents-daemon.exe" stop >nul 2>&1
"%~dp0itms-agents-daemon.exe" uninstall
if %errorLevel% equ 0 (
    echo.
    echo [SUCCESS] Windows Service 'ITMSAgentService' berhasil dicabut/dihapus.
) else (
    echo.
    echo [FAILED] Gagal mencabut service. Periksa pesan kesalahan di atas.
)

echo.
pause
