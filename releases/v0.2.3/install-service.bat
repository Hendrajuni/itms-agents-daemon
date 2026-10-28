@echo off
setlocal
echo ==============================================================
echo   ITMS Endpoint Agent Daemon v0.2.0 - Service Installer
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
"%~dp0itms-agents-daemon.exe" install
if %errorLevel% equ 0 (
    echo.
    echo [SUCCESS] Windows Service 'ITMSAgentService' berhasil didaftarkan!
    echo.
    choice /M "Apakah Anda ingin langsung menyalakan service sekarang?"
    if %errorlevel% equ 1 (
        "%~dp0itms-agents-daemon.exe" start
    )
) else (
    echo.
    echo [FAILED] Gagal mendaftarkan service. Periksa pesan kesalahan di atas.
)

echo.
pause
