@echo off
setlocal
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Script ini memerlukan hak akses Administrator!
    pause
    exit /b 1
)

echo [INFO] Menyalakan service 'ITMSAgentService'...
"%~dp0itms-agents-daemon.exe" start
pause
