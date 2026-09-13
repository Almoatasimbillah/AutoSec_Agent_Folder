@echo off
chcp 65001 >nul
title AutoSec Agent — Mission Control Server

cd /d "%~dp0"

echo =======================================================================
echo   AutoSec Agent — Mission Control Dashboard
echo   Lead Researcher: Al-Moatasem Bellah (المعتصم بالله)
echo =======================================================================
echo.

:: 1. Check if server is already running on port 8000
powershell -NoProfile -Command "$conn = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue; if ($conn) { exit 1 } else { exit 0 }"
if %ERRORLEVEL% EQU 1 (
    echo [*] السيرفر يعمل بالفعل حالياً على المنفذ 8000!
    echo [*] جاري فتح لوحة التحكم Mission Control في المتصفح...
    start http://localhost:8000
    ping 127.0.0.1 -n 3 >nul
    exit /b 0
)

:: 2. Verify virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [!] خطأ: لم يتم العثور على البيئة الافتراضية .venv
    echo [!] تأكد من وجود المجلد: %CD%\.venv
    pause
    exit /b 1
)

:: 3. Launch Mission Control Server
echo [+] جاري تشغيل الخادم على الرابط: http://localhost:8000
echo [+] سيتم فتح المتصفح تلقائياً خلال ثانيتين...
echo [+] لإيقاف السيرفر، يمكنك إغلاق هذه النافذة أو تشغيل ملف stop_server.bat
echo -----------------------------------------------------------------------
echo.

:: Open browser automatically after 2 seconds in background
start "" cmd /c "ping 127.0.0.1 -n 2 >nul & start http://localhost:8000"

:: Start Uvicorn / FastAPI server in this window so logs are visible
".venv\Scripts\python.exe" -m src.web.server

pause
