@echo off
chcp 65001 >nul
title AutoSec Agent — Stop Server

echo =======================================================================
echo   AutoSec Agent — Mission Control
echo   Stopping server on port 8000 and proxy on port 8085...
echo =======================================================================
echo.

powershell -NoProfile -Command "$ports = @(8000, 8085); $stopped = 0; foreach ($p in $ports) { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Write-Host "[+] Terminating $($proc.ProcessName) (PID: $($proc.Id)) on port $p..."; Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue; $stopped++ } } }; if ($stopped -eq 0) { Write-Host "[*] لم يتم العثور على سيرفر يعمل حالياً على المنفذ 8000 أو 8085." } else { Write-Host "`n[✓] تم إيقاف السيرفر والبروكسي بنجاح!" }"

echo.
echo اضغط أي زر للإغلاق...
ping 127.0.0.1 -n 3 >nul
