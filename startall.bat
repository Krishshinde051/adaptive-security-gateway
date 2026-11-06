@echo off
title AEGIS - Start All
cd /d "%~dp0"

echo ============================================
echo   AEGIS - starting demo app + gateway
echo ============================================
echo.

rem --- stop anything already listening on our ports ---
for /f "tokens=5" %%p in ('netstat -ano ^| findstr LISTENING ^| findstr ":5001 :8090"') do (
    taskkill /f /pid %%p >nul 2>&1
)
timeout /t 1 /nobreak >nul

rem --- 1) vulnerable demo target on :5001 ---
start "AEGIS demo app :5001" /d "%~dp0" cmd /k python demo-app\app.py
echo [1/2] demo app  -^> http://127.0.0.1:5001

rem --- 2) gateway / reverse proxy on :8090 ---
start "AEGIS gateway :8090" /d "%~dp0" cmd /k python -m uvicorn app:app --host 0.0.0.0 --port 8090 --app-dir gateway
echo [2/2] gateway    -^> http://127.0.0.1:8090

rem --- wait for the gateway to answer ---
set /a tries=0
:wait
timeout /t 1 /nobreak >nul
set /a tries+=1
curl -s -o nul http://127.0.0.1:8090/api/health
if errorlevel 1 if %tries% lss 30 goto wait

echo.
if %tries% geq 30 (
    echo [!] gateway did not answer in 30s - check the "AEGIS gateway" window
    pause
    exit /b 1
)
echo [ok] gateway is up

rem --- LAN IP of the REAL nic (the one that holds the default route) ---
rem     never pick the WSL/Hyper-V vEthernet adapters - other devices can't reach those.
set "lan="
for /f "usebackq delims=" %%a in (`python -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('8.8.8.8',80));print(s.getsockname()[0])"`) do set "lan=%%a"
set "nic="
if not defined lan for /f "usebackq delims=" %%a in (`powershell -NoProfile -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias"`) do set "nic=%%a"
if defined nic for /f "usebackq delims=" %%a in (`powershell -NoProfile -Command "(Get-NetIPAddress -InterfaceAlias '%nic%' -AddressFamily IPv4 | Select-Object -First 1).IPAddress"`) do set "lan=%%a"
set "lan=%lan: =%"

echo.
echo   Dashboard (PC)    : http://127.0.0.1:8090/
if defined lan echo   Dashboard (LAN)   : http://%lan%:8090/
echo   Demo app (PC)     : http://127.0.0.1:5001
if defined lan echo   Demo app (LAN)    : http://%lan%:5001
echo.
echo   Other devices on this network open the LAN urls above.
echo   Blocked your own IP?  Blocked clients -^> remove  (or POST /api/unblock)
echo.
echo   Close the two server windows to stop everything.
echo.

start "" http://127.0.0.1:8090/
pause
