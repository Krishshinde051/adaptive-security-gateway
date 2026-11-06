@echo off
title Adaptive Security Gateway
cd /d "%~dp0"
echo Starting gateway on http://127.0.0.1:8090 (LAN: 0.0.0.0)
python -m uvicorn app:app --host 0.0.0.0 --port 8090 --app-dir gateway
pause
