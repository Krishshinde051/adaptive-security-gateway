@echo off
title Vulnerable Demo Target
cd /d "%~dp0"
echo Starting demo target on http://127.0.0.1:5001
python demo-app\app.py
pause
