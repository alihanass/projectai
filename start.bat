@echo off
cd /d "%~dp0"
echo Starting CyberShield AI Backend + SQLite Database...
start "" http://127.0.0.1:5000
python app.py
pause
