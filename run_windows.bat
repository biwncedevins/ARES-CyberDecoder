@echo off
chcp 65001 >nul
if not exist .venv\Scripts\python.exe (
  python -m venv .venv || (echo ثبّت Python 3.10+ أولاً & pause & exit /b 1)
  .venv\Scripts\python -m pip install -r requirements.txt || (pause & exit /b 1)
)
start "" .venv\Scripts\pythonw.exe main.py %*
