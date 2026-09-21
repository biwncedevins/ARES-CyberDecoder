@echo off
chcp 65001 >nul
echo === بناء CyberDecoder كملف EXE واحد ===
where python >nul 2>nul || (echo لم يتم العثور على Python. ثبّته من python.org ثم أعد المحاولة. & pause & exit /b 1)
python -m venv .venv-build || goto :err
call .venv-build\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt || goto :err
python tools\make_icon.py
pyinstaller CyberDecoder.spec --noconfirm --clean || goto :err
echo.
echo تم! الملف: dist\CyberDecoder.exe
pause
exit /b 0
:err
echo فشل البناء.
pause
exit /b 1
