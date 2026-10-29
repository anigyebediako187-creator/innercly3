@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python 3 is not installed or is not on PATH.
  echo Install Python 3.11 or newer from python.org, then run this file again.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto fail
)
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 goto fail
set APP_ENV=development
python launch_app.py
if errorlevel 1 goto fail
exit /b 0
:fail
echo.
echo InnerCly could not start. Read the error above.
pause
exit /b 1
