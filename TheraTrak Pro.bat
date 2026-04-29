@echo off
cd /d "%~dp0"

echo ============================================================
echo  DEVELOPER LAUNCH SCRIPT - Requires Python on this machine
echo  End users should run the installed TheraTrak Pro.exe
echo ============================================================
echo.

if not exist main.py (
    echo.
    echo ERROR: main.py was not found in this folder.
    echo.
    pause
    exit /b 1
)

echo Starting TheraTrak Pro (debug mode)...
python main.py
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Could not start TheraTrak Pro.
    echo Make sure Python 3.10+ is installed and on your PATH.
    echo.
    pause
)
