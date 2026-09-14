@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  ScamCheck - starting up
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on this computer.
    echo.
    echo Please install it from https://www.python.org/downloads/
    echo IMPORTANT: on the first screen of the installer, check the box
    echo that says "Add python.exe to PATH" before clicking Install.
    echo.
    echo Then double-click this file again.
    echo.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo Setting up ScamCheck for the first time - this only happens once...
    python -m venv .venv
    if errorlevel 1 (
        echo.
        echo Something went wrong setting up Python. Please screenshot this
        echo window and share it with whoever gave you this tool.
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

echo Installing/updating requirements...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo.
    echo Something went wrong installing requirements. Please screenshot
    echo this window and share it with whoever gave you this tool.
    pause
    exit /b 1
)

echo.
echo Starting ScamCheck... your browser will open automatically in a moment.
echo Leave this window open while you use ScamCheck. Close this window to stop it.
echo.

python webapp\app.py

pause
