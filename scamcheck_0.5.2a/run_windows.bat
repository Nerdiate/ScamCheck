@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  ScamCheck - starting up
echo ============================================================
echo.

set "UV_CMD="
where uv >nul 2>nul
if not errorlevel 1 set "UV_CMD=uv"

REM "where" only sees the CURRENT session's PATH. uv's installer updates the
REM user PATH in the registry, but an already-open terminal (or a VM that
REM hasn't been restarted since installing uv) won't pick that up yet -- so
REM also check uv's standard install locations directly as a fallback.
if not defined UV_CMD if exist "%USERPROFILE%\.local\bin\uv.exe" set "UV_CMD=%USERPROFILE%\.local\bin\uv.exe"
if not defined UV_CMD if exist "%USERPROFILE%\AppData\Roaming\uv\bin\uv.exe" set "UV_CMD=%USERPROFILE%\AppData\Roaming\uv\bin\uv.exe"
if not defined UV_CMD if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\uv.exe" set "UV_CMD=%LOCALAPPDATA%\Microsoft\WinGet\Links\uv.exe"

if defined UV_CMD (
    echo Found uv - it will download the right Python version automatically
    echo if needed, then install requirements and start ScamCheck.
    echo.
    echo Starting ScamCheck... your browser will open automatically in a moment.
    echo Leave this window open while you use ScamCheck. Close this window to stop it.
    echo.
    "%UV_CMD%" run webapp\app.py
    if errorlevel 1 (
        echo.
        echo Something went wrong. Please screenshot this window and share it
        echo with whoever gave you this tool.
        pause
        exit /b 1
    )
    pause
    exit /b 0
)

echo Could not find uv on this computer's PATH.
echo If you just installed uv, this may be an already-open window that hasn't
echo picked up the change yet -- try closing this window, opening a fresh one
echo (or rebooting), and double-clicking this file again before continuing.
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Neither uv nor Python was found on this computer.
    echo.
    echo Easiest fix: install uv from https://docs.astral.sh/uv/getting-started/installation/
    echo then double-click this file again - uv installs Python for you.
    echo.
    echo Or, install Python yourself from https://www.python.org/downloads/
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
