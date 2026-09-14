#!/bin/bash
# Double-click this file in Finder to run ScamCheck.
# If macOS refuses to open it the first time ("unidentified developer"),
# right-click (or Control-click) the file and choose "Open" instead --
# you only need to do that once.

cd "$(dirname "$0")" || exit 1

echo "============================================================"
echo " ScamCheck - starting up"
echo "============================================================"
echo

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "Python 3 was not found on this computer."
    echo
    echo "Please install it from https://www.python.org/downloads/"
    echo "and then double-click this file again."
    echo
    read -r -p "Press Enter to close this window..."
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "Setting up ScamCheck for the first time - this only happens once..."
    "$PYTHON" -m venv .venv || {
        echo
        echo "Something went wrong setting up Python. Please screenshot this"
        echo "window and share it with whoever gave you this tool."
        read -r -p "Press Enter to close this window..."
        exit 1
    }
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing/updating requirements..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt || {
    echo
    echo "Something went wrong installing requirements. Please screenshot"
    echo "this window and share it with whoever gave you this tool."
    read -r -p "Press Enter to close this window..."
    exit 1
}

echo
echo "Starting ScamCheck... your browser will open automatically in a moment."
echo "Leave this window open while you use ScamCheck. Close this window (or press Ctrl+C) to stop it."
echo

python webapp/app.py

read -r -p "Press Enter to close this window..."
