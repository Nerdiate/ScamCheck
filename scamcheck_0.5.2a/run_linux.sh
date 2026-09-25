#!/bin/bash
# Run this with: bash run_linux.sh
# (Double-clicking may just open this in a text editor depending on your
# file manager -- if so, open a terminal in this folder and run the command
# above instead.)

cd "$(dirname "$0")" || exit 1

echo "============================================================"
echo " ScamCheck - starting up"
echo "============================================================"
echo

if command -v uv >/dev/null 2>&1; then
    echo "Found uv - it will download the right Python version automatically"
    echo "if needed, then install requirements and start ScamCheck."
    echo
    echo "Starting ScamCheck... your browser will open automatically in a moment."
    echo "Leave this terminal open while you use ScamCheck. Press Ctrl+C to stop it."
    echo
    uv run webapp/app.py
    exit $?
fi

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "Neither uv nor Python was found on this computer."
    echo
    echo "Easiest fix: install uv - see https://docs.astral.sh/uv/getting-started/installation/"
    echo "then run this script again; uv installs Python for you."
    echo
    echo "Or install Python yourself with your distro's package manager, e.g.:"
    echo "  sudo apt install python3 python3-venv     (Debian/Ubuntu)"
    echo "  sudo dnf install python3                  (Fedora)"
    echo "then run this script again."
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "Setting up ScamCheck for the first time - this only happens once..."
    "$PYTHON" -m venv .venv || {
        echo
        echo "Could not create a Python virtual environment. On Debian/Ubuntu you"
        echo "may need: sudo apt install python3-venv"
        exit 1
    }
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing/updating requirements..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo
echo "Starting ScamCheck... your browser will open automatically in a moment."
echo "Leave this terminal open while you use ScamCheck. Press Ctrl+C to stop it."
echo

python webapp/app.py
