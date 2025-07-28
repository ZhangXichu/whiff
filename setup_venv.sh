#!/bin/bash
set -e

VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
  echo "creating virtual environment..."
  python3 -m venv "$VENV_DIR"
fi

echo "activating virtual environment and installing requirements..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install conan
echo "done"