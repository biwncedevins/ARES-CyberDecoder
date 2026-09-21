#!/usr/bin/env bash
# بناء نسخة تنفيذية على Linux / macOS
set -e
python3 -m venv .venv-build
source .venv-build/bin/activate
pip install -r requirements-build.txt
python tools/make_icon.py
pyinstaller CyberDecoder.spec --noconfirm --clean
echo "تم: dist/CyberDecoder"
