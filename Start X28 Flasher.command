#!/bin/sh
# Double-click to open X28 Flasher in your browser. Setup (mtkclient, libusb) happens inside the page.
cd "$(dirname "$0")" || exit 1
for py in python3.15 python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
  p=$(command -v "$py" || ls /opt/homebrew/bin/"$py" 2>/dev/null)
  [ -n "$p" ] && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null && exec "$p" tools/x28-flasher/x28_flasher.py
done
echo "X28 Flasher needs Python 3.10 or newer. Install it from python.org, then double-click this file again."
printf 'Press Enter to close.'; read -r _
