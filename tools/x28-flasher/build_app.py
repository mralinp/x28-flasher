#!/usr/bin/env python3
"""Wrap the PyInstaller output (build_binary.py) in a double-clickable macOS app: no Python, Homebrew or Setup step needed.

    python build_app.py [--dist dist]      ->  dist/X28 Flasher.app

The app's executable is the frozen x28-flasher (mtkclient, libusb and the page are inside it). Opening it starts the
backend in the background and shows the page; opening it again shows the same page; Quit is in the page.
"""
import argparse
import plistlib
import shutil
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dist", type=Path, default=Path("dist"))
    args = ap.parse_args()
    src = args.dist / "x28-flasher"
    if not (src / "x28-flasher").is_file():
        raise SystemExit(f"{src}/x28-flasher not found: run build_binary.py first")
    app = args.dist / "X28 Flasher.app"
    shutil.rmtree(app, ignore_errors=True)
    (app / "Contents/MacOS").mkdir(parents=True)
    shutil.copy2(src / "x28-flasher", app / "Contents/MacOS/x28-flasher")
    shutil.copytree(src / "_internal", app / "Contents/Frameworks", symlinks=True)  # inside a .app PyInstaller looks here, not next to the executable
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleName": "X28 Flasher", "CFBundleDisplayName": "X28 Flasher", "CFBundleIdentifier": "com.mralinp.x28-flasher",
        "CFBundleExecutable": "x28-flasher", "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
        "LSUIElement": True,  # no Dock icon; the page's Quit button stops it
    }))
    print(f"built {app}")


if __name__ == "__main__":
    main()
