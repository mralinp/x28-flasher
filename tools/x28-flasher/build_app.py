#!/usr/bin/env python3
"""Wrap the PyInstaller output (build_binary.py) in a native macOS app: no Python, Homebrew or Setup step, and no browser.

    python build_app.py [--dist dist]      ->  dist/X28 Flasher.app

Contents/MacOS/X28 Flasher is a small Swift window (native/main.swift, a WKWebView) that starts the frozen x28-flasher
next to it (mtkclient, libusb and the page are inside that) and shows its page. Closing the window quits both. Without
swiftc (Xcode or the command line tools) the app falls back to the frozen binary, which opens the page in your browser.
"""
import argparse
import plistlib
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


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
    (app / "Contents/Resources").mkdir()
    shutil.copy2(src / "x28-flasher", app / "Contents/MacOS/x28-flasher")
    shutil.copytree(src / "_internal", app / "Contents/Frameworks", symlinks=True)  # inside a .app PyInstaller looks here, not next to the executable
    shutil.copy2(HERE / "assets/AppIcon.icns", app / "Contents/Resources/AppIcon.icns")
    native = bool(shutil.which("swiftc"))
    if native:
        subprocess.run(["swiftc", "-O", "-o", str(app / "Contents/MacOS/X28 Flasher"), str(HERE / "native/main.swift"),
                        "-framework", "Cocoa", "-framework", "WebKit"], check=True)
    else:
        print("swiftc not found: the app will open the page in your browser instead of its own window")
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleName": "X28 Flasher", "CFBundleDisplayName": "X28 Flasher", "CFBundleIdentifier": "com.mralinp.x28-flasher",
        "CFBundleExecutable": "X28 Flasher" if native else "x28-flasher", "CFBundleIconFile": "AppIcon",
        "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "NSHighResolutionCapable": True,
        "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},  # the window loads http://127.0.0.1
        **({} if native else {"LSUIElement": True}),  # the browser fallback has no window of its own; its page has Quit
    }))
    print(f"built {app}" + (" (native window)" if native else " (browser)"))


if __name__ == "__main__":
    main()
