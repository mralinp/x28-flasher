#!/usr/bin/env python3
"""Build the x28-flasher single binary (PyInstaller, onedir) from the pinned, patched mtkclient (#272).

    python build_binary.py --home BUILD_HOME

BUILD_HOME/src is a checkout of the pinned mtkclient commit and BUILD_HOME/venv a venv (run this with its Python) that has
pycryptodome, pycryptodomex, pyserial, pyusb, colorama, questionary and pyinstaller installed. mtkclient is installed from src without its
GUI dependencies (PySide6) and patched with setup_mtkclient.PATCHES; the developer identity check then has to accept it, and the
SHA-256 of the patched XML library is embedded as identity.json for the frozen identity check.
"""
import argparse
import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
sys.path.insert(0, str(TOOLS / "recovery"))
XML = "mtkclient/Library/DA/xmlflash/xml_lib.py"
BUILD_FILES = ("package_ubi.py", "stage_native.py", "ab_guard.py", "stock_access.py")


def run(*cmd, **kw):
    print("+", " ".join(map(str, cmd)), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def stdlib_imports(files):
    """Top-level stdlib modules the tools import: they run from data files, so PyInstaller's analysis cannot see them."""
    found = set()
    for f in files:
        for node in ast.walk(ast.parse(f.read_text())):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.module and not node.level else []
            found |= {n.split(".")[0] for n in names}
    local = {p.stem for p in (TOOLS / "recovery").glob("*.py")} | {"mtkclient", "slot_session"} | {p.stem for p in (TOOLS / "build").glob("*.py")}
    return sorted(n for n in found if n in sys.stdlib_module_names and n not in local)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--home", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("dist"))
    ap.add_argument("--loader", type=Path, help="your DA_BR.bin: put it inside this build only (it is Quectel's, never committed or built by CI; do not share the result)")
    ap.add_argument("--version", default="dev", help="the app's version, shown in the page (CI passes the release it is about to tag)")
    args = ap.parse_args()
    home = args.home.resolve()
    os.environ["X28_MTKCLIENT"] = str(home)  # before common is imported
    from common import MTKCLIENT_COMMIT
    from setup_mtkclient import PATCHES
    head = subprocess.check_output(["git", "-C", home / "src", "rev-parse", "HEAD"], text=True).strip()
    if head != MTKCLIENT_COMMIT or Path(sys.executable).resolve() != (home / "venv/bin/python").resolve():
        sys.exit("BUILD_HOME/src must be the pinned commit and this must run under BUILD_HOME/venv")

    if subprocess.check_output(["git", "-C", home / "src", "status", "--porcelain", "--ignored"], text=True).strip():
        sys.exit("BUILD_HOME/src is not a clean checkout of the pinned commit")  # the identity check only covers xml_lib.py
    run(sys.executable, "-m", "pip", "install", "-q", "--no-deps", home / "src")
    pkg = next((home / "venv").glob("**/site-packages/mtkclient"))
    for rel, old, new, required in PATCHES:
        path = pkg / rel
        text = path.read_text()
        if new in text:
            continue
        if text.count(old) != 1:
            if not required:
                continue
            sys.exit(f"patch target not found in {path}")
        path.write_text(text.replace(old, new))
    for cache in pkg.rglob("__pycache__"):
        shutil.rmtree(cache)

    from restore_entry import host_identity  # developer identity: pinned source + PATCHES == installed library
    xml = host_identity()
    work = args.out.resolve().parent / "build-x28-flasher"
    work.mkdir(parents=True, exist_ok=True)
    from importlib.metadata import version
    tools = {n: version(n) for n in ("pyinstaller", "pyusb", "pycryptodome", "pycryptodomex", "pyserial", "colorama", "questionary", "prompt_toolkit")}
    (work / "identity.json").write_text(json.dumps({"version": args.version, "commit": MTKCLIENT_COMMIT, "xml_lib_sha256": hashlib.sha256(xml.encode()).hexdigest(),
                                                    "python": sys.version.split()[0], "build_tools": tools}, indent=1))
    data = [(work / "identity.json", "."), (pkg.parent / XML, str(Path(XML).parent))]
    data += [(f, "recovery") for f in (TOOLS / "recovery").glob("*.py") if not f.name.startswith("test_")]
    data += [(TOOLS / "recovery" / "x28-mtd.txt", "recovery")]
    data += [(TOOLS / "build" / n, "build") for n in BUILD_FILES]
    # Build runs these (and mounts tools/ into its container) under the layout REPO/tools/..., which common.REPO points at when frozen
    data += [(TOOLS / "build" / n, "tools/build") for n in BUILD_FILES + ("first_boot.py", "stock_access.py", "x28-killswitch.sh")]
    data += [(TOOLS / "firmware" / n, "tools/firmware") for n in ("Dockerfile", "inventory.py")]
    data += [(TOOLS / "firmware" / "inventory.py", "firmware")]  # the guarded tools import build/stage_native, which looks for ../firmware/inventory.py
    data += [(f, "gui/fonts") for f in sorted((HERE / "gui" / "fonts").glob("*"))]  # the same fonts on every system
    data += [(HERE / "gui" / "index.html", "gui"), (HERE / "device_info.py", "gui")]  # the page and the tool it runs
    if args.loader:
        from restore_entry import DA_HASH
        if hashlib.sha256(args.loader.read_bytes()).hexdigest() != DA_HASH:
            sys.exit(f"{args.loader} is not the download agent the tools expect (SHA-256 differs)")
        shutil.copy2(args.loader, work / "DA_BR.bin")  # whatever it is called, the tools look for this name
        data += [(work / "DA_BR.bin", "vendor-da")]
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "x28-flasher",
           "--distpath", args.out, "--workpath", work, "--specpath", work, "--exclude-module", "PySide6", "--exclude-module", "mtkclient.gui",
           "--collect-data", "mtkclient", "--collect-binaries", "usb"]
    for pkg_name in ("mtkclient", "usb", "serial", "Crypto", "Cryptodome", "colorama", "questionary", "prompt_toolkit"):
        cmd += ["--collect-submodules", pkg_name]
    for name in ("session_host",):  # only imported by name at run time (x28_flasher session), so PyInstaller's scan would miss it
        cmd += ["--hidden-import", name]
    for name in stdlib_imports([f for f, d in data if f.suffix == ".py" and d in ("recovery", "build", "tools/build", "tools/firmware")]):
        cmd += ["--hidden-import", name]
    for src, dest in data:
        cmd += ["--add-data", f"{src}{os.pathsep}{dest}"]
    run(*cmd, HERE / "x28_flasher.py")
    print(f"built {args.out / 'x28-flasher'}  (patched XML library sha256 {hashlib.sha256(xml.encode()).hexdigest()[:12]})")


if __name__ == "__main__":
    main()
