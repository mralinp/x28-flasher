<div align="center">

<img src="docs/assets/logo.svg" alt="X28 Flasher" width="120">

# X28 Flasher

**Backup, verify and guarded flashing for the ZLT X28 5G CPE (MediaTek MT6890): a double-click app that walks you from a full NAND backup to native OpenWrt, and back again if anything goes wrong.**

[![CI](https://github.com/mralinp/x28-flasher/actions/workflows/ci.yml/badge.svg)](https://github.com/mralinp/x28-flasher/actions/workflows/ci.yml)
![SoC](https://img.shields.io/badge/SoC-MediaTek%20MT6890%20(T750)-orange)
![Platforms](https://img.shields.io/badge/platform-macOS%20%C2%B7%20Linux%20%C2%B7%20Windows-lightgrey)
[![License: GPL v2](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](LICENSE)

[Warning](#warning) · [What it does](#what-it-does) · [Install](#install-and-run) · [The steps](#the-steps) · [Safety model](#safety-model) · [Build](#build-the-binary-and-the-packages) · [Layout](#repository-layout) · [Tests](#tests)

</div>

> [!WARNING]
> <a id="warning"></a>**Your device, your risk.** The X28 is usually someone's only internet connection, and flashing it
> writes its NAND over the MediaTek download agent. Take a verified backup first, keep a UART attached, and read
> [docs/USAGE.md](docs/USAGE.md) before ticking any box. Not affiliated with ZLT, Tozed, MediaTek or Quectel.

The firmware itself lives in [mralinp/zlt-x28-openwrt](https://github.com/mralinp/zlt-x28-openwrt); its docs
(`docs/RECOVERY.md`, `docs/BUILD.md`, `docs/research/`) describe the procedures these tools implement. This repo does
not depend on that repo's code: images, userspace, feed packages and the overlay are downloaded from its releases and
hash-checked.

![X28 Flasher](docs/screenshot.png)

## What it does

| Step | What happens | Writes flash? |
|---|---|---|
| **Connect** | Power off, wait 10 s, power on: finds the unit over USB (BROM) | no |
| **Backup** | Reads all partitions over USB into a hash-verified archive, with a second copy | no |
| **Root access** | Reads a snapshot of slot B and writes key-only SSH (port 22) into it; once, on a fresh unit | **yes** |
| **Read & verify** | Re-reads a partition and compares it with the backup | no |
| **Get an image** | Downloads a release's signed image (checked against the X28 signing key), or assembles one from your own unit's backup plus a firmware release | no |
| **Flash OpenWrt** | Writes slot A (slot B, stock, is locked) behind a dry run and an equality gate | **yes** |
| **Boot order** | A/B switch for the slot that boots next, over SSH on the running modem | **yes** |
| **UART monitor** | Captures the serial console to a log the guarded tools require | no |

## Install and run

Download the package for your system from the [releases page](https://github.com/mralinp/x28-flasher/releases), install it and start
**X28 Flasher**. Nothing else is needed: Python, mtkclient, libusb, the page and the Quectel download agent (`DA_BR.bin`) are inside.

| System | Package | Install |
|---|---|---|
| Linux x86_64 | `X28-Flasher-linux-x86_64.deb` | `sudo apt install ./X28-Flasher-linux-x86_64.deb`, then **X28 Flasher** in the menu or `x28-flasher` |
| Windows x64 | `X28-Flasher-windows-x64-setup.exe` | run it (no administrator rights), then **X28 Flasher** in the Start menu |
| macOS, Apple silicon | `X28-Flasher-macos-arm64.dmg` | drag **X28 Flasher** to Applications; the app is not signed, so the first start is right-click, **Open** |

Every merge to `main` is a release: CI builds the packages and attaches them with a `SHA256SUMS-*.txt` each. CI has no macOS runner
while this repository is private ([#3](https://github.com/mralinp/x28-flasher/issues/3)), so the `.dmg` is only in a release when
that job ran; otherwise [build it](#build-the-binary-and-the-packages) on a Mac.

On a Mac the app has its own window; on Linux and Windows it opens the page in your browser. Only this computer can reach the page;
its **Quit** button stops the flasher.

Two steps use more than the package:

- **Building an image from your backup** and **Root access** assemble the image in a container, so they need Docker. Downloading a
  release's signed image and flashing it needs none.
- **Windows** needs a USB driver that libusb can use for the modem's download port (mtkclient uses [UsbDk](https://github.com/daynix/UsbDk/releases)).
  The Windows package is built and smoke-tested by CI but has not been used on a modem yet.

**From the checkout** instead (for work on the tools; needs Python 3.10+ and libusb, `brew install libusb` on a Mac):

```bash
git clone git@github.com:mralinp/x28-flasher.git
cd x28-flasher
python3 tools/recovery/setup_mtkclient.py        # once: the pinned, patched mtkclient (the page's Setup box does this too)
python3 tools/x28-flasher/x28_flasher.py         # prints the page address and opens it; Ctrl-C or the page's Quit stops it
python3 tools/x28-flasher/x28_flasher.py wizard  # the same steps as a terminal menu
```

The download agent is in this repo (`tools/x28-flasher/assets/DA_BR.bin`, SHA-256 checked), so there is nothing to choose here either.
The page's loader field only overrides it; a saved path that no longer exists is ignored. Log on a Mac: `~/Library/Logs/x28-flasher.log`.

## The steps

1. **Connect**: power off, wait 10 s, power on.
2. **Backup**: do this first and keep the copy off the computer you flash from.
3. **Root access**: once on a fresh unit, after the backup: reads a snapshot of slot B and writes key-only SSH into it.
4. **Get an image**: pick a firmware release and download its signed image, or build one from your backup (the overlay and userspace are downloaded and hash-checked).
5. **Flash OpenWrt**: dry run, then the real write.
6. **Read & verify**: confirm what landed.
7. **Boot order**: switch which slot boots next, when you need to.

Details, prompts and recovery are in **[the manual](docs/USAGE.md)**: what each part is for and how to use it.

## Safety model

- Every writing tool does a **dry run first**, then asks for its own **typed phrase** per step.
- The page needs the **risk checklist** ticked before a writing step starts.
- Receipts bind each step to the hashes of the recovery tools, so those files must not change mid-chain.
- The UART capture must have been updated within 60 s, or the guarded tools refuse.
- Nothing in the front end writes flash itself; it only hands over to `tools/recovery/`.
- Firmware dumps are **never committed** (`.gitignore`). The vendor download agent is the one exception: it is a fixed, hash-checked file kept in this private repository, and every build includes it, so do not make this repository or its releases public.
- Telnet is not offered; `stock_access.py` sets up key-only SSH.

## Build the binary and the packages

This is what CI does (`.github/workflows/ci.yml`), on the system you build for: there is no cross-building. On Windows run the
commands in Git Bash and use `bh/venv/Scripts/python` wherever `bh/venv/bin/python` is written.

**1. Once: libusb, the pinned mtkclient and a build venv in `bh/`**

```bash
brew install libusb                               # macOS
sudo apt-get install -y libusb-1.0-0              # Linux; Windows gets its DLL from pip below

COMMIT="$(python3 -c "import sys; sys.path.insert(0, 'tools/recovery'); import common; print(common.MTKCLIENT_COMMIT)")"
mkdir -p bh/src && git -C bh/src init -q
git -C bh/src fetch -q --depth 1 https://github.com/bkerler/mtkclient.git "$COMMIT"
git -C bh/src -c advice.detachedHead=false checkout -q FETCH_HEAD
python3 -m venv bh/venv
bh/venv/bin/python -m pip install pycryptodome pycryptodomex pyserial pyusb colorama questionary pyinstaller
bh/venv/bin/python -m pip install libusb          # Windows only
```

**2. The binary** (`dist/x28-flasher/`, one folder that runs as it is)

```bash
bh/venv/bin/python tools/x28-flasher/build_binary.py --home bh --out dist --version 0.1.0
dist/x28-flasher/x28-flasher --selftest           # prints "selftest ok"
dist/x28-flasher/x28-flasher                      # serves the page and opens your browser
```

`--version` is the number shown in the page (`dev` without it; CI passes the release it is about to tag). The build installs the
pinned mtkclient into the venv, patches it, and puts `tools/x28-flasher/assets/DA_BR.bin` inside after checking its SHA-256; it
stops if that file is missing or different. `--loader /other/DA_BR.bin` bundles another copy, under the same check.

**3. The package**, from that folder

```bash
# macOS: dist/X28 Flasher.app (a native window when swiftc is installed), then the .dmg
python3 tools/x28-flasher/build_app.py
hdiutil create -volname "X28 Flasher" -srcfolder "dist/X28 Flasher.app" -ov -format UDZO X28-Flasher-macos-arm64.dmg

# Linux: the .deb (installs to /opt/x28-flasher, with a menu entry and /usr/bin/x28-flasher)
tools/x28-flasher/installers/make_deb.sh dist 0.1.0 X28-Flasher-linux-x86_64.deb

# Windows: X28-Flasher-windows-x64-setup.exe (Inno Setup 6: choco install innosetup)
"/c/Program Files (x86)/Inno Setup 6/ISCC.exe" "//DSrc=$(cygpath -w "$PWD/dist/x28-flasher")" "//DOut=$(cygpath -w "$PWD")" "//DVersion=0.1.0" tools/x28-flasher/installers/windows.iss
```

Build again after every `git pull`; `dist/`, `bh/` and `private/` are ignored by git and stay in the checkout. A build contains
Quectel's download agent, so share it only where this repository may be shared.

## Repository layout

| Path | Contents |
|---|---|
| `tools/recovery/` | backup and verify, mtkclient setup, USB reads, guarded flash sessions. Hash-bound: do not edit mid-chain |
| `tools/x28-flasher/` | the page (`gui/`), terminal wizard, app and PyInstaller builds |
| `tools/build/` | image assembly: `stage_native.py`, `first_boot.py`, `ab_guard.py`, `package_ubi.py`, `sysupgrade_tar.py` (the unsigned sysupgrade tarball), `stock_access.py` |
| `tools/firmware/` | the tools container and partition inventory |
| `docs/` | [manual](docs/USAGE.md), assets |

`first_boot.py` reads the firmware's package files from the release's `x28-overlay-*.tar.gz` (the page downloads it; set
`X28_OVERLAY` or extract it to `overlay/` to run the scripts or tests by hand).

## Tests

```bash
export X28_OVERLAY=/path/to/zlt-x28-openwrt      # first_boot.py reads the package files from that checkout (or an extracted x28-overlay-*.tar.gz)
for t in tools/build/test_*.py tools/recovery/test_*.py tools/x28-flasher/test_*.py; do python3 "$t" || break; done
```

CI runs them on Linux x86_64 and Windows x64 (and macOS arm64 when it has a runner), then builds the binary and the package and
smoke-tests the binary.

## Support

Made with ❤️ by mralinp. If this project helps you, please give it a star on GitHub, and donations are welcome on any EVM chain: `0x6743d8fe71f18b3101f3086e8d9f8d272d0f7618`

<img src="docs/support-qr.svg" alt="QR code of the support address" width="160">

## License

GPL-2.0-only, see [LICENSE](LICENSE).
