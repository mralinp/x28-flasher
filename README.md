<div align="center">

<img src="docs/assets/logo.svg" alt="X28 Flasher" width="120">

# X28 Flasher

**Backup, verify and guarded flashing for the ZLT X28 5G CPE (MediaTek MT6890): a double-click app that walks you from a full NAND backup to native OpenWrt, and back again if anything goes wrong.**

[![CI](https://github.com/mralinp/x28-flasher/actions/workflows/ci.yml/badge.svg)](https://github.com/mralinp/x28-flasher/actions/workflows/ci.yml)
![SoC](https://img.shields.io/badge/SoC-MediaTek%20MT6890%20(T750)-orange)
![Platforms](https://img.shields.io/badge/platform-macOS%20%C2%B7%20Linux-lightgrey)
[![License: GPL v2](https://img.shields.io/badge/license-GPL--2.0--only-blue.svg)](LICENSE)

[Warning](#warning) · [What it does](#what-it-does) · [Install](#install-and-run) · [The steps](#the-steps) · [Safety model](#safety-model) · [Run and build](#run-and-build-the-commands) · [Layout](#repository-layout) · [Tests](#tests)

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
| **Build image** | Assembles a native OpenWrt slot image from your own unit's backup plus a firmware release | no |
| **Flash OpenWrt** | Writes slot A (slot B, stock, is locked) behind a dry run and an equality gate | **yes** |
| **Boot order** | A/B switch for the slot that boots next, over SSH on the running modem | **yes** |
| **UART monitor** | Captures the serial console to a log the guarded tools require | no |

## Install and run

Two flavours of `X28 Flasher.app`:

| | Packaged | From the checkout |
|---|---|---|
| Needs | nothing: Python, mtkclient, libusb and the page are inside | Python 3.10+, Homebrew (for libusb) |
| Window | native (small Swift WKWebView) | your browser |
| Can write | **no**, read-only until the [#272](https://github.com/mralinp/x28-flasher/issues/272) gate exists | yes |
| Start | double-click `dist/X28 Flasher.app` | double-click `X28 Flasher.app`, or `python3 tools/x28-flasher/x28_flasher.py` |

```bash
git clone git@github.com:mralinp/x28-flasher.git
cd x28-flasher
python3 tools/recovery/setup_mtkclient.py     # once: the pinned, patched mtkclient (the page's Setup box does this too)
python3 tools/x28-flasher/x28_flasher.py      # opens the page in your browser
python3 tools/x28-flasher/x28_flasher.py wizard   # the same steps as a terminal menu
```

Only this computer's browser can reach the page; its **Quit** button stops the flasher. Log:
`~/Library/Logs/x28-flasher.log`.

The Quectel download agent (`DA_BR.bin`) is in this repo (`tools/x28-flasher/assets/`, SHA-256 checked) and every build bundles it, so there is nothing to choose. The page's loader field only overrides it; a saved path that no longer exists is ignored.

## The steps

1. **Connect**: power off, wait 10 s, power on.
2. **Backup**: do this first and keep the copy off the computer you flash from.
3. **Root access**: once on a fresh unit, after the backup: reads a snapshot of slot B and writes key-only SSH into it.
4. **Build image**: pick a firmware release; the overlay and userspace are downloaded and hash-checked.
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

## Run and build: the commands

**Run from the checkout** (the version that can write; use this for a flash):

```bash
cd x28-flasher
python3 tools/recovery/setup_mtkclient.py        # once: the pinned, patched mtkclient (the page's Setup box does this too)
python3 tools/x28-flasher/x28_flasher.py         # prints the page address and opens it; Ctrl-C or the page's Quit stops it
python3 tools/x28-flasher/x28_flasher.py wizard  # the same steps as a terminal menu
```

**Run the packaged app** (read-only until [#272](https://github.com/mralinp/x28-flasher/issues/272); a program in the terminal, not a window, unless you built the app below):

```bash
dist/x28-flasher/x28-flasher                     # the frozen binary: serves the page and opens your browser
open "dist/X28 Flasher.app"                      # the same in a native window
```

**Test:**

```bash
export X28_OVERLAY=/path/to/zlt-x28-openwrt      # first_boot.py reads the package files from that checkout (or an extracted x28-overlay-*.tar.gz)
for t in tools/build/test_*.py tools/recovery/test_*.py tools/x28-flasher/test_*.py; do python3 "$t" || break; done
```

**Build the app** from a fresh clone (macOS on Apple silicon; `brew install libusb` once). This is what CI does, in `.github/workflows/ci.yml`:

```bash
# 1. the pinned mtkclient and a build venv in bh/
COMMIT="$(python3 -c "import sys; sys.path.insert(0, 'tools/recovery'); import common; print(common.MTKCLIENT_COMMIT)")"
mkdir -p bh/src && git -C bh/src init -q
git -C bh/src fetch -q --depth 1 https://github.com/bkerler/mtkclient.git "$COMMIT"
git -C bh/src -c advice.detachedHead=false checkout -q FETCH_HEAD
python3 -m venv bh/venv
bh/venv/bin/pip install pycryptodome pycryptodomex pyserial pyusb colorama questionary pyinstaller
# 2. the binary (dist/x28-flasher/), then the app (dist/X28 Flasher.app, a native window when swiftc is available)
bh/venv/bin/python tools/x28-flasher/build_binary.py --home bh --out dist
python3 tools/x28-flasher/build_app.py
```

The download agent from `tools/x28-flasher/assets/DA_BR.bin` is bundled automatically (checked against its expected SHA-256; it is Quectel's file, so do not share a build). `--loader /other/DA_BR.bin` uses another copy.
Name a version if you want one shown in the page (a local build says `dev`; CI passes the release it is about to tag):

```bash
bh/venv/bin/python tools/x28-flasher/build_binary.py --home bh --out dist --version 0.1.0
python3 tools/x28-flasher/build_app.py
```

Build again after every `git pull`; `dist/`, `bh/` and `private/` are ignored by git and stay in the checkout.

## Repository layout

| Path | Contents |
|---|---|
| `tools/recovery/` | backup and verify, mtkclient setup, USB reads, guarded flash sessions. Hash-bound: do not edit mid-chain |
| `tools/x28-flasher/` | the page (`gui/`), terminal wizard, app and PyInstaller builds |
| `tools/build/` | image assembly: `stage_native.py`, `first_boot.py`, `ab_guard.py`, `package_ubi.py`, `stock_access.py` |
| `tools/firmware/` | the tools container and partition inventory |
| `docs/` | [manual](docs/USAGE.md), assets |

`first_boot.py` reads the firmware's package files from the release's `x28-overlay-*.tar.gz` (the page downloads it; set
`X28_OVERLAY` or extract it to `overlay/` to run the scripts or tests by hand).

## Tests

```bash
for t in tools/build/test_*.py tools/recovery/test_*.py tools/x28-flasher/test_*.py; do python3 "$t" || break; done
```

CI runs them on macOS arm64 and Linux x86_64, then builds the read-only binary.

## Support

Made with ❤️ by mralinp. If this project helps you, please give it a star on GitHub, and donations are welcome on any EVM chain: `0x6743d8fe71f18b3101f3086e8d9f8d272d0f7618`

<img src="docs/support-qr.svg" alt="QR code of the support address" width="160">

## License

GPL-2.0-only, see [LICENSE](LICENSE).
