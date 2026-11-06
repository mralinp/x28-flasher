# x28-flasher

Backup, verify and guarded flashing tools for the ZLT X28 5G CPE (MediaTek MT6890). The firmware itself lives in
[mralinp/zlt-x28-openwrt](https://github.com/mralinp/zlt-x28-openwrt); its docs (`docs/RECOVERY.md`, `docs/BUILD.md`,
`docs/research/`) describe the procedures these tools implement.

- `tools/recovery/`: backup and verify, mtkclient setup, USB reads, and the guarded flash sessions (dry run first, typed phrase per step). Do not edit these mid-chain: their hashes bind the receipts.
- `tools/x28-flasher/`: the wizard and the single-binary build (PyInstaller). Frozen builds are read-only.
- `tools/build/`, `tools/firmware/`: image assembly (`stage_native.py`, `first_boot.py`, `ab_guard.py`, `package_ubi.py`) and the tools container. `first_boot.py` reads the firmware's package files from the release's `x28-overlay-*.tar.gz` (the wizard downloads it; set `X28_OVERLAY` or extract it to `overlay/` to run the scripts or tests by hand).

```
git clone git@github.com:mralinp/x28-flasher.git
for t in tools/recovery/test_*.py tools/x28-flasher/test_*.py; do python3 "$t"; done
```

This repo does not depend on the firmware repo's code: images, userspace, feed packages and the overlay are downloaded from its releases and hash-checked. The vendor download agent and any firmware dumps are never committed.
Licence: GPL-2.0-only.

## Using it

Open `X28 Flasher.app` (double-click it in Finder). The packaged app is a native window (a small Swift WKWebView, built by `build_app.py` when `swiftc` is available) around the page; closing the window quits it. The app from the checkout starts the flasher in the background and shows the page in your browser; the page's **Quit** button stops it. Log: `~/Library/Logs/x28-flasher.log`.

Two flavours of the app:

- **Packaged** (`python tools/x28-flasher/build_binary.py --home bh --out dist && python tools/x28-flasher/build_app.py` gives `dist/X28 Flasher.app`; see the CI steps for `bh`): holds Python, mtkclient, libusb and the page, so nothing needs installing. Add `--loader /path/to/DA_BR.bin` to `build_binary.py` to put your download agent inside the app too (checked against the expected SHA-256; it is Quectel's file, so it is never committed or built by CI, and an app built with it is for your own use); without it you choose the file in the page. It is read-only: Connect, Backup, Read & verify, Self-test, UART and Build image work; writing steps are refused until the #272 gate exists.
- **From the checkout** (`X28 Flasher.app` in the repo, or `python3 tools/x28-flasher/x28_flasher.py`): needs Python 3.10 or newer; the page's Setup box installs libusb (needs Homebrew) and the pinned, patched mtkclient, then restarts itself. This one can write (Flash OpenWrt, Stock SSH access, Rescue). `x28_flasher.py wizard` is the terminal menu.

The page walks you through Connect (power off, 10 s, power on), then Backup, Build image, Flash OpenWrt, Read & verify, Self-test, UART monitor, Stock SSH access and Rescue (slot B). Every step runs the guarded tools; a step that writes needs the risk checklist ticked and the tool's own typed phrase. Only this computer's browser can reach the page. The packaged binary is read-only (#272). Telnet is not offered: `stock_access.py` sets up key-only SSH.
