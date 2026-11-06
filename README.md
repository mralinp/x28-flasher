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
