# Using X28 Flasher

Read the warning in the [README](../README.md#warning) first. The firmware side of every step is documented in
[zlt-x28-openwrt `docs/RECOVERY.md`](https://github.com/mralinp/zlt-x28-openwrt/blob/main/docs/RECOVERY.md).

## Before you start

- A **verified backup** of your own unit, stored on a second disk. Nothing here replaces it.
- A **UART** adapter on the unit's debug pins. The guarded tools refuse to flash unless its log updated in the last 60 s.
- `DA_BR.bin`, the Quectel download agent (not distributed here).
- A USB cable to the modem port; the unit powered from its own supply.

## Connect

Power the unit off, wait **10 s**, power it on. The page tells you when to plug in USB (only for tools that wait for the
modem). If the unit is not found, repeat the sequence; do not start a write on a flaky connection.

## Backup, then Read & verify

**Backup** reads every partition over USB and verifies the hashes. **Read & verify** re-reads one partition by name
and compares it with the backup, read-only. Run it after every write.

## Build image

Choose a firmware release (the **refresh** button re-fetches the list). The overlay and userspace tarballs are
downloaded and SHA-256 checked; the image is assembled locally from your backup, so nothing proprietary is published.

## Flash OpenWrt

Only slot A is written; slot B (stock) is locked. The flow is: dry run, tick the risk checklist, type the tool's phrase,
write, then Read & verify. Booting slot A needs the boot order changed, which needs SSH on the stock system
(see below). The packaged app refuses this step.

## Stock SSH access

Sets up key-only SSH on the stock firmware so the boot order can be changed. Telnet is deliberately not offered.

## Rescue (slot B)

Restores the stock slot from your backup. Use it when slot A will not boot and the unit does not fall back.

## UART monitor and Self-test

**UART monitor** keeps a capture running into a log. **Self-test** checks the tools, the loader identity and the patched
mtkclient. Both are read-only.

## Terminal use

```bash
python3 tools/x28-flasher/x28_flasher.py wizard                 # menu
python3 tools/x28-flasher/x28_flasher.py ports                  # serial ports
python3 tools/x28-flasher/x28_flasher.py uart                   # capture UART (Ctrl-C stops)
python3 tools/x28-flasher/x28_flasher.py read [partition]       # read and compare with the backup
python3 tools/x28-flasher/x28_flasher.py flash identical|write --candidate-dir D [--base-dir D]
```
