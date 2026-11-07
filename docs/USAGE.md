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

### Operator lock (SIM lock)

On the Root access page, for a fresh unit that refuses other operators' SIMs. With the stock slot B running and reachable over SSH, **Check the lock**
shows the two config keys the stock firmware uses (`SYS_LOCK_OPERATOR_SW`, `SYS_LOCK_OPERATOR_LIST`, in `system_config.use`); **Clear the operator
lock** sets the switch to 0 and empties the list, after saving a copy of the file on this computer (`~/.x28-flasher/config-backups`) and on the modem,
and reads it back. Nothing else in the config changes and nothing reboots. It is a software lock only: a code-based (NCK) lock is not touched. This
was built from the config of unlocked units and has not been tried on a locked one.

## Build image

Choose a firmware release (the **refresh** button re-fetches the list). The overlay and userspace tarballs are
downloaded and SHA-256 checked; the image is assembled locally from your backup, so nothing proprietary is published.

## Flash OpenWrt

Only slot A is written; slot B (stock) is locked. The flow is: dry run, tick the risk checklist, type the tool's phrase,
write, then Read & verify. Booting slot A needs the boot order changed, which is the Boot order page. The packaged app refuses this step.

## Root access

Once, on a fresh unit, right after the Backup. It reads a snapshot of slot B from the modem (proinfo, misc, rootfs_a, rootfs_b and
boot_para, about 130 MiB; rootfs_a is read so the write can prove slot A stays untouched), builds a key-only SSH image from it, then
rehearses and writes only slot B's overlay tail. You choose an RSA key from `~/.ssh`, or a new pair (`~/.ssh/x28_rsa`) is made.
SSH then answers on port 22 (and 2222). Telnet is deliberately not offered.

## Boot order

A switch between slot A (OpenWrt) and slot B (stock): flip it, press **Change boot order** and accept the risk. It works over SSH on the
running modem (address and root password are optional fields), saves a copy of the boot partition first and changes two bytes in each of its
four copies. The change applies at the next power-up; nothing reboots the modem for you.

## UART monitor

**UART monitor** keeps a capture running into a log. It is read-only.

## Terminal use

```bash
python3 tools/x28-flasher/x28_flasher.py wizard                 # menu
python3 tools/x28-flasher/x28_flasher.py ports                  # serial ports
python3 tools/x28-flasher/x28_flasher.py uart                   # capture UART (Ctrl-C stops)
python3 tools/x28-flasher/x28_flasher.py read [partition]       # read and compare with the backup
python3 tools/x28-flasher/x28_flasher.py flash identical|write --candidate-dir D [--base-dir D]
```
