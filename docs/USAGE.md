# X28 Flasher usage guide

[Install and quick start](../README.md#install) · [Contributing](../CONTRIBUTING.md)

Read the [safety warning](../README.md#warning) before writing. This guide applies to the packaged desktop apps on Windows, Linux and macOS.
Firmware and recovery details live in [zlt-x28-openwrt](https://github.com/mralinp/zlt-x28-openwrt), particularly its
[recovery guide](https://github.com/mralinp/zlt-x28-openwrt/blob/main/docs/RECOVERY.md).

## Before you start

- Use the modem's power supply and a reliable **USB data cable**. Keep both connected throughout a write.
- Make a **complete, verified backup of this unit**, and keep a copy on another disk before writing anything.
- A UART adapter is recommended for recording boot output. USB flashing can run without one, but boot failures are harder to diagnose.
- The download agent (`DA_BR.bin`) is bundled. You normally do not need to choose a loader file.
- **Docker:** needed only for building from a backup and for Root access, not for signed-image downloads or USB flashing.
- **OpenSSH:** Boot order needs `ssh`; Root access also uses `ssh-keygen`. On Windows, install **OpenSSH Client** through Optional Features if needed.

The left panel shows device information and Connect / Disconnect. Choose an action from the sidebar.
Only one job runs at a time; changing pages does not stop it. Closing the window warns before interrupting a running job.

## Choose an action

| Action | Purpose | Writes to the modem? |
|---|---|---|
| Connect device | Read board information and stored boot selection | No |
| Backup | Save and verify all partitions | No |
| Get an image | Download a signed image, or build from a backup | No |
| Flash OpenWrt | Write a built/downloaded image or restore a backup rootfs to A or B | **Yes**, including a rehearsal |
| Boot order | Choose the slot for the next power-up, over SSH | **Yes**, boot-selection records |
| Root access | Add key-only SSH to supported stock firmware in slot B | **Yes**, slot B's overlay tail |
| Read & verify | Compare a partition with its backed-up contents | No |
| UART monitor | Capture the serial console | No |

## Connect device

Connect USB, click **Connect device**, and follow the power prompts: turn the modem off, wait at least **10 seconds**, then turn it on when asked.
Do not press modem buttons unless the app explicitly tells you to.

The app reads hardware information, identifiers, partitions and the four copies of the boot record. **Boot slot** is the stored boot selection,
not proof of which OS was running. An unreadable or ambiguous record is shown as unknown.

The download-agent connection stays open for subsequent USB actions. Do not power-cycle between actions unless prompted.
When finished, click **Disconnect**, then power-cycle the modem to boot normally.

## Backup

Choose a writable output folder, such as a new folder under Documents, and let the job finish. Do not use a protected application-install folder.
The app reads partitions twice and checks their hashes.
A stopped backup can be resumed; an incomplete folder is not a finished recovery backup.

Copy the finished backup to another disk. It contains device-specific data, so **do not share it publicly or use another unit's backup**.

## Get an image

Choose one of:

- **Download the signed image:** no Docker needed. The app downloads a firmware release's image and checks its hash, signature, board/release metadata and UBI layout before keeping it.
- **Build from my backup:** requires Docker. The app downloads the release's assembly bundle, checks its hashes, and builds an image with stock files from your own backup.

The list shows **stable firmware releases only** by default. Tick **Include beta releases** to also show pre-releases.
If the list is empty, try that checkbox and **Refresh versions**. A signed download is available only when that firmware release provides one.

## Flash OpenWrt

1. Select **Built / downloaded image**, then the image and your verified backup. To use saved firmware instead, choose **Rootfs from a verified backup** as described below.
2. Choose **slot A or B** deliberately. A/B are slot names, not a guarantee that one still contains stock firmware.
3. Decide whether to rehearse. **Rehearsal is a real write of the backed-up image**, followed by read-back comparison; it does not install the new firmware.
4. For the actual firmware write, turn **Rehearsal off**. Accept the risk checklist and type the exact phrase shown by the tool.
5. Keep power and USB stable until the tool reports successful verification.

Boot selection does not restrict the write target, and **flashing does not switch slots or change boot order**.
Writing the boot-selected slot replaces what the modem will try at its next power-up.
If you intend to boot the other slot, make sure you have the root SSH access needed for Boot order before relying on that change.

Plain A/B flashes validate the input image and write source, then read the target back and compare it with the bytes written.
They do **not** require the existing target to match the old backup or compare all neighbouring partitions. Some recovery/base-image tools retain additional checks.
A rehearsal is optional, not an automatic dry run before every flash. The tools do not retry or reboot the modem automatically.

A stopped write is not a successful flash. Keep its run folder and logs; follow the [troubleshooting notes](#troubleshooting) rather than retrying blindly.

### Restore a backup rootfs

To return to saved firmware, including vendor firmware when your backup contains it:

1. Open **Flash OpenWrt** and choose **Rootfs from a verified backup**.
2. Select the **complete, verified backup folder from this unit**—the normal Backup output with its images and checksums, not just a loose `.bin` or tar file.
3. Choose source **`rootfs_a` or `rootfs_b`**, then independently choose target **A or B**. For example, saved `rootfs_b` can be written back to B or copied to A.
4. Accept the checklist and type the phrase naming the target, image hash and backup source. Wait for successful read-back verification.

This source option needs no built-image manifest or Docker. The tool checks backup integrity/layout, source size/hash, loader and live unit identity.
It writes the exact captured rootfs bytes and settings, even if the current target differs from the backup. It does not change boot selection.

**This is a rootfs-only restore, not a full NAND recovery.** Boot-chain, calibration and other partitions stay untouched.
A backup containing OpenWrt restores OpenWrt, not vendor firmware; use your original vendor backup to go back to vendor.
Old network settings and SSH configuration are restored too, which may remove keys you added later.
If boot-chain or other partitions were changed, restoring a rootfs alone may not be sufficient to boot vendor firmware.

The desktop backup-source option performs the actual write directly, without the built-image rehearsal switch. All writes still require explicit confirmation.
For any stopped write, preserve logs and consult recovery guidance rather than retrying blindly.

## Boot order

This is separate from flashing and uses **SSH to the running modem**, not the USB download-agent connection.
Disconnect the USB session and boot the modem normally before using it.

1. Ensure root SSH access works. The app tries known modem addresses, or you can enter a host / `host:port` and password if needed.
2. Read the current state, choose **A or B**, then press **Change boot order** and accept the warning.
3. The change applies at the next power-up. The app does not reboot the modem.

The app saves a copy of `misc`, then changes the two priority bytes in each of its four boot-record copies, last copy first, checking each read-back.
The images already in A and B remain unchanged. If the modem has no SSH access, a USB flash alone does not provide this boot-order operation.

## Root access

Optional, for a supported fresh unit still using stock firmware in slot B. It is **not required for a USB firmware flash**.
Use it after taking a full backup if you need key-only root SSH on stock firmware, for example to manage boot order.

The app reads a fresh snapshot of `proinfo`, `misc`, `rootfs_a`, `rootfs_b` and `boot_para`, builds an SSH-enabled image with Docker,
rehearses, and writes only slot B's overlay tail. Choose an RSA public key from `~/.ssh`, or let it create `~/.ssh/x28_rsa`.
It enables key-only SSH on port 22; Telnet is not offered. Keep the private key private.
Do not use this stock-overlay operation as a general replacement for flashing a new image.

## Read & verify

Read a partition and compare it with **your backup**. This does not write anything.

A partition you intentionally changed can legitimately differ from the backup. Use the flash job's automatic image read-back result to verify a new image;
Read & verify is not a comparison against that new image.

## UART monitor

Start it before an operation if you have a suitable serial adapter and want boot diagnostics. It runs separately from the current job.
Some low-level recovery tools require a fresh UART log; the normal desktop USB flash can run without one.
Consult the firmware project's hardware/recovery documentation before wiring an adapter.

## Troubleshooting

| Problem | What to check |
|---|---|
| macOS says the app is “damaged” | Download again from the official release and compare the DMG with its `SHA256SUMS-macos-arm64.txt`. Report the version if it persists; this can be a bundle/signature defect, not just a download problem. Do not disable Gatekeeper globally. |
| macOS blocks an unidentified developer | After attempting to open the app, use System Settings → Privacy & Security → Open Anyway, only for your trusted official download. The app is not Apple-notarized. |
| Device not found | Use a data cable, a working USB port and stable power; repeat the app's power-off / 10-second wait / power-on sequence. On Windows, the installer adds the UsbDk driver (one admin prompt); if it was declined, install `UsbDk_1.0.22_x64.msi` from github.com/daynix/UsbDk/releases, then power-cycle the modem (it is visible for only a few seconds); on Linux, check USB access permissions. |
| No firmware listed | Refresh versions, optionally include betas, and check whether that release includes a signed image. |
| Build / Root access fails | Install and start Docker. For Root access, also check `ssh-keygen` is available. |
| Boot order cannot connect | The modem must be booted normally and reachable by root SSH; verify its address, SSH key or password and the host's OpenSSH client. |
| A write stopped | Keep the run folder and logs. Do not blindly retry, change boot order or reboot. Check the firmware [recovery guide](https://github.com/mralinp/zlt-x28-openwrt/blob/main/docs/RECOVERY.md) and report the exact error with identifiers/secrets redacted. |

Keep backups in the output folder you selected. New packaged backups default to **`~/x28-flasher/backups/`**;
USB run records and UART logs use **`~/x28-flasher/usb-probe/`**. Windows uses your user home folder. The job output prints the exact paths. Desktop startup logs are:

- **Windows:** `%LOCALAPPDATA%\X28 Flasher\native.log`
- **Linux:** `${XDG_STATE_HOME:-~/.local/state}/x28-flasher/native.log`
- **macOS:** `~/Library/Logs/x28-flasher.log`

When [reporting a problem](https://github.com/mralinp/x28-flasher/issues), include the app version, OS, action, slot if relevant and error text.
Redact IMEI, MEID, serial numbers, MAC addresses, passwords and keys. Never attach a full firmware backup publicly.

## Terminal use

On Linux, `x28-flasher` opens the desktop window; subcommands such as `x28-flasher wizard` use the bundled terminal backend.
For source/developer commands on other platforms, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Support

The app's Support box contains the project's EVM donation address and QR code. Stars, bug reports and contributions are welcome.
