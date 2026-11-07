#!/usr/bin/env python3
"""Offline: stock rootfs_b with key-only SSH, by replacing only the rootfs_data (overlay) volume (#5). Never touches a device.

Every PEB that is not part of rootfs_data (the signed SquashFS volume and both layout copies) is copied byte for byte.
The overlay is rebuilt from the unit's own overlay files and directories (mount points, config, ownership) plus
/etc/x28-ssh.sh, one hook line in /etc/rc.local and the public key. NOT carried over: the few overlayfs whiteouts
(device nodes) and trusted.overlay xattrs, which the extractor cannot read; the backup is the way back. Output is
NOT-FLASHABLE: only slot_b_entry.py writes it, with the owner's typed phrase.

Run as root in the tools container (needs mkfs.ubifs and ubireader; -k keeps file modes), inputs read-only, no network:
    python3 stock_access.py --image mtd42-rootfs_b.bin --public-key router.pub --output DIR
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

PEB, MIN_IO, ROOTFS_DATA, LAYOUT = 0x40000, 4096, 1, 0x7fffefff
# Runs in the background from the top of rc.local, so nothing before it can hold SSH back. The host key is made on the unit.
SSH_SCRIPT = """#!/bin/sh
# x28 stock access (x28-flasher#5): key-only SSH on ports 22 and 2222 via the stock multi-call binary
K=/etc/dropbear/authorized_keys
H=/etc/dropbear/dropbear_rsa_host_key
[ -s "$K" ] || exit 0
[ -s "$H" ] || { rm -f "$H"; /usr/sbin/msn dropbearkey -t rsa -s 2048 -f "$H" >/dev/null 2>&1; }  # stock ships an empty file; dropbearkey will not overwrite
exec /usr/sbin/msn dropbear -r "$H" -s -p 22 -p 2222 -P /var/run/x28-ssh.pid
"""
HOOK = "\n# x28 stock access (x28-flasher#5)\n[ -f /etc/x28-ssh.sh ] && sh /etc/x28-ssh.sh &\n"


def crc(data):
    return (zlib.crc32(data) ^ 0xffffffff) & 0xffffffff


def parse(raw):
    """[(peb_index, ec_header_fields, vol_id, lnum, sqnum)] for every non-empty PEB; vol_id None for an EC-only block."""
    out = []
    for i in range(len(raw) // PEB):
        b = raw[i * PEB:(i + 1) * PEB]
        if b == b"\xff" * PEB:
            out.append((i, None, None, None, None))
            continue
        assert b[:4] == b"UBI#" and crc(b[:60]) == struct.unpack_from(">I", b, 60)[0], f"bad EC header in PEB {i}"
        ec, vid_off, data_off, seq = struct.unpack_from(">QIII", b, 8)
        v = b[vid_off:vid_off + 64]
        if v[:4] != b"UBI!":
            out.append((i, (ec, vid_off, data_off, seq), None, None, None))
            continue
        assert crc(v[:60]) == struct.unpack_from(">I", v, 60)[0], f"bad VID header in PEB {i}"
        out.append((i, (ec, vid_off, data_off, seq), *struct.unpack_from(">II", v, 8), struct.unpack_from(">Q", v, 40)[0]))
    return out


def ec_header(ec, vid_off, data_off, seq):
    h = b"UBI#" + bytes([1, 0, 0, 0]) + struct.pack(">QIII", ec, vid_off, data_off, seq) + b"\0" * 32
    return h + struct.pack(">I", crc(h))


def vid_header(lnum, sqnum):
    """Dynamic-volume VID header: type 1, no copy, vol_id/lnum/sqnum set, data_size/used_ebs/data_pad/data_crc 0."""
    h = b"UBI!" + bytes([1, 1, 0, 0]) + struct.pack(">II", ROOTFS_DATA, lnum) + b"\0" * 24 + struct.pack(">Q", sqnum) + b"\0" * 12
    assert len(h) == 60
    return h + struct.pack(">I", crc(h))


def splice(raw, ubifs, leb):
    """raw with the rootfs_data PEBs replaced by the LEBs of ubifs; all other PEBs untouched. Returns (new_raw, changed_pebs)."""
    pebs = parse(raw)
    slots = [p for p in pebs if p[2] == ROOTFS_DATA]
    assert slots, "no rootfs_data volume"
    lebs = [ubifs[i:i + leb].ljust(leb, b"\xff") for i in range(0, len(ubifs), leb)]
    lebs = [(n, d) for n, d in enumerate(lebs) if d != b"\xff" * leb]
    assert len(lebs) <= len(slots), f"new overlay needs {len(lebs)} blocks, the volume had {len(slots)} mapped"
    top = max(p[4] for p in pebs if p[4] is not None)
    out = bytearray(raw)
    for k, (i, ecf, *_rest) in enumerate(slots):
        ec, vid_off, data_off, seq = ecf
        block = ec_header(ec, vid_off, data_off, seq).ljust(PEB, b"\xff")
        if k < len(lebs):
            n, data = lebs[k]
            block = bytearray(block)
            block[vid_off:vid_off + 64] = vid_header(n, top + 1 + k)
            block[data_off:data_off + leb] = data
            block = bytes(block)
        out[i * PEB:(i + 1) * PEB] = block
    return bytes(out), [p[0] for p in slots]


def volume_payload(raw, volume):
    blocks = {}
    for i, ecf, vol, lnum, _ in parse(raw):
        if vol == volume:
            blocks[lnum] = raw[i * PEB + ecf[2]:(i + 1) * PEB]
    size = PEB - next(p[1][2] for p in parse(raw) if p[2] == volume)
    return b"".join(blocks.get(n, b"\xff" * size) for n in range(max(blocks) + 1))  # unmapped LEBs read as erased


def squashfs_payload(raw):
    sq = volume_payload(raw, 0)
    assert sq[:4] == b"hsqs", "rootfs is not SquashFS"
    return sq[:struct.unpack_from("<Q", sq, 40)[0]]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--public-key", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    raw = args.image.read_bytes()
    assert len(raw) == 0x4000000, "expected a 64 MiB rootfs partition image"
    key = args.public_key.read_text().strip()
    assert key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-")) and "PRIVATE" not in key, "not a public key"
    pebs = parse(raw)
    ecf = next(p[1] for p in pebs if p[2] == ROOTFS_DATA)
    leb = PEB - ecf[2]
    # The volume's size comes from the layout volume's table (172-byte records, reserved_pebs first), not from how many PEBs are mapped.
    i, e = next((p[0], p[1]) for p in pebs if p[2] == LAYOUT)
    reserved = struct.unpack_from(">I", raw, i * PEB + e[2] + 172 * ROOTFS_DATA)[0]
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "sq").write_bytes(squashfs_payload(raw))
        subprocess.run(["unsquashfs", "-n", "-d", str(t / "base"), str(t / "sq"), "etc/rc.local"], check=True, stdout=subprocess.DEVNULL)
        (t / "old.ubifs").write_bytes(volume_payload(raw, ROOTFS_DATA))
        subprocess.run(["ubireader_extract_files", "-k", "-o", str(t / "old"), str(t / "old.ubifs")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tree = t / "old"
        assert (tree / "upper").is_dir(), "unexpected overlay layout"
        (tree / "work").mkdir(exist_ok=True)
        rc_path = tree / "upper/etc/rc.local"
        rc = rc_path.read_text() if rc_path.exists() else (t / "base/etc/rc.local").read_text()
        assert rc.rstrip().endswith("exit 0") and "x28-ssh" not in rc, "unexpected rc.local"
        (tree / "upper/etc/dropbear").mkdir(parents=True, exist_ok=True)
        rc_path.write_text(HOOK + rc)
        rc_path.chmod(0o755)
        (tree / "upper/etc/x28-ssh.sh").write_text(SSH_SCRIPT)
        (tree / "upper/etc/x28-ssh.sh").chmod(0o755)
        (tree / "upper/etc/dropbear/authorized_keys").write_text(key + "\n")
        (tree / "upper/etc/dropbear/authorized_keys").chmod(0o600)
        subprocess.run(["mkfs.ubifs", "-r", str(tree), "-m", str(MIN_IO), "-e", str(leb), "-c", str(reserved), "-F", "-U", "-o", str(t / "overlay.ubifs")], check=True)
        new, changed = splice(raw, (t / "overlay.ubifs").read_bytes(), leb)
        listing = subprocess.run(["find", str(tree), "-mindepth", "1"], capture_output=True, text=True).stdout.replace(str(tree), "").splitlines()
    args.output.mkdir(parents=True)
    (args.output / "rootfs_b-access.bin").write_bytes(new)
    kept = [i for i in range(len(raw) // PEB) if i not in changed]
    assert all(new[i * PEB:(i + 1) * PEB] == raw[i * PEB:(i + 1) * PEB] for i in kept)
    report = {"source_sha256": hashlib.sha256(raw).hexdigest(), "output_sha256": hashlib.sha256(new).hexdigest(),
              "changed_pebs": changed, "untouched_pebs": len(kept), "overlay_entries": len(listing),
              "overlay": "the unit's own overlay files and directories plus the SSH pieces (whiteouts and trusted.overlay xattrs not carried over)",
              "ssh": "stock msn dropbear -s -p 22 -p 2222 from /etc/x28-ssh.sh (background, host key made on the unit), key only",
              "public_key_sha256": hashlib.sha256(key.encode()).hexdigest(),
              "mkfs_ubifs": subprocess.run(["mkfs.ubifs", "--version"], capture_output=True, text=True).stdout.strip()}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output / "overlay-tree.txt").write_text("\n".join(sorted(listing)) + "\n")
    (args.output / "NOT-FLASHABLE").write_text("Written only by slot_b_entry.py with the owner's typed phrase; see x28-flasher#5.\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    sys.exit(main())
