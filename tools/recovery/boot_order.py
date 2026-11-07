#!/usr/bin/env python3
"""Choose which slot the preloader boots: swap the two slots' priorities in all four copies of the `misc` record.

    boot_order.py show              read misc and say, in words, which slot boots first (read-only)
    boot_order.py a | b             boot slot A (OpenWrt) or slot B (the vendor firmware) first
    boot_order.py undo              put back the exact misc the last change replaced

The record in each 256 KiB erase block (offset 0x800) is `00 41 42 30 ff ff ff ff`, then slot A's and slot B's four bytes
(priority, tries, success, flag). The preloader boots the higher priority (0x0f over 0x0e); nothing else changes: tries, success and
the flags stay as they are, so the change is two bytes per copy and its undo is the original misc. The four blocks are written one at
a time, last to first, each read back before the next, so an interruption leaves the first copy (the one most likely read) as it was.
A flash never touches misc; this is its own step. The typed phrase is the owner's go-ahead (stable power, USB cable connected).
Run it inside a live session (the page does) or alone: the connection comes from read_by_name.connect either way.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from common import PRIVATE, VENDOR_DA, ensure_venv, loaded_code_matches, probe_dir

MISC_ADDR, MISC_SIZE, BLOCK = 0x700000, 0x100000, 0x40000
COPIES = tuple(0x800 + k * BLOCK for k in range(4))
MAGIC = b"\x00AB0\xff\xff\xff\xff"
PRIO = (0x0e, 0x0f)
UNDO = PRIVATE / "boot-order-undo"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def records(misc):
    """The four 16-byte records of a misc image, after checking it is one consistent boot-order record."""
    if len(misc) != MISC_SIZE:
        raise ValueError(f"misc must be {MISC_SIZE:#x} bytes, got {len(misc):#x}")
    recs = [misc[o:o + 16] for o in COPIES]
    if len(set(recs)) != 1:
        raise ValueError("the four copies of the boot-order record differ: refusing to touch it")
    rec = recs[0]
    if rec[:8] != MAGIC or sorted((rec[8], rec[12])) != list(PRIO):
        raise ValueError(f"not a boot-order record this tool knows: {rec.hex()}")
    return rec


def first(rec):
    """'a' or 'b': the slot with the higher priority."""
    return "a" if rec[8] > rec[12] else "b"


def describe(rec):
    def slot(b):
        return f"priority {b[0]:#04x}, tries {b[1]}, success {b[2]}, flag {b[3]}"
    return f"slot {first(rec).upper()} boots first. A: {slot(rec[8:12])}. B: {slot(rec[12:16])}."


def choose(misc, slot):
    """misc with `slot` first: the two priority bytes swapped in every copy. Raises if it already is."""
    rec = records(misc)
    if first(rec) == slot:
        raise ValueError(f"slot {slot.upper()} already boots first: nothing to change")
    out = bytearray(misc)
    for off in COPIES:
        out[off + 8], out[off + 12] = out[off + 12], out[off + 8]
    records(bytes(out))
    return bytes(out)


def read_misc(da, path):
    ack = da.readflash(addr=MISC_ADDR, length=MISC_SIZE, filename=str(path), parttype=None, display=False)
    data = path.read_bytes() if path.is_file() else b""
    if ack is not True or len(data) != MISC_SIZE:
        raise ValueError("STOP: misc could not be read; nothing was written")
    return data


def write_blocks(da, candidate, work, say=print):
    """Erase-block by block, last to first, each read back before the next."""
    for k in (3, 2, 1, 0):
        piece, back = work / f"block{k}.bin", work / f"back{k}.bin"
        want = candidate[k * BLOCK:(k + 1) * BLOCK]
        piece.write_bytes(want)
        say(f"--- writing block {k + 1} of 4")
        ack = da.writeflash(addr=MISC_ADDR + k * BLOCK, length=BLOCK, filename=str(piece), parttype=None, display=True)
        if ack is not True:
            raise ValueError(f"STOP: block {k} was not acknowledged; do not power-cycle, run `undo` or ask for help")
        ok = da.readflash(addr=MISC_ADDR + k * BLOCK, length=BLOCK, filename=str(back), parttype=None, display=False)
        if ok is not True or not back.is_file() or back.read_bytes() != want:
            raise ValueError(f"STOP: block {k} did not read back as written; do not power-cycle, run `undo` or ask for help")


def newest_undo():
    files = sorted(UNDO.glob("misc-*.bin"), key=lambda p: p.stat().st_mtime, reverse=True) if UNDO.is_dir() else []
    if not files:
        raise ValueError("nothing to undo: no earlier boot-order change was recorded")
    return files[0]


def phrase(action, before, after):
    return f"BOOT-ORDER {action} {digest(before)[:12]} TO {digest(after)[:12]}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=("show", "a", "b", "undo"))
    ap.add_argument("--loader", type=Path, default=VENDOR_DA if VENDOR_DA.is_file() else None)
    args = ap.parse_args()
    ensure_venv()
    from read_by_name import connect
    out = probe_dir()
    os.chdir(out)  # mtkclient drops its hwparam/state files in the working directory
    mtk = connect(out, args.loader and args.loader.resolve())
    try:
        da = mtk.daloader
        work = Path(tempfile.mkdtemp(prefix="boot-order-", dir=out)).resolve()
        before = read_misc(da, work / "before.bin")
        rec = records(before)
        print(f"misc record: {rec.hex()}\n{describe(rec)}", flush=True)
        if args.action == "show":
            return
        if args.action == "undo":
            saved = newest_undo()
            candidate = saved.read_bytes()
            records(candidate)
            if candidate == before:
                raise ValueError("misc already is what the last change replaced: nothing to undo")
            print(f"undo: back to {saved.name}", flush=True)
        else:
            candidate = choose(before, args.action)
        print(f"new record: {records(candidate).hex()}\n{describe(records(candidate))}", flush=True)
        xml = sys.modules.get("mtkclient.Library.DA.xmlflash.xml_lib")
        if xml is None or not loaded_code_matches(xml):
            raise ValueError("loaded XML implementation differs from the bundled one: refusing to write")
        if not sys.stdin.isatty():
            raise ValueError("the typed confirmation needs an interactive terminal")
        print("Keep the modem on stable power and the USB cable connected until this finishes. A power or USB loss in the middle of a write\n"
              "can leave the boot-order record damaged; the way back is a USB restore from your backup.", flush=True)
        expected = phrase(args.action, before, candidate)
        if input(f"Type exactly {expected!r} to authorize this change: ") != expected:
            raise ValueError("not confirmed: nothing was written")
        UNDO.mkdir(parents=True, exist_ok=True, mode=0o700)
        if args.action != "undo":
            (UNDO / f"misc-{time.strftime('%Y%m%d-%H%M%S')}-{digest(before)[:12]}.bin").write_bytes(before)
        (work / "journal.json").write_text(json.dumps({"action": args.action, "before": digest(before), "after": digest(candidate)}))
        write_blocks(da, candidate, work)
        final = read_misc(da, work / "after.bin")
        if final != candidate:
            raise ValueError("STOP: misc does not read back as written; do not power-cycle, run `undo` or ask for help")
        print(f"verified: {describe(records(final))}\nThe change takes effect at the next boot: disconnect, then power-cycle the modem.", flush=True)
    finally:
        mtk.port.close()  # a held (live-session) connection stays open


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(str(error))
