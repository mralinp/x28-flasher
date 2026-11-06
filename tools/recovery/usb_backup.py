#!/usr/bin/env python3
"""Full read-only backup of the X28's NAND over USB (download agent), in the layout the guarded tools read (#284).

Reads every partition of the fixed X28 layout (x28-mtd.txt) twice, keeps it only if both reads agree, and writes
OUT/images/*, OUT/mtd.txt, OUT/SHA256SUMS, OUT/complete-captured-partitions.tar and OUT/ARCHIVE.sha256. The router must be
unpowered when this starts; plug it in when mtkclient is waiting. Nothing is written to the router. Re-run with the same
--out to resume after an interruption.

    python3 tools/recovery/usb_backup.py --out DIR --loader DA_BR.bin [--no-verify]
"""
import argparse
import json
import os
import sys
import tarfile
import time
from pathlib import Path

from common import fmt_eta, image_name, parse_mtd, sha256_file

LAYOUT = Path(__file__).with_name("x28-mtd.txt")
PARTIAL = "SHA256SUMS.partial"
DEGRADED = "DEGRADED.json"
BEST_EFFORT = {"expdb"}  # crash logs the running system rewrites; the download agent stops reading this one at 18 MiB (#284)
CHUNK = 4 << 20  # one 20 MiB READ-FLASH came back at 18 MiB on this DA, twice; small reads also show which piece fails


def read_chunked(readflash, part, path, chunk=CHUNK, say=print, clock=time.monotonic):
    """readflash(addr, length, filename) -> bool for one piece; the pieces are joined into path. False at the first bad piece."""
    tmp = Path(str(path) + ".chunk")
    with open(path, "wb") as out:
        for off in range(0, part["size"], chunk):
            n = min(chunk, part["size"] - off)
            tmp.unlink(missing_ok=True)
            t0 = clock()
            ok = readflash(part["offset"] + off, n, str(tmp))
            got = tmp.stat().st_size if tmp.exists() else 0
            if not ok or got != n:
                say(f"\n  piece at +{off:#x} of {part['name']} failed: {got:#x} of {n:#x} bytes")
                tmp.unlink(missing_ok=True)
                return False
            out.write(tmp.read_bytes())
            say(f"\r  {part['name']}: {off + n >> 20} of {part['size'] >> 20} MiB  {n / 2**20 / max(clock() - t0, 1e-9):.2f} MiB/s", end="")
    tmp.unlink(missing_ok=True)
    say("")
    return True


class NeedsRestart(Exception):
    """A best-effort partition was cut short: the session is over but the backup can be resumed."""


def read_whole(read, p, path, best_effort):
    """Read a partition into path. Returns the bytes really read: the full size, or for a best-effort partition the whole pieces
    before the fault with the rest filled with 0xFF. Anything else short raises."""
    if read(p, path) and path.stat().st_size == p["size"]:
        return p["size"]
    good = path.stat().st_size if path.exists() else 0
    if p["name"] not in best_effort or good >= p["size"]:
        raise RuntimeError(f"read of {p['name']} failed or came back short; run again with the same --out to resume")
    with open(path, "ab") as f:
        f.write(b"\xff" * (p["size"] - good))
    return good


def note_degraded(out, p, good):
    path = out / DEGRADED
    data = json.loads(path.read_text()) if path.exists() else {}
    data[p["name"]] = {"read": good, "size": p["size"]}
    path.write_text(json.dumps(data, indent=1))


def write_backup(out, parts, read, verify=True, say=print, best_effort=BEST_EFFORT):
    """read(part, path) -> bool fills path with the partition's bytes. Returns the list of (sha256, relative path)."""
    images = out / "images"
    images.mkdir(parents=True, exist_ok=True)
    partial = out / PARTIAL
    done = dict(reversed(l.split("  ", 1)) for l in partial.read_text().splitlines()) if partial.exists() else {}
    total, finished, started = sum(p["size"] for p in parts), 0, time.monotonic()
    sums = []
    for i, p in enumerate(parts, 1):
        name, path = image_name(p), images / image_name(p)
        rel = f"images/{name}"
        if rel in done and path.is_file() and path.stat().st_size == p["size"] and sha256_file(path) == done[rel]:
            say(f"[{i}/{len(parts)}] {p['name']}: already read, kept")
            sums.append((done[rel], rel))
            finished += p["size"]
            continue
        say(f"[{i}/{len(parts)}] reading {p['name']} ({p['size'] / 2**20:.1f} MiB)")
        good = read_whole(read, p, path, best_effort)
        digest = sha256_file(path)
        if good < p["size"]:
            # The download agent stops answering after a fault, so this partition cannot be read twice and the session cannot go on.
            note_degraded(out, p, good)
            with partial.open("a") as f:
                f.write(f"{digest}  {rel}\n")
            raise NeedsRestart(f"{p['name']}: only the first {good >> 20} of {p['size'] >> 20} MiB could be read (the rest is filled with 0xFF "
                               "and noted). Power-cycle the router and run Backup again with the same folder to continue.")
        if verify:
            again = out / (name + ".verify")
            if read_whole(read, p, again, best_effort) != good or sha256_file(again) != digest:
                again.unlink(missing_ok=True)
                raise RuntimeError(f"two reads of {p['name']} disagree; nothing was kept for it")
            again.unlink()
        with partial.open("a") as f:
            f.write(f"{digest}  {rel}\n")
        sums.append((digest, rel))
        finished += p["size"]
        rate = finished / max(time.monotonic() - started, 1e-9)
        say(f"  ok  {digest[:12]}   overall {finished / total:6.1%}  ETA {fmt_eta((total - finished) / rate)}")
    return sums


def seal(out, sums, layout_text):
    """Write the files the guarded tools expect and the archive used as the second copy."""
    (out / "mtd.txt").write_text(layout_text)
    (out / "SHA256SUMS").write_text("".join(f"{d}  {r}\n" for d, r in sums))
    archive = out / "complete-captured-partitions.tar"
    with tarfile.open(archive, "w") as tar:
        for _, rel in sums:
            tar.add(out / rel, arcname=rel)
        tar.add(out / "mtd.txt", arcname="mtd.txt")
        tar.add(out / "SHA256SUMS", arcname="SHA256SUMS")
    (out / "ARCHIVE.sha256").write_text(f"{sha256_file(archive)}  {archive.name}\n")
    degraded = json.loads((out / DEGRADED).read_text()) if (out / DEGRADED).exists() else {}
    if degraded:
        (out / "BACKUP-NOTES.txt").write_text("This backup is complete except for best-effort partitions the download agent could not read in full.\n"
                                             "The unread part of each is filled with 0xFF.\n" + "".join(
            f"{n}: bytes {d['read']:#x}..{d['size']:#x} not read (read {d['read'] >> 20} of {d['size'] >> 20} MiB)\n" for n, d in degraded.items()))
    (out / PARTIAL).unlink(missing_ok=True)
    return archive


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--loader", type=Path, required=True, help="download agent file (DA_BR.bin)")
    ap.add_argument("--fast", action="store_true", help="mtkclient's fast USB read path (experimental; compare the MiB/s shown)")
    ap.add_argument("--chunk-mib", type=int, default=CHUNK >> 20, help="size of one READ-FLASH piece (the DA stops at 18 MiB, so keep it small)")
    ap.add_argument("--no-verify", action="store_true", help="read each partition once (half the time, no cross-check)")
    args = ap.parse_args()
    layout_text = LAYOUT.read_text()
    parts = parse_mtd(layout_text)
    print(f"{len(parts)} partitions, {sum(p['size'] for p in parts) / 2**20:.0f} MiB"
          f"{'' if args.no_verify else ', each read twice'}; writing to {args.out}")
    args.out.mkdir(parents=True, exist_ok=True)
    from read_by_name import connect, problems  # re-runs this script under the mtkclient venv when not frozen
    os.chdir(args.out)  # mtkclient drops its hwparam/state files in the working directory
    mtk = connect(args.out.resolve(), args.loader.resolve())
    if args.fast:
        mtk.port.cdc.set_fast_mode(True)
    try:
        def read(p, path):
            problems.attach()
            return read_chunked(lambda addr, n, name: mtk.daloader.readflash(addr=addr, length=n, filename=name, parttype=None, display=False) is True,
                                p, path, chunk=args.chunk_mib << 20, say=lambda m, **kw: print(m, flush=True, **kw))
        sums = write_backup(args.out.resolve(), parts, read, verify=not args.no_verify)
    except NeedsRestart as stop:
        print(f"\n{stop}")
        sys.exit(3)
    finally:
        print("cycle the modem's power to boot it normally")
        mtk.port.close()
    archive = seal(args.out.resolve(), sums, layout_text)
    print(f"backup complete: {len(sums)} partitions, archive {archive} ({sha256_file(archive)[:12]})")
    if (args.out / "BACKUP-NOTES.txt").exists():
        print("NOTE: " + (args.out / "BACKUP-NOTES.txt").read_text().splitlines()[-1] + "  (see BACKUP-NOTES.txt)")
    problems.report()


if __name__ == "__main__":
    main()
