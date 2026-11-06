"""Shared helpers for the ZLT X28 recovery scripts.

Run `python3 tools/recovery/common.py` for the self-check.
"""
import datetime
import hashlib
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]  # frozen: tools/build and tools/firmware are bundled under it
# git-ignored: dumps, probe logs and chip IDs live here; a frozen binary has no repo, so it keeps them in the user's home
PRIVATE = Path(os.environ["X28_PRIVATE"]) if "X28_PRIVATE" in os.environ else (
    Path.home() / "x28-flasher" if getattr(sys, "frozen", False) else REPO / "private")
# mtkclient commit that reads this board's NAND (with setup_mtkclient.py's patches); v2.1.4.1 could not
MTKCLIENT_COMMIT = "7cb40e727727dfe3faa065eefb29b16ed29bbdf1"
MTK_HOME = Path(os.environ.get("X28_MTKCLIENT", PRIVATE / f"mtkclient-{MTKCLIENT_COMMIT[:7]}")).resolve()
MTK = MTK_HOME / "venv" / "bin" / "mtk"
FROZEN = getattr(sys, "frozen", False)  # the x28-flasher binary: mtkclient is bundled, there is no venv to enter


def ensure_venv():
    """Developer runs re-exec into the private mtkclient venv; a frozen binary already contains mtkclient."""
    venv_python = MTK_HOME / "venv" / "bin" / "python"
    # sys.prefix, not the executable: every venv's python symlinks to the same base interpreter
    if FROZEN or os.path.realpath(sys.prefix) == os.path.realpath(MTK_HOME / "venv"):
        return
    if not venv_python.exists():
        sys.exit("mtkclient not installed: run tools/recovery/setup_mtkclient.py")
    os.execv(venv_python, [str(venv_python), *sys.argv])

# Quectel T750 download agent from the community X28 package (see docs/RECOVERY.md); mtkclient's bundled one refuses reads
VENDOR_DA = PRIVATE / "vendor-da" / "20261022-mt6890-cpe-recovery-zlt-x28" / "extracted" / "DA_BR.bin"
if FROZEN and (Path(sys._MEIPASS) / "vendor-da" / "DA_BR.bin").is_file():  # a build made with build_binary.py --loader carries its own
    VENDOR_DA = Path(sys._MEIPASS) / "vendor-da" / "DA_BR.bin"

_MTD_LINE = re.compile(r'mtd(\d+): ([0-9a-f]+) ([0-9a-f]+) "([A-Za-z0-9_]+)"')


def parse_mtd(text):
    """Parse /proc/mtd. Offsets assume partitions sit back to back from 0, which the
    X28 layout does; read_verify.py proves it per partition by hash."""
    parts, offset = [], 0
    for line in text.splitlines()[1:]:
        m = _MTD_LINE.fullmatch(line.strip())
        if not m:
            raise ValueError(f"unexpected /proc/mtd line: {line!r}")
        index, size, erase, name = int(m[1]), int(m[2], 16), int(m[3], 16), m[4]
        if index != len(parts):
            raise ValueError(f"mtd{index} out of order")
        parts.append({"index": index, "name": name, "size": size,
                      "erase_size": erase, "offset": offset})
        offset += size
    return parts


def image_name(part):
    return f"mtd{part['index']:02d}-{part['name']}.bin"


DEFAULT_BACKUP = PRIVATE / "recovery" / "20261020-capture-prepared-20261021"


def backup_table(backup):
    """All partitions of a verified backup, each with its expected 'sha256' and raw 'image' path."""
    mtd = next(p for p in (backup / "mtd.txt", backup / "metadata" / "mtd.txt") if p.exists())
    sums = dict(reversed(l.split("  ", 1)) for l in (backup / "SHA256SUMS").read_text().splitlines())
    return [{**p, "sha256": sums[f"images/{image_name(p)}"], "image": backup / "images" / image_name(p)}
            for p in parse_mtd(mtd.read_text())]


def backup_partition(backup, name):
    """Return (partition, expected SHA-256) for `name` from a verified backup."""
    part = next((p for p in backup_table(backup) if p["name"] == name), None)
    if part is None:
        sys.exit(f"no partition {name!r} in {backup}")
    return part, part["sha256"]


def probe_dir():
    out = PRIVATE / "usb-probe" / datetime.date.today().strftime("%Y%m%d")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    return out


ANSI = re.compile(r"\x1b\[[0-9;]*m")
# mtkclient prints warnings/errors as "<Class> - [LIB]: ...", plus Python tracebacks and USB errors
PROBLEM = re.compile(r"\[LIB\]|Traceback|Error|[Ff]ailed")
PROGRESS = re.compile(r"^\s*(Progress:|Done \||Read:|Write:)|\d+(\.\d+)?% ")
BAR_PREFIX = re.compile(r"^.*\d+(\.\d+)?% [^()]*\([^)]*\)[^A-Za-z]*")  # a progress bar glued to a message


def report_problems(found):
    """Print a warnings/errors summary: each distinct message once, with a count."""
    counts = {}
    for msg in found:
        counts[msg] = counts.get(msg, 0) + 1
    print(f"warnings/errors: {sum(counts.values()) or 'none'}")
    for msg, n in counts.items():
        print(f"  x{n}  {msg[:200]}")


class Problems(logging.Handler):
    """Collects mtkclient warnings and errors in-process; its loggers all propagate to root."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.found = []
        self.attach()

    def attach(self):
        # ponytail: mtkclient re-runs logging.dictConfig when it defines classes, which drops root
        # handlers; re-attach before each step. A warning in that window could be missed.
        if self not in logging.getLogger().handlers:
            logging.getLogger().addHandler(self)

    def emit(self, record):
        self.found.append(f"{record.levelname} {record.name}: {ANSI.sub('', record.getMessage())}".strip())

    def report(self):
        report_problems(self.found)


def fmt_eta(seconds):
    return f"{int(seconds) // 60}:{int(seconds) % 60:02d}"


def run_mtk(args, logname):
    """Run mtkclient with its live output (progress bars update in place), save a colour-free
    log under private/usb-probe/<date>/ (it holds the chip's ME_ID, so it stays private), and
    finish with a warnings/errors summary. The modem must be unpowered when this starts
    (mtkclient rejects a device already on USB); plug it in once mtkclient is waiting."""
    if not MTK.exists():
        sys.exit("mtkclient not installed: run tools/recovery/setup_mtkclient.py")
    out = probe_dir()
    print(f"modem power must be OFF now; plug it in when mtkclient is waiting (log: {out / logname})",
          flush=True)
    proc = subprocess.Popen([str(MTK), *args], cwd=out, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    found, buf = [], b""
    with open(out / logname, "w") as log:
        while chunk := proc.stdout.read1(4096):
            sys.stdout.buffer.write(chunk)
            sys.stdout.flush()
            *lines, buf = re.split(rb"[\r\n]", buf + chunk)
            for raw in lines:
                line = ANSI.sub("", raw.decode(errors="replace")).rstrip()
                if PROBLEM.search(line):  # before the progress filter: a message can share a bar's line
                    found.append(BAR_PREFIX.sub("", line))
                if line and (PROBLEM.search(line) or not PROGRESS.search(line)):
                    log.write(line + "\n")
    code = proc.wait()
    print()
    report_problems(found)
    return code, out


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            h.update(block)
    return h.hexdigest()


if __name__ == "__main__":
    sample = ('dev:    size   erasesize  name\n'
              'mtd0: 00400000 00040000 "preloader"\n'
              'mtd1: 00200000 00040000 "preloader_backup"\n')
    p = parse_mtd(sample)
    assert [x["offset"] for x in p] == [0, 0x400000] and image_name(p[1]) == "mtd01-preloader_backup.bin"
    for bad in ('mtd1: 00200000 00040000 "x"', 'mtd0: zz 00040000 "x"'):
        try:
            parse_mtd("dev:\n" + bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    assert PROBLEM.search("DAXML - [LIB]: xread: Wrong length") and PROBLEM.search("USBError(32, 'Pipe error')")
    assert not PROBLEM.search("DAXML - DA Stage 1 successfully loaded.")
    assert PROGRESS.search("Progress: |███| 42.0% Read: (0x1000/0x2000)") and fmt_eta(125) == "2:05"
    assert BAR_PREFIX.sub("", "Progress: |#| 100.0% Read: (0x64/0x64)DAXML - [LIB]: x") == "DAXML - [LIB]: x"
    mtd = PRIVATE / "recovery/20261020-capture-prepared-20261021/metadata/mtd.txt"
    if mtd.exists():  # the real X28 table, when the private backup is present
        lk_b = next(x for x in parse_mtd(mtd.read_text()) if x["name"] == "lk_b")
        assert lk_b["offset"] == 0x1D800000, hex(lk_b["offset"])
    print("common.py self-check OK")
