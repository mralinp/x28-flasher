#!/usr/bin/env python3
"""Read-only: reach the download agent and report what the board is (the GUI's Connect step).

Same handshake as read_by_name.py (watchdog untouched), then READ-PARTITION proinfo and READ-PARTITION-TABLE. Nothing is
written. Prints one `X28INFO {json}` line: hwcode, meid, flash type and size, security flags, the partition table, and the
printable strings in proinfo (where the unit's identity lives; the page shows them rather than guess which one is the serial).

    device_info.py --loader DA_BR.bin
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.environ.get("X28_RECOVERY") or str(Path(__file__).resolve().parents[1] / "recovery"))
from common import VENDOR_DA, ensure_venv, probe_dir  # noqa: E402

ensure_venv()

import read_by_name  # noqa: E402

ROW = re.compile(r"<name>(.*?)</name><start>(.*?)</start><size>(.*?)</size>")
STRING = re.compile(rb"[ -~]{6,40}")


def attr(config, name):
    value = getattr(config, name, None)
    return value.hex() if isinstance(value, (bytes, bytearray)) else value


def identity_strings(data, limit=12):
    """Distinct printable runs of the first 4 KiB, in order."""
    seen = []
    for m in STRING.finditer(data[:4096]):
        text = m.group().decode()
        if text not in seen:
            seen.append(text)
    return seen[:limit]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--loader", type=Path, default=VENDOR_DA if VENDOR_DA.is_file() else None)
    args = ap.parse_args()
    loader = args.loader and args.loader.resolve()
    out = probe_dir()
    os.chdir(out)  # mtkclient drops its hwparam/state files in the working directory
    mtk = read_by_name.connect(out, loader)
    da = mtk.daloader.da
    info = {}
    try:
        proinfo = read_by_name.read_partition(da, "proinfo")  # first: after a refused command this DA stops answering
        table, _ = da.read_partition_table()
        text = (table.decode(errors="replace") if isinstance(table, bytes) else table) if table else ""
        cfg = mtk.config
        info = {"hwcode": attr(cfg, "hwcode"), "meid": attr(cfg, "meid"), "flashtype": attr(cfg, "flashtype"),
                "flashsize": attr(cfg, "flashsize"), "flashmode": attr(cfg, "flashmode"),
                "target_config": getattr(cfg, "target_config", None) if isinstance(getattr(cfg, "target_config", None), dict) else None,
                "table": [{"name": n, "start": s, "size": z} for n, s, z in ROW.findall(text)],
                "proinfo_strings": identity_strings(proinfo) if proinfo else []}
    finally:
        print("cycle the modem's power to boot it normally", flush=True)
        mtk.port.close()
    print("X28INFO " + json.dumps(info, default=str), flush=True)
    sys.exit(0 if info.get("table") else 1)


if __name__ == "__main__":
    main()
