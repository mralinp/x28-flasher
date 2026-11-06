#!/usr/bin/env python3
"""Offline inventory of X28 firmware: kernel config, kernel modules, packages and their files.

    # kernel config embedded in a boot partition image (CONFIG_IKCONFIG), on the host:
    python3 tools/firmware/inventory.py kconfig private/recovery/<backup>/images/mtd40-boot_b.bin out.config

    # modules and packages of an extracted rootfs. Run it on a case-sensitive filesystem,
    # e.g. the Docker volume from the rootfs extraction (no network, read-only):
    docker run --rm --network none -v x28-rootfs-b-analysis-20261021:/r:ro -v "$PWD/tools/firmware:/t:ro" \
        x28-firmware-tools:local python3 /t/inventory.py rootfs /r/rootfs > private/firmware/inventory.json

Reads only; never executes anything from the firmware.
"""
import json
import os
import re
import struct
import sys
import zlib

MODINFO = re.compile(rb"(?:^|\x00)(name|vermagic|depends|license|description|srcversion)=([^\x00]*)")
BINARY = re.compile(r"(?<![\w/.-])(/(?:usr/)?s?bin/[\w.+-]+|/usr/lib/[\w./+-]+\.sh)")


def elf_dynamic(data):
    """(SONAME, [DT_NEEDED]) of a little-endian ELF64 file, read from its dynamic section."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None, []
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    loads, dyn = [], None
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:
            dyn = (p_offset, p_filesz)
    if not dyn:
        return None, []  # static binary
    entries = [struct.unpack_from("<qQ", data, dyn[0] + o) for o in range(0, dyn[1], 16)]
    strtab = next((v for t, v in entries if t == 5), None)
    off = next((o + strtab - va for va, o, sz in loads if va <= strtab < va + sz), None) if strtab else None
    if off is None:
        return None, []

    def s(i):
        return data[off + i:data.index(b"\0", off + i)].decode(errors="replace")
    return (next((s(v) for t, v in entries if t == 14), None), [s(v) for t, v in entries if t == 1])


def elf_symbols(data):
    """(defined, undefined) global/weak dynamic symbol names of an ELF64 LE file.

    Read through the dynamic segment like the dynamic linker does, because OpenWrt's
    sstrip removes section headers (and with them the .dynsym section entry)."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return set(), set()
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    loads, dyn = [], None
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:
            dyn = (p_offset, p_filesz)
    if not dyn:
        return set(), set()
    tags = dict(struct.unpack_from("<qQ", data, dyn[0] + o) for o in range(0, dyn[1], 16))

    def off(vaddr):
        return next((o + vaddr - va for va, o, sz in loads if va <= vaddr < va + sz), None)
    symtab, strtab = off(tags.get(6, 0)), off(tags.get(5, 0))
    if symtab is None or strtab is None:
        return set(), set()
    if 4 in tags:  # DT_HASH: nchain is the symbol count
        count = struct.unpack_from("<I", data, off(tags[4]) + 4)[0]
    elif 0x6FFFFEF5 in tags:  # DT_GNU_HASH: walk the last bucket's chain
        h = off(tags[0x6FFFFEF5])
        nbuckets, symoffset, bloom_size, _ = struct.unpack_from("<IIII", data, h)
        buckets = struct.unpack_from(f"<{nbuckets}I", data, h + 16 + 8 * bloom_size)
        count = max(buckets + (symoffset,))
        chains = h + 16 + 8 * bloom_size + 4 * nbuckets
        if count > symoffset:
            while not struct.unpack_from("<I", data, chains + 4 * (count - symoffset))[0] & 1:
                count += 1
            count += 1
    else:
        return set(), set()
    defined, undefined = set(), set()
    for i in range(1, count):  # entry 0 is the null symbol
        name, info, _, shndx = struct.unpack_from("<IBBH", data, symtab + 24 * i)
        if info >> 4 not in (1, 2) or not name:  # GLOBAL or WEAK only
            continue
        n = data[strtab + name:data.index(b"\0", strtab + name)].decode(errors="replace")
        (undefined if shndx == 0 else defined).add(n)
    return defined, undefined


def services(root):
    """Enabled init scripts in start order, with the binaries each one launches."""
    rcd = os.path.join(root, "etc/rc.d")
    out = []
    for link in sorted(os.listdir(rcd)) if os.path.isdir(rcd) else []:
        # names may start with digits (`3ccci_mdinit`): try every split of the number prefix
        m = next((m for m in (re.fullmatch(rf"S(\d{{{n}}})(.+)", link) for n in range(1, 4))
                  if m and os.path.isfile(os.path.join(root, "etc/init.d", m[2]))), None)
        if not m:
            continue
        script = os.path.join(root, "etc/init.d", m[2])
        text = open(script, errors="replace").read()
        out.append({"order": int(m[1]), "name": m[2], "procd": "USE_PROCD=1" in text,
                    "runs": sorted(set(BINARY.findall(text)))})
    return out


def kconfig(boot_img, out):
    d = open(boot_img, "rb").read()
    if d[:8] != b"ANDROID!":
        sys.exit("not an Android boot image")
    kernel_size, page = struct.unpack_from("<I", d, 8)[0], struct.unpack_from("<I", d, 0x24)[0]
    k = d[page:page + kernel_size]
    raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(k[k.find(b"\x1f\x8b\x08"):], 128 << 20)
    i = raw.find(b"IKCFG_ST")
    if i < 0:
        sys.exit("kernel has no embedded config (CONFIG_IKCONFIG not set)")
    cfg = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw[i + 8:], 8 << 20)
    banner = re.search(rb"Linux version [ -~]+", raw)
    open(out, "wb").write(cfg)
    options = cfg.count(b"\nCONFIG_")
    print(f"{out}: {options} options set; {banner.group().decode() if banner else ''}")


def rootfs(root):
    info_dir = os.path.join(root, "usr/lib/opkg/info")
    status_path = os.path.join(root, "usr/lib/opkg/status")
    packages = {}
    for block in (open(status_path).read() if os.path.exists(status_path) else "").split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z-]+): (.*)$", block, re.M))
        if "Package" in f:
            packages[f["Package"]] = {"version": f.get("Version"), "arch": f.get("Architecture"), "files": 0}
    owner = {}
    for f in sorted(os.listdir(info_dir)) if os.path.isdir(info_dir) else []:
        if f.endswith(".list"):
            for line in open(os.path.join(info_dir, f)):
                owner[line.strip()] = f[:-5]
    files, modules = [], []
    for dp, _, names in os.walk(root):
        rel = "/" + os.path.relpath(dp, root)
        if rel.startswith(("/proc", "/sys", "/dev", "/tmp", "/overlay", "/rom")):
            continue
        for n in names:
            p = os.path.join(dp, n)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            path = os.path.normpath(os.path.join(rel, n))
            data = open(p, "rb").read()
            pkg = owner.get(path)
            if pkg in packages:
                packages[pkg]["files"] += 1
            entry = {"path": path, "size": len(data), "pkg": pkg, "elf": data[:4] == b"\x7fELF"}
            if entry["elf"]:
                entry["soname"], entry["needed"] = elf_dynamic(data)
            files.append(entry)
            if n.endswith(".ko"):
                mi = {}
                for m in MODINFO.finditer(data):
                    mi.setdefault(m[1].decode(), m[2].decode(errors="replace"))
                modules.append({"path": path, "size": len(data), "pkg": pkg, **mi})
    autoload = {}
    for d in ("etc/modules-boot.d", "etc/modules.d"):
        for f in sorted(os.listdir(os.path.join(root, d))) if os.path.isdir(os.path.join(root, d)) else []:
            lines = open(os.path.join(root, d, f), errors="replace").read().split("\n")
            autoload[f"{d}/{f}"] = [l.split()[0] for l in lines if l.strip() and not l.startswith("#")]
    json.dump({"packages": packages, "modules": modules, "files": files,
               "services": services(root), "autoload": autoload}, sys.stdout, indent=0)


def selftest():
    import subprocess, tempfile
    so, needed = elf_dynamic(open(sys.executable, "rb").read())
    if open(sys.executable, "rb").read(6)[4:6] == b"\x02\x01":  # an ELF64 LE interpreter (Linux)
        assert any("libc" in n or "python" in n for n in needed), needed
        defined, undefined = elf_symbols(open(sys.executable, "rb").read())
        assert defined | undefined, "no dynamic symbols read"
    assert elf_symbols(b"not an elf") == (set(), set())
    assert elf_dynamic(b"not an elf") == (None, [])
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(f"{t}/etc/init.d"); os.makedirs(f"{t}/etc/rc.d")
        open(f"{t}/etc/init.d/demo", "w").write("USE_PROCD=1\nprocd_set_param command /usr/bin/demo_d -f\n")
        os.symlink("../init.d/demo", f"{t}/etc/rc.d/S42demo")
        open(f"{t}/etc/init.d/3ccci_mdinit", "w").write("start() { /usr/bin/ccci_mdinit 0; }\n")
        os.symlink("../init.d/3ccci_mdinit", f"{t}/etc/rc.d/S113ccci_mdinit")
        assert services(t) == [{"order": 11, "name": "3ccci_mdinit", "procd": False, "runs": ["/usr/bin/ccci_mdinit"]},
                               {"order": 42, "name": "demo", "procd": True, "runs": ["/usr/bin/demo_d"]}], services(t)
    print("inventory.py self-check OK")


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        selftest()
    elif len(sys.argv) == 4 and sys.argv[1] == "kconfig":
        kconfig(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "rootfs":
        rootfs(sys.argv[2])
    else:
        sys.exit(__doc__)
