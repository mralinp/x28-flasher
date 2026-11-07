"""Which slot the modem boots, read and changed over SSH on the running system (no USB, no download agent).

The preloader boots the slot with the higher priority in the `misc` record (offset 0x800 of each of its four 256 KiB blocks:
`00414230 ffffffff`, then A's priority/tries/success/flag, then B's). The USB download agent never acknowledges a block write
there, so the change is made from the running OS with the stock `dd-nand` helper, the way docs/research/slot-selection.md in
zlt-x28-openwrt describes: only the two priority bytes change, last copy first, each read back before the next.
"""
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path

HOSTS = {"a": ("192.168.70.1", 22), "b": ("192.168.0.1", 2222)}  # where the unit answers when it runs slot A (OpenWrt) or B (vendor)
REC = 2048 + 8  # A's four bytes, then B's four, in each block
PRIO = {"a": 0x0f, "b": 0x0e}  # the higher one boots; slot A boots with A=0f, B=0e
BACKUPS = Path.home() / ".x28-flasher" / "misc-backups"
FIND = """M=$(sed -n 's/^\\(mtd[0-9]*\\): [0-9a-f]* [0-9a-f]* "misc"$/\\1/p' /proc/mtd); [ -n "$M" ] || exit 3\n"""
READ = FIND + """for k in 0 1 2 3; do dd if=/dev/${M}ro bs=1 skip=$((%d + 262144 * k)) count=8 2>/dev/null | hexdump -v -e '1/1 "%%02x"'; echo; done
sed -n 's/.*bootslot=\\(.\\).*/slot \\1/p' /proc/cmdline""" % REC


class BootError(Exception):
    pass


def ssh(slot, cmd, stdin=None, timeout=60):
    host, port = HOSTS[slot]
    askpass = Path(tempfile.mkdtemp()) / "askpass"
    askpass.write_text("#!/bin/sh\necho ''\n")  # the OpenWrt image has an empty root password
    askpass.chmod(stat.S_IRWXU)
    env = {**os.environ, "SSH_ASKPASS": str(askpass), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":0"}
    argv = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-o", "ConnectTimeout=5", "-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
    for key in (Path.home() / ".ssh" / "router",):
        if key.is_file():
            argv += ["-i", str(key)]
    try:
        return subprocess.run(argv + [f"root@{host}", cmd], input=stdin, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise BootError(f"{host} did not answer in {timeout} s")
    finally:
        askpass.unlink(missing_ok=True)
        askpass.parent.rmdir()


def parse(out):
    """-> (running slot or None, the four 16-hex records "A prio,tries,success,flag + B ..."). The copies must agree."""
    lines = out.strip().splitlines()
    recs = [l.strip() for l in lines if len(l.strip()) == 16]
    if len(recs) != 4:
        raise BootError("the boot record could not be read")
    if len(set(recs)) != 1:
        raise BootError("the four copies of the boot record differ: " + ", ".join(recs) + ". Not changing anything.")
    running = next((l.split()[1] for l in lines if l.startswith("slot ")), None)
    return running, recs


def boot_slot(rec):
    a, b = int(rec[0:2], 16), int(rec[8:10], 16)
    if a == b:
        raise BootError("both slots have the same priority; not changing anything")
    return "a" if a > b else "b"


def plan(rec, slot):
    """The 5 bytes to write for the slot to boot: A prio, A tries/success/flag as they are, B prio."""
    a, b = PRIO[slot], PRIO["b" if slot == "a" else "a"]
    return bytes([a]) + bytes.fromhex(rec[2:8]) + bytes([b])


def state():
    """Ask the unit on the address of the slot it runs: {"host", "running", "boot", "record"}."""
    errors = []
    for slot in HOSTS:
        try:
            r = ssh(slot, READ)
        except BootError as err:
            errors.append(str(err))
            continue
        if r.returncode == 0 and r.stdout.strip():
            running, recs = parse(r.stdout.decode(errors="replace"))
            return {"via": slot, "running": running, "boot": boot_slot(recs[0]), "record": recs[0]}
        errors.append(f"{HOSTS[slot][0]}: " + (r.stderr.decode(errors="replace").strip().splitlines() or ["no answer"])[-1])
    raise BootError("Could not reach the modem over SSH. " + " | ".join(errors))


def set_slot(slot):
    """Make `slot` the one that boots at the next power-up. Returns the new state."""
    if slot not in PRIO:
        raise BootError("choose slot a or b")
    cur = state()
    if cur["boot"] == slot:
        return cur
    via = cur["via"]
    BACKUPS.mkdir(parents=True, exist_ok=True)
    r = ssh(via, FIND + "cat /dev/${M}ro", timeout=120)
    if r.returncode or len(r.stdout) != 0x100000:
        raise BootError("could not save a copy of the boot partition first; nothing was changed")
    (BACKUPS / time.strftime("misc-%Y%m%d-%H%M%S.bin")).write_bytes(r.stdout)
    want = plan(cur["record"], slot)
    new = want.hex() + cur["record"][10:]
    for k in (3, 2, 1, 0):  # last copy first: copy 0, read first by the preloader, keeps saying the old slot if anything stops early
        off = REC + 262144 * k
        esc = "".join(f"\\x{c:02x}" for c in want)
        out = ssh(via, FIND + f"printf '{esc}' | dd-nand of=/dev/$M seek={off} bs=1 count=5 >/dev/null 2>&1; "
                  f"dd if=/dev/${{M}}ro bs=1 skip={off} count=8 2>/dev/null | hexdump -v -e '1/1 \"%02x\"'", timeout=120)
        if out.stdout.decode().strip() != new:
            raise BootError(f"copy {k} read back {out.stdout.decode().strip()!r}, expected {new!r}. Stopped; "
                            f"the copies before it are changed. Run it again, or restore the copy saved in {BACKUPS}.")
    return state()
