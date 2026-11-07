"""The stock firmware's operator (SIM network) lock, read and cleared over SSH on the running stock slot B (after Root access).

The vendor keeps its settings as plain `export KEY="value"` lines in `system_config.use` on the user_config partition (yaffs2, mounted at
/mnt/data). Only two keys are touched: SYS_LOCK_OPERATOR_SW (the switch) and SYS_LOCK_OPERATOR_LIST (the allowed operators). The SIM PIN
and phone lock keys next to them are not carriers' locks and stay as they are. The file is copied to this computer and on the modem first,
changed in one write and read back. Clearing the keys is what the unlocked units' own backups show (switch "0", empty list); it was not
tried on a locked unit.
"""
import re
import time
from pathlib import Path

import boot_ssh
from boot_ssh import BootError, ssh, targets

KEYS = {"SYS_LOCK_OPERATOR_SW": "0", "SYS_LOCK_OPERATOR_LIST": ""}
BACKUPS = Path.home() / ".x28-flasher" / "config-backups"
FIND = """F=/mnt/data/etc/tzcfg/system_config.use
[ -f "$F" ] || F=$(find /mnt/data -name system_config.use 2>/dev/null | head -1)
[ -n "$F" ] && [ -f "$F" ] || exit 3
"""


def line_re(key):
    return re.compile(r'^export ' + key + r'="(.*)"\s*$', re.M)


def values(text):
    """The two lock keys' current values; a key that is not there exactly once is an error (an unknown layout is not edited)."""
    out = {}
    for key in KEYS:
        found = line_re(key).findall(text)
        if len(found) != 1:
            raise BootError(f"{key} appears {len(found)} times in the config; expected once. Not changing anything.")
        out[key] = found[0]
    return out


def unlocked(vals):
    return all(vals[k] == v for k, v in KEYS.items())


def cleared(text):
    """The config text with the lock keys cleared, every other byte as it was."""
    values(text)
    for key, value in KEYS.items():
        text = line_re(key).sub(lambda m: f'export {key}="{value}"', text, count=1)
    return text


def read(addr="", pw=""):
    """-> (target, remote path, config text). The first address that answers with the config file."""
    errors = []
    for target in targets(addr):
        try:
            r = ssh(target, FIND + 'echo "$F"; cat "$F"', pw=pw, timeout=60)
        except BootError as err:
            errors.append(str(err))
            continue
        if r.returncode == 0 and r.stdout:
            path, _, body = r.stdout.decode(errors="replace").partition("\n")
            return target, path, body
        errors.append(f"{target[0]}: " + (r.stderr.decode(errors="replace").strip().splitlines() or ["no config file found (is this the stock firmware?)"])[-1])
    raise BootError("Could not read the stock config over SSH. " + " | ".join(errors))


def state(addr="", pw=""):
    target, path, text = read(addr, pw)
    vals = values(text)
    return {"via": list(target), "file": path, "values": vals, "unlocked": unlocked(vals)}


def unlock(addr="", pw=""):
    target, path, text = read(addr, pw)
    vals = values(text)
    if unlocked(vals):
        return {"via": list(target), "file": path, "values": vals, "unlocked": True}
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (BACKUPS / f"system_config.use-{stamp}").write_text(text)
    (BACKUPS / f"system_config.use-{stamp}").chmod(0o600)
    new = cleared(text)
    r = ssh(target, FIND + f'[ -e "$F.x28-before-unlock" ] || cp "$F" "$F.x28-before-unlock"; cat > "$F.x28new" && sync && mv "$F.x28new" "$F" && sync',
            stdin=new.encode(), pw=pw, timeout=60)
    if r.returncode:
        raise BootError("writing the config failed: " + r.stderr.decode(errors="replace").strip()[-200:])
    again = read(addr, pw)[2]
    if again != new:
        raise BootError(f"the config read back differently from what was written. The original is saved on this computer in {BACKUPS} and on the modem as {path}.x28-before-unlock.")
    return {"via": list(target), "file": path, "values": values(again), "unlocked": True}
