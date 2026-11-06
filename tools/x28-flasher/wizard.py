"""The guided session behind a bare `x28-flasher` (#272): questions instead of flags, then the same guarded tools."""
import json
import os
import sys
import time
from pathlib import Path

try:
    import questionary
except ImportError:  # the numbered prompts below work without it
    questionary = None

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}


def paint(text, *styles):
    if not USE_COLOR:
        return text
    return f"\033[{';'.join(CODES[s] for s in styles)}m{text}\033[0m"


def good(text):
    return paint("\u2713 ", "green") + text


def bad(text):
    return paint("\u2717 ", "red") + text


def warn(text):
    return paint("! ", "yellow") + text


STYLE = None
if questionary:
    STYLE = questionary.Style([("qmark", "fg:cyan bold"), ("question", "bold"), ("pointer", "fg:cyan bold"),
                               ("highlighted", "fg:cyan bold"), ("answer", "fg:green bold"), ("instruction", "fg:ansibrightblack")])

MENU = [("Set up UART logger", "uart"), ("Backup", "backup"), ("Build", "build"), ("Test (read-only checks)", "test"),
        ("Flash slot A (rehearsal or write)", "flash"), ("Auto pilot", "auto"), ("Read one partition and verify it", "read"), ("Quit", "quit")]


def printable_share(data):
    """Fraction of console-looking bytes; garbage from a wrong baud rate scores low."""
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data) if data else 0.0


def pick(items, what, ask=None):
    """Numbered choice; returns the chosen item. Enter takes the first entry."""
    if not items:
        sys.exit(f"no {what} found")
    for i, item in enumerate(items, 1):
        print(f"  {i}) {item}")
    while True:
        answer = (ask or input)(f"{what} [1]: ").strip() or "1"
        if answer.isdigit() and 1 <= int(answer) <= len(items):
            return items[int(answer) - 1]
        print("  enter a number from the list")


class Ui:
    """Arrow-key prompts on a terminal when questionary is installed, numbered prompts otherwise."""

    def __init__(self, fancy=None):
        self.fancy = bool(questionary and sys.stdin.isatty() and sys.stdout.isatty()) if fancy is None else fancy

    def _ask(self, question):
        answer = question.ask()
        if answer is None:  # Ctrl-C inside a prompt
            raise KeyboardInterrupt
        return answer

    def select(self, msg, choices):
        """choices: [(label, value)]"""
        if self.fancy:  # by index: questionary returns the label for a None value, which would turn "None / not known" into a base image
            return choices[self._ask(questionary.select(msg, choices=[questionary.Choice(label, value=i) for i, (label, _) in enumerate(choices)], style=STYLE, qmark="\u276f"))][1]
        return dict(choices)[pick([label for label, _ in choices], msg)]

    def text(self, msg, default=""):
        if self.fancy:
            return self._ask(questionary.text(msg, default=default, style=STYLE, qmark="\u276f"))
        return input(f"{msg} [{default}]: ").strip() or default

    def confirm(self, msg, default=True):
        if self.fancy:
            return self._ask(questionary.confirm(msg, default=default, style=STYLE, qmark="\u276f"))
        return (input(f"{msg} [{'Y/n' if default else 'y/N'}]: ").strip().lower() or ('y' if default else 'n')).startswith('y')


class Config:
    """What the user answered last time (paths, UART), kept next to the logs."""

    def __init__(self, path):
        self.path = path
        try:
            self.data = json.loads(path.read_text())
        except (OSError, ValueError):
            self.data = {}

    def get(self, key, default=""):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=1))


def ask_path(ui, cfg, key, msg, default, is_dir):
    """Last answer, else the repo default if it exists, else ask; the answer must exist."""
    value = cfg.get(key) or (str(default) if default and Path(default).exists() else "")
    while not (value and (Path(value).is_dir() if is_dir else Path(value).is_file())):
        value = ui.text(msg, value).strip()
        if value and not Path(value).exists():
            print("  " + bad(f"not found: {value}"))
    cfg.set(key, value)
    return value


def verified_identicals(probe, now=None):
    """Rehearsal runs a write may build on: VERIFIED and younger than 24 h (the tools enforce the same)."""
    now = now or time.time()
    out = []
    for receipt in sorted(probe.glob("slot-rootfs_a-identical-*/receipt.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(receipt.read_text())
        except (OSError, ValueError):
            continue
        if data.get("status") == "VERIFIED" and 0 <= now - data.get("created", 0) <= 86400:
            out.append(receipt.parent)
    return out


def image_dirs(build):
    return sorted((d for d in build.glob("native-ubi-*") if (d / "rootfs-a-experimental.bin").is_file()),
                  key=lambda d: d.stat().st_mtime, reverse=True)


def check_setup(fl, ui, cfg):
    from common import DEFAULT_BACKUP, backup_table, sha256_file
    from restore_entry import DA_HASH, host_identity
    print(paint("  Setup check", "bold"))
    ports = fl.list_ports()
    print("  " + (good if ports else bad)(f"serial ports: {', '.join(d for d, _ in ports) or 'none found'}"))
    pre = any("Preloader" in x for _, x in ports)
    print("  " + (warn if pre else good)("preloader port present: power-cycle the router before using it" if pre else "no preloader port (normal while the router runs)"))
    backup = Path(cfg.get("backup") or DEFAULT_BACKUP)
    try:
        print("  " + good(f"backup: {backup} ({len(backup_table(backup))} partitions)"))
    except Exception:
        print("  " + bad(f"backup not found at {backup}"))
    loader = Path(cfg.get("loader") or fl.VENDOR_DA)
    ok = loader.is_file() and sha256_file(loader) == DA_HASH
    print("  " + (good if ok else bad)(f"download agent: {loader}" if ok else f"download agent missing or not the expected file: {loader}"))
    try:
        host_identity()
        print("  " + good("mtkclient matches the pinned, patched build"))
    except Exception as err:
        print("  " + bad(f"mtkclient: {err}"))
    copies = fl.find_backup_copies()
    print("  " + (good(f"second backup copy: {copies[0]}") if copies else warn("no second backup copy on a connected drive")))


def read_partition(fl, ui, cfg):
    from common import DEFAULT_BACKUP, VENDOR_DA, backup_table
    backup = ask_path(ui, cfg, "backup", "Folder with your verified backup", DEFAULT_BACKUP, True)
    loader = ask_path(ui, cfg, "loader", "Vendor download agent file (DA_BR.bin)", VENDOR_DA, False)
    names = [p["name"] for p in backup_table(Path(backup))]
    part = ui.select("Which partition?", [(n, n) for n in names])
    print("  " + paint("Read-only. Nothing is written to the router.", "dim"))
    return fl.cmd_read(__import__("argparse").Namespace(partition=part, backup=backup, loader=loader))


def watch_uart(fl, ui, cfg):
    fl.start_capture(ui)  # runs in the background until you quit; flash, read and test use the same log
    return 0


def backup(fl, ui, cfg):
    """Full read-only backup over USB, in the folder layout the guarded tools read."""
    from common import VENDOR_DA
    loader = ask_path(ui, cfg, "loader", "Vendor download agent file (DA_BR.bin)", VENDOR_DA, False)
    default = fl.default_backup_dir()
    unfinished = sorted(default.parent.glob("x28-backup-*/SHA256SUMS.partial"), key=lambda p: p.stat().st_mtime, reverse=True)
    if unfinished:
        done = len(unfinished[0].read_text().splitlines())
        if ui.confirm(f"Resume the unfinished backup {unfinished[0].parent.name} ({done} partitions done)?", True):
            default = unfinished[0].parent
    out = ui.text("Save the backup in", str(default))
    twice = ui.confirm("Read every partition twice to verify it? (about twice as long, recommended)", True)
    print("  " + paint("Read-only. Nothing is written to the router.", "dim"))
    argv = ["--out", out, "--loader", loader] + ([] if twice else ["--no-verify"])
    fl.power_off_countdown()
    code = fl.run_tool("usb_backup.py", argv)
    if code == 3:
        print("  " + warn("Paused: a best-effort partition was cut short. Power-cycle the router and run Backup again to continue."))
    else:
        print("  " + (good(f"Backup saved in {out}") if code == 0 else bad(f"Backup stopped (exit {code}). Run it again with the same folder to resume.")))
    return code


def build(fl, ui, cfg):
    """A flashable image: the newest release, or a local run of the build pipeline. Both land in private/build/native-ubi-*, where Flash looks."""
    import images
    from common import PRIVATE
    how = ui.select("Where should the image come from?", [("Download the newest release image", "download"), ("Build it here from your own inputs", "local")])
    dest = PRIVATE / "build"
    try:
        if how == "download":
            out = images.download(dest)
            cfg.set("last_image", str(out))
            print("  " + good(f"Image saved in {out} (checksum and manifest verified)"))
            print("  " + paint("The checksum only shows the download is intact; Flash still asks you to type the image hash.", "dim"))
            return 0
        if fl.FROZEN:
            print("  " + warn("A local build needs a source checkout (tools/build and Docker). Download the release image or run from a checkout."))
            return 1
        return build_local(fl, ui, cfg, dest)
    except (RuntimeError, ValueError, OSError) as err:
        print("  " + bad(str(err)))
        return 1


def choose_key(ui, cfg):
    """The key that goes into the image is never guessed: the user picks it from ~/.ssh each time, the last choice listed first."""
    keys = sorted(str(p) for p in (Path.home() / ".ssh").glob("*.pub"))
    last = cfg.get("build_key")
    keys.sort(key=lambda k: k != last)
    choice = ui.select("Which SSH public key goes into the image? (it is the only key that can log in)",
                       [(k, k) for k in keys] + [("Another file...", None)]) if keys else None
    key = choice or ui.text("Path of the SSH public key").strip()
    while not Path(key).is_file():
        key = ui.text(f"not found: {key}. Path of the SSH public key").strip()
    cfg.set("build_key", key)
    return key


def build_local(fl, ui, cfg, dest):
    import images
    import shutil
    import subprocess
    from common import DEFAULT_BACKUP, PRIVATE, REPO
    if not shutil.which("docker") or subprocess.call(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
        print("  " + bad("Docker is not installed or not running: extracting the stock rootfs and packaging the image run in a container."))
        return 1
    backup = Path(ask_path(ui, cfg, "backup", "Folder with your verified backup", DEFAULT_BACKUP, True))
    rootfs_b = next(iter(sorted(backup.glob("images/*-rootfs_b.bin"))), None)
    if not rootfs_b:
        print("  " + bad(f"no rootfs_b image in {backup}/images"))
        return 1
    cache = dest / "inputs"
    cache.mkdir(parents=True, exist_ok=True)
    try:
        print("  " + paint("Fetching the public inputs (userspace, feed packages, OpenWrt ipks), each checked against its SHA-256...", "dim"))
        inputs = images.fetch_inputs(cache)
        stock = cache / "rootfs-b-system.tar.gz"
        if not stock.is_file():
            print("  " + paint("Extracting the stock rootfs from your backup in the container...", "dim"))
            if subprocess.call(["docker", "build", "-q", "-t", "x28-firmware-tools:ubi", "-f", str(REPO / "tools/firmware/Dockerfile"), str(REPO / "tools/firmware")], stdout=subprocess.DEVNULL) \
                    or subprocess.call(images.stock_command(rootfs_b, cache, REPO)) or not stock.is_file() or stock.stat().st_size < 10_000_000:
                stock.unlink(missing_ok=True)
                print("  " + bad("Could not extract the stock rootfs."))
                return 1
    except (RuntimeError, ValueError, OSError) as err:
        print("  " + bad(str(err)))
        return 1
    inputs["stock"] = str(stock)
    inputs["key"] = choose_key(ui, cfg)
    inputs["kmods"] = ask_path(ui, cfg, "build_kmods", "Folder with the built kernel modules (private SDK build)", PRIVATE / "kmods", True)
    work = dest / f"local-{images.stamp()}"
    out = dest / f"native-ubi-local-{images.stamp()}"
    print("  " + paint("Writes only under private/build. Nothing touches the router.", "dim"))
    if not ui.confirm(f"Build the image in {work.name} now? (several minutes)", True):
        return 0
    work.mkdir(parents=True)
    for cmd in images.local_commands(inputs, work, out, REPO):
        print("  " + paint("$ " + " ".join(cmd[:3]) + " ...", "dim"))
        if subprocess.call(cmd, env={**os.environ, "X28_OVERLAY": inputs["overlay"]}) != 0:
            print("  " + bad(f"Build stopped at {cmd[0]} {cmd[1]}; nothing was flashed. Folder kept: {work}"))
            return 1
    cfg.set("last_image", str(out))
    print("  " + good(f"Image built: {out}"))
    return 0


def autopilot(fl, ui, cfg):
    """Backup, build, test, rehearsal, write as one job. Each step is the menu entry itself, so every guard and
    typed phrase stays; any failure stops the run and nothing is retried or skipped."""
    from common import PRIVATE
    if fl.FROZEN:
        print("  " + warn("Auto pilot ends in a flash, which this build cannot do (#272). Run the steps from the menu, or use a source checkout."))
        return 0
    print("  " + paint("Backup, Build, Test, then a rehearsal and the write, each with its own confirmation.", "dim"))
    existing = sorted((p.parent for p in PRIVATE.glob("backups/x28-backup-*/ARCHIVE.sha256")), key=lambda d: d.stat().st_mtime, reverse=True)
    if existing and ui.confirm(f"Use the finished backup {existing[0].name} instead of making a new one?", True):
        cfg.set("backup", str(existing[0]))
    else:
        code = backup(fl, ui, cfg)
        if code != 0:
            return stopped("Backup", code)
    for title, step in (("Build", build), ("Test", test_readonly)):
        print("\n  " + paint(title, "bold"))
        code = step(fl, ui, cfg)
        if code != 0:
            return stopped(title, code)
    image = cfg.get("last_image")
    if not image or not Path(image).is_dir():
        print("  " + bad("No image from Build."))
        return 1
    base = ui.select("Image now on slot A (the base)", [("None / not known", None), ("Another folder...", "other")])
    base = ui.text("Folder of the image now on slot A") if base == "other" else base
    for title, mode in (("Rehearsal", "identical"), ("Write", "write")):
        print("\n  " + paint(title, "bold"))
        if mode == "write":
            runs = verified_identicals(PRIVATE / "usb-probe")
            if not runs:
                return stopped("Rehearsal", 1)
        code = flash(fl, ui, cfg, {"mode": mode, "candidate": image, "base": base})
        if code != 0:
            return stopped(title, code)
    print("\n  " + good("Auto pilot finished. Power-cycle the router and check it boots."))
    return 0


def stopped(step, code):
    print("  " + bad(f"Auto pilot stopped at {step} (exit {code}). Fix that, then run it again; finished steps are kept."))
    return code or 1


def test_readonly(fl, ui, cfg):
    """Everything we check before a real flash, without writing: setup, patched-library identity, then a real read."""
    check_setup(fl, ui, cfg)
    if ui.confirm("Also read lk_b from the router and compare it with your backup? (needs a power cycle)", True):
        from common import DEFAULT_BACKUP, VENDOR_DA
        import argparse
        backup = ask_path(ui, cfg, "backup", "Folder with your verified backup", DEFAULT_BACKUP, True)
        loader = ask_path(ui, cfg, "loader", "Vendor download agent file (DA_BR.bin)", VENDOR_DA, False)
        return fl.cmd_read(argparse.Namespace(partition="lk_b", backup=backup, loader=loader))
    return 0


def flash(fl, ui, cfg, preset=None):
    import argparse
    from common import DEFAULT_BACKUP, PRIVATE, VENDOR_DA
    if fl.FROZEN:
        print("  " + warn("This build is read-only. Flash from a source checkout until the build-time equality gate exists (#272)."))
        return 0
    backup = ask_path(ui, cfg, "backup", "Folder with your verified backup", DEFAULT_BACKUP, True)
    loader = ask_path(ui, cfg, "loader", "Vendor download agent file (DA_BR.bin)", VENDOR_DA, False)
    preset = preset or {}
    mode = preset.get("mode") or ui.select("Which run?", [("Rehearsal: write the image, read it back, compare (identical)", "identical"),
                                    ("Write the image (needs a verified rehearsal from the last 24 h)", "write")])
    images = [(d.name, str(d)) for d in image_dirs(PRIVATE / "build")]
    candidate = preset.get("candidate") or (ui.select("Image to flash", images + [("Another folder...", None)]) if images else None)
    candidate = candidate or ui.text("Folder with the image (package_ubi output)")
    base = preset["base"] if "base" in preset else ui.select("Image now on slot A (the base)", [("None / not known", None)] + images + [("Another folder...", "other")])
    if base == "other":
        base = ui.text("Folder of the image now on slot A")
    no_ssh = bool(preset["no_ssh"] if "no_ssh" in preset else (not base and ui.confirm(
        "No SSH to this router? Then the USB read of misc replaces the live-slot check; slot A and misc must still equal your backup (stock).", False)))
    no_uart = bool(preset["no_uart"] if "no_uart" in preset else ui.confirm(
        "No UART adapter? Then there is no boot log if the new image fails; the way back is a USB restore from your backup.", False))
    prior = None
    if mode == "write":
        runs = verified_identicals(PRIVATE / "usb-probe")
        if not runs:
            print("  " + bad("No verified rehearsal from the last 24 h. Run the rehearsal first."))
            return 1
        prior = ui.select("Rehearsal to build on", [(r.name, str(r)) for r in runs])
    print(f"\n  {mode}: {candidate}" + (f"  base {base}" if base else ""))
    if not ui.confirm("Continue to the UART and the typed confirmation?", True):
        return 0
    args = argparse.Namespace(mode=mode, candidate_dir=candidate, base_dir=base, prior_identical=prior,
                              backup_copy=None, backup=backup, loader=loader, no_ssh=no_ssh, no_uart=no_uart)
    code = fl.cmd_flash(args, ui)
    print("  " + (good("Done.") if code == 0 else bad(f"Stopped (exit {code}). The run folder above keeps the logs; nothing was retried.")))
    return code


ACTIONS = {"backup": backup, "build": build, "auto": autopilot, "test": test_readonly, "read": read_partition, "uart": watch_uart, "flash": flash}


def run_action(fl, action):
    """One step with plain numbered prompts (no terminal tricks), for the page that relays the questions."""
    return ACTIONS[action](fl, Ui(fancy=False), Config(fl.PRIVATE / "x28-flasher.json")) or 0


def run(fl, ui=None):
    ui = ui or Ui()
    cfg = Config(fl.PRIVATE / "x28-flasher.json")
    print("\n  " + paint("x28-flasher", "bold", "cyan") + paint("  ZLT X28 flash and recovery", "dim") + "\n")
    try:
        if ui.confirm("Start the UART logger now? It runs in the background for the whole session, and a flash needs it unless you have no UART adapter.", True):
            fl.start_capture(ui)
    except KeyboardInterrupt:
        print("\n  skipped; start it from the menu before flashing")
    try:
        while True:
            try:
                action = ui.select("What do you want to do?", MENU)
                if action == "quit":
                    return 0
                ACTIONS[action](fl, ui, cfg)
            except KeyboardInterrupt:
                print("\n  cancelled")
            print()
    finally:
        fl.stop_capture()
