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


def verified_identicals(probe, now=None, tools=None):
    """Rehearsal runs a write may build on: VERIFIED, younger than 24 h and, when tools is given, made with the same tool sources (the tools
    enforce the same, so a rebuild in between means running the rehearsal again)."""
    now = now or time.time()
    out = []
    for receipt in sorted(probe.glob("slot-rootfs_a-identical-*/receipt.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(receipt.read_text())
        except (OSError, ValueError):
            continue
        if data.get("status") == "VERIFIED" and 0 <= now - data.get("created", 0) <= 86400 and (tools is None or data.get("identity", {}).get("tools") == tools):
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
    import da_file
    loader = da_file.pick(cfg.get("loader"))
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


def backup_problem(path, check_hash=False):
    """Why a folder is not a usable backup, or None. Build needs a finished one: its ARCHIVE.sha256 and the rootfs_b image.
    check_hash also re-reads the archive (seconds); the cheap check only looks for the files."""
    from common import sha256_file
    path = Path(path)
    sums = path / "ARCHIVE.sha256"
    if not sums.is_file():
        return "no finished backup here (ARCHIVE.sha256 is missing); run Backup to the end first"
    if not next(iter(path.glob("images/*-rootfs_b.bin")), None):
        return "the backup has no rootfs_b image"
    if check_hash:
        want, _, name = sums.read_text().strip().partition("  ")
        if not (path / name).is_file() or sha256_file(path / name) != want:
            return "the backup archive does not match its checksum; take the backup again"
    return None


def build(fl, ui, cfg):
    """A flashable image assembled here from a GitHub release of the OpenWrt repo and the user's backup; lands in private/build/native-ubi-*,
    where Flash looks. The page passes its answers in X28_BUILD (nothing is asked); the terminal asks for them. (A prebuilt, flashable release
    image is not offered yet: images.download is kept for that.)"""
    import images
    from common import DEFAULT_BACKUP, PRIVATE
    try:
        given = json.loads(os.environ["X28_BUILD"]) if os.environ.get("X28_BUILD") else None
        if not given:
            tags = images.releases()
            given = {"backup": ask_path(ui, cfg, "backup", "Folder with your verified backup", DEFAULT_BACKUP, True),
                     "tag": ui.select("Which release should the image be built from?", [(f"{r['tag']}  {'beta' if r['beta'] else 'stable'}  {r['date']}", r["tag"]) for r in tags])}
        return build_local(fl, ui, cfg, PRIVATE / "build", given)
    except (RuntimeError, ValueError, OSError) as err:
        print("  " + bad(str(err)))
        return 1


def choose_key(ui, cfg):
    """The RSA key that goes into the stock slot (dropbear there takes ssh-rsa): picked from ~/.ssh each time, the last choice first; a new pair is made on request or when there is none."""
    import subprocess
    ssh = Path.home() / ".ssh"
    keys = sorted(str(p) for p in ssh.glob("*.pub") if p.read_text().startswith("ssh-rsa "))
    last = cfg.get("build_key")
    keys.sort(key=lambda k: k != last)
    choice = ui.select("Which RSA SSH public key gets root access? (it is the only key that can log in)",
                       [(k, k) for k in keys] + [("Make a new key pair (~/.ssh/x28_rsa)", "new"), ("Another file...", None)]) if keys else "new"
    if choice == "new":
        ssh.mkdir(mode=0o700, exist_ok=True)
        path = ssh / "x28_rsa"
        if not path.exists() and subprocess.call(["ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-C", "x28-root-access", "-f", str(path)]):
            raise RuntimeError("ssh-keygen failed")
        choice = str(path) + ".pub"
        print(f"  Using {choice} (its private key is {path}, no passphrase)")
    key = choice or ui.text("Path of the SSH public key").strip()
    while not Path(key).is_file():
        key = ui.text(f"not found: {key}. Path of the SSH public key").strip()
    cfg.set("build_key", key)
    return key


def build_local(fl, ui, cfg, dest, given):
    import images
    import shutil
    import subprocess
    from common import DEFAULT_BACKUP, PRIVATE, REPO
    if not shutil.which("docker") or subprocess.call(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
        print("  " + bad("Docker is not installed or not running: extracting the stock rootfs and packaging the image run in a container."))
        return 1
    backup = Path(given["backup"])
    problem = backup_problem(backup, check_hash=True)
    if problem:
        print("  " + bad(problem))
        return 1
    rootfs_b = next(iter(sorted(backup.glob("images/*-rootfs_b.bin"))), None)
    if not rootfs_b:
        print("  " + bad(f"no rootfs_b image in {backup}/images"))
        return 1
    cache = dest / "inputs"
    cache.mkdir(parents=True, exist_ok=True)
    try:
        print("  " + paint("Fetching the release's assembly bundle (userspace, package files, kernel modules, extra packages), checked against its SHA-256...", "dim"))
        inputs = images.fetch_inputs(cache, given["tag"])
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
    work = dest / f"local-{images.stamp()}"
    out = dest / f"native-ubi-local-{images.stamp()}"
    print("  " + paint("Writes only under private/build. Nothing touches the router.", "dim"))
    work.mkdir(parents=True)
    for cmd in images.local_commands(inputs, work, out, REPO, [sys.executable, "--run-script"] if fl.FROZEN else "python3"):
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
    from common import PRIVATE, slot_tools_digest
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
            runs = verified_identicals(PRIVATE / "usb-probe", tools=slot_tools_digest())
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
    from common import slot_tools_digest
    from common import DEFAULT_BACKUP, PRIVATE, VENDOR_DA
    given = json.loads(os.environ["X28_FLASH"]) if os.environ.get("X28_FLASH") else None  # the page's form: only the typed phrase is asked
    if given:
        backup, loader = given["backup"], given["loader"]
        preset = {k: given.get(k) for k in ("mode", "candidate", "base", "no_ssh", "no_uart")}
    else:
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
    if mode == "write" and given:
        prior = given.get("prior")
    elif mode == "write":
        runs = verified_identicals(PRIVATE / "usb-probe", tools=slot_tools_digest())
        if runs:  # a rehearsal is optional: it proves the write and read-back path first
            prior = ui.select("Rehearsal to build on", [("None: write without a rehearsal", None)] + [(r.name, str(r)) for r in runs])
        else:
            print("  " + paint("No rehearsal from the last 24 h with this version of the app: this write goes without one.", "dim"))
    print(f"\n  {mode}: {candidate}" + (f"  base {base}" if base else ""))
    if not given and not ui.confirm("Continue to the UART and the typed confirmation?", True):
        return 0
    args = argparse.Namespace(mode=mode, candidate_dir=candidate, base_dir=base, prior_identical=prior,
                              backup_copy=given.get("copy") if given else None, backup=backup, loader=loader, no_ssh=no_ssh, no_uart=no_uart)
    code = fl.cmd_flash(args, ui)
    print("  " + (good("Done.") if code == 0 else bad(f"Stopped (exit {code}). The run folder above keeps the logs; nothing was retried.")))
    return code


def b_runs(probe, mode):
    """Finished rootfs_b runs of one mode, newest first; slot_b_entry checks the receipt itself before it builds on one."""
    return sorted((p.parent for p in probe.glob(f"slot-rootfs_b-{mode}-*/receipt.json")), key=lambda d: d.stat().st_mtime, reverse=True)


def slot_b_snapshot(fl, ui, cfg):
    """A fresh read of the five partitions a slot B write is pinned to (about 130 MiB, each read twice), in place of a full backup.
    The unit is not running while it is connected, so its overlay cannot change between this read and the write; the write tool
    still compares the live partitions with it and stops on any difference. Returns the folder, or None."""
    import images
    from common import PRIVATE, SLOT_B_SNAPSHOT, VENDOR_DA
    last = cfg.get("snapshot")
    pick = ui.select("Slot B image to build from", [("Read slot B from the modem now (fresh, recommended)", "new")]
                     + ([(f"Use the last snapshot: {Path(last).name}", "last")] if last and (Path(last) / "SNAPSHOT.json").is_file() else []))
    if pick == "last":
        return last
    loader = ask_path(ui, cfg, "loader", "Vendor download agent file (DA_BR.bin)", VENDOR_DA, False)
    out = PRIVATE / "snapshots" / f"slot-b-{images.stamp()}"
    print("  " + paint("Read-only. Nothing is written to the router.", "dim"))
    fl.power_off_countdown()
    code = fl.run_tool("usb_backup.py", ["--out", str(out), "--loader", loader, "--only", ",".join(SLOT_B_SNAPSHOT)])
    if code != 0:
        print("  " + bad(f"The snapshot did not finish (exit {code}); nothing was changed."))
        return None
    cfg.set("snapshot", str(out))
    print("  " + good(f"Snapshot saved in {out}"))
    return str(out)


def flash_b(fl, ui, cfg, mode, candidate, backup=None):
    """identical | write | restore of the rootfs_b overlay tail through slot_b_entry.py (every guard and the typed phrase stay)."""
    import argparse
    from common import DEFAULT_BACKUP, PRIVATE, VENDOR_DA
    backup = backup or ask_path(ui, cfg, "backup", "Folder with a FRESH verified backup of this unit (taken just now, unit idle)", DEFAULT_BACKUP, True)
    loader = ask_path(ui, cfg, "loader", "Vendor download agent file (DA_BR.bin)", VENDOR_DA, False)
    prior = resume = None
    wanted = {"write": ("identical", "Rehearsal to build on"), "restore": ("write", "Write run to undo")}.get(mode)
    if wanted:
        runs = b_runs(PRIVATE / "usb-probe", wanted[0])
        if not runs:
            print("  " + bad(f"No {wanted[0]} run of rootfs_b found. Run the {wanted[0]} first."))
            return 1
        chosen = ui.select(wanted[1], [(r.name, str(r)) for r in runs])
        prior, resume = (chosen, None) if mode == "write" else (None, chosen)
    no_uart = ui.confirm("No UART adapter? Then there is no boot log if the image fails; the way back is a USB restore from your backup.", False)
    print(f"\n  {mode}: {candidate}")
    if not ui.confirm("Continue to the UART and the typed confirmation?", True):
        return 0
    args = argparse.Namespace(mode=mode, candidate_dir=str(candidate), backup=backup, loader=loader, backup_copy=None, no_uart=no_uart,
                              prior_identical=prior, resume=resume)
    code = fl.cmd_flash_b(args, ui)
    print("  " + (good("Done.") if code == 0 else bad(f"Stopped (exit {code}). The run folder above keeps the logs; nothing was retried.")))
    return code


def access(fl, ui, cfg):
    """Key-only SSH on the stock unit (slot B, #5): build the candidate offline in the tools container, then rehearse and write it."""
    import images
    import shutil
    import subprocess
    from common import DEFAULT_BACKUP, PRIVATE, REPO
    snap = slot_b_snapshot(fl, ui, cfg)
    if not snap:
        return 1
    backup = Path(snap)
    last = cfg.get("access_candidate")
    fresh = ui.select("Candidate image", [("Build a new one from the snapshot and an SSH key", "new")] + ([(f"Use the last one: {Path(last).name}", "last")] if last and Path(last).is_dir() else []))
    if fresh == "new":
        if not shutil.which("docker") or subprocess.call(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
            print("  " + bad("Docker is not installed or not running: the candidate is built in a container."))
            return 1
        rootfs_b = next(iter(sorted(backup.glob("images/*-rootfs_b.bin"))), None)
        if not rootfs_b:
            print("  " + bad(f"no rootfs_b image in {backup}/images"))
            return 1
        key = choose_key(ui, cfg)
        out = PRIVATE / "build" / f"stock-access-{images.stamp()}"
        out.mkdir(parents=True)
        print("  " + paint("Offline: nothing touches the router while the candidate is built.", "dim"))
        if subprocess.call(["docker", "build", "-q", "-t", "x28-firmware-tools:ubi", "-f", str(REPO / "tools/firmware/Dockerfile"), str(REPO / "tools/firmware")], stdout=subprocess.DEVNULL) \
                or subprocess.call(images.stock_access_command(rootfs_b, key, out, REPO)) \
                or not (out / "rootfs_b-access.bin").is_file() or not (out / "report.json").is_file():
            print("  " + bad(f"Could not build the candidate. Folder kept: {out}"))
            return 1
        cfg.set("access_candidate", str(out))
        last = str(out)
        print("  " + good(f"Candidate built: {out}"))
    mode = ui.select("Which run?", [("Rehearsal: rewrite the same bytes, read back, compare (identical)", "identical"),
                                    ("Write the candidate (needs a verified rehearsal)", "write")])
    return flash_b(fl, ui, cfg, mode, last, backup=backup)


def rescue(fl, ui, cfg):
    """Undo a finished rootfs_b write: restore the original overlay tail from the backup (not single-use; each try is a manual run)."""
    candidate = cfg.get("access_candidate")
    if not candidate or not Path(candidate).is_dir():
        candidate = ui.text("Folder of the candidate the write used (stock_access output)").strip()
        if not Path(candidate).is_dir():
            print("  " + bad(f"not found: {candidate}"))
            return 1
    return flash_b(fl, ui, cfg, "restore", candidate)


ACTIONS = {"backup": backup, "build": build, "auto": autopilot, "test": test_readonly, "read": read_partition, "uart": watch_uart, "flash": flash,
           "access": access, "rescue": rescue}


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
