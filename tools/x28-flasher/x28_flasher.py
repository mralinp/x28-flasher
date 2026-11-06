#!/usr/bin/env python3
"""x28-flasher: guided front end for the ZLT X28 recovery tools (#272).

Picks the UART, keeps its capture running, then hands over to the guarded tools in tools/recovery/, which
keep every guard (dry run, receipts, typed phrase, second backup copy, base hash). Nothing here writes flash itself.

    x28_flasher.py                 open the page in the browser (gui)
    x28_flasher.py wizard          the menu in the terminal
    x28_flasher.py ports           serial ports found
    x28_flasher.py uart            capture the chosen UART to a log (Ctrl-C stops)
    x28_flasher.py read [part]     read one partition by name and compare with the backup (read-only)
    x28_flasher.py flash identical|write --candidate-dir D [--base-dir D] [--prior-identical RUN]
"""
import argparse
import glob
import os
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

FROZEN = getattr(sys, "frozen", False)
RECOVERY = (Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parents[1]) / "recovery"
sys.path.insert(0, str(RECOVERY))
from common import MTK_HOME, PRIVATE, VENDOR_DA, ensure_venv  # noqa: E402

VENV_PY = MTK_HOME / "venv" / "bin" / "python"
if "--selftest" not in sys.argv:
    ensure_venv()

from wizard import Ui, bad, good, paint, pick, printable_share, warn  # noqa: E402

BACKUP_NAME = "x28-backup/complete-captured-partitions.tar"
NOISE = ("debug-console", "Bluetooth")


def list_ports():
    from serial.tools import list_ports as lp
    return [(p.device, p.description) for p in lp.comports() if not any(n in p.device for n in NOISE)]


def find_backup_copies():
    roots = ["/Volumes/*", "/media/*", "/media/*/*", "/run/media/*/*"]
    return sorted(p for r in roots for p in glob.glob(f"{r}/{BACKUP_NAME}"))


class Capture(threading.Thread):
    """Writes everything the UART sends to a log; the guarded tools demand it was updated within 60 s."""

    def __init__(self, port, baud, path):
        super().__init__(daemon=True)
        self.port, self.baud, self.path, self.stop_event, self.bytes = port, baud, path, threading.Event(), 0

    def run(self):
        import serial
        with serial.Serial(self.port, self.baud, timeout=0.5) as ser, open(self.path, "wb") as log:
            while not self.stop_event.is_set():
                data = ser.read(4096)
                if data:
                    log.write(data)
                    log.flush()
                    self.bytes += len(data)


def auto_baud(port, rates=(921600, 115200, 57600, 38400, 19200, 9600), listen=2.0):
    """Listen at each rate; the one whose bytes look like console text wins. None when the line is silent or ambiguous."""
    import serial
    best = (0.0, None)
    for rate in rates:
        with serial.Serial(port, rate, timeout=0.2) as ser:
            ser.reset_input_buffer()
            data, end = b"", time.time() + listen
            while time.time() < end:
                data += ser.read(4096)
        if len(data) >= 20 and printable_share(data) > best[0]:
            best = (printable_share(data), rate)
    return best[1] if best[0] >= 0.9 else None


SESSION = {}  # the one running logger: the serial port can be opened only once, and every step needs the same log


def default_backup_dir():
    """Beside the binary, named with the time; a source checkout keeps backups under private/."""
    return (Path(sys.executable).parent if FROZEN else PRIVATE / "backups") / time.strftime("x28-backup-%Y%m%d-%H%M%S")


def log_dir():
    """Beside the binary; a source checkout keeps it with the other run records."""
    return Path(sys.executable).parent if FROZEN else PRIVATE / "usb-probe"


def start_capture(ui=None):
    """Start the background UART logger, or return the one already running (cap, path)."""
    if os.environ.get("X28_UART_LOG"):  # the page already runs the logger; the serial port can be opened only once
        path = Path(os.environ["X28_UART_LOG"])
        print("  " + good(f"UART logger already running in the page: {path}"))
        return types.SimpleNamespace(bytes=path.stat().st_size if path.exists() else 0, is_alive=lambda: True, stop_event=threading.Event()), path
    if SESSION.get("cap") and SESSION["cap"].is_alive():
        print("  " + good(f"UART logger already running: {SESSION['path']} ({SESSION['cap'].bytes} bytes)"))
        return SESSION["cap"], SESSION["path"]
    ui = ui or Ui()
    port = ui.select("UART adapter", [(f"{d}  {desc}", d) for d, desc in list_ports()])
    baud = ui.select("Baud rate", [("Auto-detect (the router must be sending output)", 0), ("921600 (the X28 console)", 921600), ("115200", 115200)])
    if baud == 0:
        print("  listening at common rates, about 12 s...")
        baud = auto_baud(port)
        print(f"  detected {baud}" if baud else "  nothing readable heard (router silent or off); using 921600, the X28 console")
        baud = baud or 921600
    path = log_dir() / f"x28-uart-{time.strftime('%Y%m%d-%H%M%S')}.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    cap = Capture(port, baud, path)
    cap.start()
    time.sleep(3)
    print("  " + good(f"UART logger running in the background: {port} @ {baud} -> {path} ({cap.bytes} bytes so far)"))
    if not cap.bytes:
        print("  " + warn("nothing received yet.") + " A silent line is fine until the router boots, but the tools refuse a log\n"
              "  that was not updated within the last 60 s, so the baud rate must be right (the X28 console is 921600) and the router must be sending.")
    SESSION.update(cap=cap, path=path)
    return cap, path


def stop_capture():
    if SESSION.get("cap"):
        SESSION["cap"].stop_event.set()
        print("  " + good(f"UART log kept: {SESSION['path']}"))
        SESSION.clear()


def flash_cmd(args, uart, backup_copy):
    cmd = ["rootfs_a", args.mode, "--write", *tool_paths(args),
           "--candidate-dir", args.candidate_dir, "--backup-copy", str(backup_copy)]
    cmd += ["--no-uart"] if getattr(args, "no_uart", False) else ["--uart-log", str(uart)]
    for flag in ("base_dir", "prior_identical"):
        if getattr(args, flag):
            cmd += ["--" + flag.replace("_", "-"), getattr(args, flag)]
    if getattr(args, "no_ssh", False):
        cmd.append("--no-ssh")
    return cmd


def flash_b_cmd(args, uart, backup_copy):
    """slot_b_entry.py: the rootfs_b overlay tail (stock SSH access). write needs a rehearsal, restore a finished write run."""
    cmd = [args.mode, "--write", *tool_paths(args), "--candidate-dir", args.candidate_dir, "--backup-copy", str(backup_copy)]
    cmd += ["--no-uart"] if getattr(args, "no_uart", False) else ["--uart-log", str(uart)]
    for flag in ("prior_identical", "resume"):
        if getattr(args, flag, None):
            cmd += ["--" + flag.replace("_", "-"), getattr(args, flag)]
    return cmd


def run_tool(script, argv):
    """The guarded tools run in this process when frozen (no second interpreter), else under the mtkclient venv."""
    if FROZEN:
        import runpy
        sys.argv = [script, *argv]
        try:
            runpy.run_path(str(RECOVERY / script), run_name="__main__")
        except SystemExit as done:
            return done.code or 0
        return 0
    return subprocess.call([str(VENV_PY), str(RECOVERY / script), *argv])


def tool_paths(args):
    """--backup/--loader are explicit in a frozen binary: there is no repo with a private/ folder next to it."""
    out = []
    for flag in ("backup", "loader"):
        if getattr(args, flag, None):
            out += [f"--{flag}", getattr(args, flag)]
    if FROZEN and len(out) < 4:
        sys.exit("pass --backup DIR (your verified backup) and --loader FILE (the vendor download agent)")
    return out


def cmd_flash_b(args, ui=None):
    return cmd_flash(args, ui, "slot_b_entry.py", flash_b_cmd)


def cmd_flash(args, ui=None, tool="slot_entry.py", build_cmd=None):
    if FROZEN:  # auditor gate (#272): lifted by the PR that asserts the compiled library and tool sources equal the bundled copies
        sys.exit("frozen builds are read-only until the build-time equality gate exists (#272); flash from a source checkout")
    loader = Path(args.loader) if args.loader else VENDOR_DA
    if not loader.is_file():
        sys.exit(f"download agent missing: {loader}")
    ui = ui or Ui()
    copies = find_backup_copies()
    copy = args.backup_copy or (ui.select("Second backup copy (on a different drive)", [(c, c) for c in copies]) if copies else None)
    if not copy:
        sys.exit(f"no second backup copy found (looked for */{BACKUP_NAME}); pass --backup-copy")
    cap, uart = (None, None) if getattr(args, "no_uart", False) else start_capture(ui)
    print("\nNext: the tool shows the exact phrase to type (you type it yourself), then asks you to unplug the\n"
          "router for 10 s or more and plug it back in with no buttons. No retry, no automatic reboot.\n")
    try:
        return run_tool(tool, (build_cmd or flash_cmd)(args, uart, copy))
    finally:
        if uart:
            print(f"UART log: {uart}")


def power_off_countdown(seconds=10, ask=input, sleep=time.sleep):
    """The preloader only answers for ~1 s after power-on and a stuck DA needs a full power-off first."""
    ask("Unplug the router's power, then press Enter: ")
    for left in range(seconds, 0, -1):
        print(paint(f"\r  keep the power off: {left:2d} s ", "yellow"), end="", flush=True)
        sleep(1)
    print("\r" + good("off long enough. Starting the tool now; ") + paint("plug the power in as soon as it says it is waiting (no buttons).", "bold"))


def cmd_read(args):
    argv = [args.partition, *tool_paths(args)]  # before the countdown, so missing paths fail at once
    power_off_countdown()
    return run_tool("read_by_name.py", argv)


def cmd_uart(args, ui=None):
    cap, path = start_capture(ui)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cap.stop_event.set()
        print(f"\nstopped, {cap.bytes} bytes in {path}")
    return 0


def cmd_identity(args):
    """SHA-256 of the XML library the guards bind as 'host'; the build smoke test compares it with a developer install."""
    import hashlib
    from restore_entry import host_identity
    print(hashlib.sha256(host_identity().encode()).hexdigest())


def cmd_ports(args):
    for dev, desc in list_ports():
        print(f"{dev}  {desc}")


def selftest():
    answers = iter(["", "x", "2"])
    assert pick(["a", "b"], "thing", lambda _: next(answers)) == "a"
    assert pick(["a", "b"], "thing", lambda _: next(answers)) == "b"
    args = argparse.Namespace(mode="write", candidate_dir="C", base_dir="B", prior_identical="P", backup="Bk", loader="L")
    cmd = flash_cmd(args, Path("u.log"), Path("b.tar"))
    assert cmd[-4:] == ["--base-dir", "B", "--prior-identical", "P"] and "--write" in cmd and "rootfs_a" in cmd
    assert "--base-dir" not in flash_cmd(argparse.Namespace(mode="identical", candidate_dir="C", base_dir=None, prior_identical=None, backup="Bk", loader="L"),
                                         Path("u"), Path("b"))
    asked = []
    power_off_countdown(2, ask=asked.append, sleep=lambda _: None)
    assert len(asked) == 1
    print("selftest ok")


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if sys.argv[1:2] == ["--run-script"]:  # how the page runs a tool when frozen: no second interpreter to call
        import runpy
        sys.argv = sys.argv[2:]
        try:
            runpy.run_path(sys.argv[0], run_name="__main__")
        except SystemExit as done:
            return done.code or 0
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("gui").set_defaults(fn=lambda a: __import__("gui").serve(sys.modules[__name__]))
    sub.add_parser("wizard").set_defaults(fn=lambda a: __import__("wizard").run(sys.modules[__name__]))
    ru = sub.add_parser("run")  # one wizard step with plain prompts; the page runs these and relays the questions
    ru.add_argument("action", choices=("build", "test", "read", "flash", "access", "rescue"))
    ru.set_defaults(fn=lambda a: __import__("wizard").run_action(sys.modules[__name__], a.action))
    sub.add_parser("ports").set_defaults(fn=cmd_ports)
    sub.add_parser("uart").set_defaults(fn=cmd_uart)
    sub.add_parser("identity").set_defaults(fn=cmd_identity)
    r = sub.add_parser("read")
    r.add_argument("partition", nargs="?", default="lk_b")
    r.add_argument("--backup")
    r.add_argument("--loader")
    r.set_defaults(fn=cmd_read)
    f = sub.add_parser("flash")
    f.add_argument("mode", choices=("identical", "write"))
    f.add_argument("--candidate-dir", required=True)
    f.add_argument("--base-dir")
    f.add_argument("--prior-identical")
    f.add_argument("--backup-copy")
    f.add_argument("--backup")
    f.add_argument("--loader")
    f.set_defaults(fn=cmd_flash)
    args = ap.parse_args()
    if not args.cmd:  # a bare launch opens the page; `wizard` is the terminal menu
        import gui
        sys.exit(gui.serve(sys.modules[__name__]))
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
